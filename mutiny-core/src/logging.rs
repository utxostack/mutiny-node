use std::sync::Arc;

use crate::utils::Mutex;
use crate::{error::MutinyError, utils, utils::sleep};
use crate::{storage::MutinyStorage, utils::StopHandle};
use chrono::Utc;
use hex_conservative::DisplayHex;
use lightning::util::logger::{Level, Logger, Record};
use log::*;

pub const LOGGING_KEY: &str = "logs";

const MAX_LOG_ITEMS: usize = 10_000;

#[derive(Clone)]
pub struct MutinyLogger {
    pub session_id: String,
    should_write: bool,
    should_persist: bool,
    memory_logs: Arc<Mutex<Vec<String>>>,
    stop_handle: Option<StopHandle>,
}

impl MutinyLogger {
    pub fn memory_only() -> Self {
        Self {
            should_persist: false,
            should_write: true,
            ..Default::default()
        }
    }

    pub fn with_writer<S: MutinyStorage>(
        logging_db: S,
        session_id: Option<String>,
        logs: Vec<String>,
    ) -> Self {
        let memory_logs = Arc::new(Mutex::new(logs));

        let stop_handle = utils::spawn_with_handle({
            let memory_logs = memory_logs.clone();
            |stop_signal| {
                async move {
                    loop {
                        // wait up to 5s, checking graceful shutdown check each 1s.
                        for _ in 0..5 {
                            if stop_signal.stopping() {
                                logging_db.stop().await;
                                return;
                            }
                            sleep(1_000).await;
                        }

                        // if there's any in memory logs, append them to the file system
                        let memory_logs_clone = {
                            if let Ok(mut memory_logs) = memory_logs.lock() {
                                let logs = memory_logs.clone();
                                memory_logs.clear();
                                Some(logs)
                            } else {
                                warn!("Failed to lock memory_logs, log entries may be lost.");
                                None
                            }
                        };

                        if let Some(logs) = memory_logs_clone {
                            if !logs.is_empty() {
                                // append them to storage
                                match write_logging_data(&logging_db, logs) {
                                    Ok(_) => {}
                                    Err(_) => {
                                        error!("could not write logging data to storage, trying again next time, log entries may be lost");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        MutinyLogger {
            session_id: session_id.unwrap_or_else(gen_session_id),
            should_write: true,
            should_persist: true,
            memory_logs,
            stop_handle: Some(stop_handle),
        }
    }

    pub fn get_memory_logs(&self) -> Result<Vec<String>, MutinyError> {
        let logs = self
            .memory_logs
            .lock()
            .map_err(|_err| MutinyError::Other(anyhow::anyhow!("can't get memory logs lock")))?
            .to_vec();
        Ok(logs)
    }

    pub(crate) fn get_logs<S: MutinyStorage>(
        &self,
        storage: &S,
    ) -> Result<Option<Vec<String>>, MutinyError> {
        if !self.should_write || !self.should_persist {
            return Ok(None);
        }
        get_logging_data(storage)
    }

    pub(crate) async fn stop(&self) {
        if let Some(stop_handle) = self.stop_handle.as_ref() {
            stop_handle.stop().await
        }
    }
}

impl Default for MutinyLogger {
    fn default() -> Self {
        Self {
            session_id: gen_session_id(),
            should_write: false,
            should_persist: false,
            memory_logs: Arc::new(Mutex::new(vec![])),
            stop_handle: None,
        }
    }
}

fn gen_session_id() -> String {
    let mut entropy = vec![0u8; 2];
    getrandom::getrandom(&mut entropy).unwrap();
    entropy.to_lower_hex_string()
}

impl Logger for MutinyLogger {
    fn log(&self, record: Record) {
        let raw_log = record.args.to_string();
        let log = format!(
            "{} {} {:<5} [{}:{}] {}\n",
            // Note that a "real" lightning node almost certainly does *not* want subsecond
            // precision for message-receipt information as it makes log entries a target for
            // deanonymization attacks. For testing, however, its quite useful.
            Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            // log the session id so we can tie logs to a particular session, useful for detecting
            // if we have multiple sessions running at once
            self.session_id,
            record.level,
            record.module_path,
            record.line,
            raw_log
        );

        if self.should_write && record.level >= Level::Trace {
            if let Ok(mut memory_logs) = self.memory_logs.lock() {
                memory_logs.push(log.clone());
            } else {
                warn!("Failed to lock memory_logs, log entry may be lost.");
            }
        }

        match record.level {
            Level::Gossip => (), // way too noisy
            Level::Trace => trace!("{}", log),
            Level::Debug => debug!("{}", log),
            Level::Info => info!("{}", log),
            Level::Warn => warn!("{}", log),
            Level::Error => error!("{}", log),
        }
    }
}

fn get_logging_data<S: MutinyStorage>(storage: &S) -> Result<Option<Vec<String>>, MutinyError> {
    storage.get_data(LOGGING_KEY)
}

fn write_logging_data<S: MutinyStorage>(
    storage: &S,
    mut recent_logs: Vec<String>,
) -> Result<(), MutinyError> {
    // get the existing data so we can append to it, trimming if needed
    // Note there is a potential race condition here if the logs are being written to
    // concurrently, but we don't care about that for now.
    let mut existing_logs: Vec<String> = get_logging_data(storage)?.unwrap_or_default();
    existing_logs.append(&mut recent_logs);
    if existing_logs.len() > MAX_LOG_ITEMS {
        let start_index = existing_logs.len() - MAX_LOG_ITEMS;
        existing_logs.drain(..start_index);
    }

    // Save the logs
    storage.write_data(LOGGING_KEY.to_string(), &existing_logs, None)?;

    Ok(())
}

#[cfg(test)]
use crate::test_utils::log;

#[cfg(test)]
#[derive(Clone)]
pub struct TestLogger {}

#[cfg(test)]
impl Logger for TestLogger {
    fn log(&self, record: Record) {
        let raw_log = record.args.to_string();
        let log = format!(
            "{} {:<5} [{}:{}] {}\n",
            // Note that a "real" lightning node almost certainly does *not* want subsecond
            // precision for message-receipt information as it makes log entries a target for
            // deanonymization attacks. For testing, however, its quite useful.
            Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            record.level,
            record.module_path,
            record.line,
            raw_log
        );

        log!("{}", log);
    }
}

#[cfg(test)]
mod tests {
    use lightning::{log_debug, util::logger::Logger};
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    use crate::{test_utils::*, utils::sleep};

    use crate::logging::MutinyLogger;
    use crate::storage::MemoryStorage;

    #[test]
    async fn log_without_storage() {
        let test_name = "log_without_storage";
        log!("{}", test_name);

        let logger = MutinyLogger::default();
        assert_eq!(logger.get_logs(&()).unwrap(), None);

        log_debug!(logger, "testing");

        // saves every 5s, so do one second later
        sleep(6_000).await;

        assert_eq!(logger.get_logs(&()).unwrap(), None);
    }

    #[test]
    async fn log_with_storage() {
        let test_name = "log_with_storage";
        log!("{}", test_name);

        let storage = MemoryStorage::default();

        let logger = MutinyLogger::with_writer(storage.clone(), None, Default::default());

        let log_str = "testing logging with storage";
        log_debug!(logger, "{}", log_str);

        // saves every 5s, so do one second later
        sleep(6_000).await;

        assert!(logger
            .get_logs(&storage)
            .unwrap()
            .unwrap()
            .first()
            .unwrap()
            .contains(log_str));

        logger.stop().await;
    }
}
