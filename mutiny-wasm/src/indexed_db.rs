use anyhow::{anyhow, Context};
use async_trait::async_trait;
use bip39::Mnemonic;
use futures::lock::Mutex;
use futures::FutureExt;
use gloo_utils::format::JsValueSerdeExt;
use lightning::util::logger::Logger;
use lightning::{log_debug, log_error, log_info};
use log::error;
use messagehandler::{BumpChannelClosureTransaction, CommonLnEventCallback};
use mutiny_core::event::PaymentInfo;
use mutiny_core::logging::MutinyLogger;
use mutiny_core::logging::LOGGING_KEY;
use mutiny_core::nodemanager::NodeStorage;
use mutiny_core::storage::*;
use mutiny_core::vss::*;
use mutiny_core::BroadcastTx1InMultiOut;
use mutiny_core::*;
use mutiny_core::{
    encrypt::Cipher,
    error::{MutinyError, MutinyStorageError},
};
use nodemanager::ChannelClosure;
use rexie::{ObjectStore, Rexie, TransactionMode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock};
use utils::DBTasks;
use wasm_bindgen::JsValue;

pub(crate) const WALLET_DATABASE_NAME: &str = "wallet";
pub(crate) const WALLET_OBJECT_STORE_NAME: &str = "wallet_store";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RexieContainer(Option<Rexie>);

// These are okay because we never actually send across threads in the browser
unsafe impl Send for RexieContainer {}
unsafe impl Sync for RexieContainer {}

#[derive(Clone)]
pub struct IndexedDbStorage {
    pub(crate) database: String,
    pub(crate) password: Option<String>,
    pub cipher: Option<Cipher>,
    /// In-memory cache of the wallet data
    /// This is used to avoid having to read from IndexedDB on every get.
    /// This is a RwLock because we want to be able to read from it without blocking
    memory: Arc<RwLock<HashMap<String, Value>>>,
    pub(crate) indexed_db: Arc<RwLock<RexieContainer>>,
    vss: Option<Arc<MutinyVssClient>>,
    ln_event_callback: Option<CommonLnEventCallback>,
    logger: Arc<MutinyLogger>,
    delayed_keys: Arc<Mutex<HashMap<String, DelayedKeyValueItem>>>,
    activity_index: Arc<RwLock<BTreeSet<IndexItem>>>,
    tasks: Arc<DBTasks>,
}

impl IndexedDbStorage {
    pub async fn new(
        database: String,
        password: Option<String>,
        cipher: Option<Cipher>,
        vss: Option<Arc<MutinyVssClient>>,
        ln_event_callback: Option<CommonLnEventCallback>,
        logger: Arc<MutinyLogger>,
    ) -> Result<IndexedDbStorage, MutinyError> {
        if !database.starts_with(WALLET_DATABASE_NAME) {
            log_error!(
                logger,
                "IndexedDB database must prefix with '{WALLET_DATABASE_NAME}', got '{database}'",
            );
            return Err(MutinyError::PersistenceFailed {
                source: MutinyStorageError::IndexedDBError,
            });
        }
        log_debug!(
            logger,
            "Initialize indexed DB storage with password {} cipher {}",
            password.is_some(),
            cipher.is_some()
        );
        let idx = Self::build_indexed_db_database(database.clone()).await?;
        let indexed_db = Arc::new(RwLock::new(RexieContainer(Some(idx))));
        let password = password.filter(|p| !p.is_empty());

        let map = Self::read_all(
            &indexed_db,
            password.clone(),
            cipher.clone(),
            vss.as_deref(),
            &logger,
        )
        .await?;
        let memory = Arc::new(RwLock::new(map));

        log_debug!(logger, "Complete initialize indexed DB storage");

        Ok(IndexedDbStorage {
            database,
            password,
            cipher,
            memory,
            indexed_db,
            vss,
            ln_event_callback,
            logger,
            delayed_keys: Arc::new(Mutex::new(HashMap::new())),
            activity_index: Arc::new(RwLock::new(BTreeSet::new())),
            tasks: Arc::new(Default::default()),
        })
    }

    pub(crate) async fn has_mnemonic(database: String) -> Result<bool, MutinyError> {
        let indexed_db = Self::build_indexed_db_database(database).await?;
        let tx = indexed_db
            .transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadOnly)
            .map_err(|e| {
                MutinyError::read_err(
                    anyhow!("Failed to create read only indexed db transaction: {e}").into(),
                )
            })?;

        let store = tx.store(WALLET_OBJECT_STORE_NAME).map_err(|e| {
            MutinyError::read_err(
                anyhow!("Failed to create read only indexed db store: {e}").into(),
            )
        })?;

        let key = JsValue::from(MNEMONIC_KEY);
        let read = store
            .get(&key)
            .await
            .map_err(|_| MutinyError::read_err(MutinyStorageError::IndexedDBError))?;

        Ok(!read.is_null() && !read.is_undefined())
    }

    /// Read the mnemonic from indexed db, if one does not exist,
    /// then generate a new one and save it to indexed db.
    pub(crate) async fn get_mnemonic(
        database: String,
        override_mnemonic: Option<Mnemonic>,
        password: Option<&str>,
        cipher: Option<Cipher>,
    ) -> Result<Mnemonic, MutinyError> {
        let indexed_db = Self::build_indexed_db_database(database).await?;
        let tx = indexed_db
            .transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadWrite)
            .map_err(|e| {
                MutinyError::read_err(
                    anyhow!("Failed to create indexed db transaction: {e}").into(),
                )
            })?;

        let store = tx.store(WALLET_OBJECT_STORE_NAME).map_err(|e| {
            MutinyError::read_err(anyhow!("Failed to create indexed db store: {e}").into())
        })?;

        let key = JsValue::from(MNEMONIC_KEY);
        let read = store
            .get(&key)
            .await
            .map_err(|_| MutinyError::read_err(MutinyStorageError::IndexedDBError))?;

        // if there is no mnemonic in indexed db generate a new one and insert
        let res = if read.is_null() || read.is_undefined() {
            let seed = override_mnemonic.unwrap_or_else(|| generate_seed(12).unwrap());

            // encrypt and save to indexed db
            let value = encrypt_value(MNEMONIC_KEY, serde_json::to_value(seed.clone())?, cipher)?;
            store
                .put(&JsValue::from_serde(&value)?, Some(&key))
                .await
                .map_err(|_| MutinyError::write_err(MutinyStorageError::IndexedDBError))?;

            seed
        } else {
            // if there is a mnemonic in indexed db, then decrypt it
            let value = decrypt_value(MNEMONIC_KEY, read.into_serde()?, password)?;

            // If we can't deserialize the value, then the password was incorrect when we tried to decrypt
            let seed: Mnemonic =
                serde_json::from_value(value).map_err(|_| MutinyError::IncorrectPassword)?;

            // if we hae an override mnemonic, then we need to check that it matches the one in indexed db
            if override_mnemonic.is_some_and(|m| m != seed) {
                return Err(MutinyError::InvalidMnemonic);
            }

            seed
        };

        tx.done()
            .await
            .map_err(|_| MutinyError::write_err(MutinyStorageError::IndexedDBError))?;

        Ok(res)
    }

    pub(crate) async fn get_logs(database: String) -> Result<Option<Vec<String>>, MutinyError> {
        let indexed_db = Self::build_indexed_db_database(database).await?;
        let tx = indexed_db
            .transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadOnly)
            .map_err(|e| {
                MutinyError::read_err(
                    anyhow!("Failed to create indexed db transaction: {e}").into(),
                )
            })?;

        let store = tx.store(WALLET_OBJECT_STORE_NAME).map_err(|e| {
            MutinyError::read_err(anyhow!("Failed to create indexed db store: {e}").into())
        })?;

        let key = JsValue::from(LOGGING_KEY);
        let read = store
            .get(&key)
            .await
            .map_err(|_| MutinyError::read_err(MutinyStorageError::IndexedDBError))?;

        let result: Option<Vec<String>> = read.into_serde()?;

        Ok(result)
    }

    async fn save_to_indexed_db(
        indexed_db: &Arc<RwLock<RexieContainer>>,
        items: &[(String, Value)],
    ) -> Result<(), MutinyError> {
        // Device lock is only saved to VSS
        if items.len() == 1 && items.iter().all(|(k, _)| k == DEVICE_LOCK_KEY) {
            return Ok(());
        }

        let tx = indexed_db
            .try_write()
            .map_err(|e| MutinyError::read_err(e.into()))
            .and_then(|indexed_db_lock| {
                if let Some(indexed_db) = &indexed_db_lock.0 {
                    indexed_db
                        .transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadWrite)
                        .map_err(|e| {
                            MutinyError::read_err(
                                anyhow!("Failed to create indexed db transaction: {e}").into(),
                            )
                        })
                } else {
                    Err(MutinyError::read_err(MutinyStorageError::IndexedDBError))
                }
            })?;

        let store = tx.store(WALLET_OBJECT_STORE_NAME).map_err(|e| {
            MutinyError::read_err(anyhow!("Failed to create indexed db store: {e}").into())
        })?;

        // save to indexed db
        for (key, data) in items {
            store
                .put(&JsValue::from_serde(&data)?, Some(&JsValue::from(key)))
                .await
                .map_err(|_| MutinyError::write_err(MutinyStorageError::IndexedDBError))?;
        }

        tx.done()
            .await
            .map_err(|_| MutinyError::write_err(MutinyStorageError::IndexedDBError))?;

        Ok(())
    }

    async fn delete_from_indexed_db(
        indexed_db: &Arc<RwLock<RexieContainer>>,
        keys: &[String],
    ) -> Result<(), MutinyError> {
        let tx = indexed_db
            .try_write()
            .map_err(|e| {
                error!("Failed to acquire indexed db lock: {e}");
                MutinyError::read_err(e.into())
            })
            .and_then(|indexed_db_lock| {
                if let Some(indexed_db) = &indexed_db_lock.0 {
                    indexed_db
                        .transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadWrite)
                        .map_err(|e| {
                            error!("Failed to create indexed db transaction: {e}");
                            MutinyError::read_err(
                                anyhow!("Failed to create indexed db transaction: {e}").into(),
                            )
                        })
                } else {
                    error!("No indexed db instance found");
                    Err(MutinyError::read_err(MutinyStorageError::IndexedDBError))
                }
            })?;

        let store = tx.store(WALLET_OBJECT_STORE_NAME).map_err(|e| {
            error!("Failed to create indexed db store: {e}");
            MutinyError::read_err(anyhow!("Failed to create indexed db store {e}").into())
        })?;

        // delete from indexed db
        for key in keys {
            store
                .delete(&JsValue::from(key))
                .await
                .map_err(|_| MutinyError::write_err(MutinyStorageError::IndexedDBError))?;
        }

        tx.done()
            .await
            .map_err(|_| MutinyError::write_err(MutinyStorageError::IndexedDBError))?;

        Ok(())
    }

    pub(crate) async fn read_all(
        indexed_db: &Arc<RwLock<RexieContainer>>,
        password: Option<String>,
        cipher: Option<Cipher>,
        vss: Option<&MutinyVssClient>,
        logger: &MutinyLogger,
    ) -> Result<HashMap<String, Value>, MutinyError> {
        let store = {
            let tx = indexed_db
                .try_read()
                .map_err(|e| MutinyError::read_err(e.into()))
                .and_then(|indexed_db_lock| {
                    if let Some(indexed_db) = &indexed_db_lock.0 {
                        indexed_db
                            .transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadOnly)
                            .map_err(|e| {
                                MutinyError::read_err(
                                    anyhow!("Failed to create indexed db transaction: {e}").into(),
                                )
                            })
                    } else {
                        Err(MutinyError::read_err(MutinyStorageError::IndexedDBError))
                    }
                })?;
            tx.store(WALLET_OBJECT_STORE_NAME).map_err(|e| {
                MutinyError::read_err(anyhow!("Failed to create indexed db store {e}").into())
            })?
        };

        let start = instant::Instant::now();
        // use a memory storage to handle encryption and decryption
        let map = MemoryStorage::new(password, cipher, None, None);

        let all_json = store.get_all(None, None, None, None).await.map_err(|e| {
            MutinyError::read_err(anyhow!("Failed to get all from store: {e}").into())
        })?;

        log_info!(
            logger,
            "Read {} key values from browser storage",
            all_json.len()
        );

        for (key, value) in all_json {
            let key = key
                .as_string()
                .ok_or(MutinyError::read_err(MutinyStorageError::Other(anyhow!(
                    "key from indexedDB is not a string"
                ))))?;

            // we no longer need to read this key,
            // so we can remove it from memory
            if key == NETWORK_GRAPH_KEY {
                continue;
            }

            let json: Value = value.into_serde()?;
            map.write_raw(vec![(key, json)])?;
        }
        log_debug!(
            logger,
            "Reading browser storage took {}ms",
            start.elapsed().as_millis()
        );

        match vss {
            None => {
                log_info!(logger, "No VSS configured");
                let final_map = map.memory.read().unwrap();
                Ok(final_map.clone())
            }
            Some(vss) => {
                log_info!(logger, "Reading from vss");
                let start = instant::Instant::now();
                let keys = vss.list_key_versions(None).await?;
                log_info!(logger, "Read {} keys from vss", keys.len());
                let mut futs = Vec::with_capacity(keys.len());
                for kv in keys {
                    let key = kv.key.clone();
                    futs.push(
                        Self::handle_vss_key(kv, vss, &map, logger).then(|r| async move {
                            r.with_context(|| format!("handle vss key {}", key))
                        }),
                    );
                }
                let results = futures::future::try_join_all(futs).await?;

                for (key, value) in results.into_iter().flatten() {
                    // save to memory and batch the write to local storage
                    map.write_data(key.clone(), value.clone(), None)?;
                }
                let inner_map = map.memory.read().unwrap().clone();

                if !inner_map.is_empty() {
                    let items: Vec<_> = inner_map
                        .iter()
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect();
                    // write them so we don't have to pull them down again
                    Self::save_to_indexed_db(indexed_db, &items).await?;
                }

                log_debug!(logger, "Reading VSS took {}ms", start.elapsed().as_millis());

                Ok(inner_map)
            }
        }
    }

    async fn handle_vss_key(
        kv: KeyVersion,
        vss: &MutinyVssClient,
        current: &MemoryStorage,
        logger: &MutinyLogger,
    ) -> Result<Option<(String, Value)>, MutinyError> {
        log_debug!(
            logger,
            "Found vss key {} with version {}",
            kv.key,
            kv.version
        );

        match kv.key.as_str() {
            NODES_KEY => {
                // we can get version from node storage, so we should compare
                match current.get_data::<NodeStorage>(&kv.key)? {
                    Some(local) => {
                        if local.version < kv.version {
                            let obj = vss.get_object(&kv.key).await?;
                            if serde_json::from_value::<NodeStorage>(obj.value.clone()).is_ok() {
                                return Ok(Some((kv.key, obj.value)));
                            }
                        }
                    }
                    None => {
                        let obj = vss.get_object(&kv.key).await?;
                        return Ok(Some((kv.key, obj.value)));
                    }
                }
            }
            DEVICE_LOCK_KEY => {
                // we can get version from device lock, so we should compare
                match current.get_data::<DeviceLock>(&kv.key)? {
                    Some(lock) => {
                        // we use time as version for device lock
                        if lock.time < kv.version {
                            let obj = vss.get_object(&kv.key).await?;
                            if serde_json::from_value::<DeviceLock>(obj.value.clone()).is_ok() {
                                return Ok(Some((kv.key, obj.value)));
                            }
                        }
                    }
                    None => {
                        let obj = vss.get_object(&kv.key).await?;
                        return Ok(Some((kv.key, obj.value)));
                    }
                }
            }
            SERVICE_TOKENS => {
                let obj = vss.get_object(&kv.key).await?;
                return Ok(Some((kv.key, obj.value)));
            }
            KEYCHAIN_STORE_KEY => match current
                .get_data::<VersionedValue>(&kv.key)
                .with_context(|| "read keychain data from storage")?
            {
                Some(local) => {
                    if local.version < kv.version {
                        let obj = vss.get_object(&kv.key).await?;
                        if serde_json::from_value::<VersionedValue>(obj.value.clone()).is_ok() {
                            return Ok(Some((kv.key, obj.value)));
                        }
                    }
                }
                None => {
                    let obj = vss.get_object(&kv.key).await?;
                    return Ok(Some((kv.key, obj.value)));
                }
            },
            key => {
                if key.starts_with(MONITORS_PREFIX_KEY) {
                    // we can get versions from monitors, so we should compare
                    match current.get::<Vec<u8>>(&kv.key)? {
                        Some(bytes) => {
                            let current_version = utils::get_monitor_version(&bytes);

                            // if the current version is less than the version from vss, then we want to use the vss version
                            if current_version < kv.version as u64 {
                                let obj = vss.get_object(&kv.key).await?;
                                return Ok(Some((kv.key, obj.value)));
                            } else {
                                log_debug!(
                                    logger,
                                    "Skipping vss key {} with version {}, current version is {current_version}",
                                    kv.key,
                                    kv.version
                                );
                                return Ok(None);
                            }
                        }
                        None => {
                            let obj = vss.get_object(&kv.key).await?;
                            return Ok(Some((kv.key, obj.value)));
                        }
                    }
                } else if key.starts_with(CHANNEL_MANAGER_KEY) {
                    // we can get versions from channel manager, so we should compare
                    match current.get_data::<VersionedValue>(&kv.key)? {
                        Some(local) => {
                            if local.version < kv.version {
                                let obj = vss.get_object(&kv.key).await?;
                                if serde_json::from_value::<VersionedValue>(obj.value.clone())
                                    .is_ok()
                                {
                                    return Ok(Some((kv.key, obj.value)));
                                }
                            } else {
                                log_debug!(
                                    logger,
                                    "Skipping vss key {} with version {}, current version is {}",
                                    kv.key,
                                    kv.version,
                                    local.version
                                );
                                return Ok(None);
                            }
                        }
                        None => {
                            let obj = vss.get_object(&kv.key).await?;
                            if serde_json::from_value::<VersionedValue>(obj.value.clone()).is_ok() {
                                return Ok(Some((kv.key, obj.value)));
                            }
                        }
                    }
                } else if key.starts_with(PAYMENT_INBOUND_PREFIX_KEY)
                    || key.starts_with(PAYMENT_OUTBOUND_PREFIX_KEY)
                {
                    // we can get version from payment info, so we should compare
                    match current.get_data::<PaymentInfo>(&kv.key)? {
                        Some(info) => {
                            if (info.last_update as u32) < kv.version {
                                let obj = vss.get_object(&kv.key).await?;
                                if serde_json::from_value::<PaymentInfo>(obj.value.clone()).is_ok()
                                {
                                    return Ok(Some((kv.key, obj.value)));
                                }
                            } else {
                                log_debug!(
                                    logger,
                                    "Skipping vss key {} with version {}, current version is {}",
                                    kv.key,
                                    kv.version,
                                    info.last_update
                                );
                                return Ok(None);
                            }
                        }
                        None => {
                            let obj = vss.get_object(&kv.key).await?;
                            if serde_json::from_value::<PaymentInfo>(obj.value.clone()).is_ok() {
                                return Ok(Some((kv.key, obj.value)));
                            }
                        }
                    }
                } else if key.starts_with(CHANNEL_CLOSURE_PREFIX) {
                    // we can get version from channel closure info, so we should compare
                    match current.get_data::<ChannelClosure>(&kv.key)? {
                        Some(closure) => {
                            if (closure.timestamp as u32) < kv.version {
                                let obj = vss.get_object(&kv.key).await?;
                                if serde_json::from_value::<ChannelClosure>(obj.value.clone())
                                    .is_ok()
                                {
                                    return Ok(Some((kv.key, obj.value)));
                                }
                            } else {
                                log_debug!(
                                    logger,
                                    "Skipping vss key {} with version {}, current version is {}",
                                    kv.key,
                                    kv.version,
                                    closure.timestamp
                                );
                                return Ok(None);
                            }
                        }
                        None => {
                            let obj = vss.get_object(&kv.key).await?;
                            if serde_json::from_value::<ChannelClosure>(obj.value.clone()).is_ok() {
                                return Ok(Some((kv.key, obj.value)));
                            }
                        }
                    }
                } else if key.starts_with(CHANNEL_CLOSURE_BUMP_PREFIX) {
                    // we can get version from channel closure bumping info, so we should compare
                    match current.get_data::<BumpChannelClosureTransaction>(&kv.key)? {
                        Some(closure) => {
                            if (closure.timestamp as u32) < kv.version {
                                let obj = vss.get_object(&kv.key).await?;
                                if serde_json::from_value::<BumpChannelClosureTransaction>(
                                    obj.value.clone(),
                                )
                                .is_ok()
                                {
                                    return Ok(Some((kv.key, obj.value)));
                                }
                            } else {
                                log_debug!(
                                    logger,
                                    "Skipping vss key {} with version {}, current version is {}",
                                    kv.key,
                                    kv.version,
                                    closure.timestamp
                                );
                                return Ok(None);
                            }
                        }
                        None => {
                            let obj = vss.get_object(&kv.key).await?;
                            if serde_json::from_value::<BumpChannelClosureTransaction>(
                                obj.value.clone(),
                            )
                            .is_ok()
                            {
                                return Ok(Some((kv.key, obj.value)));
                            }
                        }
                    }
                } else if key.starts_with(BROADCAST_TX_1_IN_MULTI_OUT) {
                    match current.get_data::<BroadcastTx1InMultiOut>(&kv.key)? {
                        Some(tx) => {
                            if (tx.timestamp as u32) < kv.version {
                                let obj = vss.get_object(&kv.key).await?;
                                if serde_json::from_value::<BroadcastTx1InMultiOut>(
                                    obj.value.clone(),
                                )
                                .is_ok()
                                {
                                    return Ok(Some((kv.key, obj.value)));
                                }
                            } else {
                                log_debug!(
                                    logger,
                                    "Skipping vss key {} with version {}, current version is {}",
                                    kv.key,
                                    kv.version,
                                    tx.timestamp
                                );
                                return Ok(None);
                            }
                        }
                        None => {
                            let obj = vss.get_object(&kv.key).await?;
                            if serde_json::from_value::<BroadcastTx1InMultiOut>(obj.value.clone())
                                .is_ok()
                            {
                                return Ok(Some((kv.key, obj.value)));
                            }
                        }
                    }
                }
            }
        }

        log_debug!(
            logger,
            "Skipping vss key {} with version {}",
            kv.key,
            kv.version
        );

        Ok(None)
    }

    async fn build_indexed_db_database(database: String) -> Result<Rexie, MutinyError> {
        if database.is_empty() {
            return Err(MutinyError::PersistenceFailed {
                source: MutinyStorageError::IndexedDBError,
            });
        }
        let rexie = Rexie::builder(&database)
            .version(1)
            .add_object_store(ObjectStore::new(WALLET_OBJECT_STORE_NAME))
            .build()
            .await
            .map_err(|e| {
                MutinyError::read_err(anyhow!("Failed to create indexed db database {e}").into())
            })?;

        Ok(rexie)
    }

    #[cfg(test)]
    pub(crate) async fn reload_from_indexed_db(&self) -> Result<(), MutinyError> {
        let map = Self::read_all(
            &self.indexed_db,
            self.password.clone(),
            self.cipher.clone(),
            self.vss.as_deref(),
            &self.logger,
        )
        .await?;
        let mut memory = self
            .memory
            .try_write()
            .map_err(|e| MutinyError::write_err(e.into()))?;
        *memory = map;
        Ok(())
    }
}

/// Some values only are read once, so we can remove them from memory after reading them
/// to save memory.
///
/// We also need to skip writing them to the in memory storage on updates.
fn used_once(key: &str) -> bool {
    match key {
        NETWORK_GRAPH_KEY | PROB_SCORER_KEY | GOSSIP_SYNC_TIME_KEY | BITCOIN_PRICE_CACHE_KEY => {
            true
        }
        str if str.starts_with(MONITORS_PREFIX_KEY) => true,
        str if str.starts_with(CHANNEL_MANAGER_KEY) => true,
        _ => false,
    }
}

#[async_trait(?Send)]
impl MutinyStorage for IndexedDbStorage {
    fn database(&self) -> Result<String, MutinyError> {
        Ok(self.database.clone())
    }

    fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    fn cipher(&self) -> Option<Cipher> {
        self.cipher.to_owned()
    }

    fn vss_client(&self) -> Option<Arc<MutinyVssClient>> {
        self.vss.clone()
    }

    fn ln_event_callback(&self) -> Option<CommonLnEventCallback> {
        self.ln_event_callback.clone()
    }

    fn activity_index(&self) -> Arc<RwLock<BTreeSet<IndexItem>>> {
        self.activity_index.clone()
    }

    fn write_raw<T>(&self, items: Vec<(String, T)>) -> Result<(), MutinyError>
    where
        T: Serialize + Send,
    {
        let items = items
            .into_iter()
            .map(|(k, v)| {
                serde_json::to_value(v)
                    .map_err(|e| MutinyError::PersistenceFailed {
                        source: MutinyStorageError::SerdeError { source: e },
                    })
                    .map(|d| (k, d))
            })
            .collect::<Result<Vec<(String, Value)>, MutinyError>>()?;

        let indexed_db = self.indexed_db.clone();
        let items_clone = items.clone();

        // write to index DB in background job
        self.spawn(async move {
            Self::save_to_indexed_db(&indexed_db, &items_clone)
                .await
                .map_err(|e| MutinyError::PersistenceFailed {
                    source: MutinyStorageError::Other(anyhow!(
                        "Failed to save ({items_clone:?}) to indexed db: {e}"
                    )),
                })
        });

        // some values only are read once, so we don't need to write them to memory,
        // just need them in indexed db for next time
        let mut map = self
            .memory
            .try_write()
            .map_err(|e| MutinyError::write_err(e.into()))?;
        for (key, data) in items {
            if !used_once(key.as_ref()) {
                map.insert(key, data);
            }
        }

        Ok(())
    }

    fn get<T>(&self, key: impl AsRef<str>) -> Result<Option<T>, MutinyError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let map = self
            .memory
            .try_read()
            .map_err(|e| MutinyError::read_err(e.into()))?;
        match map.get(key.as_ref()).cloned() {
            None => Ok(None),
            Some(value) => {
                // drop the map so we aren't holding the lock while deserializing
                // we also need to drop if we are going to remove the value from memory
                drop(map);

                let data: T = serde_json::from_value(value)?;

                // some values only are read once, so we can remove them from memory
                let mut map = self
                    .memory
                    .try_write()
                    .map_err(|e| MutinyError::write_err(e.into()))?;
                if used_once(key.as_ref()) {
                    map.remove(key.as_ref());
                }

                Ok(Some(data))
            }
        }
    }

    fn delete(&self, keys: &[impl AsRef<str>]) -> Result<(), MutinyError> {
        let keys: Vec<String> = keys.iter().map(|k| k.as_ref().to_string()).collect();

        let indexed_db = self.indexed_db.clone();
        let keys_clone = keys.clone();

        self.spawn(async move {
            Self::delete_from_indexed_db(&indexed_db, &keys_clone)
                .await
                .map_err(|e| MutinyError::PersistenceFailed {
                    source: MutinyStorageError::Other(anyhow!(
                        "Failed to delete ({keys_clone:?}) from indexed db: {e}"
                    )),
                })
        });

        let mut map = self
            .memory
            .try_write()
            .map_err(|e| MutinyError::write_err(e.into()))?;

        for key in keys {
            map.remove(&key);
        }

        Ok(())
    }

    async fn start(&mut self) -> Result<(), MutinyError> {
        log_debug!(self.logger, "starting storage");
        let indexed_db = if self.indexed_db.try_read()?.0.is_none() {
            Arc::new(RwLock::new(RexieContainer(Some(
                Self::build_indexed_db_database(self.database.clone()).await?,
            ))))
        } else {
            self.indexed_db.clone()
        };

        let map = Self::read_all(
            &indexed_db,
            self.password.clone(),
            self.cipher.clone(),
            self.vss.as_deref(),
            &self.logger,
        )
        .await?;
        let memory = Arc::new(RwLock::new(map));
        self.indexed_db = indexed_db;
        self.memory = memory;
        log_debug!(self.logger, "started storage");
        Ok(())
    }

    fn spawn<Fut: futures::future::Future<Output = Result<(), MutinyError>> + 'static>(
        &self,
        fut: Fut,
    ) {
        let logger = self.logger.clone();
        let tasks = self.tasks.clone();
        tasks.inc_started();
        utils::spawn(async move {
            if let Err(err) = fut.await {
                log_error!(logger, "DBTask error {:?}", err);
            }
            tasks.inc_done();
        })
    }

    async fn stop(&self) {
        log_debug!(self.logger, "stopping storage");
        // Wait all back ground tasks
        self.tasks.wait().await;

        // close DB
        if let Ok(mut indexed_db_lock) = self.indexed_db.try_write() {
            if let Some(indexed_db) = indexed_db_lock.0.take() {
                indexed_db.close();
            }
        }
        log_debug!(self.logger, "stopped storage");
    }

    fn connected(&self) -> Result<bool, MutinyError> {
        Ok(self.indexed_db.try_read()?.0.is_some())
    }

    fn scan_keys(&self, prefix: &str, suffix: Option<&str>) -> Result<Vec<String>, MutinyError> {
        let map = self
            .memory
            .try_read()
            .map_err(|e| MutinyError::read_err(e.into()))?;

        Ok(map
            .keys()
            .filter(|key| {
                key.starts_with(prefix) && (suffix.is_none() || key.ends_with(suffix.unwrap()))
            })
            .cloned()
            .collect())
    }

    fn change_password(
        &mut self,
        new: Option<String>,
        new_cipher: Option<Cipher>,
    ) -> Result<(), MutinyError> {
        self.password = new;
        self.cipher = new_cipher;
        Ok(())
    }

    async fn import(database: String, json: Value) -> Result<(), MutinyError> {
        Self::clear(database.clone()).await?;
        let indexed_db = Self::build_indexed_db_database(database).await?;
        let tx = indexed_db
            .transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadWrite)
            .map_err(|e| {
                MutinyError::write_err(
                    anyhow!("Failed to create indexed db transaction: {e}").into(),
                )
            })?;
        let store = tx.store(WALLET_OBJECT_STORE_NAME).map_err(|e| {
            MutinyError::write_err(anyhow!("Failed to create indexed db store: {e}").into())
        })?;

        let map = json
            .as_object()
            .ok_or(MutinyError::write_err(MutinyStorageError::Other(anyhow!(
                "json is not an object"
            ))))?;

        for (key, value) in map {
            let key = JsValue::from(key);
            let value = JsValue::from_serde(&value)?;
            store.put(&value, Some(&key)).await.map_err(|e| {
                MutinyError::write_err(anyhow!("Failed to write to indexed db: {e}").into())
            })?;
        }

        tx.done().await.map_err(|e| {
            MutinyError::write_err(anyhow!("Failed to write to indexed db: {e}").into())
        })?;
        indexed_db.close();

        Ok(())
    }

    async fn clear(database: String) -> Result<(), MutinyError> {
        let indexed_db = Self::build_indexed_db_database(database).await?;
        let tx = indexed_db
            .transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadWrite)
            .map_err(|e| MutinyError::write_err(anyhow!("Failed clear indexed db: {e}").into()))?;
        let store = tx
            .store(WALLET_OBJECT_STORE_NAME)
            .map_err(|e| MutinyError::write_err(anyhow!("Failed clear indexed db: {e}").into()))?;

        store
            .clear()
            .await
            .map_err(|e| MutinyError::write_err(anyhow!("Failed clear indexed db: {e}").into()))?;

        tx.done()
            .await
            .map_err(|e| MutinyError::write_err(anyhow!("Failed clear indexed db: {e}").into()))?;

        Ok(())
    }

    async fn fetch_device_lock(&self) -> Result<Option<DeviceLock>, MutinyError> {
        match self.vss.as_ref() {
            None => self.get_device_lock(),
            Some(vss) => {
                let json = vss.get_object(DEVICE_LOCK_KEY).await?;
                let device_lock = serde_json::from_value(json.value)?;
                Ok(Some(device_lock))
            }
        }
    }

    fn get_delayed_objects(&self) -> Arc<Mutex<HashMap<String, DelayedKeyValueItem>>> {
        self.delayed_keys.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexed_db::IndexedDbStorage;
    use crate::utils::test::log;
    use bip39::Mnemonic;
    use mutiny_core::storage::MutinyStorage;
    use mutiny_core::utils::sleep;
    use mutiny_core::{encrypt::encryption_key_from_pass, logging::MutinyLogger};
    use serde_json::json;
    use std::str::FromStr;
    use std::sync::Arc;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn test_empty_string_as_none() {
        let test_name = "test_empty_string_as_none";
        log!("{test_name}");

        let logger = Arc::new(MutinyLogger::default());
        let storage = IndexedDbStorage::new(
            WALLET_DATABASE_NAME.to_string(),
            Some("".to_string()),
            None,
            None,
            None,
            logger,
        )
        .await
        .unwrap();

        assert_eq!(storage.password, None);
    }

    #[test]
    async fn test_get_set_delete() {
        let test_name = "test_get_set_delete";
        log!("{test_name}");

        let key = "test_key".to_string();
        let value = "test_value";

        let logger = Arc::new(MutinyLogger::default());
        let password = "password".to_string();
        let cipher = encryption_key_from_pass(&password).unwrap();
        let storage = IndexedDbStorage::new(
            WALLET_DATABASE_NAME.to_string(),
            Some(password),
            Some(cipher),
            None,
            None,
            logger,
        )
        .await
        .unwrap();

        let result: Option<String> = storage.get(&key).unwrap();
        assert_eq!(result, None);

        storage.write_raw(vec![(key.clone(), value)]).unwrap();

        let result: Option<String> = storage.get(&key).unwrap();
        assert_eq!(result, Some(value.to_string()));

        // wait for the storage to be persisted
        sleep(1_000).await;
        // reload and check again
        storage.reload_from_indexed_db().await.unwrap();
        let result: Option<String> = storage.get(&key).unwrap();
        assert_eq!(result, Some(value.to_string()));

        storage.delete(&[key.clone()]).unwrap();

        let result: Option<String> = storage.get(&key).unwrap();
        assert_eq!(result, None);

        // wait for the storage to be persisted
        sleep(1_000).await;
        // reload and check again
        storage.reload_from_indexed_db().await.unwrap();
        let result: Option<String> = storage.get(&key).unwrap();
        assert_eq!(result, None);

        // clear the storage to clean up
        IndexedDbStorage::clear(WALLET_DATABASE_NAME.to_string())
            .await
            .unwrap();
    }

    #[test]
    async fn test_import() {
        let test_name = "test_import";
        log!("{test_name}");

        let json = json!(
            {
                "test_key": "test_value",
                "test_key2": "test_value2"
            }
        );

        IndexedDbStorage::import(WALLET_DATABASE_NAME.to_string(), json)
            .await
            .unwrap();

        let logger = Arc::new(MutinyLogger::default());
        let password = "password".to_string();
        let cipher = encryption_key_from_pass(&password).unwrap();
        let storage = IndexedDbStorage::new(
            WALLET_DATABASE_NAME.to_string(),
            Some(password),
            Some(cipher),
            None,
            None,
            logger,
        )
        .await
        .unwrap();

        let result: Option<String> = storage.get("test_key").unwrap();
        assert_eq!(result, Some("test_value".to_string()));

        let result: Option<String> = storage.get("test_key2").unwrap();
        assert_eq!(result, Some("test_value2".to_string()));

        // clear the storage to clean up
        IndexedDbStorage::clear(WALLET_DATABASE_NAME.to_string())
            .await
            .unwrap();
    }

    #[test]
    async fn test_clear() {
        let test_name = "test_clear";
        log!("{test_name}");

        let key = "test_key".to_string();
        let value = "test_value";

        let logger = Arc::new(MutinyLogger::default());
        let password = "password".to_string();
        let cipher = encryption_key_from_pass(&password).unwrap();
        let storage = IndexedDbStorage::new(
            WALLET_DATABASE_NAME.to_string(),
            Some(password),
            Some(cipher),
            None,
            None,
            logger,
        )
        .await
        .unwrap();

        storage.write_raw(vec![(key.clone(), value)]).unwrap();

        IndexedDbStorage::clear(WALLET_DATABASE_NAME.to_string())
            .await
            .unwrap();

        storage.reload_from_indexed_db().await.unwrap();

        let result: Option<String> = storage.get(key).unwrap();
        assert_eq!(result, None);

        // clear the storage to clean up
        IndexedDbStorage::clear(WALLET_DATABASE_NAME.to_string())
            .await
            .unwrap();
    }

    #[test]
    async fn insert_and_get_mnemonic_no_password() {
        let test_name = "insert_and_get_mnemonic_no_password";
        log!("{test_name}");

        let seed = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").expect("could not generate");

        let logger = Arc::new(MutinyLogger::default());
        let storage = IndexedDbStorage::new(
            WALLET_DATABASE_NAME.to_string(),
            None,
            None,
            None,
            None,
            logger,
        )
        .await
        .unwrap();
        let mnemonic = storage.insert_mnemonic(seed).unwrap();

        let stored_mnemonic = storage.get_mnemonic().unwrap();
        assert_eq!(Some(mnemonic), stored_mnemonic);

        // clear the storage to clean up
        IndexedDbStorage::clear(WALLET_DATABASE_NAME.to_string())
            .await
            .unwrap();
    }

    #[test]
    async fn insert_and_get_mnemonic_with_password() {
        let test_name = "insert_and_get_mnemonic_with_password";
        log!("{test_name}");

        let seed = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").expect("could not generate");

        let logger = Arc::new(MutinyLogger::default());
        let password = "password".to_string();
        let cipher = encryption_key_from_pass(&password).unwrap();
        let storage = IndexedDbStorage::new(
            WALLET_DATABASE_NAME.to_string(),
            Some(password),
            Some(cipher),
            None,
            None,
            logger,
        )
        .await
        .unwrap();

        let mnemonic = storage.insert_mnemonic(seed).unwrap();

        let stored_mnemonic = storage.get_mnemonic().unwrap();
        assert_eq!(Some(mnemonic), stored_mnemonic);

        // clear the storage to clean up
        IndexedDbStorage::clear(WALLET_DATABASE_NAME.to_string())
            .await
            .unwrap();
    }

    #[test]
    async fn test_correct_incorrect_password_error() {
        let test_name = "test_correct_incorrect_password_error";
        log!("{test_name}");
        let logger = Arc::new(MutinyLogger::default());

        let storage = IndexedDbStorage::new(
            WALLET_DATABASE_NAME.to_string(),
            None,
            None,
            None,
            None,
            logger.clone(),
        )
        .await
        .unwrap();
        let seed = generate_seed(12).unwrap();
        storage
            .write_data(MNEMONIC_KEY.to_string(), seed, None)
            .unwrap();
        // wait for the storage to be persisted
        utils::sleep(1_000).await;

        let password = Some("password".to_string());
        let cipher = password
            .as_ref()
            .filter(|p| !p.is_empty())
            .map(|p| encryption_key_from_pass(p))
            .transpose()
            .unwrap();

        let storage = IndexedDbStorage::new(
            WALLET_DATABASE_NAME.to_string(),
            password,
            cipher,
            None,
            None,
            logger,
        )
        .await
        .unwrap();

        match storage.get_mnemonic() {
            Err(MutinyError::IncorrectPassword) => (),
            Ok(_) => panic!("Expected IncorrectPassword error, got Ok"),
            Err(e) => panic!("Expected IncorrectPassword error, got {:?}", e),
        }

        // clear the storage to clean up
        IndexedDbStorage::clear(WALLET_DATABASE_NAME.to_string())
            .await
            .unwrap();
    }
}
