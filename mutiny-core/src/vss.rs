use crate::authclient::MutinyAuthClient;
use crate::encrypt::{decrypt_with_key, encrypt_with_key};
use crate::utils;
use crate::DEVICE_LOCK_INTERVAL_SECS;
use crate::{error::MutinyError, logging::MutinyLogger};
use anyhow::anyhow;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use hex_conservative::DisplayHex;
use lightning::util::logger::*;
use lightning::{log_debug, log_error, log_info, log_warn};
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use utils::Mutex;

const VSS_TIMEOUT_DURATION: u64 = DEVICE_LOCK_INTERVAL_SECS * 2 * 3; // 3x the device lock lifetime

pub static VSS_MANAGER: once_cell::sync::Lazy<VssManager> =
    once_cell::sync::Lazy::new(VssManager::default);

pub struct MutinyVssClient {
    auth_client: Option<Arc<MutinyAuthClient>>,
    client: Option<reqwest::Client>,
    url: String,
    store_id: Option<String>,
    encryption_key: SecretKey,
    pub logger: Arc<MutinyLogger>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyVersion {
    pub key: String,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VssKeyValueItem {
    pub key: String,
    pub value: Value,
    pub version: u32,
}

impl VssKeyValueItem {
    /// Encrypts the value of the item using the encryption key
    /// and returns an encrypted version of the item
    pub(crate) fn encrypt(self, encryption_key: &SecretKey) -> EncryptedVssKeyValueItem {
        // should we handle this unwrap better?
        let bytes = self.value.to_string().into_bytes();

        let value = encrypt_with_key(encryption_key, &bytes);

        EncryptedVssKeyValueItem {
            key: self.key,
            value,
            version: self.version,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedVssKeyValueItem {
    pub key: String,
    pub value: Vec<u8>,
    pub version: u32,
}

impl EncryptedVssKeyValueItem {
    pub(crate) fn decrypt(
        self,
        encryption_key: &SecretKey,
    ) -> Result<VssKeyValueItem, MutinyError> {
        let decrypted = decrypt_with_key(encryption_key, self.value)?;
        let decrypted_value = String::from_utf8(decrypted)?;
        let value = serde_json::from_str(&decrypted_value)?;

        Ok(VssKeyValueItem {
            key: self.key,
            value,
            version: self.version,
        })
    }
}

impl MutinyVssClient {
    pub fn new_authenticated(
        auth_client: Arc<MutinyAuthClient>,
        url: String,
        encryption_key: SecretKey,
        logger: Arc<MutinyLogger>,
    ) -> Self {
        log_info!(logger, "Creating authenticated vss client");
        Self {
            auth_client: Some(auth_client),
            client: None,
            url,
            store_id: None, // we get this from the auth client
            encryption_key,
            logger,
        }
    }

    pub fn new_unauthenticated(
        url: String,
        encryption_key: SecretKey,
        logger: Arc<MutinyLogger>,
    ) -> Self {
        log_info!(logger, "Creating unauthenticated vss client");
        let pk = encryption_key
            .public_key(&Secp256k1::new())
            .serialize()
            .to_lower_hex_string();
        Self {
            auth_client: None,
            client: Some(reqwest::Client::new()),
            url,
            store_id: Some(pk),
            encryption_key,
            logger,
        }
    }

    async fn make_request(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
    ) -> Result<reqwest::Response, MutinyError> {
        match (self.auth_client.as_ref(), self.client.as_ref()) {
            (Some(auth_client), _) => auth_client.request(method, url, body).await,
            (None, Some(client)) => {
                let mut request = client.request(method, url);
                if let Some(body) = body {
                    request = request.json(&body);
                }
                request.send().await.map_err(|e| {
                    log_error!(self.logger, "Error making request: {e}");
                    MutinyError::Other(anyhow!("Error making request: {e}"))
                })
            }
            (None, None) => unreachable!("No auth client or http client"),
        }
    }

    pub async fn put_objects(&self, items: Vec<VssKeyValueItem>) -> Result<(), MutinyError> {
        let url = Url::parse(&format!("{}/putObjects", self.url)).map_err(|e| {
            log_error!(self.logger, "Error parsing put objects url: {e}");
            MutinyError::InvalidArgumentsError
        })?;

        let items = items
            .into_iter()
            .map(|item| item.encrypt(&self.encryption_key))
            .collect::<Vec<_>>();

        // todo do we need global version here?
        let body = json!({ "store_id": self.store_id, "transaction_items": items });

        self.make_request(Method::PUT, url, Some(body)).await?;

        Ok(())
    }

    pub async fn get_object(&self, key: &str) -> Result<VssKeyValueItem, MutinyError> {
        let url = Url::parse(&format!("{}/getObject", self.url)).map_err(|e| {
            log_error!(self.logger, "Error parsing get objects url: {e}");
            MutinyError::InvalidArgumentsError
        })?;

        let body = json!({ "store_id": self.store_id, "key": key });

        let response = self.make_request(Method::POST, url, Some(body)).await?;

        let response_text = response.text().await.map_err(|e| {
            log_error!(self.logger, "Error reading response body: {e}");
            MutinyError::FailedParsingVssValue
        })?;

        if response_text == "null" {
            log_debug!(
                self.logger,
                "Vss key not found, response is 'null' for key: {}",
                key
            );
            return Err(MutinyError::VssKeyNotFound);
        }

        let result: EncryptedVssKeyValueItem =
            serde_json::from_str(&response_text).map_err(|e| {
                log_error!(self.logger, "Error parsing get objects response: {e}");
                MutinyError::FailedParsingVssValue
            })?;

        result.decrypt(&self.encryption_key)
    }

    pub async fn list_key_versions(
        &self,
        key_prefix: Option<String>,
    ) -> Result<Vec<KeyVersion>, MutinyError> {
        let url = Url::parse(&format!("{}/listKeyVersions", self.url)).map_err(|e| {
            log_error!(self.logger, "Error parsing list key versions url: {e}");
            MutinyError::InvalidArgumentsError
        })?;

        let body = json!({ "store_id": self.store_id, "key_prefix": key_prefix });

        let result = self
            .make_request(Method::POST, url, Some(body))
            .await?
            .json()
            .await
            .map_err(|e| {
                log_error!(self.logger, "Error parsing list key versions response: {e}");
                MutinyError::Other(anyhow!("Error parsing list key versions response: {e}"))
            })?;

        Ok(result)
    }

    pub fn get_store_id(&self) -> Option<String> {
        self.store_id.clone()
    }
}

#[derive(Debug, Clone)]
pub struct VssPendingWrite {
    start_timestamp: u64,
}

pub struct VssManager {
    pub pending_writes: Arc<Mutex<HashMap<String, VssPendingWrite>>>,
    logger: Mutex<Option<Arc<MutinyLogger>>>,
}

impl Default for VssManager {
    fn default() -> Self {
        Self::new()
    }
}

impl VssManager {
    pub fn new() -> Self {
        Self {
            pending_writes: Arc::new(Mutex::new(HashMap::new())),
            logger: Mutex::new(None),
        }
    }

    pub fn get_pending_writes(&self) -> Vec<(String, VssPendingWrite)> {
        self.check_timeout();
        let writes = self
            .pending_writes
            .lock()
            .expect("Failed to lock pending writes");
        writes.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    pub fn set_logger(&self, logger: Arc<MutinyLogger>) {
        let mut guard = self.logger.lock().expect("Failed to lock logger");
        *guard = Some(logger);
    }

    pub fn on_start_write(&self, key: String, start_timestamp: u64) {
        let mut pending_writes = self
            .pending_writes
            .lock()
            .expect("Failed to lock pending writes");
        pending_writes.insert(key, VssPendingWrite { start_timestamp });
    }

    pub fn on_complete_write(&self, key: String) {
        let mut pending_writes = self
            .pending_writes
            .lock()
            .expect("Failed to lock pending writes");
        pending_writes.remove(&key);
    }

    pub fn has_in_progress(&self) -> bool {
        self.check_timeout();
        let writes = self
            .pending_writes
            .lock()
            .expect("Failed to lock pending writes");
        !writes.is_empty()
    }

    fn check_timeout(&self) {
        let current_time = utils::now().as_secs();
        let mut writes = self
            .pending_writes
            .lock()
            .expect("Failed to lock pending writes");
        let logger = {
            let guard = self.logger.lock().expect("Failed to lock logger");
            guard.clone()
        };
        writes.retain(|key, write| {
            let valid = current_time - write.start_timestamp < VSS_TIMEOUT_DURATION;
            if !valid {
                if let Some(logger) = &logger {
                    log_warn!(
                        logger,
                        "VSS write timeout: {}. VSS Manager will ignoring this record.",
                        key
                    );
                }
            }
            valid
        });
    }
}
