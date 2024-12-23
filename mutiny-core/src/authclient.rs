use crate::{authmanager::AuthManager, error::MutinyError, logging::MutinyLogger, utils};
use async_lock::RwLock;
use bitcoin::hashes::{hex::prelude::*, sha256, Hash};
use bitcoin::key::rand::Rng;
use bitcoin::secp256k1::rand::thread_rng;
use jwt_compact::UntrustedToken;
use lightning::{log_debug, log_error, log_info};
use lightning::{log_trace, util::logger::*};
use reqwest::Client;
use reqwest::{Method, StatusCode, Url};
use serde_json::Value;

use std::sync::Arc;

pub struct MutinyAuthClient {
    pub auth: AuthManager,
    url: String,
    http_client: Client,
    jwt: RwLock<Option<String>>,
    logger: Arc<MutinyLogger>,
}

impl MutinyAuthClient {
    pub fn new(auth: AuthManager, logger: Arc<MutinyLogger>, url: String) -> Self {
        let http_client = Client::new();
        Self {
            auth,
            url,
            http_client,
            jwt: RwLock::new(None),
            logger,
        }
    }

    pub async fn authenticate(&self) -> Result<(), MutinyError> {
        self.retrieve_new_jwt().await?;
        Ok(())
    }

    pub async fn is_authenticated(&self) -> Option<String> {
        let lock = self.jwt.read().await;
        if let Some(jwt) = lock.as_ref() {
            return Some(jwt.to_string()); // TODO parse and make sure still valid
        }
        None
    }

    pub async fn request(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
    ) -> Result<reqwest::Response, MutinyError> {
        let res = self
            .authenticated_request(method.clone(), url.clone(), body.clone())
            .await?;
        match res.status() {
            // If we get a 401, refresh the JWT and try again
            StatusCode::UNAUTHORIZED => {
                self.retrieve_new_jwt().await?;
                self.authenticated_request(method, url, body).await
            }
            StatusCode::OK | StatusCode::ACCEPTED | StatusCode::CREATED => Ok(res),
            code => {
                log_error!(self.logger, "Received unexpected status code: {code}");
                Err(MutinyError::ConnectionFailed)
            }
        }
    }

    async fn authenticated_request(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
    ) -> Result<reqwest::Response, MutinyError> {
        log_trace!(self.logger, "Doing an authenticated request {url:?}");

        let mut request = self.http_client.request(method, url);

        let mut jwt = self.is_authenticated().await;
        if jwt.is_none() {
            jwt = Some(self.retrieve_new_jwt().await?);
        }
        request = request.bearer_auth(jwt.expect("either had one or retrieved new"));

        if let Some(json) = body {
            request = request.json(&json);
        }

        utils::fetch_with_timeout(
            &self.http_client,
            request.build().expect("should build req"),
        )
        .await
    }

    // TODO: Multiple concurrent `retrieve_new_jwt` calls could trigger multiple token refreshes.
    // In a future PR, maybe we can add JWT parsing and validation before initiating a new token request.
    async fn retrieve_new_jwt(&self) -> Result<String, MutinyError> {
        let mut lock = self.jwt.write().await;
        log_debug!(self.logger, "Retrieving new JWT token");

        let jwt_url = self.url.clone();

        // message: timestamp + '-' + random data
        let timestamp = utils::now().as_secs() - 1;
        let random_data: u64 = thread_rng().gen_range(u32::MAX as u64..u64::MAX);
        let challenge = format!("{}-{}", timestamp, random_data);

        let hashed_msg = sha256::Hash::hash(challenge.as_bytes());
        let (sig, pubkey) = self.auth.sign(hashed_msg.as_ref())?;

        let sig_hex = format!("{:x}", sig.serialize_der().as_hex());
        let pubkey_hex = format!("{:x}", pubkey.serialize().as_hex());

        let response = self
            .http_client
            .post(&jwt_url)
            .json(&serde_json::json!({
                "public_key": pubkey_hex,
                "signature": sig_hex,
                "challenge": challenge,
            }))
            .send()
            .await
            .map_err(|e| {
                log_error!(self.logger, "JWT auth request failed: {e}");
                MutinyError::JwtAuthFailure
            })?;

        if response.status().is_success() {
            let response_text = response
                .text()
                .await
                .map_err(|_| MutinyError::JwtAuthFailure)?;

            let jwt: String = serde_json::from_str::<Value>(&response_text)
                .map_err(|_| MutinyError::JwtAuthFailure)?
                .get("token")
                .and_then(|token| token.as_str().map(String::from))
                .ok_or(MutinyError::JwtAuthFailure)?;

            // basic validation to make sure it is a valid string
            let _ = UntrustedToken::new(&jwt).map_err(|e| {
                log_error!(self.logger, "Could not validate JWT {jwt}: {e}");
                MutinyError::JwtAuthFailure
            })?;

            log_info!(self.logger, "Retrieved new JWT token");
            *lock = Some(jwt.clone());
            Ok(jwt)
        } else {
            // Attempt to parse error message from response body
            let status = response.status();
            let response_text = response.text().await.unwrap_or_default();
            let error_message = serde_json::from_str::<serde_json::Value>(&response_text)
                .ok()
                .and_then(|json| {
                    json.get("message")
                        .and_then(|m| m.as_str().map(|s| s.to_string()))
                })
                .unwrap_or_else(|| "Unknown error".to_string());
            log_error!(
                self.logger,
                "Error trying to retrieve JWT: {} - {}",
                status,
                error_message
            );
            Err(MutinyError::JwtAuthFailure)
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::MutinyAuthClient;
    use crate::authmanager::AuthManager;
    use crate::logging::MutinyLogger;
    use crate::test_utils::*;
    use crate::utils;

    use bip39::Mnemonic;
    use bitcoin::bip32::Xpriv;
    use bitcoin::hashes::{hex::prelude::*, sha256, Hash};
    use bitcoin::key::rand::Rng;
    use bitcoin::secp256k1::{self, rand::thread_rng, Message, PublicKey, Secp256k1};
    use bitcoin::Network;
    use env_logger::Builder;
    use log::LevelFilter;
    use secp256k1::ecdsa::Signature;
    use secp256k1::rand::rngs::OsRng;
    use serde_json::json;
    use warp::Filter;

    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::Once;
    use std::time::{SystemTime, UNIX_EPOCH};

    static INIT: Once = Once::new();

    fn initialize_logger() {
        INIT.call_once(|| {
            Builder::new()
                .filter(None, LevelFilter::Debug)
                .is_test(true)
                .init();
        });
    }

    #[tokio::test]
    async fn test_authentication() {
        initialize_logger();

        let jwt_route = warp::post()
            .and(warp::path("auth"))
            .and(warp::header::exact_ignore_case(
                "content-type",
                "application/json",
            ))
            .map(|| {
                let token_response = json!({
                    "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA"
                });
                warp::reply::with_status(
                    warp::reply::json(&token_response),
                    warp::http::StatusCode::OK,
                )
            });

        let (addr, server) =
            warp::serve(jwt_route).bind_with_graceful_shutdown(([127, 0, 0, 1], 3030), async {
                // Use ctrl_c to ensure the server does not shut down before receiving an interrupt signal,
                // preventing the server from closing prematurely before test requests are completed
                tokio::signal::ctrl_c()
                    .await
                    .expect("failed to listen for shutdown signal");
            });

        tokio::spawn(server);

        let auth_manager = create_manager();
        let logger = Arc::new(MutinyLogger::default());
        let client = MutinyAuthClient::new(auth_manager, logger, format!("http://{}/auth", addr));

        client.authenticate().await.expect("Authentication failed");
        assert!(client.is_authenticated().await.is_some());
    }

    #[tokio::test]
    async fn test_authentication_error_case() {
        initialize_logger();

        let jwt_route = warp::post()
            .and(warp::path("auth"))
            .and(warp::header::exact_ignore_case(
                "content-type",
                "application/json",
            ))
            .map(|| {
                warp::reply::with_status(
                    warp::reply::json(&json!({
                        "message": "signature verification failed"
                    })),
                    warp::http::StatusCode::UNAUTHORIZED,
                )
            });

        let (addr, server) =
            warp::serve(jwt_route).bind_with_graceful_shutdown(([127, 0, 0, 1], 3031), async {
                tokio::signal::ctrl_c()
                    .await
                    .expect("failed to listen for shutdown signal");
            });

        tokio::spawn(server);

        let auth_manager = create_manager();
        let logger = Arc::new(MutinyLogger::default());
        let client = MutinyAuthClient::new(auth_manager, logger, format!("http://{}/auth", addr));

        let result = client.authenticate().await;
        assert!(result.is_err(), "Expected authentication to fail");
    }

    #[tokio::test]
    async fn test_verify_jwt_signature_success() {
        let secp = Secp256k1::new();
        let (secret_key, pubkey) = secp.generate_keypair(&mut OsRng);

        // message: timestamp + '-' + random data
        let timestamp = utils::now().as_secs() - 1;
        let timestamp_2 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
            - 1;
        assert_eq!(timestamp, timestamp_2);

        let random_data: u64 = thread_rng().gen_range(u32::MAX as u64..u64::MAX);
        let challenge = format!("{}-{}", timestamp, random_data);

        let hashed_msg = sha256::Hash::hash(challenge.as_bytes());
        let msg =
            Message::from_digest_slice(hashed_msg.as_ref()).expect("32 bytes, guaranteed by type");
        let sig = secp.sign_ecdsa(&msg, &secret_key);

        // hex
        let pubkey_hex = format!("{:x}", pubkey.serialize().as_hex());
        let sig_hex = format!("{:x}", sig.serialize_der().as_hex());

        // verify
        let signature_bytes = Vec::from_hex(&sig_hex).unwrap();
        let public_key_bytes = Vec::from_hex(&pubkey_hex).unwrap();

        let secp = Secp256k1::verification_only();
        let pubkey = PublicKey::from_slice(&public_key_bytes).unwrap();
        let signature = Signature::from_der(&signature_bytes).unwrap();

        // Hash the message before verifying (because the signature was created using the hashed message)
        let hashed_message = sha256::Hash::hash(challenge.as_bytes());
        let msg = Message::from_digest_slice(hashed_message.as_ref()).unwrap();

        let ret = secp.verify_ecdsa(&msg, &signature, &pubkey);

        assert!(ret.is_ok());
    }

    #[tokio::test]
    async fn test_lightning_pubkey() {
        let mnemonic_str =
            "drift main obtain birth salon coyote cream build pottery attack attend glue";
        let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();

        let seed = mnemonic.to_seed("");
        let xprivkey = Xpriv::new_master(Network::Testnet, &seed).unwrap();
        let auth = AuthManager::new(xprivkey).unwrap();
        let pubkey_hex = format!("{:x}", auth.pubkey().serialize().as_hex());
        assert_eq!(
            pubkey_hex,
            "037ff12d3f50e36df10d8a5d5bfcf678e6fa891ae87dc526026922f7b47ae8e2a7"
        );
    }

    #[tokio::test]
    async fn test_auth_manager_sign() {
        let mnemonic_str =
            "earn stem rate film cat mesh hold violin elite usage maze crane robot fan market sing pepper web collect spice decorate turn creek owner";
        let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();

        let seed = mnemonic.to_seed("");
        let xprivkey = Xpriv::new_master(Network::Testnet, &seed).unwrap();
        let auth = AuthManager::new(xprivkey).unwrap();
        let pubkey_hex = format!("{:x}", auth.pubkey().serialize().as_hex());
        assert_eq!(
            pubkey_hex,
            "037474ffe18d09f9a65030f8c01899eec41e1d4ee3dead23556c1a0f7863931e29"
        );
        println!("pubkey_hex: {}", pubkey_hex);

        let timestamp = utils::now().as_secs() - 1;
        let random_data: u64 = thread_rng().gen_range(u32::MAX as u64..u64::MAX);
        let challenge = format!("{}-{}", timestamp, random_data);

        let hashed_msg = sha256::Hash::hash(challenge.as_bytes());
        let (sig, pubkey) = auth.sign(hashed_msg.as_ref()).unwrap();
        assert_eq!(format!("{:x}", pubkey.serialize().as_hex()), pubkey_hex);

        let sig_hex = format!("{:x}", sig.serialize_der().as_hex());
        println!("sig_hex: {}", sig_hex);
        println!("pubkey_hex2: {}", pubkey_hex);

        // verify
        let signature_bytes = Vec::from_hex(&sig_hex).unwrap();
        let public_key_bytes = Vec::from_hex(&pubkey_hex).unwrap();

        let secp = Secp256k1::verification_only();
        let pubkey = PublicKey::from_slice(&public_key_bytes).unwrap();
        let signature = Signature::from_der(&signature_bytes).unwrap();

        // Hash the message before verifying (because the signature was created using the hashed message)
        let hashed_message = sha256::Hash::hash(challenge.as_bytes());
        let msg = Message::from_digest_slice(hashed_message.as_ref()).unwrap();

        let ret = secp.verify_ecdsa(&msg, &signature, &pubkey);

        assert!(ret.is_ok());
    }
}
