use crate::{authmanager::AuthManager, error::MutinyError, logging::MutinyLogger, utils};
use async_lock::RwLock;
use bitcoin::hashes::hex::prelude::*;
use bitcoin::key::rand::Rng;
use bitcoin::secp256k1;
use jwt_compact::UntrustedToken;
use lightning::{log_debug, log_error, log_info};
use lightning::{log_trace, util::logger::*};
use reqwest::Client;
use reqwest::{Method, StatusCode, Url};
use serde_json::Value;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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

    async fn retrieve_new_jwt(&self) -> Result<String, MutinyError> {
        let mut lock = self.jwt.write().await;
        log_debug!(self.logger, "Retrieving new JWT token");

        let jwt_url = self.url.clone();

        // message: "1698480000-1234567890123456789"
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let mut msg_bytes = [0u8; 32];
        msg_bytes[..8].copy_from_slice(&timestamp.to_be_bytes());
        msg_bytes[8] = b'-';
        secp256k1::rand::thread_rng().fill(&mut msg_bytes[9..]);

        let (sig, pubkey) = self.auth.sign(&msg_bytes)?;

        let sig_hex = format!("{:x}", sig.serialize_compact().as_hex());
        let pubkey_hex = format!("{:x}", pubkey.serialize().as_hex());

        let response = self
            .http_client
            .post(&jwt_url)
            .json(&serde_json::json!({
                "signature": sig_hex,
                "public_key": pubkey_hex,
            }))
            .send()
            .await
            .map_err(|e| {
                log_error!(self.logger, "JWT auth request failed: {e}");
                MutinyError::JwtAuthFailure
            })?;

        if response.status().is_success() {
            let jwt = response
                .text()
                .await
                .map_err(|_| MutinyError::JwtAuthFailure)?;

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
    use crate::logging::MutinyLogger;
    use crate::test_utils::*;

    use env_logger::Builder;
    use log::LevelFilter;
    use serde_json::json;
    use warp::Filter;

    use std::sync::Arc;
    use std::sync::Once;

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
                warp::reply::with_status(
                    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA",
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
}
