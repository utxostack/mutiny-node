use std::str::FromStr;

use bitcoin::{psbt::PartiallySignedTransaction, PublicKey};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{auth::MutinyAuthClient, error::MutinyError, logging::MutinyLogger};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PsbtLspConfig {
    pub url: String,
    pub pubkey: Option<PublicKey>,
}

pub struct PsbtLspClient {
    url: String,
    http_client: Client,
}

impl PsbtLspClient {
    pub fn new(url: String) -> Self {
        let http_client = Client::new();
        Self { url, http_client }
    }

    pub async fn fetch_fund_psbt(
        &self,
        funding_psbt: &PartiallySignedTransaction,
    ) -> Result<PartiallySignedTransaction, MutinyError> {
        let url = Url::parse(&format!("{}/funding/fetch-psbt", self.url))
            .map_err(|_| MutinyError::ConnectionFailed)?;

        let response = self
            .http_client
            .request(Method::GET, url)
            .query(&[("psbt", funding_psbt.to_string())])
            .build()
            .map_err(|_| MutinyError::ConnectionFailed)?;

        let full_psbt: String = serde_json::from_slice(
            response
                .body()
                .ok_or_else(|| MutinyError::ConnectionFailed)?
                .as_bytes()
                .ok_or_else(|| MutinyError::ConnectionFailed)?,
        )
        .map_err(|_| MutinyError::ConnectionFailed)?;

        let psbt = PartiallySignedTransaction::from_str(&full_psbt)
            .map_err(|_| MutinyError::ConnectionFailed)?;
        Ok(psbt)
    }

    pub async fn fund_psbt_channel(
        &self,
        funding_psbt: &PartiallySignedTransaction,
    ) -> Result<(), MutinyError> {
        let url = Url::parse(&format!("{}/funding/open-channel", self.url))
            .map_err(|_| MutinyError::ConnectionFailed)?;

        let response = self
            .http_client
            .request(Method::POST, url)
            .json(&funding_psbt.to_string())
            .build()
            .map_err(|_| MutinyError::ConnectionFailed)?;

        let result: String = serde_json::from_slice(
            &response
                .body()
                .ok_or_else(|| MutinyError::ConnectionFailed)?
                .as_bytes()
                .ok_or_else(|| MutinyError::ConnectionFailed)?,
        )
        .map_err(|_| MutinyError::ConnectionFailed)?;
        dbg!(result);
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetInfoResponse {
    pub pubkey: PublicKey,
}

/// Get the pubkey and connection string from the LSP from the /info endpoint
pub(crate) async fn fetch_connection_info(
    http_client: &Client,
    url: &str,
    logger: &MutinyLogger,
) -> Result<PublicKey, MutinyError> {
    let url =
        Url::parse(&format!("{}/get-info", url)).map_err(|_| MutinyError::ConnectionFailed)?;
    let response = http_client
        .request(Method::GET, url)
        .build()
        .map_err(|_| MutinyError::ConnectionFailed)?;

    let get_info_response: GetInfoResponse = serde_json::from_slice(
        response
            .body()
            .ok_or_else(|| MutinyError::ConnectionFailed)?
            .as_bytes()
            .ok_or_else(|| MutinyError::ConnectionFailed)?,
    )
    .map_err(|_| MutinyError::ConnectionFailed)?;

    Ok(get_info_response.pubkey)
}
