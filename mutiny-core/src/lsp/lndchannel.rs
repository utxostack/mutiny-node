use crate::logging::MutinyLogger;
use crate::{error::MutinyError, utils};

use lightning::{log_error, util::logger::*};
use reqwest::Client;
use serde::{Deserialize, Serialize};

const CHANNELS: &str = "/api/v1/ln/channels";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChannelConstraints {
    pub csv_delay: u32,
    pub chan_reserve_sat: u64,
    pub dust_limit_sat: u64,
    pub max_pending_amt_msat: u64,
    pub min_htlc_msat: u64,
    pub max_accepted_htlcs: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LndChannel {
    pub active: bool,
    pub remote_pubkey: String,
    pub channel_point: String,
    pub chan_id: String,
    pub capacity: u64,
    pub local_balance: u64,
    pub remote_balance: u64,
    pub commit_fee: u64,
    pub commit_weight: u64,
    pub fee_per_kw: u64,
    #[serde(default)]
    pub num_updates: u64,
    pub csv_delay: u64,
    pub private: bool,
    pub initiator: bool,
    pub chan_status_flags: String,
    pub commitment_type: String,
    pub lifetime: u64,
    pub uptime: u64,
    pub push_amount_sat: u64,
    pub alias_scids: Vec<u64>,
    pub peer_scid_alias: u64,
    pub memo: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LndListChannelsResponse {
    pub channels: Vec<LndChannel>,
}

pub(crate) async fn fetch_lnd_channels(
    http_client: &Client,
    url: &str,
    pubkey: &str,
    logger: &MutinyLogger,
) -> Result<Vec<LndChannel>, MutinyError> {
    let full_url = format!("{}{}/{}", url.trim_end_matches('/'), CHANNELS, pubkey);

    let builder = http_client.get(&full_url);
    let request = builder.build().map_err(|_| MutinyError::LspGenericError)?;

    let response = utils::fetch_with_timeout(http_client, request)
        .await
        .map_err(|e| {
            log_error!(logger, "Error fetching channels info: {}", e);
            MutinyError::LspGenericError
        })?;

    if !response.status().is_success() {
        log_error!(logger, "Non-success status code: {}", response.status());
        return Err(MutinyError::LspGenericError);
    }

    let channels_response: LndListChannelsResponse = response.json().await.map_err(|e| {
        log_error!(logger, "Error parsing channels JSON: {}", e);
        MutinyError::LspGenericError
    })?;

    Ok(channels_response.channels)
}
