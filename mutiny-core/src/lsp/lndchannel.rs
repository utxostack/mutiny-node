use crate::logging::MutinyLogger;
use crate::utils::now;
use crate::{error::MutinyError, utils};

use lightning::{log_error, util::logger::*};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LndChannelsSnapshot {
    pub snapshot: BTreeMap<String, u64>,
    pub timestamp: u32,
}

impl LndChannelsSnapshot {
    pub fn from_channels(channels: Vec<LndChannel>) -> Self {
        let snapshot = channels
            .into_iter()
            .map(|channel| (channel.chan_id, channel.num_updates))
            .collect::<BTreeMap<_, _>>();
        LndChannelsSnapshot {
            snapshot,
            timestamp: now().as_secs() as u32,
        }
    }
}

impl From<Vec<LndChannel>> for LndChannelsSnapshot {
    fn from(channels: Vec<LndChannel>) -> Self {
        LndChannelsSnapshot::from_channels(channels)
    }
}

pub(crate) async fn fetch_lnd_channels_snapshot(
    http_client: &Client,
    url: &str,
    pubkey: &str,
    logger: &MutinyLogger,
) -> Result<LndChannelsSnapshot, MutinyError> {
    let channels = fetch_lnd_channels(http_client, url, pubkey, logger).await?;
    Ok(channels.into())
}
