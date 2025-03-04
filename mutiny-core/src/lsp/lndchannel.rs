use crate::logging::MutinyLogger;
use crate::{error::MutinyError, utils};

use bitcoin::secp256k1::PublicKey;
use lightning::{log_error, util::logger::*};
use reqwest::Client;
use serde::{Deserialize, Serialize};

const CHANNELS: &str = "/api/v1/channels";

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
    pub total_satoshis_sent: u64,
    pub total_satoshis_received: u64,
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

async fn get_channels(_pubkey: PublicKey) -> Result<Vec<LndChannel>, MutinyError> {
    let mock_channel = LndChannel {
        active: false,
        remote_pubkey: "02cabb332ae4505a7326440cf43bd02d6a2917cfffa7d9fb175672e628286879e6"
            .to_string(),
        channel_point: "2823c1bba2b1c75636549ef12beaa4f8d2b590a3491e6f11ac2671dbffb911cb:0"
            .to_string(),
        chan_id: "4289150879585599488".to_string(),
        capacity: 180875,
        local_balance: 5051,
        remote_balance: 174879,
        commit_fee: 285,
        commit_weight: 1116,
        fee_per_kw: 253,
        total_satoshis_sent: 15506,
        total_satoshis_received: 2001,
        num_updates: 20,
        csv_delay: 288,
        private: true,
        initiator: true,
        chan_status_flags: "ChanStatusDefault".to_string(),
        commitment_type: "ANCHORS".to_string(),
        lifetime: 564362,
        uptime: 17475,
        push_amount_sat: 161375,
        alias_scids: vec![17592186044416000479],
        peer_scid_alias: 1972756956701786116,
        memo: "JoyID dual-funded channel".to_string(),
    };

    Ok(vec![mock_channel])
}

pub(crate) async fn fetch_lnd_channels(
    http_client: &Client,
    url: &str,
    pubkey: &PublicKey,
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
