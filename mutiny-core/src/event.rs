use crate::ldkstorage::{MutinyNodePersister, PhantomChannelManager};
use crate::logging::MutinyLogger;
use crate::lsp::{AnyLsp, Lsp};
use crate::messagehandler::{BumpChannelClosureTransaction, CommonLnEvent, CommonLnEventCallback};
use crate::node::BumpTxEventHandler;
use crate::nodemanager::ChannelClosure;
use crate::onchain::OnChainWallet;
use crate::storage::MutinyStorage;
use crate::utils::{self, sleep};
use crate::{fees::MutinyFeeEstimator, storage::read_payment_info, PrivacyLevel};
use crate::{keymanager::PhantomKeysManager, storage::persist_payment_info};
use anyhow::anyhow;
use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::Secp256k1;
use core::fmt;
use lightning::events::{BumpTransactionEvent, ClosureReason, Event, PaymentPurpose, ReplayEvent};
use lightning::sign::SpendableOutputDescriptor;
use lightning::{
    log_debug, log_error, log_info, log_warn, util::errors::APIError, util::logger::Logger,
};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PaymentInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preimage: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<[u8; 32]>,
    pub status: HTLCStatus,
    #[serde(skip_serializing_if = "MillisatAmount::is_none")]
    pub amt_msat: MillisatAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_paid_msat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bolt11: Option<Bolt11Invoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payee_pubkey: Option<PublicKey>,
    #[serde(default)]
    pub privacy_level: PrivacyLevel,
    pub last_update: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MillisatAmount(pub Option<u64>);

impl MillisatAmount {
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HTLCStatus {
    /// Our invoice has not been paid yet
    Pending,
    /// We are currently trying to pay an invoice
    InFlight,
    /// An invoice has been paid
    Succeeded,
    /// We failed to pay an invoice
    Failed,
}

impl fmt::Display for HTLCStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HTLCStatus::Pending => write!(f, "Pending"),
            HTLCStatus::InFlight => write!(f, "InFlight"),
            HTLCStatus::Succeeded => write!(f, "Succeeded"),
            HTLCStatus::Failed => write!(f, "Failed"),
        }
    }
}

impl FromStr for HTLCStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Pending" => Ok(HTLCStatus::Pending),
            "InFlight" => Ok(HTLCStatus::InFlight),
            "Succeeded" => Ok(HTLCStatus::Succeeded),
            "Failed" => Ok(HTLCStatus::Failed),
            _ => Err(format!("'{}' is not a valid HTLCStatus", s)),
        }
    }
}

#[derive(Clone)]
pub struct EventHandler<S: MutinyStorage> {
    channel_manager: Arc<PhantomChannelManager<S>>,
    fee_estimator: Arc<MutinyFeeEstimator<S>>,
    wallet: Arc<OnChainWallet<S>>,
    keys_manager: Arc<PhantomKeysManager<S>>,
    persister: Arc<MutinyNodePersister<S>>,
    bump_tx_event_handler: Arc<BumpTxEventHandler<S>>,
    lsp_client: Option<AnyLsp<S>>,
    logger: Arc<MutinyLogger>,
    do_not_bump_channel_closed_tx: bool,
    sweep_target_address: Option<bitcoin::Address>,
    ln_event_callback: Option<CommonLnEventCallback>,
}

impl<S: MutinyStorage> EventHandler<S> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        channel_manager: Arc<PhantomChannelManager<S>>,
        fee_estimator: Arc<MutinyFeeEstimator<S>>,
        wallet: Arc<OnChainWallet<S>>,
        keys_manager: Arc<PhantomKeysManager<S>>,
        persister: Arc<MutinyNodePersister<S>>,
        bump_tx_event_handler: Arc<BumpTxEventHandler<S>>,
        lsp_client: Option<AnyLsp<S>>,
        logger: Arc<MutinyLogger>,
        do_not_bump_channel_closed_tx: bool,
        sweep_target_address: Option<bitcoin::Address>,
        ln_event_callback: Option<CommonLnEventCallback>,
    ) -> Self {
        Self {
            channel_manager,
            fee_estimator,
            wallet,
            keys_manager,
            lsp_client,
            persister,
            bump_tx_event_handler,
            logger,
            do_not_bump_channel_closed_tx,
            sweep_target_address,
            ln_event_callback,
        }
    }

    pub async fn handle_event(&self, event: Event) -> Result<(), ReplayEvent> {
        match event {
            Event::FundingGenerationReady {
                temporary_channel_id,
                counterparty_node_id,
                channel_value_satoshis,
                output_script,
                user_channel_id,
            } => {
                log_debug!(self.logger, "EVENT: FundingGenerationReady processing");

                // Get the open parameters for this channel
                let params_opt = match self.persister.get_channel_open_params(user_channel_id) {
                    Ok(params) => params,
                    Err(e) => {
                        log_error!(self.logger, "ERROR: Could not get channel open params: {e}");
                        return Ok(());
                    }
                };

                let psbt_result = match &params_opt {
                    None => {
                        log_warn!(
                            self.logger,
                            "WARNING: Could not find channel open params for channel {user_channel_id}"
                        );
                        self.wallet.create_signed_psbt_to_spk(
                            output_script,
                            channel_value_satoshis,
                            None,
                        )
                    }
                    Some(params) => {
                        log_debug!(self.logger, "Opening channel with params: {params:?}");
                        if let Some(utxos) = &params.utxos {
                            self.wallet.create_sweep_psbt_to_output(
                                utxos,
                                output_script,
                                channel_value_satoshis,
                                params.absolute_fee.expect("Absolute fee should be set"),
                            )
                        } else {
                            self.wallet.create_signed_psbt_to_spk(
                                output_script,
                                channel_value_satoshis,
                                Some(params.sats_per_vbyte),
                            )
                        }
                    }
                };

                let label = format!("LN Channel: {}", counterparty_node_id);
                let labels = params_opt
                    .as_ref()
                    .and_then(|p| p.labels.clone())
                    .unwrap_or_else(|| vec![label]);

                let psbt = match psbt_result {
                    Ok(psbt) => {
                        if let Err(e) = self.wallet.label_psbt(&psbt, labels) {
                            log_warn!(
                                self.logger,
                                "ERROR: Could not label PSBT, but continuing: {e}"
                            );
                        };
                        psbt
                    }
                    Err(e) => {
                        let error_msg = format!("ERROR: Could not create a signed transaction to open channel with: {e}");
                        if let Err(e) = self.channel_manager.force_close_without_broadcasting_txn(
                            &temporary_channel_id,
                            &counterparty_node_id,
                            error_msg,
                        ) {
                            log_error!(
                                self.logger,
                                "ERROR: Could not force close failed channel: {e:?}"
                            );
                        }
                        return Ok(());
                    }
                };

                let tx = match psbt.extract_tx() {
                    Ok(tx) => tx,
                    Err(err) => {
                        log_error!(self.logger, "ERROR: extract tx from pstb: {err:?}");
                        return Ok(());
                    }
                };

                if let Err(e) = self.channel_manager.funding_transaction_generated(
                    temporary_channel_id,
                    counterparty_node_id,
                    tx.clone(),
                ) {
                    log_error!(
                        self.logger,
                        "ERROR: Could not send funding transaction to channel manager: {e:?}"
                    );
                    return Ok(());
                }

                if let Some(mut params) = params_opt {
                    params.opening_tx = Some(tx);

                    let _ = self
                        .persister
                        .persist_channel_open_params(user_channel_id, params);
                }

                log_info!(self.logger, "EVENT: FundingGenerationReady success");
            }
            Event::PaymentClaimable {
                receiver_node_id,
                payment_hash,
                purpose,
                amount_msat,
                counterparty_skimmed_fee_msat,
                ..
            } => {
                log_debug!(self.logger, "EVENT: PaymentReceived received payment from payment hash {} of {amount_msat} millisatoshis to {receiver_node_id:?}", payment_hash);

                if let Some(payment_info) =
                    read_payment_info(&self.persister.storage, &payment_hash.0, true, &self.logger)
                {
                    if matches!(
                        payment_info.status,
                        HTLCStatus::Succeeded | HTLCStatus::Failed
                    ) {
                        self.channel_manager.fail_htlc_backwards(&payment_hash);
                        return Ok(());
                    }
                }

                let expected_skimmed_fee_msat = self
                    .lsp_client
                    .as_ref()
                    .map(|lsp_client| {
                        lsp_client.get_expected_skimmed_fee_msat(payment_hash, amount_msat)
                    })
                    .unwrap_or(0);

                if counterparty_skimmed_fee_msat > expected_skimmed_fee_msat {
                    log_error!(self.logger, "ERROR: Payment with hash {} skimmed a fee of {} millisatoshis when we expected a fee of {} millisatoshis", payment_hash, counterparty_skimmed_fee_msat, expected_skimmed_fee_msat);
                    self.channel_manager.fail_htlc_backwards(&payment_hash);
                    return Ok(());
                }

                if let Some(payment_preimage) = match purpose {
                    PaymentPurpose::Bolt11InvoicePayment {
                        payment_preimage, ..
                    } => payment_preimage,
                    PaymentPurpose::SpontaneousPayment(preimage) => Some(preimage),
                    PaymentPurpose::Bolt12OfferPayment { .. }
                    | PaymentPurpose::Bolt12RefundPayment { .. } => {
                        log_error!(self.logger, "Not support Bolt12");
                        self.channel_manager.fail_htlc_backwards(&payment_hash);
                        return Ok(());
                    }
                } {
                    self.channel_manager.claim_funds(payment_preimage);
                } else {
                    self.channel_manager.fail_htlc_backwards(&payment_hash);
                    log_error!(self.logger, "ERROR: No payment preimage found");
                };
            }
            Event::PaymentClaimed {
                receiver_node_id,
                payment_hash,
                purpose,
                amount_msat,
                htlcs,
                sender_intended_total_msat,
                onion_fields: _,
            } => {
                log_debug!(self.logger, "EVENT: PaymentClaimed claimed payment from payment hash {} of {} millisatoshis ({sender_intended_total_msat:?} intended)  from {} htlcs", payment_hash, amount_msat, htlcs.len());

                let (payment_preimage, payment_secret) = match purpose {
                    PaymentPurpose::Bolt11InvoicePayment {
                        payment_preimage,
                        payment_secret,
                        ..
                    } => (payment_preimage, Some(payment_secret)),
                    PaymentPurpose::SpontaneousPayment(preimage) => (Some(preimage), None),
                    PaymentPurpose::Bolt12OfferPayment { .. }
                    | PaymentPurpose::Bolt12RefundPayment { .. } => {
                        log_error!(self.logger, "Not support Bolt12");
                        return Ok(());
                    }
                };
                match read_payment_info(
                    &self.persister.storage,
                    &payment_hash.0,
                    true,
                    &self.logger,
                ) {
                    Some(mut saved_payment_info) => {
                        let payment_preimage = payment_preimage.map(|p| p.0);
                        let payment_secret = payment_secret.map(|p| p.0);
                        saved_payment_info.status = HTLCStatus::Succeeded;
                        saved_payment_info.preimage = payment_preimage;
                        saved_payment_info.secret = payment_secret;
                        saved_payment_info.amt_msat = MillisatAmount(Some(amount_msat));
                        saved_payment_info.last_update = crate::utils::now().as_secs();
                        match persist_payment_info(
                            &self.persister.storage,
                            &payment_hash.0,
                            &saved_payment_info,
                            true,
                        ) {
                            Ok(_) => (),
                            Err(e) => log_error!(
                                self.logger,
                                "ERROR: could not persist payment info: {e}"
                            ),
                        }
                    }
                    None => {
                        let payment_preimage = payment_preimage.map(|p| p.0);
                        let payment_secret = payment_secret.map(|p| p.0);
                        let last_update = crate::utils::now().as_secs();

                        let payment_info = PaymentInfo {
                            preimage: payment_preimage,
                            secret: payment_secret,
                            status: HTLCStatus::Succeeded,
                            amt_msat: MillisatAmount(Some(amount_msat)),
                            fee_paid_msat: None,
                            payee_pubkey: receiver_node_id,
                            bolt11: None,
                            last_update,
                            privacy_level: PrivacyLevel::NotAvailable,
                        };
                        match persist_payment_info(
                            &self.persister.storage,
                            &payment_hash.0,
                            &payment_info,
                            true,
                        ) {
                            Ok(_) => (),
                            Err(e) => log_error!(
                                self.logger,
                                "ERROR: could not persist payment info: {e}"
                            ),
                        }
                    }
                }

                if let Some(cb) = self.ln_event_callback.as_ref() {
                    let event = CommonLnEvent::PaymentClaimed {
                        receiver_node_id: receiver_node_id.map(|node_id| format!("{node_id}")),
                        amount_msat,
                        payment_hash: format!("{payment_hash:x}"),
                    };
                    cb.trigger(event);
                }
            }
            Event::PaymentSent {
                payment_preimage,
                payment_hash,
                fee_paid_msat,
                ..
            } => {
                log_debug!(self.logger, "EVENT: PaymentSent: {}", payment_hash);

                match read_payment_info(
                    &self.persister.storage,
                    &payment_hash.0,
                    false,
                    &self.logger,
                ) {
                    Some(mut saved_payment_info) => {
                        saved_payment_info.status = HTLCStatus::Succeeded;
                        saved_payment_info.preimage = Some(payment_preimage.0);
                        saved_payment_info.fee_paid_msat = fee_paid_msat;
                        saved_payment_info.last_update = crate::utils::now().as_secs();
                        match persist_payment_info(
                            &self.persister.storage,
                            &payment_hash.0,
                            &saved_payment_info,
                            false,
                        ) {
                            Ok(_) => (),
                            Err(e) => log_error!(
                                self.logger,
                                "ERROR: could not persist payment info: {e}"
                            ),
                        }
                    }
                    None => {
                        // we succeeded in a payment that we didn't have saved? ...
                        log_warn!(
                            self.logger,
                            "WARN: payment succeeded but we did not have it stored"
                        );
                    }
                }
                if let Some(cb) = self.ln_event_callback.as_ref() {
                    let event = CommonLnEvent::PaymentSent {
                        payment_hash: format!("{payment_hash:x}"),
                    };
                    cb.trigger(event);
                }
            }
            Event::OpenChannelRequest {
                temporary_channel_id,
                counterparty_node_id,
                channel_type,
                ..
            } => {
                let lsp_pubkey = match self.lsp_client {
                    Some(ref lsp) => Some(lsp.get_lsp_pubkey().await),
                    None => None,
                };
                log_debug!(
                    self.logger,
                    "EVENT: OpenChannelRequest counterparty: {counterparty_node_id} and LSP pubkey: {lsp_pubkey:?}"
                );

                let mut internal_channel_id_bytes = [0u8; 16];
                if getrandom::getrandom(&mut internal_channel_id_bytes).is_err() {
                    log_debug!(
                        self.logger,
                        "EVENT: OpenChannelRequest failed random number generation"
                    );
                };
                let internal_channel_id = u128::from_be_bytes(internal_channel_id_bytes);

                let log_result = |result: Result<(), APIError>| match result {
                    Ok(_) => log_debug!(self.logger, "EVENT: OpenChannelRequest accepted"),
                    Err(e) => log_debug!(self.logger, "EVENT: OpenChannelRequest error: {e:?}"),
                };

                let is_zero_conf_channel = channel_type.requires_zero_conf();
                log_debug!(
                    self.logger,
                    "EVENT: OpenChannelRequest zero-conf channel: {is_zero_conf_channel}"
                );

                if lsp_pubkey.as_ref() != Some(&counterparty_node_id) {
                    log_error!(
                        self.logger,
                        "EVENT: OpenChannelRequest error: The counterparty node id doesn't match the LSP pubkey"
                    );
                } else if is_zero_conf_channel {
                    // if the event request channel type is 0-conf, accept 0 conf channel
                    let result = self
                        .channel_manager
                        .accept_inbound_channel_from_trusted_peer_0conf(
                            &temporary_channel_id,
                            &counterparty_node_id,
                            internal_channel_id,
                        );
                    log_result(result);
                    log_debug!(
                        self.logger,
                        "Accept zero confirmation channel when matched LSP Pubkey"
                    );
                } else {
                    // if the event request channel type is not 0-conf, open normal channel
                    let result = self.channel_manager.accept_inbound_channel(
                        &temporary_channel_id,
                        &counterparty_node_id,
                        internal_channel_id,
                    );
                    log_result(result);
                }
            }
            Event::PaymentPathSuccessful { .. } => {
                log_debug!(self.logger, "EVENT: PaymentPathSuccessful, ignored");
            }
            Event::PaymentPathFailed { .. } => {
                log_debug!(self.logger, "EVENT: PaymentPathFailed, ignored");
            }
            Event::ProbeSuccessful { .. } => {
                log_debug!(self.logger, "EVENT: ProbeSuccessful, ignored");
            }
            Event::ProbeFailed { .. } => {
                log_debug!(self.logger, "EVENT: ProbeFailed, ignored");
            }
            Event::PaymentFailed {
                payment_hash,
                reason,
                ..
            } => {
                if let Some(payment_hash) = payment_hash {
                    log_error!(
                        self.logger,
                        "EVENT: PaymentFailed: {} for reason {reason:?}",
                        payment_hash
                    );

                    match read_payment_info(
                        &self.persister.storage,
                        &payment_hash.0,
                        false,
                        &self.logger,
                    ) {
                        Some(mut saved_payment_info) => {
                            saved_payment_info.status = HTLCStatus::Failed;
                            saved_payment_info.last_update = crate::utils::now().as_secs();
                            match persist_payment_info(
                                &self.persister.storage,
                                &payment_hash.0,
                                &saved_payment_info,
                                false,
                            ) {
                                Ok(_) => (),
                                Err(e) => log_error!(
                                    self.logger,
                                    "ERROR: could not persist payment info: {e}"
                                ),
                            }
                        }
                        None => {
                            // we failed in a payment that we didn't have saved? ...
                            log_warn!(
                                self.logger,
                                "WARN: payment failed but we did not have it stored"
                            );
                        }
                    }
                    if let Some(cb) = self.ln_event_callback.as_ref() {
                        let event = CommonLnEvent::PaymentFailed {
                            payment_hash: format!("{payment_hash:x}"),
                            reason: reason.map(|r| format!("{r:?}")),
                        };
                        cb.trigger(event);
                    }
                }
            }
            Event::PaymentForwarded { .. } => {
                log_info!(self.logger, "EVENT: PaymentForwarded somehow...");
            }
            Event::HTLCHandlingFailed { .. } => {
                log_debug!(self.logger, "EVENT: HTLCHandlingFailed, ignored");
            }
            Event::PendingHTLCsForwardable { time_forwardable } => {
                log_debug!(
                    self.logger,
                    "EVENT: PendingHTLCsForwardable: {time_forwardable:?}, processing..."
                );

                let forwarding_channel_manager = self.channel_manager.clone();
                let min = time_forwardable.as_millis() as i32;
                sleep(min).await;
                forwarding_channel_manager.process_pending_htlc_forwards();
            }
            Event::SpendableOutputs { outputs, .. } => {
                if let Err(e) = self.handle_spendable_outputs(&outputs).await {
                    log_error!(self.logger, "Failed to handle spendable outputs: {e}");
                    // if we have an error we should persist the outputs so we can try again later
                    if let Err(e) = self.persister.persist_failed_spendable_outputs(outputs) {
                        log_error!(
                            self.logger,
                            "Failed to persist failed spendable outputs: {e}"
                        );
                    }
                }
            }
            Event::ChannelClosed {
                channel_id,
                reason,
                user_channel_id,
                counterparty_node_id: node_id,
                channel_capacity_sats,
                channel_funding_txo,
                ..
            } => {
                // if we still have channel open params, then it was just a failed channel open
                // we should not persist this as a closed channel and pass back the failure reason
                if let Ok(Some(mut params)) =
                    self.persister.get_channel_open_params(user_channel_id)
                {
                    // Remove the LDK fluff from the error message
                    let reason_str = reason.to_string().replace(
                        "Channel closed because counterparty force-closed with message: ",
                        "",
                    );

                    params.failure_reason = Some(reason_str);
                    let _ = self
                        .persister
                        .persist_channel_open_params(user_channel_id, params);
                    return Ok(());
                };

                log_debug!(
                    self.logger,
                    "EVENT: Channel {} of size {} closed due to: {:?}",
                    channel_id,
                    channel_capacity_sats
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    reason
                );

                // We guess this is a force close if the reason isn't belongs to a cooperative reason
                let maybe_force_closed = !matches!(
                    reason,
                    ClosureReason::LegacyCooperativeClosure
                        | ClosureReason::LocallyInitiatedCooperativeClosure
                        | ClosureReason::CounterpartyCoopClosedUnfundedChannel
                        | ClosureReason::CounterpartyInitiatedCooperativeClosure
                );

                let event = CommonLnEvent::ChannelClosed {
                    channel_id: format!("{channel_id}"),
                    reason: format!("{reason}"),
                    channel_funding_txo: channel_funding_txo.map(|txo| format!("{txo}")),
                    counterparty_node_id: node_id.map(|node_id| format!("{node_id:x}")),
                    maybe_force_closed,
                };

                let closure = ChannelClosure::new(
                    user_channel_id,
                    channel_id,
                    channel_funding_txo,
                    node_id,
                    reason,
                );
                if let Err(e) = self
                    .persister
                    .persist_channel_closure(user_channel_id, closure)
                {
                    log_error!(self.logger, "Failed to persist channel closure: {e}");
                }

                if let Some(cb) = self.ln_event_callback.as_ref() {
                    cb.trigger(event);
                }
            }
            Event::DiscardFunding { .. } => {
                // A "real" node should probably "lock" the UTXOs spent in funding transactions until
                // the funding transaction either confirms, or this event is generated.
                log_debug!(self.logger, "EVENT: DiscardFunding, ignored");
            }
            Event::ChannelReady {
                channel_id,
                user_channel_id,
                counterparty_node_id,
                channel_type,
            } => {
                log_debug!(
                    self.logger,
                    "EVENT: ChannelReady channel_id: {}, user_channel_id: {}, counterparty_node_id: {}, channel_type: {}",
                    channel_id,
                    user_channel_id,
                    counterparty_node_id,
                    channel_type);
            }
            Event::ChannelPending {
                channel_id,
                user_channel_id,
                counterparty_node_id,
                funding_txo,
                ..
            } => {
                log_debug!(
                    self.logger,
                    "EVENT: ChannelPending channel_id: {}, user_channel_id: {}, counterparty_node_id: {}",
                    channel_id,
                    user_channel_id,
                    counterparty_node_id);

                if let Err(e) = self.persister.delete_channel_open_params(user_channel_id) {
                    log_warn!(
                        self.logger,
                        "ERROR: Could not delete channel open params, but continuing: {e}"
                    );
                }

                let all_channels = self.channel_manager.list_channels();
                let found_channel = all_channels.iter().find(|chan| {
                    chan.funding_txo.map(|a| a.into_bitcoin_outpoint()) == Some(funding_txo)
                });
                if let Some(channel) = found_channel {
                    let closure = ChannelClosure::new_placeholder(
                        user_channel_id,
                        channel_id,
                        funding_txo,
                        counterparty_node_id,
                        channel.force_close_spend_delay,
                    );
                    if let Err(e) = self
                        .persister
                        .persist_channel_closure(user_channel_id, closure)
                    {
                        log_error!(self.logger, "Failed to persist channel closure: {e}");
                    }
                } else {
                    log_warn!(
                        self.logger,
                        "WARNING: Could not find channel with funding txo {funding_txo:?} when calling list_channels in ChannelPending event"
                    );
                }
            }
            Event::HTLCIntercepted { .. } => {}
            Event::BumpTransaction(event) => match &event {
                BumpTransactionEvent::ChannelClose {
                    channel_id,
                    commitment_tx,
                    ..
                } => {
                    let txid = format!("{:x}", commitment_tx.compute_txid());
                    let hex_tx = bitcoin::consensus::encode::serialize_hex(commitment_tx);
                    let timestamp = utils::now().as_secs();
                    log_debug!(
                        self.logger,
                        "EVENT: BumpTransaction channel_id {} tx_id {} timestamp {}\nhex_tx {}",
                        channel_id,
                        txid,
                        timestamp,
                        hex_tx
                    );

                    // Leverages the `BumpTransactionEvent::ChannelClose` mechanism to automatically retry
                    // rebroadcasting the commitment transaction if the initial broadcast fails.
                    // This operation has almost no side effects, as broadcasting the same transaction multiple times
                    // does not alter its state or the blockchain, and nodes will simply ignore duplicate broadcasts.
                    log_debug!(
                        self.logger,
                        "Trying rebroadcast for commitment tx transaction: {event:?}"
                    );
                    if let Err(e) = self
                        .wallet
                        .broadcast_transaction(commitment_tx.clone())
                        .await
                    {
                        log_error!(self.logger, "Failed to rebroadcast commitment tx: {e}");
                    }

                    if self.do_not_bump_channel_closed_tx {
                        log_debug!(self.logger, "Skip channel close transaction");
                    } else {
                        log_debug!(self.logger, "Bump channel close transaction");
                        self.bump_tx_event_handler.handle_event(&event);
                    }
                    if let Some(cb) = self.ln_event_callback.as_ref() {
                        let closure_bumping_event = BumpChannelClosureTransaction {
                            channel_id: format!("{channel_id}"),
                            txid,
                            hex_tx,
                            timestamp,
                        };

                        if let Err(e) = self
                            .persister
                            .persist_channel_closure_bumping_event(&closure_bumping_event)
                        {
                            log_error!(
                                self.logger,
                                "Failed to persist channel closure bumping event: {e}"
                            );
                        }
                        cb.trigger(CommonLnEvent::BumpChannelCloseTransaction {
                            channel_id: closure_bumping_event.channel_id,
                            txid: closure_bumping_event.txid,
                            hex_tx: closure_bumping_event.hex_tx,
                            timestamp,
                        });
                    }
                }
                _ => {
                    log_debug!(self.logger, "EVENT: BumpTransaction: {event:?}");
                    self.bump_tx_event_handler.handle_event(&event);
                }
            },
            Event::ConnectionNeeded { node_id, addresses } => {
                // we don't support bolt 12 yet, and we won't have the connection info anyways
                log_debug!(
                    self.logger,
                    "EVENT: ConnectionNeeded: {node_id} @ {addresses:?}"
                );
            }
            Event::FundingTxBroadcastSafe {
                channel_id,
                counterparty_node_id,
                ..
            } => {
                log_debug!(
                    self.logger,
                    "EVENT: FundingTxBroadcastSafe: {counterparty_node_id:?}/{channel_id}"
                );
            }
            Event::InvoiceReceived { payment_id, .. } => {
                log_debug!(self.logger, "EVENT: InvoiceReceived: {payment_id}");
            }
            Event::OnionMessageIntercepted { peer_node_id, .. } => {
                log_debug!(
                    self.logger,
                    "EVENT: OnionMessageIntercepted: {peer_node_id}"
                );
            }
            Event::OnionMessagePeerConnected { peer_node_id } => {
                log_debug!(
                    self.logger,
                    "EVENT: OnionMessagePeerConnected: {peer_node_id}"
                );
            }
        }
        Ok(())
    }

    // Separate function to handle spendable outputs
    // This is so we can return a result and handle errors
    // without having to use a lot of nested if statements
    pub(crate) async fn handle_spendable_outputs(
        &self,
        outputs: &[SpendableOutputDescriptor],
    ) -> anyhow::Result<()> {
        // Filter out static outputs, we don't want to spend them
        // because they have gone to our BDK wallet.
        // This would only be a waste in fees.
        let output_descriptors = outputs
            .iter()
            .filter(|d| match d {
                SpendableOutputDescriptor::StaticOutput { .. } => false,
                SpendableOutputDescriptor::DelayedPaymentOutput(_) => true,
                SpendableOutputDescriptor::StaticPaymentOutput(_) => true,
            })
            .collect::<Vec<_>>();

        // If there are no spendable outputs, we don't need to do anything
        if output_descriptors.is_empty() {
            return Ok(());
        }

        log_debug!(
            self.logger,
            "EVENT: processing SpendableOutputs {}",
            output_descriptors.len()
        );

        let tx_feerate = self.fee_estimator.get_normal_fee_rate();

        // We set nLockTime to the current height to discourage fee sniping.
        // Occasionally randomly pick a nLockTime even further back, so
        // that transactions that are delayed after signing for whatever reason,
        // e.g. high-latency mix networks and some CoinJoin implementations, have
        // better privacy.
        // Logic copied from core: https://github.com/bitcoin/bitcoin/blob/1d4846a8443be901b8a5deb0e357481af22838d0/src/wallet/spend.cpp#L936
        let mut height = self.channel_manager.current_best_block().height;

        let mut rand = [0u8; 4];
        getrandom::getrandom(&mut rand).unwrap();
        // 10% of the time
        if (u32::from_be_bytes(rand) % 10) == 0 {
            // subtract random number between 0 and 100
            getrandom::getrandom(&mut rand).unwrap();
            height -= u32::from_be_bytes(rand) % 100;
        }

        let locktime = LockTime::from_height(height).ok();

        let spending_tx = self
            .keys_manager
            .spend_spendable_outputs(
                &output_descriptors,
                Vec::new(),
                tx_feerate,
                locktime,
                &Secp256k1::new(),
                self.sweep_target_address.clone(),
            )
            .map_err(|_| anyhow!("Failed to spend spendable outputs"))?;

        self.wallet.broadcast_transaction(spending_tx).await?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::event::{HTLCStatus, MillisatAmount, PaymentInfo};
    use crate::{utils, PrivacyLevel};
    use bitcoin::secp256k1::PublicKey;
    use lightning_invoice::Bolt11Invoice;
    use std::str::FromStr;

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};
    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    fn test_payment_info_serialization_symmetry() {
        let preimage = [1; 32];
        let pubkey = PublicKey::from_str(
            "02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b",
        )
        .unwrap();

        let payment_info = PaymentInfo {
            preimage: Some(preimage),
            status: HTLCStatus::Succeeded,
            privacy_level: PrivacyLevel::Anonymous,
            amt_msat: MillisatAmount(Some(420)),
            fee_paid_msat: None,
            bolt11: None,
            payee_pubkey: Some(pubkey),
            secret: None,
            last_update: utils::now().as_secs(),
        };

        let serialized = serde_json::to_string(&payment_info).unwrap();
        let deserialized: PaymentInfo = serde_json::from_str(&serialized).unwrap();
        assert_eq!(payment_info, deserialized);

        let serialized = serde_json::to_value(&payment_info).unwrap();
        let deserialized: PaymentInfo = serde_json::from_value(serialized).unwrap();
        assert_eq!(payment_info, deserialized);
    }

    #[test]
    fn test_payment_info_without_amount() {
        let pubkey = PublicKey::from_str(
            "02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b",
        )
        .unwrap();

        let payment_info = PaymentInfo {
            preimage: None,
            status: HTLCStatus::Succeeded,
            privacy_level: PrivacyLevel::Anonymous,
            amt_msat: MillisatAmount(None),
            fee_paid_msat: None,
            bolt11: Some(Bolt11Invoice::from_str("lntb1pnmghqhdqqnp4qty5slw3t6d6gt43tndkq6p6ut9ewrqrfq2nj67wnmk6dqzefweqcpp5fk6cxcwnjdrzw5zm9mzjuhfrwnee3feewmtycj5nk7klngava7gqsp5qajl23w8dluhxn90duny44ar0syrxqa4w3ap8635aat78lvdvfds9qyysgqcqzptxqyz5vqrzjqg7s0fwc76ky6umpgeuh7p7qm4l4jljw0uxa3uu5vrupjzjlpeny0apyqqqqqqqqsgqqqqlgqqqqlgqqjqr5p4cd64qa80ksthgdff908gxmjwvrwwmhnxnxlsrc0c2weuzcw3kthknu6cgalqdk0cnqsugvmcz9dvgr5l9rtphgm37ycg362s9sspwvxmj0").unwrap()),
            payee_pubkey: Some(pubkey),
            secret: None,
            last_update: utils::now().as_secs(),
        };

        let serialized = serde_json::to_string(&payment_info).unwrap();
        println!("{:}", serialized);
        let deserialized: PaymentInfo = serde_json::from_str(&serialized).unwrap();
        assert_eq!(payment_info, deserialized);

        let serialized = serde_json::to_value(&payment_info).unwrap();
        let deserialized: PaymentInfo = serde_json::from_value(serialized).unwrap();
        assert_eq!(payment_info, deserialized);
    }
}
