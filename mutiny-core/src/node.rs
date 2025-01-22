use crate::lsp::LspConfig;
use crate::messagehandler::CommonLnEventCallback;
use crate::nodemanager::ChannelClosure;
use crate::peermanager::{LspMessageRouter, PeerManager};
use crate::storage::MutinyStorage;
use crate::utils::get_monitor_version;
use crate::{
    chain::MutinyChain,
    error::{MutinyError, MutinyStorageError},
    event::{EventHandler, HTLCStatus, MillisatAmount, PaymentInfo},
    fees::MutinyFeeEstimator,
    gossip::{get_all_peers, read_peer_info, save_peer_connection_info},
    keymanager::{
        create_keys_manager, deterministic_uuid_from_keys_manager, pubkey_from_keys_manager,
    },
    ldkstorage::{MutinyNodePersister, PhantomChannelManager},
    logging::MutinyLogger,
    lsp::{AnyLsp, FeeRequest, Lsp},
    nodemanager::NodeIndex,
    onchain::OnChainWallet,
    peermanager::{GossipMessageHandler, PeerManagerImpl},
    utils::{self, sleep},
    MutinyInvoice, PrivacyLevel,
};
use crate::{fees::P2WSH_OUTPUT_SIZE, peermanager::connect_peer_if_necessary};
use crate::{keymanager::PhantomKeysManager, scorer::HubPreferentialScorer};
use crate::{labels::LabelStorage, DEFAULT_PAYMENT_TIMEOUT};
use crate::{
    ldkstorage::{persist_monitor, ChannelOpenParams},
    storage::persist_payment_info,
};
use crate::{messagehandler::MutinyMessageHandler, storage::read_payment_info};
use anyhow::{anyhow, Context};
use bitcoin::bip32::Xpriv;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::Address;
use bitcoin::{hashes::Hash, secp256k1::PublicKey, FeeRate, Network, OutPoint};
use core::time::Duration;
use esplora_client::AsyncClient;
use futures_util::lock::Mutex;
use hex_conservative::DisplayHex;
use lightning::events::bump_transaction::{BumpTransactionEventHandler, Wallet};
use lightning::ln::channel_state::ChannelDetails;
use lightning::ln::invoice_utils::{
    create_invoice_from_channelmanager_and_duration_since_epoch, create_phantom_invoice,
};
use lightning::ln::PaymentSecret;
use lightning::onion_message::messenger::OnionMessenger as LdkOnionMessenger;
use lightning::routing::scoring::ProbabilisticScoringDecayParameters;
use lightning::sign::{InMemorySigner, NodeSigner, Recipient};
use lightning::util::config::MaxDustHTLCExposure;
use lightning::util::ser::Writeable;
use lightning::{
    chain::{chainmonitor, Filter, Watch},
    ln::{
        channelmanager::{PaymentId, PhantomRouteHints, Retry},
        peer_handler::{IgnoringMessageHandler, MessageHandler as LdkMessageHandler},
        PaymentHash, PaymentPreimage,
    },
    log_debug, log_error, log_info, log_trace, log_warn,
    routing::{
        gossip,
        gossip::NodeId,
        router::{DefaultRouter, PaymentParameters, RouteParameters},
    },
    util::{
        config::{ChannelHandshakeConfig, ChannelHandshakeLimits, UserConfig},
        logger::Logger,
    },
};
use lightning::{
    ln::channelmanager::{RecipientOnionFields, RetryableSendFailure},
    routing::scoring::ProbabilisticScoringFeeParameters,
    util::config::ChannelConfig,
};
use lightning_background_processor::process_events_async;
use lightning_invoice::Bolt11Invoice;
use lightning_liquidity::lsps2::client::LSPS2ClientConfig;
use lightning_liquidity::{LiquidityClientConfig, LiquidityManager as LDKLSPLiquidityManager};

#[cfg(test)]
use mockall::predicate::*;
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
};
#[cfg(target_arch = "wasm32")]
use web_time::Instant;

const INITIAL_RECONNECTION_DELAY: u64 = 2;
const MAX_RECONNECTION_DELAY: u64 = 60;

pub(crate) type PendingConnections = Arc<Mutex<HashMap<NodeId, u32>>>;

pub(crate) type BumpTxEventHandler<S: MutinyStorage> = BumpTransactionEventHandler<
    Arc<MutinyChain<S>>,
    Arc<Wallet<Arc<OnChainWallet<S>>, Arc<MutinyLogger>>>,
    Arc<PhantomKeysManager<S>>,
    Arc<MutinyLogger>,
>;

pub(crate) type RapidGossipSync =
    lightning_rapid_gossip_sync::RapidGossipSync<Arc<NetworkGraph>, Arc<MutinyLogger>>;

pub(crate) type NetworkGraph = gossip::NetworkGraph<Arc<MutinyLogger>>;

pub(crate) type OnionMessenger<S: MutinyStorage> = LdkOnionMessenger<
    Arc<PhantomKeysManager<S>>,
    Arc<PhantomKeysManager<S>>,
    Arc<MutinyLogger>,
    Arc<PhantomChannelManager<S>>,
    Arc<LspMessageRouter>,
    Arc<PhantomChannelManager<S>>,
    IgnoringMessageHandler,
    IgnoringMessageHandler,
>;

pub type LiquidityManager<S> = LDKLSPLiquidityManager<
    Arc<PhantomKeysManager<S>>,
    Arc<PhantomChannelManager<S>>,
    Arc<dyn Filter + Send + Sync>,
>;

pub(crate) type MessageHandler<S: MutinyStorage> = LdkMessageHandler<
    Arc<PhantomChannelManager<S>>,
    Arc<GossipMessageHandler<S>>,
    Arc<OnionMessenger<S>>,
    Arc<MutinyMessageHandler<S>>,
>;

pub(crate) type ChainMonitor<S: MutinyStorage> = chainmonitor::ChainMonitor<
    InMemorySigner,
    Arc<dyn Filter + Send + Sync>,
    Arc<MutinyChain<S>>,
    Arc<MutinyFeeEstimator<S>>,
    Arc<MutinyLogger>,
    Arc<MutinyNodePersister<S>>,
>;

pub(crate) type Router<S: MutinyStorage> = DefaultRouter<
    Arc<NetworkGraph>,
    Arc<MutinyLogger>,
    Arc<PhantomKeysManager<S>>,
    Arc<utils::Mutex<HubPreferentialScorer>>,
    ProbabilisticScoringFeeParameters,
    HubPreferentialScorer,
>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionType {
    Tcp(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubkeyConnectionInfo {
    pub pubkey: PublicKey,
    pub connection_type: ConnectionType,
    pub original_connection_string: String,
}

impl PubkeyConnectionInfo {
    pub fn new(connection: &str) -> Result<Self, MutinyError> {
        if connection.is_empty() {
            return Err(MutinyError::PeerInfoParseFailed)
                .context("connect_peer requires peer connection info")?;
        };
        let connection = connection.to_lowercase();
        let (pubkey, peer_addr_str) = parse_peer_info(&connection)?;
        Ok(Self {
            pubkey,
            connection_type: ConnectionType::Tcp(peer_addr_str),
            original_connection_string: connection,
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn socket_address(&self) -> Result<std::net::SocketAddr, MutinyError> {
        match self.connection_type {
            ConnectionType::Tcp(ref tcp) => {
                std::net::SocketAddr::from_str(tcp).map_err(|_| MutinyError::InvalidArgumentsError)
            }
        }
    }
}

pub struct NodeBuilder<S: MutinyStorage> {
    // required
    xprivkey: Xpriv,
    storage: S,
    uuid: Option<String>,
    node_index: Option<NodeIndex>,
    gossip_sync: Option<Arc<RapidGossipSync>>,
    scorer: Option<Arc<utils::Mutex<HubPreferentialScorer>>>,
    chain: Option<Arc<MutinyChain<S>>>,
    fee_estimator: Option<Arc<MutinyFeeEstimator<S>>>,
    wallet: Option<Arc<OnChainWallet<S>>>,
    esplora: Option<Arc<AsyncClient>>,
    ln_event_callback: Option<CommonLnEventCallback>,
    #[cfg(target_arch = "wasm32")]
    websocket_proxy_addr: Option<String>,
    network: Option<Network>,
    has_done_initial_sync: Option<Arc<AtomicBool>>,

    // optional
    lsp_config: Option<LspConfig>,
    logger: Option<Arc<MutinyLogger>>,
    do_not_connect_peers: bool,
    do_not_bump_channel_close_tx: bool,
    sweep_target_address: Option<Address>,
}

impl<S: MutinyStorage> NodeBuilder<S> {
    pub fn new(xprivkey: Xpriv, storage: S) -> NodeBuilder<S> {
        NodeBuilder::<S> {
            xprivkey,
            storage,
            uuid: None,
            node_index: None,
            gossip_sync: None,
            scorer: None,
            chain: None,
            fee_estimator: None,
            wallet: None,
            esplora: None,
            has_done_initial_sync: None,
            ln_event_callback: None,
            #[cfg(target_arch = "wasm32")]
            websocket_proxy_addr: None,
            lsp_config: None,
            logger: None,
            network: None,
            do_not_connect_peers: false,
            do_not_bump_channel_close_tx: false,
            sweep_target_address: None,
        }
    }

    /// Required
    pub fn with_uuid(mut self, uuid: String) -> NodeBuilder<S> {
        self.uuid = Some(uuid);
        self
    }

    /// Required
    pub fn with_node_index(mut self, node_index: NodeIndex) -> NodeBuilder<S> {
        self.node_index = Some(node_index);
        self
    }

    /// Required
    pub fn with_gossip_sync(mut self, gossip_sync: Arc<RapidGossipSync>) -> NodeBuilder<S> {
        self.gossip_sync = Some(gossip_sync);
        self
    }

    /// Required
    pub fn with_scorer(
        mut self,
        scorer: Arc<utils::Mutex<HubPreferentialScorer>>,
    ) -> NodeBuilder<S> {
        self.scorer = Some(scorer);
        self
    }

    /// Required
    pub fn with_chain(mut self, chain: Arc<MutinyChain<S>>) -> NodeBuilder<S> {
        self.chain = Some(chain);
        self
    }

    /// Required
    pub fn with_fee_estimator(
        mut self,
        fee_estimator: Arc<MutinyFeeEstimator<S>>,
    ) -> NodeBuilder<S> {
        self.fee_estimator = Some(fee_estimator);
        self
    }

    /// Required
    pub fn with_wallet(mut self, wallet: Arc<OnChainWallet<S>>) -> NodeBuilder<S> {
        self.wallet = Some(wallet);
        self
    }

    /// Required
    pub fn with_esplora(mut self, esplora: Arc<AsyncClient>) -> NodeBuilder<S> {
        self.esplora = Some(esplora);
        self
    }

    pub fn with_network(mut self, network: Network) -> NodeBuilder<S> {
        self.network = Some(network);
        self
    }

    pub fn with_initial_sync(mut self, has_done_initial_sync: Arc<AtomicBool>) -> NodeBuilder<S> {
        self.has_done_initial_sync = Some(has_done_initial_sync);
        self
    }

    #[cfg(target_arch = "wasm32")]
    /// Required
    pub fn with_websocket_proxy_addr(&mut self, websocket_proxy_addr: String) {
        self.websocket_proxy_addr = Some(websocket_proxy_addr);
    }

    pub fn with_lsp_config(&mut self, lsp_config: LspConfig) {
        self.lsp_config = Some(lsp_config);
    }

    pub fn with_ln_event_callback(&mut self, callback: CommonLnEventCallback) {
        self.ln_event_callback = Some(callback);
    }

    pub fn with_logger(&mut self, logger: Arc<MutinyLogger>) {
        self.logger = Some(logger);
    }

    pub fn do_not_connect_peers(&mut self) {
        self.do_not_connect_peers = true;
    }

    pub fn do_not_bump_channel_close_tx(&mut self) {
        self.do_not_bump_channel_close_tx = true;
    }

    pub fn with_sweep_target_address(&mut self, sweep_target_address: Address) {
        self.sweep_target_address = Some(sweep_target_address);
    }

    pub fn log_params(&self, logger: &Arc<MutinyLogger>) {
        log_debug!(logger, "build parameters:");
        log_debug!(logger, "- uuid: {:?}", self.uuid);
        log_debug!(logger, "- node_index: {:?}", self.node_index);
        log_debug!(logger, "- gossip_sync: {:#?}", self.gossip_sync.is_some());
        log_debug!(logger, "- scorer: {:#?}", self.scorer.is_some());
        log_debug!(logger, "- chain: {:#?}", self.chain.is_some());
        log_debug!(
            logger,
            "- fee_estimator: {:#?}",
            self.fee_estimator.is_some()
        );
        log_debug!(logger, "- wallet: {:#?}", self.wallet.is_some());
        log_debug!(logger, "- esplora: {:?}", self.esplora);
        #[cfg(target_arch = "wasm32")]
        log_debug!(
            logger,
            "- websocket_proxy_addr: {:?}",
            self.websocket_proxy_addr
        );
        log_debug!(logger, "- network: {:?}", self.network);
        log_debug!(
            logger,
            "- has_done_initial_sync: {:?}",
            self.has_done_initial_sync
        );
        log_debug!(logger, "- lsp_config: {:?}", self.lsp_config);
        log_debug!(
            logger,
            "- do_not_connect_peers: {}",
            self.do_not_connect_peers
        );
    }

    pub async fn build(self) -> Result<Node<S>, MutinyError> {
        let node_start = Instant::now();

        // check for all required parameters
        let node_index = self.node_index.as_ref().map_or_else(
            || Err(MutinyError::InvalidArgumentsError),
            |v| Ok(v.clone()),
        )?;
        let gossip_sync = self.gossip_sync.as_ref().map_or_else(
            || Err(MutinyError::InvalidArgumentsError),
            |v| Ok(v.clone()),
        )?;
        let scorer = self.scorer.as_ref().map_or_else(
            || Err(MutinyError::InvalidArgumentsError),
            |v| Ok(v.clone()),
        )?;
        let chain = self.chain.as_ref().map_or_else(
            || Err(MutinyError::InvalidArgumentsError),
            |v| Ok(v.clone()),
        )?;
        let fee_estimator = self.fee_estimator.as_ref().map_or_else(
            || Err(MutinyError::InvalidArgumentsError),
            |v| Ok(v.clone()),
        )?;
        let wallet = self.wallet.as_ref().map_or_else(
            || Err(MutinyError::InvalidArgumentsError),
            |v| Ok(v.clone()),
        )?;
        let esplora = self.esplora.as_ref().map_or_else(
            || Err(MutinyError::InvalidArgumentsError),
            |v| Ok(v.clone()),
        )?;
        let network = self
            .network
            .map_or_else(|| Err(MutinyError::InvalidArgumentsError), Ok)?;
        #[cfg(target_arch = "wasm32")]
        let websocket_proxy_addr = self.websocket_proxy_addr.as_ref().map_or_else(
            || Err(MutinyError::InvalidArgumentsError),
            |v| Ok(v.clone()),
        )?;

        let logger = self
            .logger
            .clone()
            .unwrap_or(Arc::new(MutinyLogger::default()));

        self.log_params(&logger);

        log_info!(logger, "initializing a new node: {:?}", self.uuid);

        // a list of components that need to be stopped and whether or not they are stopped
        let stopped_components = Arc::new(RwLock::new(vec![]));

        let keys_manager = Arc::new(create_keys_manager(
            wallet.clone(),
            self.xprivkey,
            node_index.child_index,
            logger.clone(),
        )?);
        let pubkey = pubkey_from_keys_manager(&keys_manager);

        // if no UUID was given then this is new node, we deterministically generate
        // it from our key manager.
        let uuid = match self.uuid {
            Some(uuid) => uuid,
            None => deterministic_uuid_from_keys_manager(&keys_manager).to_string(),
        };

        // init the persister
        let persister = Arc::new(MutinyNodePersister::new(
            uuid.clone(),
            self.storage,
            logger.clone(),
        ));

        // init chain monitor
        let chain_monitor: Arc<ChainMonitor<S>> = Arc::new(ChainMonitor::new(
            Some(chain.tx_sync.clone()),
            chain.clone(),
            logger.clone(),
            fee_estimator.clone(),
            persister.clone(),
        ));

        // set chain monitor for persister for async storage
        persister
            .chain_monitor
            .lock()
            .await
            .replace(chain_monitor.clone());

        // read channelmonitor state from disk
        let channel_monitors = persister
            .read_channel_monitors(keys_manager.clone())
            .map_err(|e| MutinyError::ReadError {
                source: MutinyStorageError::Other(anyhow!("failed to read channel monitors: {e}")),
            })?;

        let network_graph = gossip_sync.network_graph().clone();

        let router: Arc<Router<_>> = Arc::new(DefaultRouter::new(
            network_graph,
            logger.clone(),
            keys_manager.clone(),
            scorer.clone(),
            scoring_params(),
        ));

        log_trace!(logger, "creating lsp config");
        let lsp_config: Option<LspConfig> = match node_index.lsp {
            None => {
                log_info!(logger, "no lsp saved, using configured one if present");
                self.lsp_config
            }
            Some(lsp) => {
                if self.lsp_config.as_ref().is_some_and(|l| l.matches(&lsp)) {
                    log_info!(logger, "lsp config matches saved lsp config");
                    // prefer node index lsp config over configured one
                    // as it may have extra info like the LSP connection info
                    Some(lsp)
                } else {
                    log_warn!(
                        logger,
                        "lsp config does not match saved lsp config, using saved one"
                    );
                    Some(lsp)
                }
            }
        };
        log_trace!(logger, "finished creating lsp config");

        // init channel manager
        log_trace!(logger, "initializing channel manager");
        let accept_underpaying_htlcs = lsp_config
            .as_ref()
            .is_some_and(|l| l.accept_underpaying_htlcs());
        let mut read_channel_manager = persister
            .read_channel_manager(
                network,
                accept_underpaying_htlcs,
                chain_monitor.clone(),
                chain.clone(),
                fee_estimator.clone(),
                logger.clone(),
                keys_manager.clone(),
                router.clone(),
                channel_monitors,
                &esplora,
            )
            .await?;
        log_trace!(logger, "finished initializing channel manager");

        let channel_manager: Arc<PhantomChannelManager<S>> =
            Arc::new(read_channel_manager.channel_manager);

        let stop = Arc::new(AtomicBool::new(false));

        log_trace!(logger, "creating lsp client");
        let (lsp_client, lsp_client_pubkey, liquidity) = match lsp_config {
            Some(LspConfig::VoltageFlow(config)) => {
                let lsp = AnyLsp::new_voltage_flow(config, logger.clone()).await?;
                let pubkey = lsp.get_lsp_pubkey().await;
                (Some(lsp), Some(pubkey), None)
            }
            Some(LspConfig::Lsps(lsps_config)) => {
                let liquidity_manager = Arc::new(LiquidityManager::new(
                    keys_manager.clone(),
                    channel_manager.clone(),
                    None,
                    None,
                    None,
                    Some(LiquidityClientConfig {
                        lsps2_client_config: Some(LSPS2ClientConfig::default()),
                    }),
                ));
                let lsp = AnyLsp::new_lsps(
                    lsps_config.connection_string.clone(),
                    lsps_config.token.clone(),
                    liquidity_manager.clone(),
                    channel_manager.clone(),
                    keys_manager.clone(),
                    network,
                    logger.clone(),
                    stop.clone(),
                )?;
                let pubkey = lsp.get_lsp_pubkey().await;
                (Some(lsp), Some(pubkey), Some(liquidity_manager))
            }
            None => (None, None, None),
        };
        log_trace!(logger, "finished creating lsp client");

        log_trace!(logger, "creating onion routers");
        let message_router = Arc::new(LspMessageRouter::new(lsp_client_pubkey));
        let onion_message_handler = Arc::new(OnionMessenger::new(
            keys_manager.clone(),
            keys_manager.clone(),
            logger.clone(),
            channel_manager.clone(),
            message_router.clone(),
            channel_manager.clone(),
            IgnoringMessageHandler {},
            IgnoringMessageHandler {},
        ));

        let route_handler = Arc::new(GossipMessageHandler {
            storage: persister.storage.clone(),
            network_graph: gossip_sync.network_graph().clone(),
            logger: logger.clone(),
        });
        log_trace!(logger, "finished creating onion routers");

        // init peer manager
        log_trace!(logger, "creating peer manager");
        let ln_msg_handler = MessageHandler {
            chan_handler: channel_manager.clone(),
            route_handler,
            onion_message_handler: onion_message_handler.clone(),
            custom_message_handler: Arc::new(MutinyMessageHandler {
                liquidity: liquidity.clone(),
                ln_event_callback: self.ln_event_callback.clone(),
            }),
        };
        log_trace!(logger, "finished creating peer manager");

        log_trace!(logger, "creating bump tx event handler");
        let bump_tx_event_handler = Arc::new(BumpTransactionEventHandler::new(
            Arc::clone(&chain),
            Arc::new(Wallet::new(Arc::clone(&wallet), Arc::clone(&logger))),
            Arc::clone(&keys_manager),
            Arc::clone(&logger),
        ));
        log_trace!(logger, "finished creating bump tx event handler");

        // init event handler
        log_trace!(logger, "creating event handler");

        if self.do_not_bump_channel_close_tx {
            log_info!(logger, "Disable bump for channel close transaction");
        }

        log_info!(
            logger,
            "Sweep target address: {:?}",
            self.sweep_target_address
        );

        let event_handler = EventHandler::new(
            channel_manager.clone(),
            fee_estimator.clone(),
            wallet.clone(),
            keys_manager.clone(),
            persister.clone(),
            bump_tx_event_handler,
            lsp_client.clone(),
            logger.clone(),
            self.do_not_bump_channel_close_tx,
            self.sweep_target_address,
            self.ln_event_callback.clone(),
        );
        log_trace!(logger, "finished creating event handler");

        log_trace!(logger, "creating peer manager");
        let peer_man = Arc::new(create_peer_manager(
            keys_manager.clone(),
            ln_msg_handler,
            logger.clone(),
        ));
        log_trace!(logger, "finished creating peer manager");

        if let Some(liquidity) = liquidity {
            log_trace!(logger, "setting liqudity callback");
            let process_msgs_pm = peer_man.clone();
            liquidity.set_process_msgs_callback(move || {
                process_msgs_pm.process_events();
            });
            log_trace!(logger, "finished setting liqudity callback");
        }

        // sync to chain tip
        log_trace!(logger, "syncing chain to tip");
        if read_channel_manager.is_restarting {
            let start = Instant::now();
            let mut chain_listener_channel_monitors =
                Vec::with_capacity(read_channel_manager.channel_monitors.len());
            for (blockhash, channel_monitor) in read_channel_manager.channel_monitors.drain(..) {
                // Get channel monitor ready to sync
                log_trace!(logger, "loading outputs to watch");
                channel_monitor.load_outputs_to_watch(&chain, &logger);

                let outpoint = channel_monitor.get_funding_txo().0;
                chain_listener_channel_monitors.push((
                    blockhash,
                    (
                        channel_monitor,
                        chain.clone(),
                        chain.clone(),
                        logger.clone(),
                    ),
                    outpoint,
                ));
            }

            // give channel monitors to chain monitor
            log_trace!(logger, "giving channel monitors to chain monitor");
            for item in chain_listener_channel_monitors.drain(..) {
                let channel_monitor = item.1 .0;
                let funding_outpoint = item.2;

                chain_monitor
                    .watch_channel(funding_outpoint, channel_monitor)
                    .map_err(|_| MutinyError::ChainAccessFailed)?;
            }

            log_trace!(
                logger,
                "Syncing monitors to chain tip took {}ms",
                start.elapsed().as_millis()
            );
        }
        log_trace!(logger, "finished syncing chain to tip");

        // Before we start the background processor, retry previously failed
        // spendable outputs. We should do this before we start the background
        // processor so we prevent any race conditions.
        // if we fail to read the spendable outputs, just log a warning and
        // continue
        log_trace!(logger, "retrying spendable outputs");
        let retry_spendable_outputs = persister
            .get_failed_spendable_outputs()
            .map_err(|e| MutinyError::ReadError {
                source: MutinyStorageError::Other(anyhow!(
                    "failed to read retry spendable outputs: {e}"
                )),
            })
            .unwrap_or_else(|e| {
                log_warn!(logger, "Failed to read retry spendable outputs: {e}");
                vec![]
            });

        if !retry_spendable_outputs.is_empty() {
            let event_handler = event_handler.clone();
            let persister = persister.clone();
            let logger = logger.clone();

            // We need to process our unhandled spendable outputs
            // can do this in the background, no need to block on it
            utils::spawn(async move {
                let start = Instant::now();
                log_info!(
                    logger,
                    "Retrying {} spendable outputs",
                    retry_spendable_outputs.len()
                );

                match event_handler
                    .handle_spendable_outputs(&retry_spendable_outputs)
                    .await
                {
                    Ok(_) => {
                        log_info!(logger, "Successfully retried spendable outputs");
                        if let Err(e) = persister.clear_failed_spendable_outputs() {
                            log_warn!(logger, "Failed to clear failed spendable outputs: {e}");
                        }
                    }
                    Err(_) => {
                        // retry them individually then only save failed ones
                        // if there was only one we don't need to retry
                        if retry_spendable_outputs.len() > 1 {
                            let mut failed = vec![];
                            for o in retry_spendable_outputs {
                                if event_handler
                                    .handle_spendable_outputs(&[o.clone()])
                                    .await
                                    .is_err()
                                {
                                    failed.push(o);
                                }
                            }
                            if let Err(e) = persister.set_failed_spendable_outputs(failed) {
                                log_warn!(logger, "Failed to set failed spendable outputs: {e}");
                            }
                        };
                    }
                }

                log_info!(
                    logger,
                    "Retrying spendable outputs took {}ms",
                    start.elapsed().as_millis()
                );
            });
        }
        log_trace!(logger, "finished retrying spendable outputs");

        // Check all existing channels against default configs.
        // If we have default config changes, those should apply
        // to all existing and new channels.
        log_trace!(logger, "checking default user config against channels");
        let default_config = default_user_config(accept_underpaying_htlcs).channel_config;
        for channel in channel_manager.list_channels() {
            // unwrap is safe after LDK.0.0.109
            if channel.config.unwrap() != default_config {
                match channel_manager.update_channel_config(
                    &channel.counterparty.node_id,
                    &[channel.channel_id],
                    &default_config,
                ) {
                    Ok(_) => {
                        log_debug!(
                            logger,
                            "changed default config for channel: {}",
                            channel.channel_id
                        )
                    }
                    Err(e) => {
                        log_error!(
                            logger,
                            "error changing default config for channel: {} - {e:?}",
                            channel.channel_id
                        )
                    }
                };
            }
        }
        log_trace!(
            logger,
            "finished checking default user config against channels"
        );

        log_trace!(logger, "spawning ldk background thread");
        let background_persister = persister.clone();
        let background_event_handler = event_handler.clone();
        let background_processor_logger = logger.clone();
        let background_processor_peer_manager = peer_man.clone();
        let background_processor_channel_manager = channel_manager.clone();
        let background_chain_monitor = chain_monitor.clone();
        let background_gossip_sync = gossip_sync.clone();
        let background_logger = logger.clone();
        let background_stop = stop.clone();
        stopped_components.try_write()?.push(false);
        let background_stopped_components = stopped_components.clone();
        utils::spawn(async move {
            loop {
                let gs = lightning_background_processor::GossipSync::rapid(
                    background_gossip_sync.clone(),
                );
                let ev = background_event_handler.clone();
                if let Err(e) = process_events_async(
                    background_persister.clone(),
                    |e| ev.handle_event(e),
                    background_chain_monitor.clone(),
                    background_processor_channel_manager.clone(),
                    Option::<Arc<OnionMessenger<S>>>::None,
                    gs,
                    background_processor_peer_manager.clone(),
                    background_processor_logger.clone(),
                    Some(scorer.clone()),
                    |d| {
                        let background_event_stop = background_stop.clone();
                        Box::pin(async move {
                            sleep(d.as_millis() as i32).await;
                            background_event_stop.load(Ordering::Relaxed)
                        })
                    },
                    true,
                    || Some(utils::now()),
                )
                .await
                {
                    log_error!(background_logger, "error running background processor: {e}",);
                }

                if background_stop.load(Ordering::Relaxed) {
                    log_debug!(
                        background_logger,
                        "stopping background component for node: {}",
                        pubkey,
                    );
                    stop_component(&background_stopped_components);
                    log_debug!(
                        background_logger,
                        "stopped background component for node: {}",
                        pubkey
                    );
                    break;
                }
            }
        });
        log_trace!(logger, "finished spawning ldk background thread");

        let pending_connections = Arc::new(Mutex::new(Default::default()));

        if !self.do_not_connect_peers {
            #[cfg(target_arch = "wasm32")]
            let reconnection_proxy_addr = websocket_proxy_addr.clone();

            log_trace!(logger, "spawning ldk reconnect thread");
            let reconnection_storage = persister.storage.clone();
            let reconnection_pubkey = pubkey;
            let reconnection_peer_man = peer_man.clone();
            let reconnection_fee = fee_estimator.clone();
            let reconnection_logger = logger.clone();
            let reconnection_uuid = uuid.clone();
            let reconnection_lsp_client = lsp_client.clone();
            let reconnection_stop = stop.clone();
            let reconnection_stopped_comp = stopped_components.clone();
            reconnection_stopped_comp.try_write()?.push(false);
            let pending_connections = pending_connections.clone();
            utils::spawn(async move {
                start_reconnection_handling(
                    &reconnection_storage,
                    reconnection_pubkey,
                    #[cfg(target_arch = "wasm32")]
                    reconnection_proxy_addr,
                    reconnection_peer_man,
                    pending_connections,
                    reconnection_fee,
                    &reconnection_logger,
                    reconnection_uuid,
                    reconnection_lsp_client.as_ref(),
                    reconnection_stop,
                    reconnection_stopped_comp,
                    network == Network::Regtest,
                )
                .await;
            });
            log_trace!(logger, "finished spawning ldk reconnect thread");
        }

        log_info!(
            logger,
            "Node started: {}",
            keys_manager.get_node_id(Recipient::Node).unwrap()
        );

        let sync_lock = Arc::new(Mutex::new(()));

        // Here we re-attempt to persist any monitors that failed to persist previously.
        log_trace!(logger, "reattempt monitor persistance thread");
        let retry_logger = logger.clone();
        let retry_persister = persister.clone();
        let retry_stop = stop.clone();
        let retry_chain_monitor = chain_monitor.clone();
        let retry_sync_lock = sync_lock.clone();
        utils::spawn(async move {
            // sleep 3 seconds before checking, we won't have any pending updates on startup
            sleep(3_000).await;

            loop {
                if retry_stop.load(Ordering::Relaxed) {
                    break;
                }

                let updates = {
                    let _lock = retry_sync_lock.lock().await;
                    retry_chain_monitor.list_pending_monitor_updates()
                };

                for (funding_txo, update_ids) in updates {
                    // if there are no updates, skip
                    if update_ids.is_empty() {
                        continue;
                    }

                    log_debug!(
                        retry_logger,
                        "Retrying to persist monitor for outpoint: {funding_txo:?}"
                    );

                    let data_opt = match retry_chain_monitor.get_monitor(funding_txo) {
                        Ok(monitor) => {
                            let key = retry_persister.get_monitor_key(&funding_txo);
                            let object = monitor.encode();
                            let update_id = monitor.get_latest_update_id();
                            debug_assert_eq!(update_id, get_monitor_version(&object));

                            // safely convert u64 to u32
                            let version = if update_id >= u32::MAX as u64 {
                                u32::MAX
                            } else {
                                update_id as u32
                            };

                            Some((key, object, version))
                        }
                        Err(_) => {
                            log_error!(
                                retry_logger,
                                "Failed to get monitor for outpoint: {funding_txo:?}"
                            );
                            None
                        }
                    };

                    if let Some((key, object, version)) = data_opt {
                        log_debug!(
                            retry_logger,
                            "Persisting monitor for output: {funding_txo:?}"
                        );
                        let res = persist_monitor(
                            retry_persister.storage.clone(),
                            key,
                            object,
                            Some(version),
                            retry_logger.clone(),
                        );

                        match res {
							Ok(_) => {
								for id in update_ids {
									if let Err(e) = retry_chain_monitor
										.channel_monitor_updated(funding_txo, id)
									{
										log_error!(retry_logger, "Error notifying chain monitor of channel monitor update: {e:?}");
									} else {
                                        log_debug!(
                                            retry_logger,
                                            "notified channel monitor updated: {funding_txo:?}"
                                        );
                                    }
								}
							}
							Err(e) => log_error!(
                                    retry_logger,
                                    "Failed to persist monitor for outpoint: {funding_txo:?}, error: {e:?}",
                                ),
						}
                    }
                }

                // sleep 3 seconds
                sleep(3_000).await;
            }
        });
        log_trace!(logger, "finished reattempt monitor persistance thread");

        log_trace!(
            logger,
            "Node started, took {}ms",
            node_start.elapsed().as_millis()
        );

        let has_done_initial_sync = self
            .has_done_initial_sync
            .unwrap_or(Arc::new(AtomicBool::new(false)));

        Ok(Node {
            uuid,
            stopped_components,
            child_index: node_index.child_index,
            pubkey,
            peer_manager: peer_man,
            pending_connections,
            keys_manager,
            channel_manager,
            chain_monitor,
            fee_estimator,
            network,
            persister,
            wallet,
            logger,
            lsp_client,
            sync_lock,
            stop,
            has_done_initial_sync,
            #[cfg(target_arch = "wasm32")]
            websocket_proxy_addr,
        })
    }
}

pub(crate) struct Node<S: MutinyStorage> {
    pub uuid: String,
    pub child_index: u32,
    stopped_components: Arc<RwLock<Vec<bool>>>,
    pub pubkey: PublicKey,
    pub peer_manager: Arc<PeerManagerImpl<S>>,
    pub pending_connections: PendingConnections,
    pub keys_manager: Arc<PhantomKeysManager<S>>,
    pub channel_manager: Arc<PhantomChannelManager<S>>,
    pub chain_monitor: Arc<ChainMonitor<S>>,
    pub fee_estimator: Arc<MutinyFeeEstimator<S>>,
    network: Network,
    pub persister: Arc<MutinyNodePersister<S>>,
    wallet: Arc<OnChainWallet<S>>,
    pub(crate) logger: Arc<MutinyLogger>,
    pub(crate) lsp_client: Option<AnyLsp<S>>,
    pub(crate) sync_lock: Arc<Mutex<()>>,
    stop: Arc<AtomicBool>,
    has_done_initial_sync: Arc<AtomicBool>,
    #[cfg(target_arch = "wasm32")]
    websocket_proxy_addr: String,
}

impl<S: MutinyStorage> Node<S> {
    pub async fn stop(&self) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling stop");

        self.stop.store(true, Ordering::Relaxed);

        self.stopped().await?;

        log_trace!(self.logger, "finished calling stop");

        Ok(())
    }

    /// stopped will await until the node is fully shut down
    pub async fn stopped(&self) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling stopped");

        loop {
            let all_stopped = {
                let stopped_components = self
                    .stopped_components
                    .try_read()
                    .map_err(|_| MutinyError::NotRunning)?;
                stopped_components.iter().all(|&x| x)
            };

            if all_stopped {
                break;
            }

            sleep(500).await;
        }

        log_trace!(self.logger, "finished calling stopped");
        Ok(())
    }

    pub async fn node_index(&self) -> NodeIndex {
        log_trace!(self.logger, "calling node_index");

        let lsp = match self.lsp_client.as_ref() {
            Some(lsp) => Some(lsp.get_config().await),
            None => None,
        };

        let n = NodeIndex {
            child_index: self.child_index,
            lsp,
            archived: Some(false),
        };

        log_trace!(self.logger, "finished calling node_index");

        n
    }

    pub async fn connect_peer(
        &self,
        peer_connection_info: PubkeyConnectionInfo,
        label: Option<String>,
    ) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling connect_peer");

        let connect_res = connect_peer_if_necessary(
            #[cfg(target_arch = "wasm32")]
            &self.websocket_proxy_addr,
            &peer_connection_info,
            &self.persister.storage,
            self.logger.clone(),
            self.peer_manager.clone(),
            self.pending_connections.clone(),
            self.fee_estimator.clone(),
            self.stop.clone(),
        )
        .await;
        let res = match connect_res {
            Ok(_) => {
                let node_id = NodeId::from_pubkey(&peer_connection_info.pubkey);

                // if we have the connection info saved in storage, update it if we need to
                // otherwise cache it in temp_peer_connection_map so we can later save it
                // if we open a channel in the future.
                if let Some(saved) = read_peer_info(&self.persister.storage, &node_id)?
                    .and_then(|p| p.connection_string)
                {
                    if saved != peer_connection_info.original_connection_string {
                        match save_peer_connection_info(
                            &self.persister.storage,
                            &self.uuid,
                            &node_id,
                            &peer_connection_info.original_connection_string,
                            label,
                        ) {
                            Ok(_) => (),
                            Err(_) => {
                                log_warn!(self.logger, "WARN: could not store peer connection info")
                            }
                        }
                    }
                } else {
                    // store this so we can reconnect later
                    if let Err(e) = save_peer_connection_info(
                        &self.persister.storage,
                        &self.uuid,
                        &node_id,
                        &peer_connection_info.original_connection_string,
                        label,
                    ) {
                        log_warn!(
                            self.logger,
                            "WARN: could not store peer connection info: {e}"
                        );
                    }
                }

                Ok(())
            }
            Err(e) => Err(e),
        };

        log_trace!(self.logger, "finished calling connect_peer");

        res
    }

    pub fn disconnect_peer(&self, peer_id: PublicKey) {
        log_trace!(self.logger, "calling disconnect_peer");
        self.peer_manager.disconnect_by_node_id(peer_id);
        log_trace!(self.logger, "finished calling disconnect_peer");
    }

    pub fn get_phantom_route_hint(&self) -> PhantomRouteHints {
        log_trace!(self.logger, "calling get_phantom_route_hint");
        let res = self.channel_manager.get_phantom_route_hints();
        log_trace!(self.logger, "calling get_phantom_route_hint");

        res
    }

    pub async fn get_lsp_fee(&self, amount_sat: u64) -> Result<u64, MutinyError> {
        log_trace!(self.logger, "calling get_lsp_fee");
        let res = match self.lsp_client.as_ref() {
            Some(lsp) => {
                let connect = lsp.get_lsp_connection_string().await;
                self.connect_peer(PubkeyConnectionInfo::new(&connect)?, None)
                    .await?;

                // Needs any amount over 0 if channel exists
                // Needs amount over minimum if no channel
                let inbound_capacity_msat: u64 = self
                    .channel_manager
                    .list_channels_with_counterparty(&lsp.get_lsp_pubkey().await)
                    .iter()
                    .map(|c| c.inbound_capacity_msat)
                    .sum();

                log_debug!(self.logger, "Current inbound liquidity {inbound_capacity_msat}msats, creating invoice for {}msats", amount_sat * 1000);

                let has_inbound_capacity = inbound_capacity_msat > amount_sat * 1_000;

                let min_amount_sat = if has_inbound_capacity {
                    1
                } else {
                    utils::min_lightning_amount(self.network, lsp.is_lsps())
                };

                if amount_sat < min_amount_sat {
                    return Err(MutinyError::BadAmountError);
                }

                // check the fee from the LSP
                let lsp_fee = lsp
                    .get_lsp_fee_msat(FeeRequest {
                        pubkey: self.pubkey.encode().to_lower_hex_string(),
                        amount_msat: amount_sat * 1000,
                    })
                    .await?;

                // Convert the fee from msat to sat for comparison and subtraction
                Ok(lsp_fee.fee_amount_msat / 1000)
            }
            None => Ok(0),
        };
        log_trace!(self.logger, "finished calling get_lsp_fee");

        res
    }

    fn get_outbound_capacity_msat(&self) -> u64 {
        let channels = self.channel_manager.list_channels();
        self.chain_monitor
            .get_claimable_balances(
                &channels
                    .iter()
                    // only consider channels that are confirmed
                    .filter(|c| !c.is_channel_ready)
                    .collect::<Vec<_>>(),
            )
            .into_iter()
            .map(|b| b.claimable_amount_satoshis())
            .sum::<u64>()
            * 1000
    }

    fn get_inbound_capacity_msat(&self) -> u64 {
        self.channel_manager
            .list_usable_channels()
            .iter()
            .map(|c| c.inbound_capacity_msat)
            .sum()
    }

    async fn try_connect_unusable_channel_peers(&self) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling try_connect_unusable_channel peers");

        let node_ids = self.peer_manager.get_peer_node_ids();
        for channel in self.channel_manager.list_channels() {
            if channel.is_usable || node_ids.contains(&channel.counterparty.node_id) {
                // skip connected peers
                continue;
            }

            let node_id = channel.counterparty.node_id.into();

            log_debug!(self.logger, "try connect peer {}", &node_id);

            let Some(peer_connection_string) = read_peer_info(&self.persister.storage, &node_id)?
                .and_then(|peer_info| peer_info.connection_string)
            else {
                log_debug!(
                        self.logger,
                        "failed to connect peer {} because we can't find peer connection string from storage",
                        &node_id
                    );
                continue;
            };

            log_debug!(
                self.logger,
                "find peer connection string {}",
                &peer_connection_string
            );

            let connect_info = match PubkeyConnectionInfo::new(&peer_connection_string) {
                Ok(info) => info,
                Err(err) => {
                    log_debug!(
                        self.logger,
                        "failed to parse peer connection string {}, error {:?}",
                        &peer_connection_string,
                        err
                    );
                    continue;
                }
            };

            if let Err(err) = self.connect_peer(connect_info, None).await {
                log_debug!(self.logger, "failed to connect, error {:?}", err);
            }
        }

        log_trace!(
            self.logger,
            "finished calling try_connect_unusable_channel peers"
        );
        Ok(())
    }

    pub async fn create_invoice(
        &self,
        amount_sat: u64,
        route_hints: Option<Vec<PhantomRouteHints>>,
        labels: Vec<String>,
        expiry_delta_secs: Option<u32>,
    ) -> Result<(Bolt11Invoice, u64), MutinyError> {
        log_trace!(self.logger, "calling create_invoice");

        if amount_sat < 1 {
            return Err(MutinyError::BadAmountError);
        }

        let res = match self.lsp_client.as_ref() {
            Some(lsp) => {
                let connect = lsp.get_lsp_connection_string().await;
                self.connect_peer(PubkeyConnectionInfo::new(&connect)?, None)
                    .await?;

                let inbound_capacity_msat: u64 = self.get_inbound_capacity_msat();
                log_debug!(self.logger, "Current inbound liquidity {inbound_capacity_msat}msats, creating invoice for {}msats", amount_sat * 1000);

                if inbound_capacity_msat < amount_sat * 1_000 {
                    log_debug!(
                        self.logger,
                        "Inbound capacity insufficient, try to resume disconnect channels..."
                    );
                    if let Err(err) = self.try_connect_unusable_channel_peers().await {
                        log_debug!(
                            self.logger,
                            "try connect unusable_channel_peers error {err:?}"
                        );
                    }

                    let inbound_capacity_msat: u64 = self.get_inbound_capacity_msat();
                    log_debug!(self.logger, "Current inbound liquidity {inbound_capacity_msat}msats, creating invoice for {}msats", amount_sat * 1000);
                    if inbound_capacity_msat < amount_sat * 1_000 {
                        return Err(MutinyError::InsufficientBalance);
                    }
                }

                Ok((
                    self.create_internal_invoice(
                        Some(amount_sat),
                        None,
                        route_hints,
                        labels,
                        expiry_delta_secs,
                    )
                    .await?,
                    0,
                ))
            }
            None => Ok((
                self.create_internal_invoice(
                    Some(amount_sat),
                    None,
                    route_hints,
                    labels,
                    expiry_delta_secs,
                )
                .await?,
                0,
            )),
        };

        log_trace!(self.logger, "finished calling create_invoice");

        res
    }

    async fn create_internal_invoice(
        &self,
        amount_sat: Option<u64>,
        fee_amount_msat: Option<u64>,
        route_hints: Option<Vec<PhantomRouteHints>>,
        labels: Vec<String>,
        expiry_delta_secs: Option<u32>,
    ) -> Result<Bolt11Invoice, MutinyError> {
        let amount_msat = amount_sat.map(|s| s * 1_000);
        // Use first element of labels as description
        let description = labels.first().unwrap_or(&"".to_string()).to_owned();

        // wait for first sync to complete
        for _ in 0..60 {
            // check if we've been stopped
            if self.stop.load(Ordering::Relaxed) {
                return Err(MutinyError::NotRunning);
            }

            if let Ok(true) = self.persister.storage.has_done_first_sync() {
                break;
            }

            sleep(1_000).await;
        }

        let invoice_res = match route_hints {
            None => {
                let now = crate::utils::now();
                create_invoice_from_channelmanager_and_duration_since_epoch(
                    &self.channel_manager.clone(),
                    self.keys_manager.clone(),
                    self.logger.clone(),
                    self.network.into(),
                    amount_msat,
                    description,
                    now,
                    expiry_delta_secs.unwrap_or(3600),
                    Some(40),
                )
            }
            Some(r) => create_phantom_invoice(
                amount_msat,
                None,
                description,
                expiry_delta_secs.unwrap_or(3600),
                r,
                self.keys_manager.clone(),
                self.keys_manager.clone(),
                self.logger.clone(),
                self.network.into(),
                Some(40),
                crate::utils::now(),
            ),
        };
        let invoice = invoice_res.map_err(|e| {
            log_error!(self.logger, "ERROR: could not generate invoice: {e}");
            MutinyError::InvoiceCreationFailed
        })?;

        self.save_invoice_payment_info(invoice.clone(), amount_msat, fee_amount_msat, labels)
            .await?;

        log_info!(self.logger, "SUCCESS: generated invoice: {invoice}");

        Ok(invoice)
    }

    async fn save_invoice_payment_info(
        &self,
        invoice: Bolt11Invoice,
        amount_msat: Option<u64>,
        fee_amount_msat: Option<u64>,
        labels: Vec<String>,
    ) -> Result<(), MutinyError> {
        let last_update = utils::now().as_secs();
        let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
        let payment_info = PaymentInfo {
            preimage: None,
            secret: Some(invoice.payment_secret().0),
            status: HTLCStatus::Pending,
            amt_msat: MillisatAmount(amount_msat),
            fee_paid_msat: fee_amount_msat,
            bolt11: Some(invoice.clone()),
            payee_pubkey: None,
            privacy_level: PrivacyLevel::NotAvailable,
            last_update,
        };
        persist_payment_info(
            &self.persister.storage,
            &payment_hash.0,
            &payment_info,
            true,
        )
        .map_err(|e| {
            log_error!(self.logger, "ERROR: could not persist payment info: {e}");
            MutinyError::InvoiceCreationFailed
        })?;

        self.persister.storage.set_invoice_labels(invoice, labels)?;

        Ok(())
    }

    /// Gets all the closed channels for this node
    pub fn get_channel_closure(
        &self,
        user_channel_id: u128,
    ) -> Result<Option<ChannelClosure>, MutinyError> {
        log_trace!(self.logger, "calling get_channel_closure");
        let res = self.persister.get_channel_closure(user_channel_id);
        log_trace!(self.logger, "finished calling get_channel_closure");

        res
    }

    /// Gets all the closed channels for this node
    pub fn get_channel_closures(&self) -> Result<Vec<ChannelClosure>, MutinyError> {
        log_trace!(self.logger, "calling get_channel_closures");
        let res = self.persister.list_channel_closures();
        log_trace!(self.logger, "finished calling get_channel_closures");

        res
    }

    fn retry_strategy() -> Retry {
        Retry::Attempts(15)
    }

    /// init_invoice_payment sends off the payment but does not wait for results
    /// use pay_invoice_with_timeout to wait for results
    pub async fn init_invoice_payment(
        &self,
        invoice: &Bolt11Invoice,
        amt_sats: Option<u64>,
    ) -> Result<(PaymentId, PaymentHash), MutinyError> {
        log_trace!(self.logger, "calling init_invoice_payment");

        let payment_hash = invoice.payment_hash().to_byte_array();

        if read_payment_info(&self.persister.storage, &payment_hash, false, &self.logger)
            .is_some_and(|p| p.status != HTLCStatus::Failed)
        {
            return Err(MutinyError::NonUniquePaymentHash);
        }

        if read_payment_info(&self.persister.storage, &payment_hash, true, &self.logger)
            .is_some_and(|p| p.status != HTLCStatus::Failed)
        {
            return Err(MutinyError::NonUniquePaymentHash);
        }

        // get invoice amount or use amt_sats
        let send_msats = invoice
            .amount_milli_satoshis()
            .or(amt_sats.map(|x| x * 1_000))
            .ok_or(MutinyError::InvoiceInvalid)?;

        // check if we have enough balance to send
        if self.get_outbound_capacity_msat() < send_msats {
            log_debug!(
                self.logger,
                "Outbound capacity insufficient, try to resume disconnect channels..."
            );
            if let Err(err) = self.try_connect_unusable_channel_peers().await {
                log_debug!(
                    self.logger,
                    "try connect unusable_channel_peers error {err:?}"
                );
            }
            if self.get_outbound_capacity_msat() < send_msats {
                // Channels exist but not enough capacity
                return Err(MutinyError::InsufficientBalance);
            }
        }

        // make sure node at least has one connection before attempting payment
        // wait for connection before paying, or otherwise instant fail anyways
        // also check we've completed initial sync this run, otherwise we might create
        // htlcs that can cause a channel to be closed
        for _ in 0..DEFAULT_PAYMENT_TIMEOUT {
            // check if we've been stopped
            if self.stop.load(Ordering::Relaxed) {
                return Err(MutinyError::NotRunning);
            }
            let has_usable = !self.channel_manager.list_usable_channels().is_empty();
            let init = self.has_done_initial_sync.load(Ordering::Relaxed);
            if has_usable && init {
                break;
            }
            log_trace!(
                self.logger,
                "waiting for channel to be usable, has usable channels: {has_usable} finished init sync:{init}"
            );
            sleep(1_000).await;
        }

        let (pay_result, amt_msat) = if invoice.amount_milli_satoshis().is_none() {
            if amt_sats.is_none() {
                return Err(MutinyError::InvoiceInvalid);
            }
            let amount_msats = amt_sats.unwrap() * 1_000;
            (
                self.pay_invoice_internal(invoice, amount_msats),
                amount_msats,
            )
        } else {
            if amt_sats.is_some() {
                return Err(MutinyError::InvoiceInvalid);
            }
            let amount_msats = invoice.amount_milli_satoshis().unwrap();
            (
                self.pay_invoice_internal(invoice, amount_msats),
                amount_msats,
            )
        };

        let last_update = utils::now().as_secs();
        let mut payment_info = PaymentInfo {
            preimage: None,
            secret: None,
            status: HTLCStatus::InFlight,
            amt_msat: MillisatAmount(Some(amt_msat)),
            fee_paid_msat: None,
            bolt11: Some(invoice.clone()),
            payee_pubkey: None,
            privacy_level: PrivacyLevel::NotAvailable,
            last_update,
        };

        persist_payment_info(&self.persister.storage, &payment_hash, &payment_info, false)?;

        let res = match pay_result {
            Ok(id) => Ok((id, PaymentHash(payment_hash))),
            Err(error) => {
                log_error!(self.logger, "failed to make payment: {error:?}");
                // call list channels to see what our channels are
                let current_channels = self.channel_manager.list_channels();
                let claimable_balance = self
                    .chain_monitor
                    .get_claimable_balances(&[])
                    .into_iter()
                    .map(|b| b.claimable_amount_satoshis())
                    .sum::<u64>()
                    * 1000;
                log_debug!(
                    self.logger,
                    "current channel details: {:?}",
                    current_channels
                );

                payment_info.status = HTLCStatus::Failed;
                persist_payment_info(&self.persister.storage, &payment_hash, &payment_info, false)?;

                Err(map_sending_failure(
                    error,
                    amt_msat,
                    &current_channels,
                    claimable_balance,
                ))
            }
        };
        log_trace!(self.logger, "finished calling init_invoice_payment");

        res
    }

    // copied from LDK, modified to change a couple params
    fn pay_invoice_internal(
        &self,
        invoice: &Bolt11Invoice,
        amount_msats: u64,
    ) -> Result<PaymentId, RetryableSendFailure> {
        let payment_id = PaymentId(invoice.payment_hash().to_byte_array());
        let payment_hash = PaymentHash((*invoice.payment_hash()).to_byte_array());
        let mut recipient_onion = RecipientOnionFields::secret_only(*invoice.payment_secret());
        recipient_onion.payment_metadata = invoice.payment_metadata().cloned();
        let mut payment_params = PaymentParameters::from_node_id(
            invoice.recover_payee_pub_key(),
            invoice.min_final_cltv_expiry_delta() as u32,
        )
        .with_expiry_time(invoice.expires_at().unwrap().as_secs())
        .with_route_hints(invoice.route_hints())
        .unwrap();
        if let Some(features) = invoice.features() {
            payment_params = payment_params
                .with_bolt11_features(features.clone())
                .unwrap();
        }
        let route_params = RouteParameters {
            payment_params,
            final_value_msat: amount_msats,
            max_total_routing_fee_msat: None, // main change from LDK, we just want payment to succeed
        };

        self.channel_manager
            .as_ref()
            .send_payment(
                payment_hash,
                recipient_onion,
                payment_id,
                route_params,
                Self::retry_strategy(),
            )
            .map(|_| payment_id)
    }

    async fn await_payment(
        &self,
        payment_id: PaymentId,
        payment_hash: PaymentHash,
        timeout: u64,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        let start = utils::now().as_secs();
        loop {
            let now = utils::now().as_secs();
            if now - start > timeout {
                // stop retrying after timeout, this should help prevent
                // payments completing unexpectedly after the timeout
                self.channel_manager.abandon_payment(payment_id);
                return Err(MutinyError::PaymentTimeout);
            }

            let payment_info = read_payment_info(
                &self.persister.storage,
                &payment_hash.0,
                false,
                &self.logger,
            );

            if let Some(info) = payment_info {
                match info.status {
                    HTLCStatus::Succeeded => {
                        let mutiny_invoice =
                            MutinyInvoice::from(info, payment_hash, false, labels)?;
                        return Ok(mutiny_invoice);
                    }
                    HTLCStatus::Failed => return Err(MutinyError::RoutingFailed),
                    _ => {}
                }
            }

            sleep(250).await;
        }
    }

    pub async fn pay_invoice_with_timeout(
        &self,
        invoice: &Bolt11Invoice,
        amt_sats: Option<u64>,
        timeout_secs: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        log_trace!(self.logger, "calling pay_invoice_with_timeout");

        // initiate payment
        let (payment_id, payment_hash) = self.init_invoice_payment(invoice, amt_sats).await?;
        let timeout: u64 = timeout_secs.unwrap_or(DEFAULT_PAYMENT_TIMEOUT);

        let res = self
            .await_payment(payment_id, payment_hash, timeout, labels)
            .await;
        log_trace!(self.logger, "finished calling pay_invoice_with_timeout");

        res
    }

    /// init_keysend_payment sends off the payment but does not wait for results
    /// use keysend_with_timeout to wait for results
    pub async fn init_keysend_payment(
        &self,
        to_node: PublicKey,
        amt_sats: u64,
        message: Option<String>,
        labels: Vec<String>,
        payment_id: PaymentId,
    ) -> Result<MutinyInvoice, MutinyError> {
        log_trace!(self.logger, "calling init_keysend_payment");

        let amt_msats = amt_sats * 1_000;

        // check if we have enough balance to send
        let channels = self.channel_manager.list_channels();
        if self
            .chain_monitor
            .get_claimable_balances(
                &channels
                    .iter()
                    // only consider channels that are confirmed
                    .filter(|c| !c.is_channel_ready)
                    .collect::<Vec<_>>(),
            )
            .into_iter()
            .map(|b| b.claimable_amount_satoshis())
            .sum::<u64>()
            * 1000
            < amt_msats
        {
            // Channels exist but not enough capacity
            return Err(MutinyError::InsufficientBalance);
        }

        // make sure node at least has one connection before attempting payment
        // wait for connection before paying, or otherwise instant fail anyways
        // also check we've completed initial sync this run, otherwise we might create
        // htlcs that can cause a channel to be closed
        for _ in 0..DEFAULT_PAYMENT_TIMEOUT {
            // check if we've been stopped
            if self.stop.load(Ordering::Relaxed) {
                return Err(MutinyError::NotRunning);
            }
            if !self.channel_manager.list_usable_channels().is_empty()
                && self.has_done_initial_sync.load(Ordering::SeqCst)
            {
                break;
            }
            sleep(1_000).await;
        }

        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).map_err(|_| MutinyError::SeedGenerationFailed)?;
        let payment_secret = PaymentSecret(entropy);

        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).map_err(|_| MutinyError::SeedGenerationFailed)?;
        let preimage = PaymentPreimage(entropy);

        let payment_params = PaymentParameters::for_keysend(to_node, 40, false);
        let route_params: RouteParameters = RouteParameters {
            final_value_msat: amt_msats,
            payment_params,
            max_total_routing_fee_msat: None,
        };

        let recipient_onion = if let Some(msg) = message {
            // keysend messages are encoded as TLV type 34349334
            RecipientOnionFields::secret_only(payment_secret)
                .with_custom_tlvs(vec![(34349334, msg.encode())])
                .map_err(|_| {
                    log_error!(self.logger, "could not encode keysend message");
                    MutinyError::InvoiceCreationFailed
                })?
        } else {
            RecipientOnionFields::spontaneous_empty()
        };

        let pay_result = self.channel_manager.send_spontaneous_payment_with_retry(
            Some(preimage),
            recipient_onion,
            payment_id,
            route_params,
            Self::retry_strategy(),
        );

        let payment_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());

        let last_update = utils::now().as_secs();
        let mut payment_info = PaymentInfo {
            preimage: Some(preimage.0),
            secret: None,
            status: HTLCStatus::InFlight,
            amt_msat: MillisatAmount(Some(amt_msats)),
            fee_paid_msat: None,
            bolt11: None,
            payee_pubkey: Some(to_node),
            privacy_level: PrivacyLevel::NotAvailable,
            last_update,
        };

        persist_payment_info(
            &self.persister.storage,
            &payment_hash.0,
            &payment_info,
            false,
        )?;

        let res = match pay_result {
            Ok(_) => {
                let mutiny_invoice =
                    MutinyInvoice::from(payment_info, payment_hash, false, labels)?;
                Ok(mutiny_invoice)
            }
            Err(error) => {
                payment_info.status = HTLCStatus::Failed;
                persist_payment_info(
                    &self.persister.storage,
                    &payment_hash.0,
                    &payment_info,
                    false,
                )?;
                let current_channels = self.channel_manager.list_channels();
                let claimable_balance = self
                    .chain_monitor
                    .get_claimable_balances(&[])
                    .into_iter()
                    .map(|b| b.claimable_amount_satoshis())
                    .sum::<u64>()
                    * 1000;
                Err(map_sending_failure(
                    error,
                    amt_msats,
                    &current_channels,
                    claimable_balance,
                ))
            }
        };
        log_trace!(self.logger, "finished calling init_keysend_payment");

        res
    }

    pub async fn keysend_with_timeout(
        &self,
        to_node: PublicKey,
        amt_sats: u64,
        message: Option<String>,
        labels: Vec<String>,
        timeout_secs: Option<u64>,
    ) -> Result<MutinyInvoice, MutinyError> {
        log_trace!(self.logger, "calling keysend_with_timeout");

        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).map_err(|_| MutinyError::SeedGenerationFailed)?;
        let payment_id = PaymentId(entropy);

        // initiate payment
        let pay = self
            .init_keysend_payment(to_node, amt_sats, message, labels.clone(), payment_id)
            .await?;

        let timeout: u64 = timeout_secs.unwrap_or(DEFAULT_PAYMENT_TIMEOUT);
        let payment_hash = PaymentHash(pay.payment_hash.to_byte_array());

        let res = self
            .await_payment(payment_id, payment_hash, timeout, labels)
            .await;
        log_trace!(self.logger, "finished calling keysend_with_timeout");

        res
    }

    async fn await_chan_funding_tx(
        &self,
        user_channel_id: u128,
        pubkey: &PublicKey,
        timeout: u64,
    ) -> Result<OutPoint, MutinyError> {
        let start = utils::now().as_secs();
        loop {
            if self.stop.load(Ordering::Relaxed) {
                return Err(MutinyError::NotRunning);
            }

            // We'll set failure reason if the peer rejects the channel
            if let Some(failure_reason) = self
                .persister
                .get_channel_open_params(user_channel_id)?
                .and_then(|p| p.failure_reason)
            {
                log_error!(self.logger, "Channel funding tx failed: {failure_reason}");
                // can now safely delete the channel open params
                let _ = self.persister.delete_channel_open_params(user_channel_id);
                return Err(MutinyError::ChannelCreationFailedWithReason(failure_reason));
            }

            let channels = self.channel_manager.list_channels_with_counterparty(pubkey);
            let channel = channels
                .iter()
                .find(|c| c.user_channel_id == user_channel_id);

            if let Some(outpoint) = channel.and_then(|c| c.funding_txo) {
                let outpoint = outpoint.into_bitcoin_outpoint();
                log_info!(self.logger, "Channel funding tx found: {}", outpoint);
                log_debug!(self.logger, "Waiting for Channel Pending event");
                loop {
                    // we delete the channel open params on channel pending event
                    // so if we can't find them, we know the channel is pending
                    // and we can safely return
                    if self
                        .persister
                        .get_channel_open_params(user_channel_id)
                        .map(|p| p.is_none())
                        .unwrap_or(false)
                    {
                        return Ok(outpoint);
                    }

                    let now = utils::now().as_secs();
                    if now - start > timeout {
                        return Err(MutinyError::ChannelCreationFailed);
                    }

                    if self.stop.load(Ordering::Relaxed) {
                        return Err(MutinyError::NotRunning);
                    }
                    sleep(250).await;
                }
            }

            let now = utils::now().as_secs();
            if now - start > timeout {
                return Err(MutinyError::ChannelCreationFailed);
            }

            sleep(250).await;
        }
    }

    pub async fn init_open_channel(
        &self,
        pubkey: PublicKey,
        amount_sat: u64,
        fee_rate: Option<u64>,
        user_channel_id: Option<u128>,
    ) -> Result<u128, MutinyError> {
        log_trace!(self.logger, "calling init_open_channel");

        let accept_underpaying_htlcs = self
            .lsp_client
            .as_ref()
            .is_some_and(|l| l.accept_underpaying_htlcs());
        let config = default_user_config(accept_underpaying_htlcs);

        let user_channel_id = user_channel_id.unwrap_or_else(|| {
            // generate random user channel id
            let mut user_channel_id_bytes = [0u8; 16];
            getrandom::getrandom(&mut user_channel_id_bytes).unwrap();
            u128::from_be_bytes(user_channel_id_bytes)
        });

        let sats_per_vbyte = if let Some(sats_vbyte) = fee_rate {
            sats_vbyte
        } else {
            let sats_per_kw = self.wallet.fees.get_normal_fee_rate();

            FeeRate::from_sat_per_kwu(sats_per_kw.into()).to_sat_per_vb_ceil()
        };

        // save params to db
        let params = ChannelOpenParams::new(sats_per_vbyte);
        self.persister
            .persist_channel_open_params(user_channel_id, params)?;

        let res = match self.channel_manager.create_channel(
            pubkey,
            amount_sat,
            0,
            user_channel_id,
            None,
            Some(config),
        ) {
            Ok(_) => {
                log_info!(
                    self.logger,
                    "SUCCESS: channel initiated with peer: {pubkey:?}"
                );
                Ok(user_channel_id)
            }
            Err(e) => {
                log_error!(
                    self.logger,
                    "ERROR: failed to open channel to pubkey {pubkey:?}: {e:?}"
                );
                Err(MutinyError::ChannelCreationFailed)
            }
        };

        log_trace!(self.logger, "finished calling init_open_channel");

        res
    }

    pub async fn open_channel_with_timeout(
        &self,
        pubkey: PublicKey,
        amount_sat: u64,
        fee_rate: Option<u64>,
        user_channel_id: Option<u128>,
        timeout: u64,
    ) -> Result<OutPoint, MutinyError> {
        log_trace!(self.logger, "calling open_channel_with_timeout");

        let init = self
            .init_open_channel(pubkey, amount_sat, fee_rate, user_channel_id)
            .await?;

        let res = self.await_chan_funding_tx(init, &pubkey, timeout).await;
        log_trace!(self.logger, "finished calling open_channel_with_timeout");

        res
    }

    pub async fn init_sweep_utxos_to_channel(
        &self,
        user_chan_id: Option<u128>,
        utxos: &[OutPoint],
        pubkey: PublicKey,
    ) -> Result<u128, MutinyError> {
        log_trace!(self.logger, "calling init_sweep_utxos_to_channel");

        // Calculate the total value of the selected utxos
        let utxo_value: u64 = {
            // find the wallet utxos
            let wallet = self.wallet.wallet.try_read()?;
            let all_utxos = wallet.list_unspent();

            // calculate total value of utxos
            let mut total = 0;
            for utxo in all_utxos {
                if utxos.contains(&utxo.outpoint) {
                    total += utxo.txout.value.to_sat();
                }
            }
            total
        };

        let sats_per_kw = self.wallet.fees.get_normal_fee_rate();

        // Calculate the expected transaction fee
        let expected_fee = self.wallet.fees.calculate_expected_fee(
            utxos.len(),
            P2WSH_OUTPUT_SIZE,
            None,
            Some(sats_per_kw),
        );

        // channel size is the total value of the utxos minus the fee
        let channel_value_satoshis = utxo_value - expected_fee;

        let accept_underpaying_htlcs = self
            .lsp_client
            .as_ref()
            .is_some_and(|l| l.accept_underpaying_htlcs());
        let config = default_user_config(accept_underpaying_htlcs);

        let user_channel_id = user_chan_id.unwrap_or_else(|| {
            // generate random user channel id
            let mut user_channel_id_bytes = [0u8; 16];
            getrandom::getrandom(&mut user_channel_id_bytes).unwrap();
            u128::from_be_bytes(user_channel_id_bytes)
        });

        let sats_per_vbyte = FeeRate::from_sat_per_kwu(sats_per_kw.into()).to_sat_per_vb_ceil();
        // save params to db
        let params = ChannelOpenParams::new_sweep(sats_per_vbyte, expected_fee, utxos.to_vec());
        self.persister
            .persist_channel_open_params(user_channel_id, params)?;

        let res = match self.channel_manager.create_channel(
            pubkey,
            channel_value_satoshis,
            0,
            user_channel_id,
            None,
            Some(config),
        ) {
            Ok(_) => {
                log_info!(
                    self.logger,
                    "SUCCESS: channel initiated with peer: {pubkey:?}"
                );
                Ok(user_channel_id)
            }
            Err(e) => {
                log_error!(
                    self.logger,
                    "ERROR: failed to open channel to pubkey {pubkey:?}: {e:?}"
                );
                // delete params from db because channel failed
                self.persister.delete_channel_open_params(user_channel_id)?;
                Err(MutinyError::ChannelCreationFailed)
            }
        };
        log_trace!(self.logger, "finished calling init_sweep_utxos_to_channel");

        res
    }

    pub async fn sweep_utxos_to_channel_with_timeout(
        &self,
        user_chan_id: Option<u128>,
        utxos: &[OutPoint],
        pubkey: PublicKey,
        timeout: u64,
    ) -> Result<OutPoint, MutinyError> {
        log_trace!(self.logger, "calling sweep_utxos_to_channel_with_timeout");

        let init = self
            .init_sweep_utxos_to_channel(user_chan_id, utxos, pubkey)
            .await?;

        let res = self.await_chan_funding_tx(init, &pubkey, timeout).await;
        log_trace!(
            self.logger,
            "finished calling sweep_utxos_to_channel_with_timeout"
        );

        res
    }
}

pub(crate) fn scoring_params() -> ProbabilisticScoringFeeParameters {
    ProbabilisticScoringFeeParameters {
        base_penalty_amount_multiplier_msat: 8192 * 100,
        base_penalty_msat: 100_000,
        liquidity_penalty_multiplier_msat: 30_000 * 15,
        liquidity_penalty_amount_multiplier_msat: 192 * 15,
        historical_liquidity_penalty_multiplier_msat: 10_000 * 15,
        historical_liquidity_penalty_amount_multiplier_msat: 64 * 15,
        ..Default::default()
    }
}

pub(crate) fn decay_params() -> ProbabilisticScoringDecayParameters {
    ProbabilisticScoringDecayParameters {
        liquidity_offset_half_life: core::time::Duration::from_secs(3 * 60 * 60),
        historical_no_updates_half_life: core::time::Duration::from_secs(60 * 60 * 24 * 3),
    }
}

fn map_sending_failure(
    error: RetryableSendFailure,
    amt_msat: u64,
    current_channels: &[ChannelDetails],
    claimable_balance: u64,
) -> MutinyError {
    // If the payment failed because of a route not found, check if the amount was
    // valid and return the correct error
    match error {
        RetryableSendFailure::RouteNotFound => {
            // If the amount was greater than our balance, return an InsufficientBalance error
            if amt_msat > claimable_balance {
                return MutinyError::InsufficientBalance;
            }

            // If the amount was within our balance but we couldn't pay because of
            // the channel reserve, return a ReserveAmountError
            let reserved_amt: u64 = current_channels
                .iter()
                .flat_map(|c| c.unspendable_punishment_reserve)
                .sum::<u64>()
                * 1_000; // multiply by 1k to convert to msat
            if claimable_balance - reserved_amt < amt_msat {
                return MutinyError::ReserveAmountError;
            }

            // if none of our channels could afford an HTLC, return a ReserveAmountError
            if current_channels
                .iter()
                .all(|c| c.next_outbound_htlc_limit_msat < amt_msat)
            {
                return MutinyError::ReserveAmountError;
            }

            MutinyError::RoutingFailed
        }
        RetryableSendFailure::PaymentExpired => MutinyError::InvoiceExpired,
        RetryableSendFailure::DuplicatePayment => MutinyError::NonUniquePaymentHash,
        RetryableSendFailure::OnionPacketSizeExceeded => MutinyError::PacketSizeExceeded,
    }
}

#[allow(clippy::too_many_arguments)]
async fn start_reconnection_handling<S: MutinyStorage>(
    storage: &S,
    node_pubkey: PublicKey,
    #[cfg(target_arch = "wasm32")] websocket_proxy_addr: String,
    peer_man: Arc<PeerManagerImpl<S>>,
    pending_connections: PendingConnections,
    fee_estimator: Arc<MutinyFeeEstimator<S>>,
    logger: &Arc<MutinyLogger>,
    uuid: String,
    lsp_client: Option<&AnyLsp<S>>,
    stop: Arc<AtomicBool>,
    stopped_components: Arc<RwLock<Vec<bool>>>,
    skip_fee_estimates: bool,
) {
    // wait for fee estimates sync to finish, it can cause issues if we try to connect before
    // we have fee estimates
    if !skip_fee_estimates {
        loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            // make sure we have fee estimates and they are not empty
            if storage
                .get_fee_estimates()
                .map(|m| m.is_some_and(|m| !m.is_empty()))
                .unwrap_or(false)
            {
                break;
            }
            sleep(1_000).await;
        }
    }

    // Attempt initial connections first in the background
    #[cfg(target_arch = "wasm32")]
    let websocket_proxy_addr_copy_proxy = websocket_proxy_addr.clone();

    let proxy_logger = logger.clone();
    let peer_man_proxy = peer_man.clone();
    let proxy_fee_estimator = fee_estimator.clone();
    let lsp_client_copy = lsp_client.cloned();
    let storage_copy = storage.clone();
    let uuid_copy = uuid.clone();
    let stop_copy = stop.clone();
    utils::spawn(async move {
        // Now try to connect to the client's LSP
        // This is here in case the LSP client node info has not saved to storage yet
        let mut lsp_node_id = None;
        if let Some(lsp) = lsp_client_copy.as_ref() {
            let pubkey = lsp.get_lsp_pubkey().await;
            let connection_string = lsp.get_lsp_connection_string().await;
            let mut node_id = NodeId::from_pubkey(&pubkey);

            let connect_res = connect_peer_if_necessary(
                #[cfg(target_arch = "wasm32")]
                &websocket_proxy_addr_copy_proxy,
                &PubkeyConnectionInfo::new(connection_string.as_str()).unwrap(),
                &storage_copy,
                proxy_logger.clone(),
                peer_man_proxy.clone(),
                pending_connections.clone(),
                proxy_fee_estimator.clone(),
                stop_copy.clone(),
            )
            .await;
            match connect_res {
                Ok(_) => {
                    log_trace!(proxy_logger, "auto connected lsp: {node_id}");
                }
                Err(e) => {
                    log_trace!(proxy_logger, "could not connect to lsp {node_id}: {e}");
                    match lsp {
                        AnyLsp::VoltageFlow(lock) => {
                            let mut client = lock.write().await;
                            if let Err(e) = client.set_connection_info().await {
                                log_error!(
                                    proxy_logger,
                                    "could not set connection info from voltage lsp: {e}"
                                );
                            } else {
                                log_trace!(proxy_logger, "set connection info from voltage lsp");
                                // get new pubkey and connection string
                                let pubkey = lsp.get_lsp_pubkey().await;
                                node_id = NodeId::from_pubkey(&pubkey);
                                let connection_string = lsp.get_lsp_connection_string().await;

                                if let Err(e) = connect_peer_if_necessary(
                                    #[cfg(target_arch = "wasm32")]
                                    &websocket_proxy_addr_copy_proxy,
                                    &PubkeyConnectionInfo::new(connection_string.as_str()).unwrap(),
                                    &storage_copy,
                                    proxy_logger.clone(),
                                    peer_man_proxy.clone(),
                                    pending_connections.clone(),
                                    proxy_fee_estimator.clone(),
                                    stop_copy.clone(),
                                )
                                .await
                                {
                                    log_error!(
                                        proxy_logger,
                                        "could not connect to lsp after setting connection info: {e}"
                                    );
                                }
                            }
                        }
                        AnyLsp::Lsps(_) => {} // nothing to do here, just retry next loop
                    }
                }
            }

            lsp_node_id = Some(node_id);
            let connection_string = lsp.get_lsp_connection_string().await;
            if let Err(e) = save_peer_connection_info(
                &storage_copy,
                &uuid_copy,
                &node_id,
                &connection_string,
                None,
            ) {
                log_error!(proxy_logger, "could not save connection to lsp: {e}");
            }
        };

        // Now try to connect to other nodes the client might have, skipping the LSP if necessary
        let stored_peers = get_all_peers(&storage_copy).unwrap_or_default();
        let initial_peers: Vec<(NodeId, String)> = stored_peers
            .into_iter()
            .filter(|(_, d)| {
                d.connection_string.is_some() && d.nodes.binary_search(&uuid.to_string()).is_ok()
            })
            .map(|(n, d)| (n, d.connection_string.unwrap()))
            .filter(|(n, _)| lsp_node_id != Some(*n))
            .collect();
        for (pubkey, conn_str) in initial_peers.into_iter() {
            log_trace!(
                proxy_logger,
                "starting initial connection to peer: {pubkey}"
            );
            let peer_connection_info = match PubkeyConnectionInfo::new(&conn_str) {
                Ok(p) => p,
                Err(e) => {
                    log_error!(proxy_logger, "could not parse connection info: {e}");
                    continue;
                }
            };

            let connect_res = connect_peer_if_necessary(
                #[cfg(target_arch = "wasm32")]
                &websocket_proxy_addr,
                &peer_connection_info,
                &storage_copy,
                proxy_logger.clone(),
                peer_man_proxy.clone(),
                pending_connections.clone(),
                proxy_fee_estimator.clone(),
                stop.clone(),
            )
            .await;
            match connect_res {
                Ok(_) => {
                    log_trace!(proxy_logger, "initial connection to peer: {pubkey}");
                }
                Err(e) => {
                    log_warn!(
                        proxy_logger,
                        "could not start initial connection to peer: {e}"
                    );
                }
            }
        }

        // keep trying to connect each lightning peer if they get disconnected
        // hashMap to store backoff times for each pubkey
        let mut backoff_times = HashMap::new();

        // Only begin this process after 30s of running
        for _ in 0..30 {
            if stop.load(Ordering::Relaxed) {
                log_debug!(
                    proxy_logger,
                    "stopping connection component and disconnecting peers for node: {}",
                    node_pubkey,
                );
                peer_man_proxy.disconnect_all_peers();
                stop_component(&stopped_components);
                log_debug!(
                    proxy_logger,
                    "stopped connection component and disconnected peers for node: {}",
                    node_pubkey,
                );
                return;
            }
            sleep(1_000).await;
        }

        loop {
            for _ in 0..INITIAL_RECONNECTION_DELAY {
                if stop.load(Ordering::Relaxed) {
                    log_debug!(
                        proxy_logger,
                        "stopping connection component and disconnecting peers for node: {}",
                        node_pubkey,
                    );
                    peer_man_proxy.disconnect_all_peers();
                    stop_component(&stopped_components);
                    log_debug!(
                        proxy_logger,
                        "stopped connection component and disconnected peers for node: {}",
                        node_pubkey,
                    );
                    return;
                }
                sleep(1_000).await;
            }

            let peer_connections = get_all_peers(&storage_copy).unwrap_or_default();
            let current_connections = peer_man_proxy.get_peer_node_ids();

            let not_connected: Vec<(NodeId, String)> = peer_connections
                .into_iter()
                .filter(|(_, d)| {
                    d.connection_string.is_some()
                        && d.nodes.binary_search(&uuid.to_string()).is_ok()
                })
                .map(|(n, d)| (n, d.connection_string.unwrap()))
                .filter(|(n, _)| {
                    !current_connections
                        .iter()
                        .any(|c| &NodeId::from_pubkey(c) == n)
                })
                .collect();

            for (pubkey, conn_str) in not_connected.into_iter() {
                let now = crate::utils::now();

                // initialize backoff time and last attempt time if they do not exist
                let backoff_entry = backoff_times
                    .entry(pubkey)
                    .or_insert((INITIAL_RECONNECTION_DELAY, now));

                // skip this pubkey if not enough time has passed since the last attempt
                if now - backoff_entry.1 < Duration::from_secs(backoff_entry.0) {
                    continue;
                }

                // Update the last attempt time
                backoff_entry.1 = now;

                log_trace!(proxy_logger, "going to auto connect to peer: {pubkey}");
                let peer_connection_info = match PubkeyConnectionInfo::new(&conn_str) {
                    Ok(p) => p,
                    Err(e) => {
                        log_error!(proxy_logger, "could not parse connection info: {e}");
                        continue;
                    }
                };

                let connect_res = connect_peer_if_necessary(
                    #[cfg(target_arch = "wasm32")]
                    &websocket_proxy_addr,
                    &peer_connection_info,
                    &storage_copy,
                    proxy_logger.clone(),
                    peer_man_proxy.clone(),
                    pending_connections.clone(),
                    proxy_fee_estimator.clone(),
                    stop.clone(),
                )
                .await;
                match connect_res {
                    Ok(_) => {
                        log_trace!(proxy_logger, "auto connected peer: {pubkey}");
                        // reset backoff time to initial value if connection is successful
                        backoff_entry.0 = INITIAL_RECONNECTION_DELAY;
                    }
                    Err(e) => {
                        log_warn!(proxy_logger, "could not auto connect peer: {e}");
                        // double the backoff time if connection fails, but do not exceed max
                        backoff_entry.0 = (backoff_entry.0 * 2).min(MAX_RECONNECTION_DELAY);
                    }
                }
            }
        }
    });
}

fn stop_component(stopped_components: &Arc<RwLock<Vec<bool>>>) {
    let mut stopped = stopped_components
        .try_write()
        .expect("can write to stopped components");
    if let Some(first_false) = stopped.iter_mut().find(|x| !**x) {
        *first_false = true;
    }
}

pub(crate) fn create_peer_manager<S: MutinyStorage>(
    km: Arc<PhantomKeysManager<S>>,
    lightning_msg_handler: MessageHandler<S>,
    logger: Arc<MutinyLogger>,
) -> PeerManagerImpl<S> {
    let now = utils::now().as_secs();
    let mut ephemeral_bytes = [0u8; 32];
    getrandom::getrandom(&mut ephemeral_bytes).expect("Failed to generate entropy");

    PeerManagerImpl::new(
        lightning_msg_handler,
        now as u32,
        &ephemeral_bytes,
        logger,
        km,
    )
}

pub(crate) fn parse_peer_info(
    peer_pubkey_and_ip_addr: &str,
) -> Result<(PublicKey, String), MutinyError> {
    let (pubkey, peer_addr_str) = split_peer_connection_string(peer_pubkey_and_ip_addr)?;

    let peer_addr_str_with_port = if peer_addr_str.contains(':') {
        peer_addr_str
    } else {
        format!("{peer_addr_str}:9735")
    };

    Ok((pubkey, peer_addr_str_with_port))
}

pub(crate) fn split_peer_connection_string(
    peer_pubkey_and_ip_addr: &str,
) -> Result<(PublicKey, String), MutinyError> {
    let mut pubkey_and_addr = peer_pubkey_and_ip_addr.split('@');
    let pubkey = pubkey_and_addr
        .next()
        .ok_or_else(|| MutinyError::PeerInfoParseFailed)?;
    let peer_addr_str = pubkey_and_addr
        .next()
        .ok_or_else(|| MutinyError::PeerInfoParseFailed)?;
    let pubkey = PublicKey::from_str(pubkey).map_err(|_| MutinyError::PeerInfoParseFailed)?;
    Ok((pubkey, peer_addr_str.to_string()))
}

pub(crate) fn default_user_config(accept_underpaying_htlcs: bool) -> UserConfig {
    UserConfig {
        channel_handshake_limits: ChannelHandshakeLimits {
            // lnd's max to_self_delay is 2016, so we want to be compatible.
            their_to_self_delay: 2016,
            ..Default::default()
        },
        channel_handshake_config: ChannelHandshakeConfig {
            minimum_depth: 1,
            announce_for_forwarding: false,
            negotiate_scid_privacy: true,
            commit_upfront_shutdown_pubkey: false,
            negotiate_anchors_zero_fee_htlc_tx: true, // enable anchor channels
            max_inbound_htlc_value_in_flight_percent_of_channel: 100,
            our_to_self_delay: 6 * 24 * 2, // 2 days
            their_channel_reserve_proportional_millionths: 0,
            ..Default::default()
        },
        manually_accept_inbound_channels: true,
        channel_config: ChannelConfig {
            // Set to max supply of bitcoin.
            // Don't care about dust exposure, we just want to be able to make payments.
            max_dust_htlc_exposure: MaxDustHTLCExposure::FixedLimitMsat(
                21_000_000 * 100_000_000 * 1_000,
            ),
            accept_underpaying_htlcs,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::get_invoice_by_hash;
    use crate::node::{map_sending_failure, parse_peer_info};
    use crate::storage::MemoryStorage;
    use crate::test_utils::*;
    use bitcoin::secp256k1::PublicKey;
    use lightning::ln::channel_state::ChannelCounterparty;
    use lightning::ln::features::InitFeatures;
    use lightning::ln::types::ChannelId;
    use lightning_invoice::Bolt11InvoiceDescription;
    use std::str::FromStr;

    #[test]
    fn test_parse_peer_info() {
        log!("test parse peer info");

        let pub_key = PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .unwrap();
        let addr = "127.0.0.1:4000";

        let (peer_pubkey, peer_addr) = parse_peer_info(&format!("{pub_key}@{addr}")).unwrap();

        assert_eq!(pub_key, peer_pubkey);
        assert_eq!(addr, peer_addr);
    }

    #[test]
    fn test_parse_peer_info_no_port() {
        log!("test parse peer info with no port");

        let pub_key = PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .unwrap();
        let addr = "127.0.0.1";
        let port = "9735";

        let (peer_pubkey, peer_addr) = parse_peer_info(&format!("{pub_key}@{addr}")).unwrap();

        assert_eq!(pub_key, peer_pubkey);
        assert_eq!(format!("{addr}:{port}"), peer_addr);
    }

    #[test]
    #[allow(deprecated)]
    fn test_map_sending_failure() {
        let amt_msat = 1_000_000;

        // test simple cases
        assert_eq!(
            map_sending_failure(
                RetryableSendFailure::PaymentExpired,
                amt_msat,
                &[],
                amt_msat
            ),
            MutinyError::InvoiceExpired
        );
        assert_eq!(
            map_sending_failure(
                RetryableSendFailure::DuplicatePayment,
                amt_msat,
                &[],
                amt_msat
            ),
            MutinyError::NonUniquePaymentHash
        );

        let mut channel_details = ChannelDetails {
            channel_id: ChannelId::new_zero(),
            counterparty: ChannelCounterparty {
                node_id: PublicKey::from_slice(&[2; 33]).unwrap(), // dummy value
                features: InitFeatures::empty(),
                unspendable_punishment_reserve: 0,
                forwarding_info: None,
                outbound_htlc_minimum_msat: None,
                outbound_htlc_maximum_msat: None,
            },
            funding_txo: None,
            channel_type: None,
            short_channel_id: None,
            outbound_scid_alias: None,
            inbound_scid_alias: None,
            channel_value_satoshis: 0,
            unspendable_punishment_reserve: None,
            user_channel_id: 0,
            feerate_sat_per_1000_weight: None,
            balance_msat: 0,
            outbound_capacity_msat: 0,
            next_outbound_htlc_limit_msat: 0,
            next_outbound_htlc_minimum_msat: 0,
            inbound_capacity_msat: 0,
            confirmations_required: None,
            confirmations: None,
            force_close_spend_delay: None,
            is_outbound: false,
            is_channel_ready: false,
            channel_shutdown_state: None,
            is_usable: false,
            is_announced: false,
            inbound_htlc_minimum_msat: None,
            inbound_htlc_maximum_msat: None,
            config: None,
            pending_inbound_htlcs: Default::default(),
            pending_outbound_htlcs: Default::default(),
        };

        assert_eq!(
            map_sending_failure(
                RetryableSendFailure::RouteNotFound,
                amt_msat,
                &[channel_details.clone()],
                0,
            ),
            MutinyError::InsufficientBalance
        );

        assert_eq!(
            map_sending_failure(
                RetryableSendFailure::RouteNotFound,
                amt_msat,
                &[channel_details.clone()],
                0,
            ),
            MutinyError::InsufficientBalance
        );

        // test punishment reserve
        channel_details.balance_msat = amt_msat + 10;
        channel_details.unspendable_punishment_reserve = Some(20);
        assert_eq!(
            map_sending_failure(
                RetryableSendFailure::RouteNotFound,
                amt_msat,
                &[channel_details.clone()],
                amt_msat + 10,
            ),
            MutinyError::ReserveAmountError
        );

        // set reserve back to 0 so we can test htlc reserve
        channel_details.unspendable_punishment_reserve = Some(0);
        assert_eq!(
            map_sending_failure(
                RetryableSendFailure::RouteNotFound,
                amt_msat,
                &[channel_details.clone()],
                amt_msat + 10,
            ),
            MutinyError::ReserveAmountError
        );

        // set htlc limit to be greater than amt_msat so we can pass the htlc limit check
        channel_details.next_outbound_htlc_limit_msat = amt_msat + 10;
        assert_eq!(
            map_sending_failure(
                RetryableSendFailure::RouteNotFound,
                amt_msat,
                &[channel_details.clone()],
                amt_msat + 10,
            ),
            MutinyError::RoutingFailed
        );
    }

    #[tokio::test]
    async fn test_create_node() {
        let storage = MemoryStorage::default();
        let node = create_node(storage).await;
        assert!(!node.pubkey.to_string().is_empty());
    }

    #[tokio::test]
    async fn test_create_invoice() {
        let storage = MemoryStorage::default();
        let node = create_node(storage.clone()).await;
        let logger = Arc::new(MutinyLogger::default());

        let now = crate::utils::now().as_secs();

        let amount_sats = 1_000;

        let (invoice, _) = node
            .create_invoice(amount_sats, None, vec![], None)
            .await
            .unwrap();

        assert_eq!(invoice.amount_milli_satoshis(), Some(amount_sats * 1000));
        match invoice.description() {
            Bolt11InvoiceDescription::Direct(desc) => {
                assert_eq!(desc.to_string(), "");
            }
            _ => panic!("unexpected invoice description"),
        }

        let from_storage = get_invoice_by_hash(invoice.payment_hash(), &storage, &logger).unwrap();
        let by_hash = get_invoice_by_hash(invoice.payment_hash(), &storage, &logger).unwrap();

        assert_eq!(from_storage, by_hash);
        assert_eq!(from_storage.bolt11, Some(invoice.clone()));
        assert_eq!(from_storage.description, None);
        assert_eq!(from_storage.payment_hash, invoice.payment_hash().to_owned());
        assert_eq!(from_storage.preimage, None);
        assert_eq!(from_storage.payee_pubkey, None);
        assert_eq!(from_storage.amount_sats, Some(amount_sats));
        assert_eq!(from_storage.status, HTLCStatus::Pending);
        assert_eq!(from_storage.fees_paid, None);
        assert!(from_storage.inbound);
        assert!(from_storage.last_updated >= now);
    }

    #[tokio::test]
    async fn test_fail_own_invoice() {
        let storage = MemoryStorage::default();
        let node = create_node(storage).await;

        let invoice = node
            .create_invoice(10_000, None, vec![], None)
            .await
            .unwrap()
            .0;

        let result = node
            .pay_invoice_with_timeout(&invoice, None, None, vec![])
            .await;

        match result {
            Err(MutinyError::NonUniquePaymentHash) => {}
            Err(e) => panic!("unexpected error {e:?}"),
            Ok(_) => panic!("somehow paid own invoice"),
        }
    }

    #[tokio::test]
    async fn test_await_payment() {
        let storage = MemoryStorage::default();
        let node = create_node(storage).await;
        let payment_id = PaymentId([0; 32]);
        let payment_hash = PaymentHash([0; 32]);

        // check that we get PaymentTimeout if we don't have the payment info

        let result = node
            .await_payment(payment_id, payment_hash, 1, vec![])
            .await;

        assert_eq!(result.unwrap_err(), MutinyError::PaymentTimeout);

        let mut payment_info = PaymentInfo {
            preimage: None,
            secret: Some([0; 32]),
            status: HTLCStatus::InFlight,
            privacy_level: PrivacyLevel::NotAvailable,
            amt_msat: MillisatAmount(Some(1000)),
            fee_paid_msat: None,
            bolt11: None,
            payee_pubkey: None,
            last_update: crate::utils::now().as_secs(),
        };

        // check that it still fails if it is inflight

        persist_payment_info(
            &node.persister.storage,
            &payment_hash.0,
            &payment_info,
            false,
        )
        .unwrap();

        let result = node
            .await_payment(payment_id, payment_hash, 1, vec![])
            .await;

        assert_eq!(result.unwrap_err(), MutinyError::PaymentTimeout);

        // check that we get proper error if it fails

        payment_info.status = HTLCStatus::Failed;
        persist_payment_info(
            &node.persister.storage,
            &payment_hash.0,
            &payment_info,
            false,
        )
        .unwrap();

        let result = node
            .await_payment(payment_id, payment_hash, 1, vec![])
            .await;

        assert_eq!(result.unwrap_err(), MutinyError::RoutingFailed);

        // check that we get success

        payment_info.status = HTLCStatus::Succeeded;
        persist_payment_info(
            &node.persister.storage,
            &payment_hash.0,
            &payment_info,
            false,
        )
        .unwrap();

        let result = node
            .await_payment(payment_id, payment_hash, 1, vec![])
            .await;

        assert!(result.is_ok());
    }
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod wasm_test {
    use crate::storage::MemoryStorage;
    use crate::test_utils::create_node;
    use crate::{error::MutinyError, storage::persist_payment_info};
    use crate::{
        event::{MillisatAmount, PaymentInfo},
        storage::get_invoice_by_hash,
    };
    use crate::{labels::LabelStorage, logging::MutinyLogger};
    use crate::{HTLCStatus, PrivacyLevel};
    use itertools::Itertools;
    use lightning::ln::channelmanager::PaymentId;
    use lightning::ln::PaymentHash;
    use lightning_invoice::Bolt11InvoiceDescription;
    use std::sync::Arc;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn test_create_node() {
        let storage = MemoryStorage::default();
        let node = create_node(storage).await;
        assert!(!node.pubkey.to_string().is_empty());
    }

    #[test]
    async fn test_create_invoice() {
        let storage = MemoryStorage::default();
        let node = create_node(storage.clone()).await;
        let logger = Arc::new(MutinyLogger::default());

        let now = crate::utils::now().as_secs();

        let amount_sats = 1_000;
        let label = "test".to_string();
        let labels = vec![label.clone()];

        let (invoice, _) = node
            .create_invoice(amount_sats, None, labels.clone(), None)
            .await
            .unwrap();

        assert_eq!(invoice.amount_milli_satoshis(), Some(amount_sats * 1000));
        match invoice.description() {
            Bolt11InvoiceDescription::Direct(desc) => {
                assert_eq!(desc.to_string(), "test");
            }
            _ => panic!("unexpected invoice description"),
        }

        let from_storage = get_invoice_by_hash(invoice.payment_hash(), &storage, &logger).unwrap();
        let by_hash = get_invoice_by_hash(invoice.payment_hash(), &storage, &logger).unwrap();

        assert_eq!(from_storage, by_hash);
        assert_eq!(from_storage.bolt11, Some(invoice.clone()));
        assert_eq!(from_storage.description, Some("test".to_string()));
        assert_eq!(from_storage.payment_hash, invoice.payment_hash().to_owned());
        assert_eq!(from_storage.preimage, None);
        assert_eq!(from_storage.payee_pubkey, None);
        assert_eq!(from_storage.amount_sats, Some(amount_sats));
        assert_eq!(from_storage.status, HTLCStatus::Pending);
        assert_eq!(from_storage.fees_paid, None);
        assert_eq!(from_storage.labels, labels.clone());
        assert!(from_storage.inbound);
        assert!(from_storage.last_updated >= now);

        // check labels

        let invoice_labels = storage.get_invoice_labels().unwrap();
        assert_eq!(invoice_labels.len(), 1);
        assert_eq!(invoice_labels.get(&invoice).cloned(), Some(labels));

        let label_item = storage.get_label("test").unwrap().unwrap();

        assert!(label_item.last_used_time >= now);
        assert!(label_item.addresses.is_empty());
        assert_eq!(label_item.invoices.into_iter().collect_vec(), vec![invoice]);
    }

    #[test]
    async fn test_fail_own_invoice() {
        let storage = MemoryStorage::default();
        let node = create_node(storage).await;

        let invoice = node
            .create_invoice(10_000, None, vec![], None)
            .await
            .unwrap()
            .0;

        let result = node
            .pay_invoice_with_timeout(&invoice, None, None, vec![])
            .await;

        match result {
            Err(MutinyError::NonUniquePaymentHash) => {}
            Err(e) => panic!("unexpected error {e:?}"),
            Ok(_) => panic!("somehow paid own invoice"),
        }
    }

    #[test]
    async fn test_await_payment() {
        let storage = MemoryStorage::default();
        let node = create_node(storage).await;
        let payment_id = PaymentId([0; 32]);
        let payment_hash = PaymentHash([0; 32]);

        // check that we get PaymentTimeout if we don't have the payment info

        let result = node
            .await_payment(payment_id, payment_hash, 1, vec![])
            .await;

        assert_eq!(result.unwrap_err(), MutinyError::PaymentTimeout);

        let mut payment_info = PaymentInfo {
            preimage: None,
            secret: Some([0; 32]),
            status: HTLCStatus::InFlight,
            privacy_level: PrivacyLevel::NotAvailable,
            amt_msat: MillisatAmount(Some(1000)),
            fee_paid_msat: None,
            bolt11: None,
            payee_pubkey: None,
            last_update: crate::utils::now().as_secs(),
        };

        // check that it still fails if it is inflight
        persist_payment_info(
            &node.persister.storage,
            &payment_hash.0,
            &payment_info,
            false,
        )
        .unwrap();

        let result = node
            .await_payment(payment_id, payment_hash, 1, vec![])
            .await;

        assert_eq!(result.unwrap_err(), MutinyError::PaymentTimeout);

        // check that we get proper error if it fails

        payment_info.status = HTLCStatus::Failed;
        persist_payment_info(
            &node.persister.storage,
            &payment_hash.0,
            &payment_info,
            false,
        )
        .unwrap();

        let result = node
            .await_payment(payment_id, payment_hash, 1, vec![])
            .await;

        assert_eq!(result.unwrap_err(), MutinyError::RoutingFailed);

        // check that we get success

        payment_info.status = HTLCStatus::Succeeded;
        persist_payment_info(
            &node.persister.storage,
            &payment_hash.0,
            &payment_info,
            false,
        )
        .unwrap();

        let result = node
            .await_payment(payment_id, payment_hash, 1, vec![])
            .await;

        assert!(result.is_ok());
    }
}
