use crate::keymanager::PhantomKeysManager;
use crate::messagehandler::CommonLnEvent;
use crate::messagehandler::MutinyMessageHandler;
#[cfg(target_arch = "wasm32")]
use crate::networking::socket::{schedule_descriptor_read, MutinySocketDescriptor};
use crate::node::{NetworkGraph, OnionMessenger, PendingConnections};
use crate::storage::MutinyStorage;
use crate::utils::{self, sleep};
use crate::{error::MutinyError, fees::MutinyFeeEstimator};
use crate::{gossip, ldkstorage::PhantomChannelManager, logging::MutinyLogger};
use crate::{gossip::read_peer_info, node::PubkeyConnectionInfo};
use bitcoin::key::{Secp256k1, Verification};
use bitcoin::secp256k1::{PublicKey, Signing};
use lightning::blinded_path::message::{BlindedMessagePath, MessageContext};
use lightning::blinded_path::IntroductionNode;
use lightning::events::{MessageSendEvent, MessageSendEventsProvider};
use lightning::ln::features::{InitFeatures, NodeFeatures};
use lightning::ln::msgs;
use lightning::ln::msgs::{LightningError, RoutingMessageHandler};
use lightning::ln::peer_handler::PeerManager as LdkPeerManager;
use lightning::ln::peer_handler::{APeerManager, PeerHandleError};
use lightning::onion_message::messenger::{Destination, MessageRouter, OnionMessagePath};
use lightning::routing::gossip::NodeId;
use lightning::util::logger::Logger;
use lightning::{ln::msgs::SocketAddress, log_warn};
use lightning::{log_debug, log_error};
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use utils::Mutex;

#[cfg(target_arch = "wasm32")]
use crate::networking::ws_socket::WsTcpSocketDescriptor;

#[cfg(target_arch = "wasm32")]
use lightning::ln::peer_handler::SocketDescriptor as LdkSocketDescriptor;

#[cfg(target_arch = "wasm32")]
use crate::networking::proxy::WsProxy;

pub static CONNECTED_PEER_MANAGER: once_cell::sync::Lazy<ConnectedPeerManager> =
    once_cell::sync::Lazy::new(ConnectedPeerManager::default);

#[allow(dead_code)]
pub trait PeerManager: Send + Sync + 'static {
    fn get_peer_node_ids(&self) -> Vec<PublicKey>;

    fn new_outbound_connection(
        &self,
        their_node_id: PublicKey,
        descriptor: AnySocketDescriptor,
        remote_network_address: Option<SocketAddress>,
    ) -> Result<Vec<u8>, PeerHandleError>;

    fn new_inbound_connection(
        &self,
        descriptor: AnySocketDescriptor,
        remote_network_address: Option<SocketAddress>,
    ) -> Result<(), PeerHandleError>;

    fn write_buffer_space_avail(
        &self,
        descriptor: &mut AnySocketDescriptor,
    ) -> Result<(), PeerHandleError>;

    fn read_event(
        &self,
        descriptor: &mut AnySocketDescriptor,
        data: &[u8],
    ) -> Result<bool, PeerHandleError>;

    fn process_events(&self);

    fn socket_disconnected(&self, descriptor: &mut AnySocketDescriptor);

    fn disconnect_by_node_id(&self, node_id: PublicKey);

    fn disconnect_all_peers(&self);

    fn timer_tick_occurred(&self);

    fn broadcast_node_announcement(
        &self,
        rgb: [u8; 3],
        alias: [u8; 32],
        addresses: Vec<SocketAddress>,
    );
}

#[cfg(target_arch = "wasm32")]
type AnySocketDescriptor = MutinySocketDescriptor;

#[cfg(not(target_arch = "wasm32"))]
type AnySocketDescriptor = lightning_net_tokio::SocketDescriptor;

pub(crate) type PeerManagerImpl<S: MutinyStorage> = LdkPeerManager<
    AnySocketDescriptor,
    Arc<PhantomChannelManager<S>>,
    Arc<GossipMessageHandler<S>>,
    Arc<OnionMessenger<S>>,
    Arc<MutinyLogger>,
    Arc<MutinyMessageHandler<S>>,
    Arc<PhantomKeysManager<S>>,
>;

impl<S: MutinyStorage> PeerManager for PeerManagerImpl<S> {
    fn get_peer_node_ids(&self) -> Vec<PublicKey> {
        self.list_peers()
            .into_iter()
            .map(|x| x.counterparty_node_id)
            .collect()
    }

    fn new_outbound_connection(
        &self,
        their_node_id: PublicKey,
        descriptor: AnySocketDescriptor,
        remote_network_address: Option<SocketAddress>,
    ) -> Result<Vec<u8>, PeerHandleError> {
        self.new_outbound_connection(their_node_id, descriptor, remote_network_address)
    }

    fn new_inbound_connection(
        &self,
        descriptor: AnySocketDescriptor,
        remote_network_address: Option<SocketAddress>,
    ) -> Result<(), PeerHandleError> {
        self.new_inbound_connection(descriptor, remote_network_address)
    }

    fn write_buffer_space_avail(
        &self,
        descriptor: &mut AnySocketDescriptor,
    ) -> Result<(), PeerHandleError> {
        self.write_buffer_space_avail(descriptor)
    }

    fn read_event(
        &self,
        peer_descriptor: &mut AnySocketDescriptor,
        data: &[u8],
    ) -> Result<bool, PeerHandleError> {
        self.read_event(peer_descriptor, data)
    }

    fn process_events(&self) {
        self.process_events()
    }

    fn socket_disconnected(&self, descriptor: &mut AnySocketDescriptor) {
        self.socket_disconnected(descriptor)
    }

    fn disconnect_by_node_id(&self, node_id: PublicKey) {
        self.disconnect_by_node_id(node_id)
    }

    fn disconnect_all_peers(&self) {
        self.disconnect_all_peers()
    }

    fn timer_tick_occurred(&self) {
        self.timer_tick_occurred()
    }

    fn broadcast_node_announcement(
        &self,
        rgb: [u8; 3],
        alias: [u8; 32],
        addresses: Vec<SocketAddress>,
    ) {
        self.broadcast_node_announcement(rgb, alias, addresses)
    }
}

#[derive(Clone)]
pub struct GossipMessageHandler<S: MutinyStorage> {
    pub(crate) storage: S,
    pub(crate) network_graph: Arc<NetworkGraph>,
    pub(crate) logger: Arc<MutinyLogger>,
}

impl<S: MutinyStorage> MessageSendEventsProvider for GossipMessageHandler<S> {
    fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
        Vec::new()
    }
}

impl<S: MutinyStorage> RoutingMessageHandler for GossipMessageHandler<S> {
    fn handle_node_announcement(
        &self,
        msg: &msgs::NodeAnnouncement,
    ) -> Result<bool, LightningError> {
        // We use RGS to sync gossip, but we can save the node's metadata (alias and color)
        // we should only save it for relevant peers however (i.e. peers we have a channel with)
        let node_id = msg.contents.node_id;
        if read_peer_info(&self.storage, &node_id)
            .ok()
            .flatten()
            .is_some()
        {
            if let Err(e) = gossip::save_ln_peer_info(&self.storage, &node_id, &msg.clone().into())
            {
                log_warn!(
                    self.logger,
                    "Failed to save node announcement for {node_id}: {e}"
                );
            }
        }

        // because we got the announcement, may as well update our network graph
        self.network_graph
            .update_node_from_unsigned_announcement(&msg.contents)?;

        Ok(false)
    }

    fn handle_channel_announcement(
        &self,
        msg: &msgs::ChannelAnnouncement,
    ) -> Result<bool, LightningError> {
        // because we got the channel, may as well update our network graph
        self.network_graph
            .update_channel_from_announcement_no_lookup(msg)?;
        Ok(false)
    }

    fn handle_channel_update(&self, msg: &msgs::ChannelUpdate) -> Result<bool, LightningError> {
        // because we got the update, may as well update our network graph
        self.network_graph.update_channel_unsigned(&msg.contents)?;
        Ok(false)
    }

    fn get_next_channel_announcement(
        &self,
        _starting_point: u64,
    ) -> Option<(
        msgs::ChannelAnnouncement,
        Option<msgs::ChannelUpdate>,
        Option<msgs::ChannelUpdate>,
    )> {
        None
    }

    fn get_next_node_announcement(
        &self,
        _starting_point: Option<&NodeId>,
    ) -> Option<msgs::NodeAnnouncement> {
        None
    }

    fn peer_connected(
        &self,
        _their_node_id: &PublicKey,
        _init: &msgs::Init,
        _inbound: bool,
    ) -> Result<(), ()> {
        Ok(())
    }

    fn handle_reply_channel_range(
        &self,
        _their_node_id: &PublicKey,
        _msg: msgs::ReplyChannelRange,
    ) -> Result<(), LightningError> {
        Ok(())
    }

    fn handle_reply_short_channel_ids_end(
        &self,
        _their_node_id: &PublicKey,
        _msg: msgs::ReplyShortChannelIdsEnd,
    ) -> Result<(), LightningError> {
        Ok(())
    }

    fn handle_query_channel_range(
        &self,
        _their_node_id: &PublicKey,
        _msg: msgs::QueryChannelRange,
    ) -> Result<(), LightningError> {
        Ok(())
    }

    fn handle_query_short_channel_ids(
        &self,
        _their_node_id: &PublicKey,
        _msg: msgs::QueryShortChannelIds,
    ) -> Result<(), LightningError> {
        Ok(())
    }

    fn processing_queue_high(&self) -> bool {
        false
    }

    fn provided_node_features(&self) -> NodeFeatures {
        NodeFeatures::empty()
    }

    fn provided_init_features(&self, _their_node_id: &PublicKey) -> InitFeatures {
        let mut features = InitFeatures::empty();
        features.set_gossip_queries_optional();
        features
    }
}

/// LDK currently can't route onion messages, so we need to do it ourselves
/// We just assume they are connected to us or the LSP.
pub struct LspMessageRouter {
    intermediate_nodes: Vec<PublicKey>,
}

impl LspMessageRouter {
    pub fn new(lsp_pubkey: Option<PublicKey>) -> Self {
        let intermediate_nodes = match lsp_pubkey {
            Some(pubkey) => vec![pubkey],
            None => vec![],
        };

        Self { intermediate_nodes }
    }
}

impl MessageRouter for LspMessageRouter {
    fn find_path(
        &self,
        _sender: PublicKey,
        peers: Vec<PublicKey>,
        destination: Destination,
    ) -> Result<OnionMessagePath, ()> {
        let first_node = match &destination {
            Destination::Node(node_id) => Some(*node_id),
            Destination::BlindedPath(path) => match path.introduction_node() {
                IntroductionNode::DirectedShortChannelId(..) => None,
                IntroductionNode::NodeId(node_id) => Some(*node_id),
            },
        };

        if first_node.is_none() || first_node.is_some_and(|node| peers.contains(&node)) {
            Ok(OnionMessagePath {
                intermediate_nodes: vec![],
                destination,
                first_node_addresses: None,
            })
        } else {
            Ok(OnionMessagePath {
                intermediate_nodes: self.intermediate_nodes.clone(),
                destination,
                first_node_addresses: None,
            })
        }
    }

    fn create_blinded_paths<T: Signing + Verification>(
        &self,
        _recipient: PublicKey,
        _context: MessageContext,
        _peers: Vec<PublicKey>,
        _secp_ctx: &Secp256k1<T>,
    ) -> Result<Vec<BlindedMessagePath>, ()> {
        // Bolt12 not yet supported
        Err(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn connect_peer_if_necessary<
    S: MutinyStorage,
    P: PeerManager + APeerManager<Descriptor = AnySocketDescriptor>,
>(
    #[cfg(target_arch = "wasm32")] websocket_proxy_addr: &str,
    peer_connection_info: &PubkeyConnectionInfo,
    storage: &S,
    logger: Arc<MutinyLogger>,
    peer_manager: Arc<P>,
    pending_connections: PendingConnections,
    fee_estimator: Arc<MutinyFeeEstimator<S>>,
    stop: Arc<AtomicBool>,
) -> Result<(), MutinyError> {
    // do not connect to same peer within 5 secs
    const IGNORE_CONN_SECS: u32 = 5;

    if peer_manager
        .get_peer_node_ids()
        .contains(&peer_connection_info.pubkey)
    {
        return Ok(());
    }

    let node_id = NodeId::from_pubkey(&peer_connection_info.pubkey);

    let mut retries = 0;
    let max_retries = 10;
    while retries < max_retries {
        match pending_connections.try_lock() {
            Some(mut pending) => {
                log_debug!(logger, "get pending connections");
                let now_secs = utils::now().as_secs() as u32;
                let pending_expire_secs = now_secs - IGNORE_CONN_SECS;
                if pending
                    .get(&node_id)
                    .is_some_and(|&last| pending_expire_secs < last)
                {
                    log_debug!(logger, "Ignoring connection request to {node_id}");
                    return Ok(());
                }

                // save pending connections
                pending.insert(node_id, now_secs);

                // clear expired pending connections
                if pending.len() > 20 {
                    pending.retain(|_, last| pending_expire_secs < *last);
                }
                break;
            }
            None if retries > max_retries => {
                log_error!(logger, "Can't get pending connections lock");
                return Err(MutinyError::ConnectionFailed);
            }
            None => {
                retries += 1;
                log_debug!(logger, "Can't get pending connections lock {retries}");
                sleep(200).await;
                continue;
            }
        };
    }

    // make sure we have the device lock before connecting
    // otherwise we could cause force closes.
    // If we didn't have the lock last, we need to panic because
    // the state could have changed.
    if let Some(lock) = storage.fetch_device_lock().await? {
        let id = storage.get_device_id()?;
        if !lock.is_last_locker(&id) {
            log_warn!(
                logger,
                "Lock has changed (remote: {}, local: {})! Aborting since state could be outdated",
                lock.device,
                id
            );
            if let Some(cb) = storage.ln_event_callback().as_ref() {
                let event = CommonLnEvent::DeviceLockChangedWhenConnecting {
                    remote_device: lock.device,
                    local_device: id,
                    timestamp: utils::now().as_secs(),
                };
                cb.trigger(event);
            }
            return Err(MutinyError::DeviceLockChangedWhenConnecting);
        }
    }

    // first check to see if the fee rate is mostly up to date
    // if not, we need to have updated fees or force closures
    // could occur due to UpdateFee message conflicts.
    fee_estimator.update_fee_estimates_if_necessary().await?;

    #[cfg(target_arch = "wasm32")]
    let ret = connect_peer(
        #[cfg(target_arch = "wasm32")]
        websocket_proxy_addr,
        peer_connection_info,
        logger,
        peer_manager,
        stop,
    )
    .await;

    #[cfg(not(target_arch = "wasm32"))]
    let ret = match lightning_net_tokio::connect_outbound(
        peer_manager.clone(),
        peer_connection_info.pubkey,
        peer_connection_info.socket_address()?,
    )
    .await
    {
        None => {
            lightning::log_error!(
                logger,
                "Connection to peer timed out: {:?}",
                peer_connection_info
            );
            Err(MutinyError::ConnectionFailed)
        }
        Some(connection_closed_future) => {
            // spawn a task to wait for the connection to close
            let mut connection_closed_future = Box::pin(connection_closed_future);
            let pubkey = peer_connection_info.pubkey;
            crate::utils::spawn(async move {
                loop {
                    // If we are stopped, exit the loop
                    if stop.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }

                    tokio::select! {
                        _ = &mut connection_closed_future => break,
                        _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {},
                    }

                    // make sure they are still a peer
                    if peer_manager
                        .get_peer_node_ids()
                        .iter()
                        .any(|id| *id == pubkey)
                    {
                        break;
                    }
                }
            });

            Ok(())
        }
    };

    ret
}

#[cfg(target_arch = "wasm32")]
async fn connect_peer<P: PeerManager>(
    #[cfg(target_arch = "wasm32")] websocket_proxy_addr: &str,
    peer_connection_info: &PubkeyConnectionInfo,
    logger: Arc<MutinyLogger>,
    peer_manager: Arc<P>,
    stop: Arc<AtomicBool>,
) -> Result<(), MutinyError> {
    let (mut descriptor, socket_addr_opt) = match peer_connection_info.connection_type {
        crate::node::ConnectionType::Tcp(ref t) => {
            let proxy = WsProxy::new(
                websocket_proxy_addr,
                peer_connection_info.clone(),
                logger.clone(),
            )
            .await?;
            let (_, net_addr) = try_parse_addr_string(t);
            (
                AnySocketDescriptor::Tcp(WsTcpSocketDescriptor::new(proxy)),
                net_addr,
            )
        }
    };

    // then give that connection to the peer manager
    let initial_bytes = peer_manager.new_outbound_connection(
        peer_connection_info.pubkey,
        descriptor.clone(),
        socket_addr_opt,
    )?;

    lightning::log_debug!(logger, "connected to peer: {:?}", peer_connection_info);

    let sent_bytes = descriptor.send_data(&initial_bytes, true);
    lightning::log_trace!(
        logger,
        "sent {sent_bytes} to node: {}",
        peer_connection_info.pubkey
    );

    // schedule a reader on the connection
    schedule_descriptor_read(
        descriptor,
        peer_manager.clone(),
        logger.clone(),
        stop.clone(),
    );

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn try_parse_addr_string(addr: &str) -> (Option<std::net::SocketAddr>, Option<SocketAddress>) {
    use std::net::SocketAddr;
    let socket_addr = addr.parse::<SocketAddr>().ok();
    let net_addr = socket_addr.map(|socket_addr| match socket_addr {
        SocketAddr::V4(sockaddr) => SocketAddress::TcpIpV4 {
            addr: sockaddr.ip().octets(),
            port: sockaddr.port(),
        },
        SocketAddr::V6(sockaddr) => SocketAddress::TcpIpV6 {
            addr: sockaddr.ip().octets(),
            port: sockaddr.port(),
        },
    });
    (socket_addr, net_addr)
}

#[derive(Debug, Clone)]
pub struct ConnectedPeerInfo {
    pub inbound: bool,
    pub remote_address: Option<String>,
    pub connected_at_timestamp: u64,
}

pub struct ConnectedPeerManager {
    peers: Arc<Mutex<HashMap<PublicKey, ConnectedPeerInfo>>>,
    logger: Mutex<Option<Arc<MutinyLogger>>>,
}

impl Default for ConnectedPeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectedPeerManager {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            logger: Mutex::new(None),
        }
    }

    pub fn set_logger(&self, logger: Arc<MutinyLogger>) {
        let mut lock = self.logger.lock().unwrap();
        *lock = Some(logger);
    }

    pub fn add_peer(
        &self,
        their_node_id: PublicKey,
        inbound: bool,
        remote_address: Option<String>,
    ) {
        let timestamp = utils::now().as_secs();

        let info = ConnectedPeerInfo {
            inbound,
            remote_address,
            connected_at_timestamp: timestamp,
        };

        let mut peers = self.peers.lock().unwrap();
        let inserted = peers.insert(their_node_id, info).is_none();
        let logger = {
            let guard = self.logger.lock().expect(
                "
                Failed to lock logger",
            );
            guard.clone()
        };
        if inserted {
            if let Some(logger) = logger {
                log_debug!(logger, "Connected to peer: {}", their_node_id);
            }
        }
    }

    pub fn remove_peer(&self, their_node_id: &PublicKey) {
        let mut peers = self.peers.lock().unwrap();
        let removed = peers.remove(their_node_id).is_some();

        let logger = {
            let guard = self.logger.lock().expect(
                "
                Failed to lock logger",
            );
            guard.clone()
        };
        if removed {
            if let Some(logger) = logger {
                log_debug!(logger, "Disconnected from peer: {}", their_node_id);
            }
        }
    }

    pub fn is_any_connected(&self) -> bool {
        let lock = self.peers.lock().unwrap();
        !lock.is_empty()
    }
}
