use std::sync::Arc;

use bitcoin::secp256k1::PublicKey;
use lightning::io::{Error, Read};
use lightning::ln::features::{InitFeatures, NodeFeatures};
use lightning::ln::msgs::{DecodeError, LightningError};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::{CustomMessageReader, Type};
use lightning::util::ser::{Writeable, Writer};
use serde::{Deserialize, Serialize};

use crate::node::LiquidityManager;
use crate::storage::MutinyStorage;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct BumpChannelClosureTransaction {
    pub channel_id: String,
    pub txid: String,
    pub hex_tx: String,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CommonLnEvent {
    // On Peer Connect
    OnConnect {
        their_node_id: String,
        inbound: bool,
        remote_network_address: Option<String>,
    },
    // On Peer Disconnect
    OnDisconnect {
        their_node_id: String,
    },
    BumpChannelCloseTransaction {
        channel_id: String,
        txid: String,
        hex_tx: String,
        timestamp: u64,
    },
    ChannelClosed {
        channel_id: String,
        reason: String,
        counterparty_node_id: Option<String>,
        channel_funding_txo: Option<String>,
        // This field may return true on a cooperate close event,
        // this must only be used to report debugging information.
        maybe_force_closed: bool,
    },
    // Sent payment
    PaymentSent {
        payment_hash: String,
    },
    // Sent payment failed
    PaymentFailed {
        payment_hash: String,
        reason: Option<String>,
    },
    // Received payment
    PaymentClaimed {
        /// The node that received the payment.
        receiver_node_id: Option<String>,
        /// The payment hash of the payment.
        payment_hash: String,
        amount_msat: u64,
    },
    // Wallet first synced
    WalletFirstSynced,
    // Try broadcast tx 1 in multi out
    TryBroadcastTx1InMultiOut {
        txid: String,
        hex_tx: String,
        timestamp: u64,
    },
    // Before sync to VSS
    BeforeSyncToVss {
        key: String,
        version: Option<u32>,
        timestamp: u64,
    },
    // Sync to VSS completed
    SyncToVssCompleted {
        key: String,
        version: Option<u32>,
        timestamp: u64,
        duration_ms: u128,
    },
}

#[derive(Clone)]
pub struct CommonLnEventCallback {
    pub callback: Arc<dyn Fn(CommonLnEvent) + Send + Sync>,
}

impl CommonLnEventCallback {
    pub fn trigger(&self, event: CommonLnEvent) {
        (self.callback)(event);
    }
}

pub struct MutinyMessageHandler<S: MutinyStorage> {
    pub liquidity: Option<Arc<LiquidityManager<S>>>,
    pub ln_event_callback: Option<CommonLnEventCallback>,
}

pub enum MutinyMessage<S: MutinyStorage> {
    Liquidity(<LiquidityManager<S> as CustomMessageReader>::CustomMessage),
}

impl<S: MutinyStorage> std::fmt::Debug for MutinyMessage<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Liquidity(arg0) => f.debug_tuple("Liquidity").field(arg0).finish(),
        }
    }
}

impl<S: MutinyStorage> CustomMessageHandler for MutinyMessageHandler<S> {
    fn handle_custom_message(
        &self,
        msg: Self::CustomMessage,
        sender_node_id: &PublicKey,
    ) -> Result<(), LightningError> {
        match msg {
            MutinyMessage::Liquidity(message) => {
                if let Some(liquidity) = &self.liquidity {
                    return CustomMessageHandler::handle_custom_message(
                        liquidity.as_ref(),
                        message,
                        sender_node_id,
                    );
                }
            }
        }

        Ok(())
    }

    fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
        if let Some(liquidity) = &self.liquidity {
            liquidity
                .get_and_clear_pending_msg()
                .into_iter()
                .map(|(pubkey, message)| (pubkey, MutinyMessage::Liquidity(message)))
                .collect()
        } else {
            vec![]
        }
    }

    fn provided_node_features(&self) -> NodeFeatures {
        match &self.liquidity {
            Some(liquidity) => liquidity.provided_node_features(),
            None => NodeFeatures::empty(),
        }
    }

    fn provided_init_features(&self, their_node_id: &PublicKey) -> InitFeatures {
        match &self.liquidity {
            Some(liquidity) => liquidity.provided_init_features(their_node_id),
            None => InitFeatures::empty(),
        }
    }

    fn peer_connected(
        &self,
        their_node_id: &PublicKey,
        msg: &lightning::ln::msgs::Init,
        inbound: bool,
    ) -> Result<(), ()> {
        if let Some(cb) = self.ln_event_callback.clone() {
            let event = CommonLnEvent::OnConnect {
                their_node_id: their_node_id.to_string(),
                inbound,
                remote_network_address: msg
                    .remote_network_address
                    .as_ref()
                    .map(|addr| format!("{}", addr)),
            };
            cb.trigger(event);
        }
        Ok(())
    }

    fn peer_disconnected(&self, their_node_id: &PublicKey) {
        if let Some(cb) = self.ln_event_callback.clone() {
            let event = CommonLnEvent::OnDisconnect {
                their_node_id: their_node_id.to_string(),
            };
            cb.trigger(event);
        }
    }
}

impl<S: MutinyStorage> CustomMessageReader for MutinyMessageHandler<S> {
    type CustomMessage = MutinyMessage<S>;
    fn read<R: Read>(
        &self,
        message_type: u16,
        buffer: &mut R,
    ) -> Result<Option<Self::CustomMessage>, DecodeError> {
        if let Some(liquidity) = &self.liquidity {
            match <LiquidityManager<S> as CustomMessageReader>::read(
                liquidity,
                message_type,
                buffer,
            )? {
                None => Ok(None),
                Some(message) => Ok(Some(MutinyMessage::Liquidity(message))),
            }
        } else {
            Ok(None)
        }
    }
}

impl<S: MutinyStorage> Type for MutinyMessage<S> {
    fn type_id(&self) -> u16 {
        match self {
            MutinyMessage::Liquidity(message) => message.type_id(),
        }
    }
}

impl<S: MutinyStorage> Writeable for MutinyMessage<S> {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
        match self {
            MutinyMessage::Liquidity(message) => message.write(writer),
        }
    }
}
