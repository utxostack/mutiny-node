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

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PeerConnectionEvent {
    OnConnect {
        their_node_id: String,
        inbound: bool,
        remote_network_address: Option<String>,
    },
    OnDisconnect {
        their_node_id: String,
    },
}

#[derive(Clone)]
pub struct PeerEventCallback {
    pub callback: Arc<dyn Fn(PeerConnectionEvent) + Send + Sync>,
}

pub struct MutinyMessageHandler<S: MutinyStorage> {
    pub liquidity: Option<Arc<LiquidityManager<S>>>,
    pub peer_event_callback: Option<PeerEventCallback>,
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
        if let Some(cb) = self.peer_event_callback.clone() {
            let event = PeerConnectionEvent::OnConnect {
                their_node_id: their_node_id.to_string(),
                inbound,
                remote_network_address: msg
                    .remote_network_address
                    .as_ref()
                    .map(|addr| format!("{}", addr)),
            };
            (cb.callback)(event);
        }
        Ok(())
    }

    fn peer_disconnected(&self, their_node_id: &PublicKey) {
        if let Some(cb) = self.peer_event_callback.clone() {
            let event = PeerConnectionEvent::OnDisconnect {
                their_node_id: their_node_id.to_string(),
            };
            (cb.callback)(event);
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
