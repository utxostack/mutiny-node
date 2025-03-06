use aes::cipher::block_padding::UnpadError;
use bdk_wallet::error::BuildFeeBumpError;
use bdk_wallet::signer::SignerError;
use bdk_wallet::tx_builder::AddUtxoError;
use bitcoin::psbt::ExtractTxError;
use hex_conservative::HexToArrayError;
use lightning::ln::channelmanager::RetryableSendFailure;
use lightning::ln::peer_handler::PeerHandleError;
use lightning_invoice::ParseOrSemanticError;
use lightning_rapid_gossip_sync::GraphSyncError;
use lightning_transaction_sync::TxSyncError;
use log::error;
use std::string::FromUtf8Error;
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
// copied from LDK lite
/// An error that possibly needs to be handled by the user.
pub enum MutinyError {
    /// Returned when trying to start Mutiny while it is already running.
    #[error("Mutiny is already running.")]
    AlreadyRunning,
    #[error("The stored LND snapshot is outdated.")]
    LndSnapshotOutdated,
    /// Returned when trying to stop Mutiny while it is not running.
    #[error("Mutiny is not running.")]
    NotRunning,
    /// Returned when Mutiny tries to startup with a different network than the one it was
    /// previously running on.
    #[error("Incorrect expected network.")]
    NetworkMismatch,
    /// Returned on any resource that is not found.
    #[error("Resource Not found.")]
    NotFound,
    /// The funding transaction could not be created.
    #[error("Funding transaction could not be created.")]
    FundingTxCreationFailed,
    /// A network connection has been closed.
    #[error("Network connection closed.")]
    ConnectionFailed,
    /// The invoice or address is on a different network
    #[error("The invoice or address is on a different network.")]
    IncorrectNetwork,
    /// Payment of the given invoice has already been initiated.
    #[error("An invoice must not get payed twice.")]
    NonUniquePaymentHash,
    /// Payment Timed out
    #[error("Payment timed out.")]
    PaymentTimeout,
    /// The given invoice is invalid.
    #[error("The given invoice is invalid.")]
    InvoiceInvalid,
    /// The given invoice is expired.
    #[error("The given invoice is expired.")]
    InvoiceExpired,
    /// Invoice creation failed.
    #[error("Failed to create invoice.")]
    InvoiceCreationFailed,
    /// We have enough balance to pay an invoice, but
    /// the this would take from our reserve amount which is not allowed.
    #[error("Channel reserve amount is too high.")]
    ReserveAmountError,
    /// We do not have enough balance to pay the given amount.
    #[error("We do not have enough balance to pay the given amount.")]
    InsufficientBalance,
    /// Could not make a request to the LSP.
    #[error("Failed to make a request to the LSP.")]
    LspGenericError,
    /// LSP indicated it could not fund the channel requested.
    #[error("Failed to request channel from LSP due to funding error.")]
    LspFundingError,
    /// LSP indicated the amount is too high to fund.
    #[error("Failed to request channel from LSP due to amount being too high.")]
    LspAmountTooHighError,
    /// LSP indicated it was not connected to the client node.
    #[error("Failed to have a connection to the LSP node.")]
    LspConnectionError,
    /// LSP required an invoice and none was provided.
    #[error("Failed to provide an invoice to the LSP.")]
    LspInvoiceRequired,
    /// Subscription Client Not Configured
    #[error("Subscription Client Not Configured")]
    SubscriptionClientNotConfigured,
    /// Invalid Arguments were given
    #[error("Invalid Arguments were given")]
    InvalidArgumentsError,
    /// No route for the given target could be found.
    #[error("Failed to find route.")]
    RoutingFailed,
    /// A given peer info could not be parsed.
    #[error("Failed to parse the given peer information.")]
    PeerInfoParseFailed,
    /// A channel could not be opened.
    #[error("Failed to create channel.")]
    ChannelCreationFailed,
    /// A channel could not be opened.
    #[error("Failed to create channel. {0}")]
    ChannelCreationFailedWithReason(String),
    /// A channel could not be closed.
    #[error("Failed to close channel.")]
    ChannelClosingFailed,
    /// Persistence failed.
    #[error("Failed to persist data.")]
    PersistenceFailed {
        #[from]
        source: MutinyStorageError,
    },
    #[error("Failed to read data from storage.")]
    ReadError { source: MutinyStorageError },
    #[error("Failed to decode lightning data.")]
    LnDecodeError,
    /// A failure to generate a mnemonic seed.
    #[error("Failed to generate seed")]
    SeedGenerationFailed,
    /// User provided invalid mnemonic.
    #[error("Invalid mnemonic")]
    InvalidMnemonic,
    /// Invalid BTC transaction or hex string.
    #[error("Invalid BTC transaction")]
    InvalidTransaction,
    /// A wallet operation failed.
    #[error("Failed to conduct wallet operation.")]
    WalletOperationFailed,
    /// A signing operation failed.
    #[error("Failed to sign given transaction.")]
    WalletSigningFailed,
    /// A chain access operation failed.
    #[error("Failed to conduct chain access operation.")]
    ChainAccessFailed,
    /// A failure to sync the on-chain wallet
    #[error("Failed to to sync on-chain wallet.")]
    WalletSyncError,
    /// An error with rapid gossip sync
    #[error("Failed to execute a rapid gossip sync function")]
    RapidGossipSyncError,
    /// A error with DLCs
    #[error("Failed to execute a dlc function")]
    DLCManagerError,
    /// Node pubkey given is invalid
    #[error("The given node pubkey is invalid.")]
    PubkeyInvalid,
    /// Error converting JS f64 value to Amount
    #[error("Satoshi amount is invalid")]
    BadAmountError,
    /// Error getting the bitcoin price
    #[error("Failed to get the bitcoin price.")]
    BitcoinPriceError,
    /// Error getting nostr data
    #[error("Failed to get nostr data.")]
    NostrError,
    /// Error with Nip07 Extension
    #[error("Error with NIP-07 extension")]
    Nip07Extension,
    /// Incorrect password entered.
    #[error("Incorrect password entered.")]
    IncorrectPassword,
    /// Cannot change password to the same password
    #[error("Cannot change password to the same password.")]
    SamePassword,
    /// Error calling Cashu Mint
    #[error("Error calling Cashu Mint.")]
    CashuMintError,
    /// Mint URL in token was empty
    #[error("Mint URL in token is empty.")]
    EmptyMintURLError,
    /// Token already spent.
    #[error("Token has been already spent.")]
    TokenAlreadySpent,
    #[error("Message Packet size exceeded")]
    PacketSizeExceeded,
    #[error("Invalid fee rate")]
    InvalidFeerate,
    #[error("Invalid psbt")]
    InvalidPsbt,
    #[error("Invalid hex")]
    InvalidHex,
    /// Failed to authenticate using JWT
    #[error("Failed to authenticate using JWT.")]
    JwtAuthFailure,
    #[error("Failed to parse VSS value from getObject response.")]
    FailedParsingVssValue,
    #[error(transparent)]
    Other(anyhow::Error),
}

#[derive(Error, Debug)]
pub enum MutinyStorageError {
    #[error("Failed to serialize or deserialize")]
    SerdeError {
        #[from]
        source: serde_json::Error,
    },
    #[error("Failed to get lock on memory storage")]
    LockError,
    #[error("Failed to use indexeddb storage")]
    IndexedDBError,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl PartialEq for MutinyStorageError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::SerdeError { .. }, Self::SerdeError { .. }) => true,
            (Self::LockError, Self::LockError) => true,
            (Self::IndexedDBError, Self::IndexedDBError) => true,
            (Self::Other(e), Self::Other(e2)) => e.to_string() == e2.to_string(),
            _ => false,
        }
    }
}

impl PartialEq for MutinyError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::AlreadyRunning, Self::AlreadyRunning) => true,
            (Self::NotRunning, Self::NotRunning) => true,
            (Self::NetworkMismatch, Self::NetworkMismatch) => true,
            (Self::NotFound, Self::NotFound) => true,
            (Self::FundingTxCreationFailed, Self::FundingTxCreationFailed) => true,
            (Self::ConnectionFailed, Self::ConnectionFailed) => true,
            (Self::IncorrectNetwork, Self::IncorrectNetwork) => true,
            (Self::NonUniquePaymentHash, Self::NonUniquePaymentHash) => true,
            (Self::PaymentTimeout, Self::PaymentTimeout) => true,
            (Self::InvoiceInvalid, Self::InvoiceInvalid) => true,
            (Self::InvoiceExpired, Self::InvoiceExpired) => true,
            (Self::InvoiceCreationFailed, Self::InvoiceCreationFailed) => true,
            (Self::ReserveAmountError, Self::ReserveAmountError) => true,
            (Self::InsufficientBalance, Self::InsufficientBalance) => true,
            (Self::LspGenericError, Self::LspGenericError) => true,
            (Self::LspFundingError, Self::LspFundingError) => true,
            (Self::LspAmountTooHighError, Self::LspAmountTooHighError) => true,
            (Self::LspConnectionError, Self::LspConnectionError) => true,
            (Self::SubscriptionClientNotConfigured, Self::SubscriptionClientNotConfigured) => true,
            (Self::InvalidArgumentsError, Self::InvalidArgumentsError) => true,
            (Self::RoutingFailed, Self::RoutingFailed) => true,
            (Self::PeerInfoParseFailed, Self::PeerInfoParseFailed) => true,
            (Self::ChannelCreationFailed, Self::ChannelCreationFailed) => true,
            (
                Self::ChannelCreationFailedWithReason(x),
                Self::ChannelCreationFailedWithReason(y),
            ) => x == y,
            (Self::ChannelClosingFailed, Self::ChannelClosingFailed) => true,
            (Self::PersistenceFailed { source }, Self::PersistenceFailed { source: source2 }) => {
                source == source2
            }
            (Self::ReadError { source }, Self::ReadError { source: source2 }) => source == source2,
            (Self::LnDecodeError, Self::LnDecodeError) => true,
            (Self::SeedGenerationFailed, Self::SeedGenerationFailed) => true,
            (Self::InvalidMnemonic, Self::InvalidMnemonic) => true,
            (Self::WalletOperationFailed, Self::WalletOperationFailed) => true,
            (Self::WalletSigningFailed, Self::WalletSigningFailed) => true,
            (Self::ChainAccessFailed, Self::ChainAccessFailed) => true,
            (Self::WalletSyncError, Self::WalletSyncError) => true,
            (Self::RapidGossipSyncError, Self::RapidGossipSyncError) => true,
            (Self::PubkeyInvalid, Self::PubkeyInvalid) => true,
            (Self::BadAmountError, Self::BadAmountError) => true,
            (Self::BitcoinPriceError, Self::BitcoinPriceError) => true,
            (Self::DLCManagerError, Self::DLCManagerError) => true,
            (Self::NostrError, Self::NostrError) => true,
            (Self::IncorrectPassword, Self::IncorrectPassword) => true,
            (Self::SamePassword, Self::SamePassword) => true,
            (Self::CashuMintError, Self::CashuMintError) => true,
            (Self::EmptyMintURLError, Self::EmptyMintURLError) => true,
            (Self::TokenAlreadySpent, Self::TokenAlreadySpent) => true,
            (Self::Other(e), Self::Other(e2)) => e.to_string() == e2.to_string(),
            _ => false,
        }
    }
}

impl MutinyError {
    pub fn read_err(e: MutinyStorageError) -> Self {
        MutinyError::ReadError { source: e }
    }

    pub fn write_err(e: MutinyStorageError) -> Self {
        MutinyError::PersistenceFailed { source: e }
    }
}

impl From<ExtractTxError> for MutinyError {
    fn from(_e: ExtractTxError) -> Self {
        Self::InvalidPsbt
    }
}

impl From<UnpadError> for MutinyError {
    fn from(_e: UnpadError) -> Self {
        Self::IncorrectPassword
    }
}

impl From<base64::DecodeError> for MutinyError {
    fn from(_e: base64::DecodeError) -> Self {
        Self::IncorrectPassword
    }
}

impl From<FromUtf8Error> for MutinyError {
    fn from(_e: FromUtf8Error) -> Self {
        Self::IncorrectPassword
    }
}

impl From<aes_gcm::Error> for MutinyError {
    fn from(_: aes_gcm::Error) -> Self {
        Self::IncorrectPassword
    }
}

impl From<aes_gcm::aes::cipher::InvalidLength> for MutinyError {
    fn from(_: aes_gcm::aes::cipher::InvalidLength) -> Self {
        Self::IncorrectPassword
    }
}

impl From<bdk_chain::local_chain::AlterCheckPointError> for MutinyError {
    fn from(_e: bdk_chain::local_chain::AlterCheckPointError) -> Self {
        Self::WalletOperationFailed
    }
}

impl From<bdk_wallet::descriptor::error::Error> for MutinyError {
    fn from(_: bdk_wallet::descriptor::error::Error) -> Self {
        Self::WalletOperationFailed
    }
}

// impl From<bdk_wallet::NewError<MutinyError>> for MutinyError {
//     fn from(e: bdk_wallet::NewError<MutinyError>) -> Self {
//         match e {
//             bdk_wallet::NewError::Write(e) => e,
//             bdk_wallet::NewError::Descriptor(e) => e.into(),
//             bdk_wallet::NewError::NonEmptyDatabase => Self::WalletOperationFailed,
//         }
//     }
// }

impl From<bdk_wallet::LoadError> for MutinyError {
    fn from(e: bdk_wallet::LoadError) -> Self {
        match e {
            bdk_wallet::LoadError::Descriptor(e) => e.into(),
            bdk_wallet::LoadError::MissingGenesis => Self::WalletOperationFailed,
            bdk_wallet::LoadError::MissingNetwork => Self::WalletOperationFailed,
            bdk_wallet::LoadError::MissingDescriptor(_keychain_kind) => Self::WalletOperationFailed,
            bdk_wallet::LoadError::Mismatch(_load_mismatch) => Self::WalletSyncError,
        }
    }
}

impl From<AddUtxoError> for MutinyError {
    fn from(_: AddUtxoError) -> Self {
        Self::WalletOperationFailed
    }
}

impl From<bip39::Error> for MutinyError {
    fn from(_e: bip39::Error) -> Self {
        Self::InvalidMnemonic
    }
}

impl From<bitcoin::bip32::Error> for MutinyError {
    fn from(_e: bitcoin::bip32::Error) -> Self {
        Self::InvalidMnemonic
    }
}

impl From<bitcoin::address::ParseError> for MutinyError {
    fn from(_e: bitcoin::address::ParseError) -> Self {
        Self::PubkeyInvalid
    }
}

impl From<bitcoin::hex::HexToBytesError> for MutinyError {
    fn from(_e: bitcoin::hex::HexToBytesError) -> Self {
        Self::InvalidHex
    }
}

impl From<bitcoin::hex::HexToArrayError> for MutinyError {
    fn from(_e: bitcoin::hex::HexToArrayError) -> Self {
        Self::InvalidHex
    }
}

impl From<TxSyncError> for MutinyError {
    fn from(_e: TxSyncError) -> Self {
        MutinyError::ChainAccessFailed
    }
}

impl From<lightning::ln::msgs::DecodeError> for MutinyError {
    fn from(_e: lightning::ln::msgs::DecodeError) -> Self {
        MutinyError::LnDecodeError
    }
}

impl From<lightning::ln::script::InvalidShutdownScript> for MutinyError {
    fn from(_e: lightning::ln::script::InvalidShutdownScript) -> Self {
        MutinyError::InvalidArgumentsError
    }
}

impl From<ParseOrSemanticError> for MutinyError {
    fn from(_e: ParseOrSemanticError) -> Self {
        Self::InvoiceInvalid
    }
}

impl From<PeerHandleError> for MutinyError {
    fn from(_e: PeerHandleError) -> Self {
        // TODO handle the case where `no_connection_possible`
        Self::ConnectionFailed
    }
}

impl From<RetryableSendFailure> for MutinyError {
    fn from(s: RetryableSendFailure) -> Self {
        match s {
            RetryableSendFailure::PaymentExpired => Self::InvoiceExpired,
            RetryableSendFailure::RouteNotFound => Self::RoutingFailed,
            RetryableSendFailure::DuplicatePayment => Self::NonUniquePaymentHash,
            RetryableSendFailure::OnionPacketSizeExceeded => Self::PacketSizeExceeded,
        }
    }
}

impl From<GraphSyncError> for MutinyError {
    fn from(_e: GraphSyncError) -> Self {
        MutinyError::RapidGossipSyncError
    }
}

impl From<std::io::Error> for MutinyError {
    fn from(e: std::io::Error) -> Self {
        MutinyError::PersistenceFailed {
            source: MutinyStorageError::Other(e.into()),
        }
    }
}

impl From<serde_json::Error> for MutinyError {
    fn from(_: serde_json::Error) -> Self {
        Self::ReadError {
            source: MutinyStorageError::Other(anyhow::anyhow!("Failed to deserialize")),
        }
    }
}

impl<G> From<std::sync::PoisonError<G>> for MutinyStorageError {
    fn from(_e: std::sync::PoisonError<G>) -> Self {
        MutinyStorageError::LockError
    }
}

impl<G> From<std::sync::TryLockError<G>> for MutinyError {
    fn from(_e: std::sync::TryLockError<G>) -> Self {
        MutinyStorageError::LockError.into()
    }
}

impl<G> From<std::sync::TryLockError<G>> for MutinyStorageError {
    fn from(_e: std::sync::TryLockError<G>) -> Self {
        MutinyStorageError::LockError
    }
}

// impl From<bitcoin::hashes::hex::Error> for MutinyError {
//     fn from(_e: bitcoin::hashes::hex::Error) -> Self {
//         MutinyError::ReadError {
//             source: MutinyStorageError::Other(anyhow::anyhow!("Failed to decode hex")),
//         }
//     }
// }

impl From<HexToArrayError> for MutinyError {
    fn from(value: HexToArrayError) -> Self {
        MutinyError::ReadError {
            source: MutinyStorageError::Other(anyhow::anyhow!(value)),
        }
    }
}

// impl From<bitcoin::address::Error> for MutinyError {
//     fn from(e: bitcoin::address::Error) -> Self {
//         match e {
//             bitcoin::address::Error::NetworkValidation { .. } => MutinyError::IncorrectNetwork,
//             bitcoin::address::Error::UnrecognizedScript => MutinyError::InvalidArgumentsError,
//             bitcoin::address::Error::UnknownAddressType(_) => MutinyError::InvalidArgumentsError,
//             _ => MutinyError::ReadError {
//                 source: MutinyStorageError::Other(anyhow::anyhow!("Failed to decode address")),
//             },
//         }
//     }
// }

impl From<esplora_client::Error> for MutinyError {
    fn from(_e: esplora_client::Error) -> Self {
        // This is most likely a chain access failure
        Self::ChainAccessFailed
    }
}

impl From<Box<esplora_client::Error>> for MutinyError {
    fn from(_e: Box<esplora_client::Error>) -> Self {
        // This is most likely a chain access failure
        Self::ChainAccessFailed
    }
}

// impl From<bdk_wallet::InsertTxError> for MutinyError {
//     fn from(_e: bdk_wallet::InsertTxError) -> Self {
//         Self::WalletSyncError
//     }
// }

impl From<bdk_wallet::error::CreateTxError> for MutinyError {
    fn from(_e: bdk_wallet::error::CreateTxError) -> Self {
        Self::WalletOperationFailed
    }
}

impl From<BuildFeeBumpError> for MutinyError {
    fn from(e: BuildFeeBumpError) -> Self {
        match e {
            BuildFeeBumpError::UnknownUtxo(_) => Self::NotFound,
            BuildFeeBumpError::TransactionNotFound(_) => Self::NotFound,
            BuildFeeBumpError::TransactionConfirmed(_) => Self::NotFound,
            BuildFeeBumpError::IrreplaceableTransaction(_) => Self::InvalidArgumentsError,
            BuildFeeBumpError::FeeRateUnavailable => Self::WalletOperationFailed,
        }
    }
}

impl From<SignerError> for MutinyError {
    fn from(_: SignerError) -> Self {
        Self::WalletOperationFailed
    }
}

impl From<anyhow::Error> for MutinyError {
    fn from(e: anyhow::Error) -> Self {
        error!("Got unhandled error: {e}");
        // handle fedimint anyhow errors
        match e.to_string().as_str() {
            "Insufficient balance" => Self::InsufficientBalance,
            "MissingInvoiceAmount" => Self::BadAmountError,
            _str => Self::Other(e),
        }
    }
}
