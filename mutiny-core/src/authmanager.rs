use crate::error::MutinyError;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::{ecdsa, All, Message, PublicKey, Secp256k1, SecretKey};

use std::str::FromStr;

#[derive(Clone)]
pub struct AuthManager {
    hashing_key: SecretKey,
    _xprivkey: Xpriv,
    context: Secp256k1<All>,
}

impl AuthManager {
    pub fn new(xprivkey: Xpriv) -> Result<Self, MutinyError> {
        let context = Secp256k1::new();

        let base_path = DerivationPath::from_str("m/138'/0")?;
        let key = xprivkey.derive_priv(&context, &base_path)?;
        let hashing_key = key.private_key;

        Ok(Self {
            hashing_key,
            _xprivkey: xprivkey,
            context,
        })
    }

    pub fn sign(&self, k1: &[u8; 32]) -> Result<(ecdsa::Signature, PublicKey), MutinyError> {
        let pubkey = self.hashing_key.public_key(&self.context);
        let msg = Message::from_digest_slice(k1).expect("32 bytes, guaranteed by type");
        let sig = self.context.sign_ecdsa(&msg, &self.hashing_key);
        Ok((sig, pubkey))
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod test {
    use crate::test_utils::*;

    use super::*;

    #[tokio::test]
    async fn test_create_signature() {
        let test_name = "test_create_signature";
        log!("{}", test_name);

        let auth = create_manager();

        let k1 = [0; 32];

        let (sig, pk) = auth.sign(&k1).unwrap();

        auth.context
            .verify_ecdsa(&Message::from_digest_slice(&k1).unwrap(), &sig, &pk)
            .unwrap();
    }
}
