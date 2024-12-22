use crate::error::MutinyError;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::{ecdsa, All, Message, PublicKey, Secp256k1, SecretKey};

use std::str::FromStr;

#[derive(Clone)]
pub struct AuthManager {
    hashing_key: SecretKey,
    context: Secp256k1<All>,
}

impl AuthManager {
    pub fn new(xprivkey: Xpriv) -> Result<Self, MutinyError> {
        let context = Secp256k1::new();

        let joyid_master_path = DerivationPath::from_str("m/0'/0'")?;
        let joyid_master_x_key = xprivkey.derive_priv(&context, &joyid_master_path)?;

        let seed = joyid_master_x_key.private_key.secret_bytes();
        let joyid_master_key = Xpriv::new_master(xprivkey.network, &seed)?;

        let joyid_lightning_key_path = DerivationPath::from_str("m/0'")?;
        let joyid_lightning_key =
            joyid_master_key.derive_priv(&context, &joyid_lightning_key_path)?;
        let hashing_key = joyid_lightning_key.private_key;

        Ok(Self {
            hashing_key,
            context,
        })
    }

    pub fn sign(
        &self,
        message_hash: &[u8; 32],
    ) -> Result<(ecdsa::Signature, PublicKey), MutinyError> {
        let pubkey = self.hashing_key.public_key(&self.context);
        let msg = Message::from_digest_slice(message_hash).expect("32 bytes, guaranteed by type");
        let sig = self.context.sign_ecdsa(&msg, &self.hashing_key);
        Ok((sig, pubkey))
    }

    pub fn pubkey(&self) -> PublicKey {
        self.hashing_key.public_key(&self.context)
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
