use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents the long-term identity of a peer in the network.
/// We use Ed25519 because it's fast, secure, and widely standardized for digital signatures.
#[derive(Clone)]
pub struct Identity {
    pub(crate) keypair: SigningKey,
}

/// The public half of the identity, used by other peers to verify signatures.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKey({}..{})",
            hex::encode(&self.0[..4]),
            hex::encode(&self.0[28..])
        )
    }
}

impl Identity {
    /// Generates a new random Ed25519 identity using a secure OS RNG.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let keypair = SigningKey::generate(&mut csprng);
        Self { keypair }
    }

    /// Reconstructs an identity from a 32-byte secret seed.
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        let keypair = SigningKey::from_bytes(secret);
        Self { keypair }
    }

    /// Converts the private signing key back to its 32-byte seed for secure storage.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.keypair.to_bytes()
    }

    /// Returns the public key associated with this identity.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.keypair.verifying_key().to_bytes())
    }

    /// Signs an arbitrary message using the private key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keypair.sign(message)
    }
}

impl PublicKey {
    /// Verifies that a message was signed by the owner of this public key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        if let Ok(vk) = VerifyingKey::from_bytes(&self.0) {
            vk.verify(message, signature).is_ok()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation_and_signing() {
        let identity = Identity::generate();
        let pub_key = identity.public_key();

        let message = b"hello world";
        let signature = identity.sign(message);

        assert!(pub_key.verify(message, &signature));
        assert!(!pub_key.verify(b"wrong message", &signature));
    }

    #[test]
    fn test_identity_serialization() {
        let identity = Identity::generate();
        let bytes = identity.to_bytes();
        let restored = Identity::from_bytes(&bytes);

        assert_eq!(identity.public_key().0, restored.public_key().0);
    }
}
