use crate::crypto::{Identity, PublicKey};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey as X25519PublicKey;

/// The initial handshake packet sent by both peers immediately after the QUIC
/// connection is established. This payload must be signed by the sender's long-term
/// Ed25519 identity key to prevent Man-in-the-Middle (MitM) attacks on the
/// Diffie-Hellman exchange.
#[derive(Serialize, Deserialize, Debug)]
pub struct HandshakePayload {
    /// The long-term Ed25519 public key of the peer.
    pub identity_pub_key: PublicKey,
    
    /// The ephemeral X25519 public key generated for this session.
    pub ephemeral_pub_key: [u8; 32],
    
    /// Signature over the ephemeral public key to prove ownership.
    /// The signature must be created by the private key corresponding to `identity_pub_key`.
    pub signature: Signature,
}

impl HandshakePayload {
    /// Constructs a new signed handshake payload.
    pub fn new(identity: &Identity, ephemeral_pub: &X25519PublicKey) -> Self {
        let ephemeral_bytes = ephemeral_pub.to_bytes();
        
        // We sign the ephemeral public key bytes to prove we own the identity
        // and that we are intentionally binding it to this specific session's DH exchange.
        let signature = identity.sign(&ephemeral_bytes);
        
        Self {
            identity_pub_key: identity.public_key(),
            ephemeral_pub_key: ephemeral_bytes,
            signature,
        }
    }

    /// Verifies the cryptographic integrity of the handshake payload.
    /// Returns true if the signature is valid and corresponds to the provided identity.
    pub fn verify(&self) -> bool {
        self.identity_pub_key.verify(&self.ephemeral_pub_key, &self.signature)
    }

    /// Converts the raw byte array back into an X25519 dalek PublicKey for the DH derivation.
    pub fn get_ephemeral_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(self.ephemeral_pub_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::exchange::generate_ephemeral_keypair;

    #[test]
    fn test_handshake_payload_signing_and_verification() {
        let identity = Identity::generate();
        let (_secret, ephemeral_pub) = generate_ephemeral_keypair();

        let payload = HandshakePayload::new(&identity, &ephemeral_pub);

        // Verification should succeed
        assert!(payload.verify());

        // Tampering with the ephemeral key invalidates the payload
        let mut tampered = bincode::serialize(&payload).unwrap();
        // Modify a byte in the serialized payload (assuming it hits the ephemeral key)
        tampered[40] ^= 0x01; 
        
        if let Ok(bad_payload) = bincode::deserialize::<HandshakePayload>(&tampered) {
            assert!(!bad_payload.verify());
        }
    }
}
