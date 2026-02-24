use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

/// Generates a new ephemeral X25519 keypair for a single session handshake.
pub fn generate_ephemeral_keypair() -> (EphemeralSecret, X25519PublicKey) {
    let mut csprng = OsRng;
    let secret = EphemeralSecret::random_from_rng(&mut csprng);
    let public = X25519PublicKey::from(&secret);
    (secret, public)
}

/// Computes the Diffie-Hellman shared secret and derives symmetric session keys using HKDF-SHA256.
///
/// * `my_secret`: Our ephemeral X25519 private key for this session.
/// * `their_public`: The remote peer's ephemeral X25519 public key.
/// * `is_initiator`: True if we initiated the connection (Alice), false if we accepted it (Bob).
///
/// Returns a tuple of `(tx_key, rx_key)` where `tx` is the key used to encrypt outgoing messages,
/// and `rx` is the key used to decrypt incoming messages.
pub fn derive_session_keys(
    my_secret: EphemeralSecret,
    their_public: &X25519PublicKey,
    is_initiator: bool,
) -> ([u8; 32], [u8; 32]) {
    // 1. Compute the Diffie-Hellman shared secret.
    let shared_secret = my_secret.diffie_hellman(their_public);

    // 2. Expand the shared secret using HKDF-SHA256 into two distinct keys.
    // By providing no salt and using the shared secret as IKM (Input Keying Material),
    // we derive 64 bytes of cryptographically strong key material.
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut okm = [0u8; 64]; // Output Keying Material

    // Use an application-specific info string to bind the key derivation context.
    hkdf.expand(b"p2p-chat-session-v1", &mut okm)
        .expect("HKDF expansion failed; this should never happen with valid length");

    let mut alice_to_bob = [0u8; 32];
    let mut bob_to_alice = [0u8; 32];

    alice_to_bob.copy_from_slice(&okm[0..32]);
    bob_to_alice.copy_from_slice(&okm[32..64]);

    // Ensure the two peers use symmetric keys properly:
    // The initiator (Alice) uses the first 32 bytes for tx, the second for rx.
    // The responder (Bob) uses the first 32 bytes for rx, the second for tx.
    if is_initiator {
        (alice_to_bob, bob_to_alice)
    } else {
        (bob_to_alice, alice_to_bob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_key_exchange_and_derivation() {
        // Alice generates her ephemeral keypair
        let (alice_secret, alice_public) = generate_ephemeral_keypair();

        // Bob generates his ephemeral keypair
        let (bob_secret, bob_public) = generate_ephemeral_keypair();

        // Alice computes keys (she is the initiator)
        let (alice_tx, alice_rx) = derive_session_keys(alice_secret, &bob_public, true);

        // Bob computes keys (he is the responder)
        let (bob_tx, bob_rx) = derive_session_keys(bob_secret, &alice_public, false);

        // Verification: Alice's TX key should be Bob's RX key, and vice versa.
        assert_eq!(alice_tx, bob_rx);
        assert_eq!(alice_rx, bob_tx);

        // Ensure TX and RX keys are distinct from each other.
        assert_ne!(alice_tx, alice_rx);
    }
}
