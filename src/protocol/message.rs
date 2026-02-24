use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use serde::{Deserialize, Serialize};

/// Encapsulates an end-to-end encrypted chat message.
/// The `ciphertext` contains the actual message content, authenticated
/// via Poly1305 MAC tag natively appended by ChaCha20-Poly1305.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedMessage {
    /// Incremental or random nonce to prevent replay attacks and ensure unique keystream.
    pub nonce: [u8; 12],
    
    /// The AES-GCM or ChaCha20-Poly1305 ciphertext.
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    /// Encrypts an arbitrary payload using a 32-byte symmetric key.
    /// The `associated_data` is authenticated but NOT encrypted (e.g., sender identity).
    pub fn encrypt(
        key: &[u8; 32],
        nonce_bytes: &[u8; 12],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Self> {
        let cipher_key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(cipher_key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad: associated_data,
        };

        // The MAC tag is automatically appended to the ciphertext.
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        Ok(Self {
            nonce: *nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypts the message using the shared symmetric key.
    /// Fails if the ciphertext was tampered with or if `associated_data` doesn't match.
    pub fn decrypt(
        &self,
        key: &[u8; 32],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher_key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(cipher_key);
        let nonce = Nonce::from_slice(&self.nonce);

        let payload = Payload {
            msg: &self.ciphertext,
            aad: associated_data,
        };

        cipher
            .decrypt(nonce, payload)
            .map_err(|e| anyhow!("Decryption/Authentication failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_and_decryption() {
        let key = [42u8; 32];
        let nonce = [7u8; 12];
        let message = b"secret chat message";
        let aad = b"sender-pk"; // E.g., authenticating the sender's public key

        let encrypted = EncryptedMessage::encrypt(&key, &nonce, message, aad).unwrap();
        
        let decrypted = encrypted.decrypt(&key, aad).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_decryption_fails_with_wrong_aad() {
        let key = [42u8; 32];
        let nonce = [7u8; 12];
        let message = b"secret chat message";
        let aad1 = b"sender-pk-1";
        let aad2 = b"sender-pk-2";

        let encrypted = EncryptedMessage::encrypt(&key, &nonce, message, aad1).unwrap();
        
        assert!(encrypted.decrypt(&key, aad2).is_err());
    }

    #[test]
    fn test_decryption_fails_with_tampered_ciphertext() {
        let key = [42u8; 32];
        let nonce = [7u8; 12];
        let message = b"secret chat message";
        let aad = b"sender-pk";

        let mut encrypted = EncryptedMessage::encrypt(&key, &nonce, message, aad).unwrap();
        
        // Flip a bit in the ciphertext
        let len = encrypted.ciphertext.len();
        encrypted.ciphertext[len - 1] ^= 0x01;
        
        assert!(encrypted.decrypt(&key, aad).is_err());
    }
}
