use crate::crypto::identity::Identity;
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

const APP_DIR: &str = "p2p-chat";
const KEY_FILE: &str = "identity.key";

pub struct KeyStore {
    key_path: PathBuf,
}

impl KeyStore {
    /// Initializes the keystore, returning the path to the key file.
    pub fn new() -> Result<Self> {
        let mut path = dirs::data_local_dir().context("Failed to find local data directory")?;
        path.push(APP_DIR);
        
        if !path.exists() {
            fs::create_dir_all(&path).context("Failed to create app data directory")?;
        }
        
        path.push(KEY_FILE);
        Ok(Self { key_path: path })
    }

    /// Loads the identity from the file, or generates a new one if it doesn't exist.
    pub fn load_or_generate(&self) -> Result<Identity> {
        if self.key_path.exists() {
            let bytes = fs::read(&self.key_path).context("Failed to read identity key file")?;
            if bytes.len() != 32 {
                anyhow::bail!("Invalid key file length: expected 32 bytes, got {}", bytes.len());
            }
            
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&bytes);
            Ok(Identity::from_bytes(&secret))
        } else {
            let identity = Identity::generate();
            self.save(&identity)?;
            Ok(identity)
        }
    }

    /// Saves the identity secret to disk.
    pub fn save(&self, identity: &Identity) -> Result<()> {
        let bytes = identity.to_bytes();
        fs::write(&self.key_path, bytes).context("Failed to write identity key file")?;
        
        // In a production app, we would also set restrictive file permissions here (e.g., chmod 600)
        // Since Rust standard library's fs permissions are platform-specific and we're targeting Windows+Linux,
        // we'd use `std::os::unix::fs::PermissionsExt` conditionally for Linux.
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&self.key_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&self.key_path, perms)?;
        }

        Ok(())
    }
}
