use std::sync::Arc;
use tokio::sync::Mutex;
use log::{info, error};
use sha2::{Sha256, Digest};
use bech32::{ToBase32, Variant};
use rand::Rng;

pub struct CryptoService {
    public_key: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
    address: Option<String>,
    initialized: bool,
}

impl CryptoService {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            public_key: None,
            private_key: None,
            address: None,
            initialized: false,
        })
    }

    pub async fn initialize(&mut self) -> Result<(), String> {
        if self.initialized {
            return Err("Crypto service is already initialized".to_string());
        }

        info!("Initializing crypto service");

        // Generate a simple random keypair for now
        let mut rng = rand::thread_rng();
        let private_key: [u8; 32] = rng.gen();
        let public_key: [u8; 32] = rng.gen();

        // Store keys
        self.public_key = Some(public_key.to_vec());
        self.private_key = Some(private_key.to_vec());

        // Generate address from public key
        self.address = Some(self.generate_address()?);

        self.initialized = true;
        info!("Crypto service initialized successfully");
        Ok(())
    }

    fn generate_address(&self) -> Result<String, String> {
        let public_key = self.public_key.as_ref()
            .ok_or("Public key not available")?;

        // Hash the public key with SHA256
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash = hasher.finalize();

        // Take first 20 bytes for address
        let payload = &hash[..20];

        // Encode as Bech32m with synv1 prefix (for validators)
        bech32::encode("synv1", payload.to_base32(), Variant::Bech32m)
            .map_err(|e| format!("Failed to encode address: {}", e))
    }

    pub fn get_public_key(&self) -> Option<&[u8]> {
        self.public_key.as_deref()
    }

    pub fn get_address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let private_key = self.private_key.as_ref()
            .ok_or("Private key not available")?;

        // Simple signature for now - just return a hash of message + private key
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.update(private_key);
        let signature = hasher.finalize();

        Ok(signature.to_vec())
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, String> {
        let public_key = self.public_key.as_ref()
            .ok_or("Public key not available")?;

        // Simple verification - rehash and compare
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.update(public_key);
        let expected_signature = hasher.finalize();

        Ok(expected_signature.as_slice() == signature)
    }
}