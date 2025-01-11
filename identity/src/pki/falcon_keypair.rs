// identity\src\pki\falcon_keypair.rs
#[cfg(feature="falcon")]
use crate::{PKIError, PKITraits}; 
#[cfg(feature="falcon")]
use pqcrypto_falcon::falcon512::*;
#[cfg(feature="falcon")]
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PublicKeyTrait};
#[cfg(feature="falcon")]
pub struct FalconKeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}
#[cfg(feature = "falcon")]
impl PKITraits for FalconKeyPair {
    type KeyPair = Self;
    type Error = PKIError;

    /// Generates a new Falcon key pair.
    fn generate_key_pair() -> Result<Self::KeyPair, Self::Error> {
        let (public_key, secret_key) = keypair();
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Signs data using the secret key.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let detached_signature = detached_sign(data, &self.secret_key);
        Ok(detached_signature.as_bytes().to_vec())
    }

    /// Verifies a signature using the public key.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        // Attempt to deserialize the signature
        let detached_signature = DetachedSignature::from_bytes(signature)
            .map_err(|_| PKIError::VerificationError("Invalid signature format".to_string()))?;

        // Verify the detached signature
        verify_detached_signature(&detached_signature, data, &self.public_key)
            .map(|_| true)
            .map_err(|e| PKIError::VerificationError(format!("Verification failed: {}", e)))
    }

    /// Retrieves the public key from the key pair.
    fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        // Assuming the public key is a fixed-size array, convert it to Vec<u8>
        self.public_key.clone().as_bytes().to_vec() // Convert array to Vec<u8>
    }

    /// Retrieves the key type.
    fn key_type() -> String {
        "Falcon".to_string()
    }
}
