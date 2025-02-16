// ======================= Public Key Infrastructure (PKI) =======================
// identity\src\pki\falcon_keypair.rs

#[cfg(feature = "falcon")]
use crate::{PKIError, PKITraits,KeySerialization};
#[cfg(feature = "falcon")]
use pqcrypto_falcon::falcon512::*;
#[cfg(feature = "falcon")]
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PublicKeyTrait,SecretKey as SecretKeyTrait};
// ======================= Falcon Key Pair Definition =======================
#[cfg(feature = "falcon")]
#[derive(Clone)]
pub struct FalconKeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

// ======================= PKITraits Implementation =======================
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
        let detached_signature = DetachedSignature::from_bytes(signature)
            .map_err(|_| PKIError::VerificationError("Invalid signature format".to_string()))?;

        verify_detached_signature(&detached_signature, data, &self.public_key)
            .map(|_| true)
            .map_err(|e| PKIError::VerificationError(format!("Verification failed: {}", e)))
    }

    /// Retrieves the public key from the key pair.
    fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        self.public_key.clone().as_bytes().to_vec()
    }

    /// Retrieves the key type.
    fn key_type() -> String {
        "Falcon".to_string()
    }
}
// ======================= Key Serialization Implmentation ====================
#[cfg(feature = "falcon")]
impl KeySerialization for FalconKeyPair {
    fn to_bytes(&self) -> Vec<u8> {
        let public_key_bytes = self.public_key.clone().as_bytes().to_vec();
        let private_key_bytes = self.secret_key.clone().as_bytes().to_vec();
        
        [public_key_bytes, private_key_bytes].concat()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, PKIError>
    where
        Self: Sized,
    {
        const PUBLIC_KEY_LEN: usize = 897;
        const PRIVATE_KEY_LEN: usize = 1281;
        const TOTAL_KEY_LEN: usize = PUBLIC_KEY_LEN + PRIVATE_KEY_LEN;

        if bytes.len() != TOTAL_KEY_LEN {
            return Err(PKIError::InvalidKey(format!(
                "Invalid Falcon key length. Expected {}, got {}",
                TOTAL_KEY_LEN,
                bytes.len()
            )));
        }

        let (public_key_bytes, private_key_bytes) = bytes.split_at(PUBLIC_KEY_LEN);

        let public_key = pqcrypto_falcon::falcon512::PublicKey::from_bytes(public_key_bytes)
            .map_err(|_| PKIError::InvalidKey("Invalid Falcon public key".to_string()))?;

        let secret_key = pqcrypto_falcon::falcon512::SecretKey::from_bytes(private_key_bytes)
            .map_err(|_| PKIError::InvalidKey("Invalid Falcon private key".to_string()))?;

        Ok(Self {
            public_key,
            secret_key,
        })
    }
}
// ================== Additional Methods ======================================
#[cfg(feature = "falcon")]
impl FalconKeyPair {
    pub fn private_key_raw_bytes(&self) -> Vec<u8> {
        SecretKey::as_bytes(&self.secret_key).to_vec()
    }
}
// ======================= Future Enhancements =================================
// Additional features such as key serialization and deserialization can be implemented here if required.
