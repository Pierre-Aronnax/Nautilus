// ======================= Public Key Infrastructure (PKI) =======================
// identity\src\pki\spincs_keypair.rs

#[cfg(feature = "spincs")]
use crate::{PKIError, PKITraits};
#[cfg(feature = "spincs")]
use fips205::slh_dsa_shake_256s::{self, PrivateKey, PublicKey};
#[cfg(feature = "spincs")]
use fips205::traits::{SerDes, Signer, Verifier};

// ======================= SPHINCS+ Key Pair Definition =======================
#[cfg(feature = "spincs")]
#[deprecated(since = "1.0.0", note = "SPHINCS+ is under beta testing and may be unstable. Use at your own risk.")]
#[derive(Clone)]
pub struct SPHINCSKeyPair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}

// ======================= PKITraits Implementation =======================
#[cfg(feature = "spincs")]
impl PKITraits for SPHINCSKeyPair {
    type KeyPair = Self;
    type Error = PKIError;

    /// Generates a new SPHINCS+ key pair.
    fn generate_key_pair() -> Result<Self::KeyPair, Self::Error> {
        let (public_key, private_key) = slh_dsa_shake_256s::try_keygen()
            .map_err(|e| PKIError::KeyPairGenerationError(format!("Key generation failed: {}", e)))?;

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Signs data using the private key.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let signature = self
            .private_key
            .try_sign(data, &[], false)
            .map_err(|e| PKIError::SigningError(format!("Signing failed: {}", e)))?;

        Ok(signature.to_vec())
    }

    /// Verifies a signature using the public key.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        let signature_array: [u8; slh_dsa_shake_256s::SIG_LEN] = signature
            .try_into()
            .map_err(|_| PKIError::VerificationError("Invalid signature length".to_string()))?;

        let is_valid = self.public_key.verify(data, &signature_array, &[]);
        Ok(is_valid)
    }

    /// Retrieves the public key from the key pair.
    fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        self.public_key.clone().into_bytes().to_vec()
    }

    /// Retrieves the key type.
    fn key_type() -> String {
        "SPHINCS+".to_string()
    }
}

// ======================= Future Enhancements =======================
// Additional features such as key serialization and deserialization can be implemented here if required.
