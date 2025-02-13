use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use identity::PKITraits;
// Import identity crate key schemes based on feature flags
#[cfg(feature = "dilithium")]
use identity::DilithiumKeyPair;
#[cfg(feature = "ecdsa")]
use identity::ECDSAKeyPair;
#[cfg(feature = "ed25519")]
use identity::Ed25519KeyPair;
#[cfg(feature = "falcon")]
use identity::FalconKeyPair;
#[cfg(feature = "kyber")]
use identity::KyberKeyPair;
#[cfg(feature = "secp256k1")]
use identity::SECP256K1KeyPair;
#[cfg(feature = "pki_rsa")]
use identity::RSAkeyPair;
#[cfg(feature = "spincs")]
use identity::SPHINCSKeyPair;

#[pymodule]
fn python_ffi(m: &Bound<'_, PyModule>) -> PyResult<()> {
    #[cfg(feature = "dilithium")]
    m.add_class::<PyDilithiumKeyPair>()?;
    #[cfg(feature = "ecdsa")]
    m.add_class::<PyECDSAKeyPair>()?;
    #[cfg(feature = "ed25519")]
    m.add_class::<PyEd25519KeyPair>()?;
    #[cfg(feature = "falcon")]
    m.add_class::<PyFalconKeyPair>()?;
    #[cfg(feature = "kyber")]
    m.add_class::<PyKyberKeyPair>()?;
    #[cfg(feature = "secp256k1")]
    m.add_class::<PySECP256K1KeyPair>()?;
    #[cfg(feature = "pki_rsa")]
    m.add_class::<PyRSAKeyPair>()?;
    Ok(())
}

/// Macro to define Python classes for each keypair
macro_rules! define_keypair_class {
    ($struct_name:ident, $rust_type:ty, $feature_name:literal, $py_name:literal) => {
        #[cfg(feature = $feature_name)]
        #[pyclass(name = $py_name)]
        pub struct $struct_name {
            keypair: $rust_type,
        }

        #[cfg(feature = $feature_name)]
        #[pymethods]
        impl $struct_name {
            #[new]
            fn new() -> PyResult<Self> {
                let keypair = <$rust_type>::generate_key_pair()
                    .map_err(|e| PyValueError::new_err(e.to_string()))?;
                Ok(Self { keypair })
            }

            #[getter]
            fn public_key(&self) -> PyResult<Vec<u8>> {
                Ok(self.keypair.get_public_key_raw_bytes())
            }

            fn sign(&self, data: Vec<u8>) -> PyResult<Vec<u8>> {
                self.keypair.sign(&data).map_err(|e| PyValueError::new_err(e.to_string()))
            }

            fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> PyResult<bool> {
                self.keypair.verify(&data, &signature).map_err(|e| PyValueError::new_err(e.to_string()))
            }
        }
    };
}

// Define Python classes for each cryptographic algorithm
#[cfg(feature = "dilithium")]
define_keypair_class!(PyDilithiumKeyPair, DilithiumKeyPair, "dilithium", "DilithiumKeyPair");
#[cfg(feature = "ecdsa")]
define_keypair_class!(PyECDSAKeyPair, ECDSAKeyPair, "ecdsa", "ECDSAKeyPair");
#[cfg(feature = "ed25519")]
define_keypair_class!(PyEd25519KeyPair, Ed25519KeyPair, "ed25519", "Ed25519KeyPair");
#[cfg(feature = "falcon")]
define_keypair_class!(PyFalconKeyPair, FalconKeyPair, "falcon", "FalconKeyPair");
#[cfg(feature = "kyber")]
define_keypair_class!(PyKyberKeyPair, KyberKeyPair, "kyber", "KyberKeyPair");
#[cfg(feature = "secp256k1")]
define_keypair_class!(PySECP256K1KeyPair, SECP256K1KeyPair, "secp256k1", "SECP256K1KeyPair");
#[cfg(feature = "pki_rsa")]
define_keypair_class!(PyRSAKeyPair, RSAkeyPair, "pki_rsa", "RSAKeyPair");
#[cfg(feature = "spincs")]
define_keypair_class!(PySPHINCSKeyPair, SPHINCSKeyPair, "spincs", "SPHINCSKeyPair");