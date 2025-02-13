// py\python_ffi\src\lib.rs
use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use identity::{PKITraits,DilithiumKeyPair};


#[pyclass]
pub struct PyDilithiumKeyPair {
    keypair: DilithiumKeyPair,
}

#[pymethods]
impl PyDilithiumKeyPair {
    #[new]
    fn new() -> PyResult<Self> {
        let keypair = DilithiumKeyPair::generate_key_pair()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyDilithiumKeyPair { keypair })
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