use async_trait::async_trait;
use futures::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rand::Rng;
use tokio::time::{sleep, Duration};
// ----- Import Handshake traits -----
use handshake::{HandshakeStream, HandshakeError, HandshakeStep};

// ----- Add Mutex + Arc if needed -----
use std::sync::{Arc, Mutex};

// ----- FIPS203 imports -----
use fips203::ml_kem_1024::{EncapsKey, /*DecapsKey,*/ KG, CipherText};
// Import SerDes to get `into_bytes()` and `try_from_bytes()`
use fips203::traits::{SerDes, KeyGen, Decaps, Encaps};

use crate::tls_state::TlsState;

// --------------------------------------------------------
// If you don’t actually use `DecapsKey`, remove or comment:
// use fips203::ml_kem_1024::DecapsKey;
// --------------------------------------------------------

// use sha3::{Sha3_256, Digest}; // remove or comment if not used

#[derive(Debug, Clone, Copy)]
pub enum HandshakeRole {
    Unknown,
    Initiator,
    Responder,
}

pub struct HelloStep {
    protocol_id: String,
    role: HandshakeRole,
}

impl HelloStep {
    pub fn new(protocol_id: &str, role: HandshakeRole) -> Self {
        Self {
            protocol_id: protocol_id.to_string(),
            role,
        }
    }
}
#[async_trait]
impl HandshakeStep for HelloStep {
    fn get_protocol_id(&self) -> &str {
        &self.protocol_id
    }

    fn set_protocol_id(&mut self, protocol_id: &str) {
        self.protocol_id = protocol_id.to_string();
    }

    fn execute<'a>(
        &'a mut self,
        stream: &'a mut dyn HandshakeStream,
        _input: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, HandshakeError>> {
        Box::pin(async move {
            match self.role {
                HandshakeRole::Unknown => {
                    println!("[Unknown] Determining role...");

                    let mut buf = [0u8; 5];
                    match tokio::time::timeout(std::time::Duration::from_secs(3), stream.read_exact(&mut buf)).await {
                        Ok(Ok(_)) if &buf == b"HELLO" => {
                            println!("[Unknown] Detected simultaneous HELLO. Backing off...");

                            // Introduce a randomized back-off before retrying
                            let delay = rand::thread_rng().gen_range(100..500); // Random delay in milliseconds
                            sleep(Duration::from_millis(delay)).await;

                            println!("[Unknown] Retrying role determination...");
                            self.role = HandshakeRole::Unknown;
                            self.execute(stream, vec![]).await
                        }
                        Err(_) => {
                            println!("[Unknown] Acting as Initiator (timeout)");
                            self.role = HandshakeRole::Initiator;
                            self.execute(stream, vec![]).await
                        }
                        Ok(Err(e)) => {
                            return Err(HandshakeError::Generic(format!("Error determining role: {e}")));
                        }
                        _ => Err(HandshakeError::Generic("Unknown role detection error".to_string())),
                    }
                }

                HandshakeRole::Initiator => {
                    println!("[Initiator] Sending HELLO");
            
                    let delay = rand::thread_rng().gen_range(100..500); // Random delay in milliseconds
                    sleep(Duration::from_millis(delay)).await;
            
                    stream.write_all(b"HELLO").await.map_err(|e| {
                        HandshakeError::Generic(format!("Failed to send HELLO: {e}"))
                    })?;
            
                    println!("[Initiator] Waiting for HELLO_ACK");
                    let mut buf = [0u8; 9];
                    stream.read_exact(&mut buf).await.map_err(|e| {
                        HandshakeError::Generic(format!("Failed to read HELLO_ACK: {e}"))
                    })?;
            
                    if &buf != b"HELLO_ACK" {
                        return Err(HandshakeError::Generic("Invalid HELLO_ACK response".to_string()));
                    }
                    println!("[Initiator] Received HELLO_ACK");
            
                    Ok(vec![])
                }

                HandshakeRole::Responder => {
                    println!("[Responder] Waiting for HELLO");
                    let mut buf = [0u8; 5];
                    stream.read_exact(&mut buf).await.map_err(|e| {
                        HandshakeError::Generic(format!("Failed to read HELLO: {e}"))
                    })?;

                    if &buf == b"HELLO" {
                        println!("[Responder] Detected simultaneous HELLO. Backing off...");
                        
                        // Randomized delay before retrying
                        let delay = rand::thread_rng().gen_range(100..500);
                        sleep(Duration::from_millis(delay)).await;
                        
                        println!("[Responder] Retrying role determination...");
                        self.role = HandshakeRole::Unknown;
                        self.execute(stream, vec![]).await
                    } else {
                        println!("[Responder] Received HELLO");

                        println!("[Responder] Sending HELLO_ACK");
                        stream.write_all(b"HELLO_ACK").await.map_err(|e| {
                            HandshakeError::Generic(format!("Failed to send HELLO_ACK: {e}"))
                        })?;

                        Ok(vec![])
                    }
                }
            }
        })
    }
}
pub struct CipherSuiteStep {
    protocol_id: String,
}

impl CipherSuiteStep {
    pub fn new(protocol_id: &str) -> Self {
        Self {
            protocol_id: protocol_id.to_string(),
        }
    }
}

#[async_trait]
impl HandshakeStep for CipherSuiteStep {
    fn get_protocol_id(&self) -> &str {
        &self.protocol_id
    }

    fn set_protocol_id(&mut self, protocol_id: &str) {
        self.protocol_id = protocol_id.to_string();
    }

    fn execute<'a>(
        &'a mut self,
        stream: &'a mut dyn HandshakeStream,
        input: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, HandshakeError>> {
        Box::pin(async move {
            // Send supported cipher suites
            stream.write_all(&input).await.map_err(|e| {
                HandshakeError::Generic(format!("Failed to send cipher suites: {}", e))
            })?;

            // Read the negotiated cipher suite
            let mut buf = vec![0; 1024];
            let n = stream.read(&mut buf).await.map_err(|e| {
                HandshakeError::Generic(format!("Failed to read cipher suite response: {}", e))
            })?;

            // Return the negotiated cipher suite
            Ok(buf[..n].to_vec())
        })
    }
}

// ---------------
// Kyber Exchange
// ---------------
pub struct KyberExchangeStep {
    role: HandshakeRole,
    /// Arc<Mutex<TlsState>> is used so we can .lock() TlsState
    state: Arc<Mutex<TlsState>>,
}

impl KyberExchangeStep {
    pub fn new(role: HandshakeRole, state: Arc<Mutex<TlsState>>) -> Self {
        Self { role, state }
    }
}

#[async_trait]
impl HandshakeStep for KyberExchangeStep {
    fn get_protocol_id(&self) -> &str {
        "TLS_HANDSHAKE"
    }

    fn set_protocol_id(&mut self, _protocol_id: &str) {}

    fn execute<'a>(
        &'a mut self,
        stream: &'a mut dyn HandshakeStream,
        _input: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, HandshakeError>> {
        Box::pin(async move {
            match self.role {
                HandshakeRole::Initiator => {
                    // Generate key pair
                    let (public_key, private_key) = KG::try_keygen().map_err(|e| {
                        HandshakeError::Generic(format!("Key generation failed: {}", e))
                    })?;

                    // Convert the public key to bytes using SerDes::into_bytes()
                    let pk_bytes = public_key.into_bytes();

                    // Send public key
                    println!("[Initiator] Sending public key");
                    stream.write_all(&pk_bytes).await.map_err(|e| {
                        HandshakeError::Generic(format!("Failed to send public key: {}", e))
                    })?;

                    // Receive ciphertext
                    println!("[Initiator] Waiting for ciphertext");
                    let mut buf = vec![0u8; 1600];
                    let n = stream.read(&mut buf).await.map_err(|e| {
                        HandshakeError::Generic(format!("Failed to read ciphertext: {}", e))
                    })?;

                    // Extract the ciphertext from the buffer
                    if n < 1568 {
                        return Err(HandshakeError::Generic(
                            "Ciphertext too small".to_string(),
                        ));
                    }

                    // Reconstruct the ciphertext using SerDes::try_from_bytes()
                    let ct_bytes: [u8; 1568] = buf[..1568].try_into().map_err(|_| {
                        HandshakeError::Generic("Invalid ciphertext size".to_string())
                    })?;
                    let ciphertext = CipherText::try_from_bytes(ct_bytes).map_err(|_| {
                        HandshakeError::Generic("Invalid ciphertext format".to_string())
                    })?;

                    // Decapsulate to derive shared key
                    let shared_key = private_key.try_decaps(&ciphertext).map_err(|e| {
                        HandshakeError::Generic(format!("Decapsulation failed: {}", e))
                    })?;

                    // Convert shared key to bytes
                    let sk_bytes = shared_key.into_bytes();
                    println!("Client Secret : {:?}",sk_bytes.to_vec());
                    // Update session key in TlsState
                    {
                        let mut guard = self.state.lock().map_err(|_| {
                            HandshakeError::Generic(
                                "Failed to lock state for session key update".to_string(),
                            )
                        })?;
                        guard.set_session_key(sk_bytes.to_vec());
                    }

                    println!("[Initiator] Shared key established");
                    Ok(vec![]) 
                }

                HandshakeRole::Responder => {
                    // Receive public key
                    println!("[Responder] Waiting for public key");
                    let mut buf = vec![0u8; 1568]; // Expected public key size for Kyber
                    stream.read_exact(&mut buf).await.map_err(|e| {
                        HandshakeError::Generic(format!("Failed to read public key: {}", e))
                    })?;

                    // Rebuild the public key using SerDes::try_from_bytes()
                    let pk_array: [u8; 1568] = buf.try_into().map_err(|_| {
                        HandshakeError::Generic("Invalid public key size".to_string())
                    })?;
                    let public_key = EncapsKey::try_from_bytes(pk_array).map_err(|_| {
                        HandshakeError::Generic("Invalid public key format".to_string())
                    })?;

                    // Encapsulate to derive shared key + ciphertext
                    let (shared_key, ciphertext) = public_key.try_encaps().map_err(|e| {
                        HandshakeError::Generic(format!("Encapsulation failed: {}", e))
                    })?;

                    // Convert ciphertext to bytes
                    let ct_bytes = ciphertext.into_bytes();

                    // Send ciphertext
                    println!("[Responder] Sending ciphertext");
                    stream.write_all(&ct_bytes).await.map_err(|e| {
                        HandshakeError::Generic(format!("Failed to send ciphertext: {}", e))
                    })?;

                    // Convert shared key to bytes
                    let sk_bytes = shared_key.into_bytes();
                    println!("Server Secret : {:?}",sk_bytes.to_vec());
                    println!("Key Length : {:?}",sk_bytes.to_vec().len());
                    // Update session key in TlsState
                    {
                        let mut guard = self.state.lock().map_err(|_| {
                            HandshakeError::Generic(
                                "Failed to lock state for session key update".to_string(),
                            )
                        })?;
                        guard.set_session_key(sk_bytes.to_vec());
                    }

                    println!("[Responder] Shared key established");
                    Ok(vec![])
                }
                HandshakeRole::Unknown => {
                    return Err(HandshakeError::Generic("Handshake role not set correctly".to_string()));
                }
            }
        })
    }
}


pub struct FinishStep {
    pub role: HandshakeRole,
}

#[async_trait]
impl HandshakeStep for FinishStep {
    fn get_protocol_id(&self) -> &str {
        "TLS_HANDSHAKE"
    }
    fn set_protocol_id(&mut self, _: &str) {}

    fn execute<'a>(
        &'a mut self,
        stream: &'a mut dyn HandshakeStream,
        input: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, HandshakeError>> {
        Box::pin(async move {
            match self.role {
                HandshakeRole::Initiator => {
                    // Send "HANDSHAKE_DONE"
                    stream.write_all(b"HANDSHAKE_DONE").await
                        .map_err(|e| HandshakeError::Generic(format!("FinishStep write: {e}")))?;
                    // Read "OK"
                    let mut buf = [0u8; 2];
                    stream.read_exact(&mut buf).await
                        .map_err(|e| HandshakeError::Generic(format!("FinishStep read: {e}")))?;
                    if &buf != b"OK" {
                        return Err(HandshakeError::Generic("FinishStep expected OK".into()));
                    }
                }
                HandshakeRole::Responder => {
                    // Responder reads "HANDSHAKE_DONE"
                    let mut buf = [0u8; 14];
                    stream.read_exact(&mut buf).await
                        .map_err(|e| HandshakeError::Generic(format!("FinishStep read: {e}")))?;
                    if &buf != b"HANDSHAKE_DONE" {
                        return Err(HandshakeError::Generic("FinishStep expected HANDSHAKE_DONE".into()));
                    }
                    // Writes "OK"
                    stream.write_all(b"OK").await
                        .map_err(|e| HandshakeError::Generic(format!("FinishStep write: {e}")))?;
                }
                HandshakeRole::Unknown => {
                    return Err(HandshakeError::Generic("FinishStep cannot proceed with Unknown role".to_string()));
                }
            }
            // Return the same input for consistency
            Ok(input)
        })
    }
}