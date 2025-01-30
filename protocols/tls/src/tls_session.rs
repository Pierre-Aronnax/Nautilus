use tokio::net::{TcpStream, TcpListener};
use tokio::sync::Mutex; // <-- Use tokio's Mutex for TlsState
use std::sync::Arc;

use crate::{
    TlsConnection, 
    TlsState, 
    HelloStep, 
    HandshakeRole, 
    KyberExchangeStep, 
    FinishStep
};
use handshake::Handshake;
use nautilus_core::connection::Connection;
use std::time::Duration;
use tokio::time::timeout;

#[derive(Clone)]
pub struct TlsSession {
    pub connection: TlsConnection,
}

impl TlsSession {
    /// Create a new TlsSession in either Initiator or Responder role
    pub async fn new(
        socket: TcpStream,
        role: HandshakeRole,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Make sure we also use tokio::sync::Mutex for TlsState
        let state = Arc::new(Mutex::new(TlsState::default()));

        let mut handshake = Handshake::new("TLS_HANDSHAKE");
        let hello_step = HelloStep::new("TLS_HANDSHAKE", role);
        let kyber_step = KyberExchangeStep::new(role, state.clone());
        handshake.add_step(Box::new(hello_step));
        handshake.add_step(Box::new(kyber_step));
        handshake.add_step(Box::new(FinishStep { role }));

        // Build TlsConnection, which does the handshake
        let connection = TlsConnection::new(socket, handshake, state).await?;

        println!("[Session] Secure connection established for {:?}", role);
        Ok(Self { connection })
    }

    pub async fn send(&mut self, message: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.connection.send(message).await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        self.connection.receive().await.map_err(Into::into)
    }
    pub async fn get_session_key(&self) -> Vec<u8> {
        self.connection.get_session_key().await
    }
    pub async fn split(&self) -> (crate::connection::TlsReader, crate::connection::TlsWriter) {
        self.connection.split().await
    }
    
    
}

/// Optional: An “adaptive” approach that tries to accept first (Responder),
/// or else tries to connect (Initiator).
pub async fn adaptive_session(
    address: &str,
) -> Result<TlsSession, Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(address).await?;
    println!("[Adaptive Session] Listening on {}", address);

    // Wait up to 2 seconds for a client to connect
    let accept_future = listener.accept();

    match timeout(Duration::from_secs(2), accept_future).await {
        Ok(Ok((socket, _))) => {
            println!("[Adaptive Session] => Acting as Responder");
            TlsSession::new(socket, HandshakeRole::Responder).await
        }
        Ok(Err(e)) => {
            println!("[Adaptive Session] => accept error: {}", e);
            Err(Box::new(e))
        }
        Err(_) => {
            println!("[Adaptive Session] => Acting as Initiator");
            let socket = TcpStream::connect(address).await?;
            TlsSession::new(socket, HandshakeRole::Initiator).await
        }
    }
}
