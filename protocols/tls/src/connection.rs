use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use async_trait::async_trait;
use tokio::sync::Mutex;   // <-- Use tokio's Mutex for async
use std::sync::Arc;

use crate::record::{TlsRecord, RecordType, RecordError};
use crate::tls_state::TlsState;
use handshake::Handshake;
use nautilus_core::connection::Connection;

#[derive(Clone)]
pub struct TlsConnection {
    // Store TcpStream in Arc<Mutex<...>> so we can clone and share it.
    inner: Arc<Mutex<TcpStream>>,
    // Store TlsState in Arc<Mutex<...>> as well, using *tokio*'s Mutex.
    state: Arc<Mutex<TlsState>>,
}

pub struct TlsReader {
    inner: Arc<Mutex<TcpStream>>,
    state: Arc<Mutex<TlsState>>,
}

impl TlsReader {
    pub async fn receive(&mut self) -> Result<Vec<u8>, RecordError> {
        let session_key = {
            let st = self.state.lock().await;
            st.session_key().to_vec()
        };

        let mut locked_stream = self.inner.lock().await;
        let mut buf = vec![0u8; 4096];
        let n = locked_stream.read(&mut buf).await.map_err(|_| RecordError::ReadError)?;

        let mut record = TlsRecord::deserialize(&buf[..n])?;
        let payload = record.decrypt(&session_key)?;
        Ok(payload)
    }
}

pub struct TlsWriter {
    inner: Arc<Mutex<TcpStream>>,
    state: Arc<Mutex<TlsState>>,
}

impl TlsWriter {
    pub async fn send(&mut self, data: &[u8]) -> Result<(), RecordError> {
        let session_key = {
            let st = self.state.lock().await;
            st.session_key().to_vec()
        };

        let mut record = TlsRecord::new(RecordType::ApplicationData, data.to_vec());
        record.encrypt(&session_key)?;

        let mut locked_stream = self.inner.lock().await;
        locked_stream.write_all(&record.serialize()).await.map_err(|_| RecordError::WriteError)?;
        Ok(())
    }
}


impl TlsConnection {
    pub async fn new(
        mut raw_stream: TcpStream,
        mut handshake: Handshake,
        state: Arc<Mutex<TlsState>>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // 1. Perform the handshake
        handshake.execute(&mut raw_stream).await?;

        // 2. Mark handshake complete
        {
            // tokio::sync::Mutex never returns a poison error, so just .await:
            let mut st = state.lock().await;
            st.set_handshake_complete(true);
        }

        // 3. Wrap the final stream in Arc<Mutex<...>>
        let connection = Self {
            inner: Arc::new(Mutex::new(raw_stream)),
            state,
        };
        Ok(connection)
    }
    pub async fn get_session_key(&self) -> Vec<u8> {
        let st = self.state.lock().await;
        st.session_key().to_vec()
    }
    pub async fn split(&self) -> (TlsReader, TlsWriter) {
        let inner_clone = self.inner.clone();
        let state_clone = self.state.clone();

        let reader = TlsReader {
            inner: inner_clone.clone(),
            state: state_clone.clone(),
        };
        let writer = TlsWriter {
            inner: inner_clone,
            state: state_clone,
        };

        (reader, writer)
    }
}

#[async_trait]
impl Connection for TlsConnection {
    type Error = RecordError;

    async fn connect(&mut self, addr: &str) -> Result<(), Self::Error> {
        // Lock and replace the underlying stream
        let mut locked_stream = self.inner.lock().await;
        *locked_stream = TcpStream::connect(addr)
            .await
            .map_err(|_| RecordError::WriteError)?;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), Self::Error> {
        let mut locked_stream = self.inner.lock().await;
        locked_stream
            .shutdown()
            .await
            .map_err(|_| RecordError::WriteError)?;
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        // 1. Get session key
        let session_key = {
            let st = self.state.lock().await;
            st.session_key().to_vec()
        };

        // 2. Encrypt into TlsRecord
        let mut record = TlsRecord::new(RecordType::ApplicationData, data.to_vec());
        record.encrypt(&session_key)?;

        // 3. Lock stream and write
        let mut locked_stream = self.inner.lock().await;
        locked_stream
            .write_all(&record.serialize())
            .await
            .map_err(|_| RecordError::WriteError)?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
        // 1. Get session key
        let session_key = {
            let st = self.state.lock().await;
            st.session_key().to_vec()
        };

        // 2. Lock stream and read
        let mut locked_stream = self.inner.lock().await;
        let mut buf = vec![0u8; 4096];
        let n = locked_stream
            .read(&mut buf)
            .await
            .map_err(|_| RecordError::ReadError)?;

        // 3. Deserialize & decrypt
        let mut record = TlsRecord::deserialize(&buf[..n])?;
        let payload = record.decrypt(&session_key)?;
        Ok(payload)
    }

    fn is_connected(&self) -> bool {
        // This is a best-effort check
        if let Ok(locked_stream) = self.inner.try_lock() {
            locked_stream.peer_addr().is_ok()
        } else {
            // If we can't lock (someone else holds it), we assume connected
            true
        }
    }
}
