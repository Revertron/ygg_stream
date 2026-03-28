//! UniFFI export layer for ygg_stream (TCP/KEY).

use std::sync::{Arc, Once};
use tokio::sync::broadcast::error::RecvError;
use crate::node::{Conn, Node};

fn init_tracing(filter: &str) {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::EnvFilter;

        let filter = if filter.is_empty() { "info" } else { filter };
        let env_filter = EnvFilter::new(filter);

        #[cfg(target_os = "android")]
        {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_android::layer("ygg_stream").unwrap())
                .init();
        }
        #[cfg(not(target_os = "android"))]
        {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer())
                .init();
        }
    });
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum YggError {
    #[error("{0}")]
    Generic(String),
}

impl From<String> for YggError {
    fn from(s: String) -> Self {
        YggError::Generic(s)
    }
}

#[derive(uniffi::Record)]
pub struct FfiDatagram {
    pub data: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(uniffi::Object)]
pub struct FfiNode {
    node: Node,
}

#[uniffi::export]
impl FfiNode {
    #[uniffi::constructor]
    pub fn new_(peer_addr: String, log_filter: String) -> Result<Arc<FfiNode>, YggError> {
        init_tracing(&log_filter);
        Node::new(&peer_addr)
            .map(|m| Arc::new(FfiNode { node: m }))
            .map_err(YggError::Generic)
    }

    #[uniffi::constructor]
    pub fn new_with_key(key_bytes: Vec<u8>, peers: Vec<String>, log_filter: String) -> Result<Arc<FfiNode>, YggError> {
        init_tracing(&log_filter);
        Node::new_with_key(&key_bytes, peers)
            .map(|m| Arc::new(FfiNode { node: m }))
            .map_err(YggError::Generic)
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.node.public_key()
    }

    pub fn connect(&self, public_key: Vec<u8>, port: u16) -> Result<Arc<FfiConn>, YggError> {
        self.node
            .connect(&public_key, port)
            .map(|c| Arc::new(FfiConn(c)))
            .map_err(YggError::Generic)
    }

    pub fn accept(&self, port: u16) -> Result<Arc<FfiConn>, YggError> {
        self.node
            .accept(port)
            .map(|c| Arc::new(FfiConn(c)))
            .map_err(YggError::Generic)
    }

    pub fn add_peer(&self, addr: String) -> Result<(), YggError> {
        self.node.add_peer(&addr).map_err(YggError::Generic)
    }

    pub fn remove_peer(&self, addr: String) -> Result<(), YggError> {
        self.node.remove_peer(&addr).map_err(YggError::Generic)
    }

    pub fn retry_peers_now(&self) {
        self.node.retry_peers_now();
    }

    pub fn close_connection(&self, public_key: Vec<u8>) {
        self.node.close_connection(&public_key);
    }

    pub fn get_peers_json(&self) -> String {
        self.node.get_peers_json()
    }

    pub fn get_paths_json(&self) -> String {
        self.node.get_paths_json()
    }

    pub fn get_tree_json(&self) -> String {
        self.node.get_tree_json()
    }

    pub fn send_datagram(&self, public_key: Vec<u8>, port: u16, data: Vec<u8>) -> Result<(), YggError> {
        self.node
            .send_datagram(&public_key, port, &data)
            .map_err(YggError::Generic)
    }

    pub fn recv_datagram(&self, port: u16) -> Result<FfiDatagram, YggError> {
        let (data, public_key) = self
            .node
            .recv_datagram(port)
            .map_err(YggError::Generic)?;
        Ok(FfiDatagram { data, public_key })
    }

    pub fn recv_datagram_with_timeout(&self, port: u16, timeout_ms: i64) -> Result<FfiDatagram, YggError> {
        let (data, public_key) = self
            .node
            .recv_datagram_with_timeout(port, timeout_ms)
            .map_err(YggError::Generic)?;
        Ok(FfiDatagram { data, public_key })
    }

    pub fn wait_peer_change(&self, timeout_ms: i64) -> Result<String, YggError> {
        self.node.rt.block_on(async {
            let mut rx = self.node.inner.subscribe_peer_events();
            let event = if timeout_ms > 0 {
                let dur = std::time::Duration::from_millis(timeout_ms as u64);
                match tokio::time::timeout(dur, rx.recv()).await {
                    Ok(data) => data,
                    Err(_) => return Ok(self.node.inner.get_peers_json().await),
                }
            } else {
                rx.recv().await
            };
            match event {
                Ok(_) | Err(RecvError::Lagged(_)) => Ok(self.node.inner.get_peers_json().await),
                Err(e) => Err(e.to_string()),
            }
        })
        .map_err(YggError::Generic)
    }
}

impl Drop for FfiNode {
    fn drop(&mut self) {
        self.node.close();
    }
}

#[derive(uniffi::Object)]
pub struct FfiConn(Conn);

#[uniffi::export]
impl FfiConn {
    pub fn public_key(&self) -> Vec<u8> {
        self.0.public_key()
    }

    pub fn port(&self) -> u16 {
        self.0.port()
    }

    pub fn is_alive(&self) -> bool {
        self.0.is_alive()
    }

    pub fn read_with_timeout(&self, max_bytes: u64, timeout_ms: i64) -> Result<Vec<u8>, YggError> {
        let mut buf = vec![0u8; max_bytes as usize];
        let n = if timeout_ms <= 0 {
            self.0.read(&mut buf).map_err(YggError::Generic)?
        } else {
            self.0
                .read_with_timeout(&mut buf, timeout_ms)
                .map_err(YggError::Generic)?
        };
        Ok(buf[..n].to_vec())
    }

    pub fn write_with_timeout(&self, data: Vec<u8>, timeout_ms: i64) -> Result<u64, YggError> {
        self.0
            .write_with_timeout(&data, timeout_ms)
            .map(|n| n as u64)
            .map_err(YggError::Generic)
    }

    pub fn write(&self, data: Vec<u8>) -> Result<u64, YggError> {
        self.0
            .write(&data)
            .map(|n| n as u64)
            .map_err(YggError::Generic)
    }
}

impl Drop for FfiConn {
    fn drop(&mut self) {
        self.0.close();
    }
}
