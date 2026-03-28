//! Blocking wrappers for mobile FFI (Android/iOS).

use std::sync::Arc;
use tokio::runtime::Runtime;

use crate::async_node::{AsyncConn, AsyncNode};
use crate::manager::{DatagramListener, TcpListener};

// ── Conn ─────────────────────────────────────────────────────────────────────

/// A single bidirectional connection to a remote Yggdrasil peer (blocking API).
pub struct Conn {
    inner: AsyncConn,
    rt: Arc<Runtime>,
}

impl Conn {
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key()
    }

    pub fn port(&self) -> u16 {
        self.inner.port()
    }

    pub fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        self.rt.block_on(self.inner.read(buf))
    }

    pub fn read_with_timeout(&self, buf: &mut [u8], timeout_ms: i64) -> Result<usize, String> {
        self.rt.block_on(self.inner.read_with_timeout(buf, timeout_ms))
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, String> {
        self.rt.block_on(self.inner.write(buf))
    }

    pub fn write_with_timeout(&self, buf: &[u8], timeout_ms: i64) -> Result<usize, String> {
        self.rt.block_on(self.inner.write_with_timeout(buf, timeout_ms))
    }

    pub fn close(&self) {
        self.rt.block_on(self.inner.close());
    }
}

// ── Node ─────────────────────────────────────────────────────────────────

/// High-level Yggdrasil node (blocking API for mobile).
pub struct Node {
    pub(crate) inner: Arc<AsyncNode>,
    pub(crate) rt: Arc<Runtime>,
}

impl Node {
    pub fn new(peer_addr: &str) -> Result<Self, String> {
        let rt = Arc::new(Runtime::new().map_err(|e| e.to_string())?);
        let inner = rt.block_on(AsyncNode::new(peer_addr))?;
        Ok(Self {
            inner: Arc::new(inner),
            rt,
        })
    }

    pub fn new_with_key(signing_key_bytes: &[u8], peers: Vec<String>) -> Result<Self, String> {
        let rt = Arc::new(Runtime::new().map_err(|e| e.to_string())?);
        let inner = rt.block_on(AsyncNode::new_with_key(signing_key_bytes, peers))?;
        Ok(Self {
            inner: Arc::new(inner),
            rt,
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key()
    }

    pub fn connect(&self, public_key: &[u8], port: u16) -> Result<Conn, String> {
        let inner = self.rt.block_on(self.inner.connect(public_key, port))?;
        Ok(Conn {
            inner,
            rt: self.rt.clone(),
        })
    }

    pub fn accept(&self, port: u16) -> Result<Conn, String> {
        let inner = self.rt.block_on(self.inner.accept(port))?;
        Ok(Conn {
            inner,
            rt: self.rt.clone(),
        })
    }

    pub fn listen(&self, port: u16) -> TcpListener {
        self.rt.block_on(self.inner.listen(port))
    }

    pub fn send_datagram(&self, public_key: &[u8], port: u16, data: &[u8]) -> Result<(), String> {
        self.rt.block_on(self.inner.send_datagram(public_key, port, data))
    }

    pub fn listen_datagram(&self, port: u16) -> DatagramListener {
        self.rt.block_on(self.inner.listen_datagram(port))
    }

    pub fn recv_datagram(&self, port: u16) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.rt.block_on(self.inner.recv_datagram(port))
    }

    pub fn recv_datagram_with_timeout(&self, port: u16, timeout_ms: i64) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.rt.block_on(self.inner.recv_datagram_with_timeout(port, timeout_ms))
    }

    pub fn add_peer(&self, addr: &str) -> Result<(), String> {
        self.rt.block_on(self.inner.add_peer(addr))
    }

    pub fn remove_peer(&self, addr: &str) -> Result<(), String> {
        self.rt.block_on(self.inner.remove_peer(addr))
    }

    pub fn retry_peers_now(&self) {
        self.rt.block_on(self.inner.retry_peers_now());
    }

    pub fn close_connection(&self, public_key: &[u8]) {
        self.rt.block_on(self.inner.close_connection(public_key));
    }

    pub fn get_peers_json(&self) -> String {
        self.rt.block_on(self.inner.get_peers_json())
    }

    pub fn get_paths_json(&self) -> String {
        self.rt.block_on(self.inner.get_paths_json())
    }

    pub fn get_tree_json(&self) -> String {
        self.rt.block_on(self.inner.get_tree_json())
    }

    pub fn close(&self) {
        self.rt.block_on(self.inner.close());
    }
}
