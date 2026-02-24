//! High-level Node API for Yggdrasil stream connections.
//!
//! Mirrors the API of yggquic-new's `Node` (messenger.go) so Android apps
//! can use an identical mental model regardless of which transport they pick.
//!
//! # Design
//!
//! ```text
//!  App thread (blocking)
//!       │
//!  Node::connect() / listen() / accept()
//!       │  rt.block_on(...)
//!       ▼
//!  tokio Runtime (owned by Node)
//!       ├── ConnectHandle (Arc-cloned, &self connect / listen)
//!       └── Background accept loop per listen() port
//! ```
//!
//! The connect side and listen side are fully decoupled:
//! - Connect: cloneable `ConnectHandle` with `&self` — no blocking mutex.
//! - Listen: per-port `Listener` with exclusive ownership of its receiver.
//!
//! Internally delegates to [`AsyncNode`](crate::AsyncNode) and
//! [`AsyncConn`](crate::AsyncConn), adding only a `tokio::Runtime` and
//! `block_on()` calls for synchronous callers.

use std::sync::Arc;

use tokio::runtime::Runtime;

use crate::async_node::{AsyncConn, AsyncNode};
use crate::manager::{DatagramListener, Listener};

// ── Conn ─────────────────────────────────────────────────────────────────────

/// A single bidirectional stream to a remote Yggdrasil peer.
///
/// All I/O methods are **blocking** (suitable for calling from Java/Kotlin on Android).
/// Timeout variants accept milliseconds (`i64`; ≤ 0 means no timeout).
pub struct Conn {
    inner: AsyncConn,
    rt: Arc<Runtime>,
}

impl Conn {
    /// Remote peer's 32-byte ed25519 public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key()
    }

    /// The port this stream is on.
    pub fn port(&self) -> u16 {
        self.inner.port()
    }

    /// Returns `true` while the stream is open.
    pub fn is_alive(&self) -> bool {
        self.rt.block_on(self.inner.is_alive())
    }

    /// Blocking read. Fills `buf` and returns the number of bytes read.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        self.rt.block_on(self.inner.read(buf))
    }

    /// Blocking read with timeout (milliseconds). Returns `Err("timeout")` on expiry.
    pub fn read_with_timeout(&self, buf: &mut [u8], timeout_ms: i64) -> Result<usize, String> {
        self.rt
            .block_on(self.inner.read_with_timeout(buf, timeout_ms))
    }

    /// Blocking write. Returns the number of bytes written.
    pub fn write(&self, buf: &[u8]) -> Result<usize, String> {
        self.rt.block_on(self.inner.write(buf))
    }

    /// Blocking write with timeout (milliseconds). Returns `Err("timeout")` on expiry.
    pub fn write_with_timeout(&self, buf: &[u8], timeout_ms: i64) -> Result<usize, String> {
        self.rt
            .block_on(self.inner.write_with_timeout(buf, timeout_ms))
    }

    /// Close the stream gracefully.
    pub fn close(&self) {
        self.rt.block_on(self.inner.close());
    }
}

// ── Node ─────────────────────────────────────────────────────────────────

/// High-level Yggdrasil node — manages a full node and provides
/// simple connect / listen / accept / peer-management operations.
///
/// Mirrors yggquic-new's `Node` API for easy Android integration.
///
/// All methods are **blocking** (backed by an internal `tokio::Runtime`),
/// so they can be called directly from Java/Kotlin without any async plumbing.
pub struct Node {
    inner: AsyncNode,
    rt: Arc<Runtime>,
}

impl Node {
    // ── constructors ──────────────────────────────────────────────────────

    /// Create a new node with a randomly generated key and connect to `peer_addr`.
    ///
    /// `peer_addr` uses Yggdrasil URI syntax, e.g. `"tcp://1.2.3.4:1234"`.
    /// Pass an empty string to start a node without any initial peers.
    pub fn new(peer_addr: &str) -> Result<Self, String> {
        let rt = Arc::new(Runtime::new().map_err(|e| e.to_string())?);
        let inner = rt.block_on(AsyncNode::new(peer_addr))?;
        Ok(Self { inner, rt })
    }

    /// Create a node with a specific 32-byte signing key and a list of peers.
    pub fn new_with_key(signing_key_bytes: &[u8], peers: Vec<String>) -> Result<Self, String> {
        let rt = Arc::new(Runtime::new().map_err(|e| e.to_string())?);
        let inner = rt.block_on(AsyncNode::new_with_key(signing_key_bytes, peers))?;
        Ok(Self { inner, rt })
    }

    // ── identity ──────────────────────────────────────────────────────────

    /// Local node's 32-byte ed25519 public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key()
    }

    // ── connection API ────────────────────────────────────────────────────

    /// Open a stream to the remote peer on the given port.
    ///
    /// Reuses an existing ironwood session if one exists; otherwise establishes
    /// a new one. Blocks until the stream handshake completes (≤ 30 s default).
    pub fn connect(&self, public_key: &[u8], port: u16) -> Result<Conn, String> {
        let inner = self.rt.block_on(self.inner.connect(public_key, port))?;
        Ok(Conn {
            inner,
            rt: self.rt.clone(),
        })
    }

    /// Register a listener for the given port and block until an incoming stream arrives.
    ///
    /// This is a convenience that combines `listen` + single `accept`.
    pub fn accept(&self, port: u16) -> Result<Conn, String> {
        let inner = self.rt.block_on(self.inner.accept(port))?;
        Ok(Conn {
            inner,
            rt: self.rt.clone(),
        })
    }

    /// Register a listener and return a [`Listener`] for continuous accept.
    ///
    /// The returned `Listener` can be used in a loop to accept many streams.
    pub fn listen(&self, port: u16) -> Listener {
        self.rt.block_on(self.inner.listen(port))
    }

    // ── datagram API ──────────────────────────────────────────────────────

    /// Send a connectionless datagram to a peer on the given port.
    ///
    /// No handshake, no flow control, no ordering guarantees.
    pub fn send_datagram(&self, public_key: &[u8], port: u16, data: &[u8]) -> Result<(), String> {
        self.rt
            .block_on(self.inner.send_datagram(public_key, port, data))
    }

    /// Register a datagram listener for the given port.
    ///
    /// Returns a [`DatagramListener`] for continuous receive.
    pub fn listen_datagram(&self, port: u16) -> DatagramListener {
        self.rt.block_on(self.inner.listen_datagram(port))
    }

    /// Register a listener and block until one datagram arrives.
    ///
    /// Returns `(data, sender_public_key)`.
    pub fn recv_datagram(&self, port: u16) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.rt.block_on(self.inner.recv_datagram(port))
    }

    /// Block until a datagram arrives or the timeout expires.
    ///
    /// `timeout_ms ≤ 0` means no timeout.
    /// Returns `(data, sender_public_key)`.
    pub fn recv_datagram_with_timeout(
        &self,
        port: u16,
        timeout_ms: i64,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.rt
            .block_on(self.inner.recv_datagram_with_timeout(port, timeout_ms))
    }

    // ── peer management ───────────────────────────────────────────────────

    /// Add a peer by URI (e.g. `"tcp://1.2.3.4:1234"` or `"tls://…"`).
    pub fn add_peer(&self, addr: &str) -> Result<(), String> {
        self.rt.block_on(self.inner.add_peer(addr))
    }

    /// Remove a peer by URI.
    pub fn remove_peer(&self, addr: &str) -> Result<(), String> {
        self.rt.block_on(self.inner.remove_peer(addr))
    }

    /// Wake all sleeping peer reconnect loops so they retry immediately.
    pub fn retry_peers_now(&self) {
        self.rt.block_on(self.inner.retry_peers_now());
    }

    /// Force-close and remove a cached stream connection to the peer with the given 32-byte public key.
    pub fn close_connection(&self, public_key: &[u8]) {
        self.rt.block_on(self.inner.close_connection(public_key));
    }

    // ── network introspection ─────────────────────────────────────────────

    /// Peer list as a JSON array.
    ///
    /// Each element contains `key`, `address`, `uri`, `up`, `inbound`,
    /// `priority`, `rx_bytes`, `tx_bytes`, `rx_rate`, `tx_rate`, `uptime`.
    pub fn get_peers_json(&self) -> String {
        self.rt.block_on(self.inner.get_peers_json())
    }

    /// Cached routing paths as a JSON array.
    ///
    /// Each element contains `key`, `address`, `path` (port sequence), `sequence`.
    pub fn get_paths_json(&self) -> String {
        self.rt.block_on(self.inner.get_paths_json())
    }

    /// Spanning-tree entries as a JSON array.
    ///
    /// Each element contains `key`, `address`, `parent`, `sequence`.
    pub fn get_tree_json(&self) -> String {
        self.rt.block_on(self.inner.get_tree_json())
    }

    // ── lifecycle ─────────────────────────────────────────────────────────

    /// Shut down the node and all background tasks.
    pub fn close(&self) {
        self.rt.block_on(self.inner.close());
    }
}
