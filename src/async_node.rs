//! Async high-level Node API for Yggdrasil stream connections.
//!
//! [`AsyncNode`] and [`AsyncConn`] mirror the blocking [`Node`](crate::Node)
//! and [`Conn`](crate::Conn) API but use `async fn` instead of
//! `rt.block_on()`, so they can be used directly inside a tokio runtime
//! without risk of panics or nested blocking.
//!
//! # Example
//!
//! ```rust,ignore
//! use ygg_stream::AsyncNode;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), String> {
//!     let node = AsyncNode::new("tcp://1.2.3.4:1234").await?;
//!
//!     // Server side
//!     let conn = node.accept(80).await?;
//!
//!     // Client side
//!     let conn = node.connect(&peer_key, 80).await?;
//!
//!     let mut buf = vec![0u8; 1024];
//!     let n = conn.read(&mut buf).await?;
//!     conn.write(&buf[..n]).await?;
//!     conn.close().await;
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use yggdrasil::config::Config;
use yggdrasil::core::Core;

use crate::manager::{ConnectHandle, DatagramListener, Listener};
use crate::stream::Stream;
use crate::StreamManager;

// ── AsyncConn ────────────────────────────────────────────────────────────────

/// A single bidirectional stream to a remote Yggdrasil peer.
///
/// All I/O methods are **async** — suitable for use inside a tokio runtime.
/// This is the async counterpart of [`Conn`](crate::Conn).
pub struct AsyncConn {
    /// The underlying stream. All fields inside are `Arc`-wrapped, so
    /// `Stream::clone()` is cheap and the clones share state.  We clone
    /// into a local `&mut Stream` for each I/O call so that read and write
    /// can proceed concurrently without an outer mutex.
    stream: Stream,
    /// Remote peer's 32-byte ed25519 public key.
    public_key: Vec<u8>,
    /// The port this stream is on.
    port: u16,
}

impl AsyncConn {
    pub(crate) fn new(stream: Stream, public_key: Vec<u8>, port: u16) -> Self {
        Self {
            stream,
            public_key,
            port,
        }
    }

    /// Remote peer's 32-byte ed25519 public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// The port this stream is on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get a clone of the underlying [`Stream`].
    ///
    /// `Stream` is `Clone` and all internals are `Arc`-wrapped, so this is
    /// cheap.  The returned value implements `AsyncRead + AsyncWrite` and can
    /// be used directly with [`tokio::io::copy_bidirectional`].
    pub fn stream(&self) -> Stream {
        self.stream.clone()
    }

    /// Consume this `AsyncConn` and return the underlying [`Stream`].
    pub fn into_stream(self) -> Stream {
        self.stream
    }

    /// Returns `true` while the stream is open.
    pub async fn is_alive(&self) -> bool {
        matches!(
            self.stream.state().await,
            crate::StreamState::Open | crate::StreamState::Opening
        )
    }

    /// Read data into `buf`. Returns the number of bytes read.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut s = self.stream.clone();
        AsyncReadExt::read(&mut s, buf)
            .await
            .map_err(|e| e.to_string())
    }

    /// Read with timeout (milliseconds). Returns `Err("timeout")` on expiry.
    /// `timeout_ms ≤ 0` behaves like [`read`](Self::read).
    pub async fn read_with_timeout(
        &self,
        buf: &mut [u8],
        timeout_ms: i64,
    ) -> Result<usize, String> {
        if timeout_ms <= 0 {
            return self.read(buf).await;
        }
        let dur = Duration::from_millis(timeout_ms as u64);
        let mut s = self.stream.clone();
        tokio::time::timeout(dur, AsyncReadExt::read(&mut s, buf))
            .await
            .map_err(|_| "timeout".to_string())?
            .map_err(|e| e.to_string())
    }

    /// Write `buf` to the stream. Returns the number of bytes written.
    pub async fn write(&self, buf: &[u8]) -> Result<usize, String> {
        let mut s = self.stream.clone();
        AsyncWriteExt::write(&mut s, buf)
            .await
            .map_err(|e| e.to_string())
    }

    /// Write with timeout (milliseconds). Returns `Err("timeout")` on expiry.
    /// `timeout_ms ≤ 0` behaves like [`write`](Self::write).
    pub async fn write_with_timeout(
        &self,
        buf: &[u8],
        timeout_ms: i64,
    ) -> Result<usize, String> {
        if timeout_ms <= 0 {
            return self.write(buf).await;
        }
        let dur = Duration::from_millis(timeout_ms as u64);
        let mut s = self.stream.clone();
        tokio::time::timeout(dur, AsyncWriteExt::write(&mut s, buf))
            .await
            .map_err(|_| "timeout".to_string())?
            .map_err(|e| e.to_string())
    }

    /// Close the stream gracefully.
    pub async fn close(&self) {
        let mut s = self.stream.clone();
        let _ = s.shutdown().await;
    }
}

// ── AsyncNode ────────────────────────────────────────────────────────────────

/// High-level async Yggdrasil node — manages a full node and provides
/// simple connect / listen / accept / peer-management operations.
///
/// This is the async counterpart of [`Node`](crate::Node). It does **not**
/// own a tokio `Runtime` — it expects to be used from within one.
pub struct AsyncNode {
    core: Arc<Core>,
    handle: ConnectHandle,
    /// Persistent stream listeners, keyed by port.
    stream_listeners: Mutex<HashMap<u16, Listener>>,
    /// Persistent datagram listeners, keyed by port.
    datagram_listeners: Mutex<HashMap<u16, DatagramListener>>,
}

impl AsyncNode {
    // ── constructors ──────────────────────────────────────────────────────

    /// Create a new node with a randomly generated key and connect to `peer_addr`.
    ///
    /// `peer_addr` uses Yggdrasil URI syntax, e.g. `"tcp://1.2.3.4:1234"`.
    /// Pass an empty string to start a node without any initial peers.
    pub async fn new(peer_addr: &str) -> Result<Self, String> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut config = Config::default();
        if !peer_addr.is_empty() {
            config.peers = vec![peer_addr.to_string()];
        }
        Self::from_key_and_config(signing_key, config).await
    }

    /// Create a node with a specific 32-byte signing key and a list of peers.
    pub async fn new_with_key(signing_key_bytes: &[u8], peers: Vec<String>) -> Result<Self, String> {
        let bytes: [u8; 32] = signing_key_bytes
            .try_into()
            .map_err(|_| "signing key must be exactly 32 bytes".to_string())?;
        let signing_key = SigningKey::from_bytes(&bytes);
        let mut config = Config::default();
        config.peers = peers;
        Self::from_key_and_config(signing_key, config).await
    }

    async fn from_key_and_config(signing_key: SigningKey, config: Config) -> Result<Self, String> {
        let core = Core::new(signing_key, config);
        core.init_links().await;
        core.start().await;

        // Brief pause so TCP handshakes with bootstrap peers can begin.
        tokio::time::sleep(Duration::from_secs(1)).await;

        let manager = StreamManager::new(core.packet_conn());
        let handle = manager.split();

        Ok(Self {
            core,
            handle,
            stream_listeners: Mutex::new(HashMap::new()),
            datagram_listeners: Mutex::new(HashMap::new()),
        })
    }

    // ── identity ──────────────────────────────────────────────────────────

    /// Local node's 32-byte ed25519 public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.core.public_key().to_vec()
    }

    // ── connection API ────────────────────────────────────────────────────

    /// Open a stream to the remote peer on the given port.
    ///
    /// Reuses an existing ironwood session if one exists; otherwise establishes
    /// a new one.
    ///
    /// If the cached connection turns out to be stale (writer task dead),
    /// it is removed and a fresh connection is created automatically.
    pub async fn connect(&self, public_key: &[u8], port: u16) -> Result<AsyncConn, String> {
        if public_key.len() != 32 {
            return Err("public_key must be exactly 32 bytes".to_string());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(public_key);
        let addr = ironwood::Addr::from(key);

        let connection = self.handle.connect(addr).await.map_err(|e| e.to_string())?;
        match connection.open_stream(port).await {
            Ok(stream) => Ok(AsyncConn::new(stream, public_key.to_vec(), port)),
            Err(e) => {
                // Connection may be stale — close it and retry once with a fresh one.
                tracing::warn!(
                    "open_stream failed on cached connection to {:?}: {}, retrying with fresh connection",
                    hex::encode(&addr.as_ref()[..8]), e
                );
                self.handle.close_connection(addr).await;
                let connection = self.handle.connect(addr).await.map_err(|e| e.to_string())?;
                let stream = connection
                    .open_stream(port)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(AsyncConn::new(stream, public_key.to_vec(), port))
            }
        }
    }

    /// Await an incoming stream on the given port.
    ///
    /// Creates a listener on first call and reuses it for subsequent calls.
    pub async fn accept(&self, port: u16) -> Result<AsyncConn, String> {
        let mut listeners = self.stream_listeners.lock().await;
        let listener = if !listeners.contains_key(&port) {
            listeners.entry(port).or_insert(self.handle.listen(port).await)
        } else {
            listeners.get_mut(&port).unwrap()
        };
        let stream = listener.accept().await.map_err(|e| e.to_string())?;
        let public_key = stream.peer_addr().0.to_vec();
        Ok(AsyncConn::new(stream, public_key, port))
    }

    /// Register a listener and return a [`Listener`] for continuous accept.
    ///
    /// The returned `Listener` can be used in a loop to accept many streams.
    pub async fn listen(&self, port: u16) -> Listener {
        self.handle.listen(port).await
    }

    // ── datagram API ──────────────────────────────────────────────────────

    /// Send a connectionless datagram to a peer on the given port.
    ///
    /// No handshake, no flow control, no ordering guarantees.
    pub async fn send_datagram(&self,public_key: &[u8], port: u16, data: &[u8]) -> Result<(), String> {
        if public_key.len() != 32 {
            return Err("public_key must be exactly 32 bytes".to_string());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(public_key);
        let addr = ironwood::Addr::from(key);
        self.handle
            .send_datagram(&addr, port, data.to_vec())
            .await
            .map_err(|e| e.to_string())
    }

    /// Register a datagram listener for the given port.
    ///
    /// Returns a [`DatagramListener`] for continuous receive.
    pub async fn listen_datagram(&self, port: u16) -> DatagramListener {
        self.handle.listen_datagram(port).await
    }

    /// Await one datagram on the given port.
    ///
    /// Creates a listener on first call and reuses it for subsequent calls.
    /// Returns `(data, sender_public_key)`.
    pub async fn recv_datagram(&self, port: u16) -> Result<(Vec<u8>, Vec<u8>), String> {
        let mut listeners = self.datagram_listeners.lock().await;
        let listener = if !listeners.contains_key(&port) {
            listeners.entry(port).or_insert(self.handle.listen_datagram(port).await)
        } else {
            listeners.get_mut(&port).unwrap()
        };
        let (data, addr) = listener.recv().await.map_err(|e| e.to_string())?;
        Ok((data, addr.0.to_vec()))
    }

    /// Await one datagram on the given port with a timeout in milliseconds.
    ///
    /// Creates a listener on first call and reuses it for subsequent calls.
    /// Returns `(data, sender_public_key)`, or an error on timeout.
    pub async fn recv_datagram_with_timeout(&self,port: u16, timeout_ms: i64) -> Result<(Vec<u8>, Vec<u8>), String> {
        let mut listeners = self.datagram_listeners.lock().await;
        let listener = if !listeners.contains_key(&port) {
            listeners.entry(port).or_insert(self.handle.listen_datagram(port).await)
        } else {
            listeners.get_mut(&port).unwrap()
        };
        if timeout_ms <= 0 {
            let (data, addr) = listener.recv().await.map_err(|e| e.to_string())?;
            Ok((data, addr.0.to_vec()))
        } else {
            match tokio::time::timeout(
                Duration::from_millis(timeout_ms as u64),
                listener.recv(),
            )
            .await
            {
                Ok(Ok((data, addr))) => Ok((data, addr.0.to_vec())),
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Err("deadline exceeded".to_string()),
            }
        }
    }

    // ── peer management ───────────────────────────────────────────────────

    /// Add a peer by URI (e.g. `"tcp://1.2.3.4:1234"` or `"tls://…"`).
    pub async fn add_peer(&self, addr: &str) -> Result<(), String> {
        self.core.add_peer(addr).await
    }

    /// Remove a peer by URI.
    pub async fn remove_peer(&self, addr: &str) -> Result<(), String> {
        self.core.remove_peer(addr).await
    }

    /// Wake all sleeping peer reconnect loops so they retry immediately.
    pub async fn retry_peers_now(&self) {
        self.core.retry_peers_now().await;
    }

    /// Force-close and remove a cached stream connection to the peer
    /// with the given 32-byte public key.
    pub async fn close_connection(&self, public_key: &[u8]) {
        if public_key.len() != 32 {
            return;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(public_key);
        let addr = ironwood::Addr::from(key);
        self.handle.close_connection(addr).await;
    }

    // ── network introspection ─────────────────────────────────────────────

    /// Peer list as a JSON array.
    ///
    /// Each element contains `key`, `address`, `uri`, `up`, `inbound`,
    /// `priority`, `rx_bytes`, `tx_bytes`, `rx_rate`, `tx_rate`, `uptime`.
    pub async fn get_peers_json(&self) -> String {
        let peers = self.core.get_peers().await;
        let arr: Vec<serde_json::Value> = peers
            .iter()
            .map(|p| {
                let address = yggdrasil::address::addr_for_key(&p.key);
                serde_json::json!({
                    "key":      hex::encode(p.key),
                    "address":  address.to_string(),
                    "uri":      p.uri,
                    "up":       p.up,
                    "inbound":  p.inbound,
                    "priority": p.priority,
                    "latency":  p.latency_ms,
                    "cost":     p.cost,
                    "rx_bytes": p.rx_bytes,
                    "tx_bytes": p.tx_bytes,
                    "rx_rate":  p.rx_rate,
                    "tx_rate":  p.tx_rate,
                    "uptime":   p.uptime_secs,
                })
            })
            .collect();
        serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
    }

    /// Cached routing paths as a JSON array.
    ///
    /// Each element contains `key`, `address`, `path` (port sequence), `sequence`.
    pub async fn get_paths_json(&self) -> String {
        let paths = self.core.get_paths().await;
        let arr: Vec<serde_json::Value> = paths
            .iter()
            .map(|p| {
                let address = yggdrasil::address::addr_for_key(&p.key);
                serde_json::json!({
                    "key":      hex::encode(p.key),
                    "address":  address.to_string(),
                    "path":     p.path,
                    "sequence": p.sequence,
                })
            })
            .collect();
        serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
    }

    /// Spanning-tree entries as a JSON array.
    ///
    /// Each element contains `key`, `address`, `parent`, `sequence`.
    pub async fn get_tree_json(&self) -> String {
        let tree = self.core.get_tree().await;
        let arr: Vec<serde_json::Value> = tree
            .iter()
            .map(|t| {
                let address = yggdrasil::address::addr_for_key(&t.key);
                serde_json::json!({
                    "key":      hex::encode(t.key),
                    "address":  address.to_string(),
                    "parent":   hex::encode(t.parent),
                    "sequence": t.sequence,
                })
            })
            .collect();
        serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
    }

    // ── lifecycle ─────────────────────────────────────────────────────────

    /// Shut down the node and all background tasks.
    pub async fn close(&self) {
        let _ = self.core.close().await;
    }
}
