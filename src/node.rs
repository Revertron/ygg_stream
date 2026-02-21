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

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;
use tokio::sync::Mutex as TokioMutex;

use yggdrasil::config::Config;
use yggdrasil::core::Core;

use crate::manager::{ConnectHandle, Listener};
use crate::stream::Stream;
use crate::StreamManager;

// ── Conn ─────────────────────────────────────────────────────────────────────

/// A single bidirectional stream to a remote Yggdrasil peer.
///
/// All I/O methods are **blocking** (suitable for calling from Java/Kotlin on Android).
/// Timeout variants accept milliseconds (`i64`; ≤ 0 means no timeout).
pub struct Conn {
    stream: Arc<TokioMutex<Stream>>,
    /// Remote peer's 32-byte ed25519 public key.
    public_key: Vec<u8>,
    /// The port this stream is on.
    port: u16,
    rt: Arc<Runtime>,
}

impl Conn {
    /// Remote peer's 32-byte ed25519 public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// The port this stream is on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns `true` while the stream is open.
    pub fn is_alive(&self) -> bool {
        self.rt.block_on(async {
            let s = self.stream.lock().await;
            matches!(s.state().await, crate::StreamState::Open | crate::StreamState::Opening)
        })
    }

    /// Blocking read. Fills `buf` and returns the number of bytes read.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        let stream = self.stream.clone();
        self.rt.block_on(async move {
            let mut s = stream.lock().await;
            AsyncReadExt::read(&mut *s, buf)
                .await
                .map_err(|e| e.to_string())
        })
    }

    /// Blocking read with timeout (milliseconds). Returns `Err("timeout")` on expiry.
    pub fn read_with_timeout(&self, buf: &mut [u8], timeout_ms: i64) -> Result<usize, String> {
        let stream = self.stream.clone();
        if timeout_ms <= 0 {
            return self.read(buf);
        }
        let dur = Duration::from_millis(timeout_ms as u64);
        self.rt.block_on(async move {
            let mut s = stream.lock().await;
            tokio::time::timeout(dur, AsyncReadExt::read(&mut *s, buf))
                .await
                .map_err(|_| "timeout".to_string())?
                .map_err(|e| e.to_string())
        })
    }

    /// Blocking write. Returns the number of bytes written.
    pub fn write(&self, buf: &[u8]) -> Result<usize, String> {
        let stream = self.stream.clone();
        let data = buf.to_vec();
        self.rt.block_on(async move {
            let mut s = stream.lock().await;
            AsyncWriteExt::write(&mut *s, &data)
                .await
                .map_err(|e| e.to_string())
        })
    }

    /// Blocking write with timeout (milliseconds). Returns `Err("timeout")` on expiry.
    pub fn write_with_timeout(&self, buf: &[u8], timeout_ms: i64) -> Result<usize, String> {
        let stream = self.stream.clone();
        let data = buf.to_vec();
        if timeout_ms <= 0 {
            return self.write(buf);
        }
        let dur = Duration::from_millis(timeout_ms as u64);
        self.rt.block_on(async move {
            let mut s = stream.lock().await;
            tokio::time::timeout(dur, AsyncWriteExt::write(&mut *s, &data))
                .await
                .map_err(|_| "timeout".to_string())?
                .map_err(|e| e.to_string())
        })
    }

    /// Close the stream gracefully.
    pub fn close(&self) {
        let stream = self.stream.clone();
        self.rt.block_on(async move {
            let mut s = stream.lock().await;
            let _ = s.shutdown().await;
        });
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
    core: Arc<Core>,
    /// Connect-only handle (Arc-cloned, lock-free).
    handle: ConnectHandle,
    rt: Arc<Runtime>,
}

impl Node {
    // ── constructors ──────────────────────────────────────────────────────

    /// Create a new node with a randomly generated key and connect to `peer_addr`.
    ///
    /// `peer_addr` uses Yggdrasil URI syntax, e.g. `"tcp://1.2.3.4:1234"`.
    /// Pass an empty string to start a node without any initial peers.
    pub fn new(peer_addr: &str) -> Result<Self, String> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut config = Config::default();
        if !peer_addr.is_empty() {
            config.peers = vec![peer_addr.to_string()];
        }
        Self::from_key_and_config(signing_key, config)
    }

    /// Create a node with a specific 32-byte signing key and a list of peers.
    pub fn new_with_key(signing_key_bytes: &[u8], peers: Vec<String>) -> Result<Self, String> {
        let bytes: [u8; 32] = signing_key_bytes
            .try_into()
            .map_err(|_| "signing key must be exactly 32 bytes".to_string())?;
        let signing_key = SigningKey::from_bytes(&bytes);
        let mut config = Config::default();
        config.peers = peers;
        Self::from_key_and_config(signing_key, config)
    }

    fn from_key_and_config(signing_key: SigningKey, config: Config) -> Result<Self, String> {
        let rt = Arc::new(Runtime::new().map_err(|e| e.to_string())?);

        let (core, handle) = rt.block_on(async {
            let core = Core::new(signing_key, config);
            core.init_links().await;
            core.start().await;

            // Brief pause so TCP handshakes with bootstrap peers can begin.
            tokio::time::sleep(Duration::from_secs(1)).await;

            let manager = StreamManager::new(core.packet_conn());
            let handle = manager.split();

            (core, handle)
        });

        Ok(Self {
            core,
            handle,
            rt,
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
    /// a new one. Blocks until the stream handshake completes (≤ 30 s default).
    pub fn connect(&self, public_key: &[u8], port: u16) -> Result<Conn, String> {
        if public_key.len() != 32 {
            return Err("public_key must be exactly 32 bytes".to_string());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(public_key);
        let addr = ironwood::Addr::from(key);
        let handle = self.handle.clone();
        let rt = self.rt.clone();

        let stream = rt.block_on(async move {
            let connection = handle.connect(addr).await.map_err(|e| e.to_string())?;
            connection.open_stream(port).await.map_err(|e| e.to_string())
        })?;

        Ok(Conn {
            stream: Arc::new(TokioMutex::new(stream)),
            public_key: public_key.to_vec(),
            port,
            rt: self.rt.clone(),
        })
    }

    /// Register a listener for the given port and block until an incoming stream arrives.
    ///
    /// This is a convenience that combines `listen` + single `accept`.
    pub fn accept(&self, port: u16) -> Result<Conn, String> {
        let handle = self.handle.clone();
        let rt = self.rt.clone();

        let (stream, public_key) = rt.block_on(async move {
            let mut listener = handle.listen(port).await;
            let stream = listener
                .accept()
                .await
                .map_err(|e| e.to_string())?;
            let public_key = stream.peer_addr().0.to_vec();
            Ok::<_, String>((stream, public_key))
        })?;

        Ok(Conn {
            stream: Arc::new(TokioMutex::new(stream)),
            public_key,
            port,
            rt: self.rt.clone(),
        })
    }

    /// Register a listener and return a [`Listener`] for continuous accept.
    ///
    /// The returned `Listener` can be used in a loop to accept many streams.
    pub fn listen(&self, port: u16) -> Listener {
        self.rt.block_on(self.handle.listen(port))
    }

    // ── peer management ───────────────────────────────────────────────────

    /// Add a peer by URI (e.g. `"tcp://1.2.3.4:1234"` or `"tls://…"`).
    pub fn add_peer(&self, addr: &str) -> Result<(), String> {
        self.rt.block_on(self.core.add_peer(addr))
    }

    /// Remove a peer by URI.
    pub fn remove_peer(&self, addr: &str) -> Result<(), String> {
        self.rt.block_on(self.core.remove_peer(addr))
    }

    /// Wake all sleeping peer reconnect loops so they retry immediately.
    pub fn retry_peers_now(&self) {
        self.rt.block_on(self.core.retry_peers_now());
    }

    /// Force-close and remove a cached stream connection to the peer with the given 32-byte public key.
    pub fn close_connection(&self, public_key: &[u8]) {
        if public_key.len() != 32 {
            return;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(public_key);
        let addr = ironwood::Addr::from(key);
        let handle = self.handle.clone();
        self.rt.block_on(async move { handle.close_connection(addr).await });
    }

    // ── network introspection ─────────────────────────────────────────────

    /// Peer list as a JSON array.
    ///
    /// Each element contains `key`, `address`, `uri`, `up`, `inbound`,
    /// `priority`, `rx_bytes`, `tx_bytes`, `rx_rate`, `tx_rate`, `uptime`.
    pub fn get_peers_json(&self) -> String {
        let peers = self.rt.block_on(self.core.get_peers());
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
    pub fn get_paths_json(&self) -> String {
        let paths = self.rt.block_on(self.core.get_paths());
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
    pub fn get_tree_json(&self) -> String {
        let tree = self.rt.block_on(self.core.get_tree());
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
    pub fn close(&self) {
        self.rt.block_on(async {
            let _ = self.core.close().await;
        });
    }
}
