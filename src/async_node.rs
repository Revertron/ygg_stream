//! Async high-level Node API for Yggdrasil TCP/KEY connections.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use yggdrasil::config::Config;
use yggdrasil::core::Core;

use crate::connection::TcpConnection;
use crate::manager::{ConnectHandle, DatagramListener, TcpListener};
use crate::TcpStack;

// ── AsyncConn ────────────────────────────────────────────────────────────────

/// A single bidirectional connection to a remote Yggdrasil peer.
///
/// All I/O methods are **async**.
#[derive(Clone)]
pub struct AsyncConn {
    conn: TcpConnection,
    public_key: Vec<u8>,
    port: u16,
    write_mutex: Arc<Mutex<()>>,
}

impl AsyncConn {
    pub(crate) fn new(conn: TcpConnection, public_key: Vec<u8>, port: u16) -> Self {
        Self {
            conn,
            public_key,
            port,
            write_mutex: Arc::new(Mutex::new(())),
        }
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn is_alive(&self) -> bool {
        self.conn.is_alive()
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut c = self.conn.clone();
        AsyncReadExt::read(&mut c, buf)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn read_with_timeout(&self, buf: &mut [u8], timeout_ms: i64) -> Result<usize, String> {
        if timeout_ms <= 0 {
            return self.read(buf).await;
        }
        let dur = Duration::from_millis(timeout_ms as u64);
        let mut c = self.conn.clone();
        tokio::time::timeout(dur, AsyncReadExt::read(&mut c, buf))
            .await
            .map_err(|_| "timeout".to_string())?
            .map_err(|e| e.to_string())
    }

    pub async fn write(&self, buf: &[u8]) -> Result<usize, String> {
        let _guard = self.write_mutex.lock().await;
        let mut c = self.conn.clone();
        AsyncWriteExt::write_all(&mut c, buf)
            .await
            .map_err(|e| e.to_string())?;
        c.flush().await.map_err(|e| e.to_string())?;
        Ok(buf.len())
    }

    pub async fn write_with_timeout(&self, buf: &[u8], timeout_ms: i64) -> Result<usize, String> {
        if timeout_ms <= 0 {
            return self.write(buf).await;
        }
        let dur = Duration::from_millis(timeout_ms as u64);
        let _guard = self.write_mutex.lock().await;
        let mut c = self.conn.clone();
        tokio::time::timeout(dur, async {
            AsyncWriteExt::write_all(&mut c, buf).await?;
            c.flush().await
        })
            .await
            .map_err(|_| "timeout".to_string())?
            .map_err(|e| e.to_string())?;
        Ok(buf.len())
    }

    pub async fn close(&self) {
        let mut c = self.conn.clone();
        let _ = tokio::time::timeout(Duration::from_secs(5), c.shutdown()).await;
    }

    pub async fn abort(&self) {
        let _ = self.conn.abort().await;
    }
}

// ── AsyncNode ────────────────────────────────────────────────────────────────

/// High-level async Yggdrasil node.
pub struct AsyncNode {
    core: Arc<Core>,
    handle: ConnectHandle,
    listeners: Mutex<HashMap<u16, TcpListener>>,
    datagram_listeners: Mutex<HashMap<u16, DatagramListener>>,
}

impl AsyncNode {
    pub async fn new(peer_addr: &str) -> Result<Self, String> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut config = Config::default();
        if !peer_addr.is_empty() {
            config.peers = vec![peer_addr.to_string()];
        }
        Self::from_key_and_config(signing_key, config).await
    }

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

        tokio::time::sleep(Duration::from_secs(1)).await;

        let stack = TcpStack::new(core.packet_conn());
        let handle = stack.split();

        Ok(Self {
            core,
            handle,
            listeners: Mutex::new(HashMap::new()),
            datagram_listeners: Mutex::new(HashMap::new()),
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.core.public_key().to_vec()
    }

    pub fn handle(&self) -> ConnectHandle {
        self.handle.clone()
    }

    /// Open a connection to the remote peer on the given port.
    pub async fn connect(&self, public_key: &[u8], port: u16) -> Result<AsyncConn, String> {
        if public_key.len() != 32 {
            return Err("public_key must be exactly 32 bytes".to_string());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(public_key);
        let addr = ironwood::Addr::from(key);

        let conn = self
            .handle
            .connect(addr, port)
            .await
            .map_err(|e| e.to_string())?;
        Ok(AsyncConn::new(conn, public_key.to_vec(), port))
    }

    /// Accept an incoming connection on the given port.
    pub async fn accept(&self, port: u16) -> Result<AsyncConn, String> {
        let mut listeners = self.listeners.lock().await;
        let listener = if !listeners.contains_key(&port) {
            listeners
                .entry(port)
                .or_insert(self.handle.listen(port).await)
        } else {
            listeners.get_mut(&port).unwrap()
        };
        let conn = listener.accept().await.map_err(|e| e.to_string())?;
        let public_key = conn.remote_key().0.to_vec();
        Ok(AsyncConn::new(conn, public_key, port))
    }

    pub async fn listen(&self, port: u16) -> TcpListener {
        self.handle.listen(port).await
    }

    // ── datagram API ──────────────────────────────────────────────────────

    pub async fn send_datagram(&self, public_key: &[u8], port: u16, data: &[u8]) -> Result<(), String> {
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

    pub async fn listen_datagram(&self, port: u16) -> DatagramListener {
        self.handle.listen_datagram(port).await
    }

    pub async fn recv_datagram(&self, port: u16) -> Result<(Vec<u8>, Vec<u8>), String> {
        let mut listeners = self.datagram_listeners.lock().await;
        let listener = if !listeners.contains_key(&port) {
            listeners
                .entry(port)
                .or_insert(self.handle.listen_datagram(port).await)
        } else {
            listeners.get_mut(&port).unwrap()
        };
        let (data, addr) = listener.recv().await.map_err(|e| e.to_string())?;
        Ok((data, addr.0.to_vec()))
    }

    pub async fn recv_datagram_with_timeout(
        &self,
        port: u16,
        timeout_ms: i64,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let mut listeners = self.datagram_listeners.lock().await;
        let listener = if !listeners.contains_key(&port) {
            listeners
                .entry(port)
                .or_insert(self.handle.listen_datagram(port).await)
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

    pub async fn add_peer(&self, addr: &str) -> Result<(), String> {
        self.core.add_peer(addr).await
    }

    pub async fn remove_peer(&self, addr: &str) -> Result<(), String> {
        self.core.remove_peer(addr).await
    }

    pub async fn retry_peers_now(&self) {
        self.core.retry_peers_now().await;
    }

    pub async fn close_connection(&self, _public_key: &[u8]) {
        // In TCP/KEY, connections are identified by full ConnKey, not just peer key.
        // This is a no-op for now — individual connections are closed via their handle.
    }

    // ── network introspection ─────────────────────────────────────────────

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

    pub async fn count_active_peers(&self) -> usize {
        self.core
            .get_peers()
            .await
            .into_iter()
            .filter(|p| p.up)
            .count()
    }

    pub async fn get_first_active_peer(&self) -> Option<(String, u64)> {
        self.core
            .get_peers()
            .await
            .into_iter()
            .filter(|p| p.up)
            .next()
            .map(|p| (p.uri, p.cost))
    }

    pub fn subscribe_peer_events(
        &self,
    ) -> tokio::sync::broadcast::Receiver<yggdrasil::links::PeerEvent> {
        self.core.as_ref().subscribe_peer_events()
    }

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

    /// Force a path lookup for the given destination key.
    /// This ensures the remote peer learns our path (from the PathNotify response),
    /// which is required for it to route traffic back to us.
    /// Returns the number of peers the lookup was multicast to.
    pub async fn force_lookup(&self, public_key: &[u8; 32]) -> usize {
        self.core.force_lookup(*public_key).await
    }

    pub async fn close(&self) {
        self.handle.close_all().await;
        self.listeners.lock().await.clear();
        self.datagram_listeners.lock().await.clear();
        let _ = self.core.close().await;
    }
}
