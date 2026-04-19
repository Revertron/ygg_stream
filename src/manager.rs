use crate::connection::{ConnKey, TcpConnection, TcpState};
use crate::error::{Error, Result};
use crate::protocol::{
    Packet, MAX_DATA_SIZE, MAX_SYN_RETRIES,
    SYN_INITIAL_RETRY_MS,
};
use ironwood::{Addr, EncryptedPacketConn, PacketConn};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

/// Start of ephemeral port range
const EPHEMERAL_PORT_START: u16 = 49152;
/// Number of ports in the ephemeral range (49152..=65535)
const EPHEMERAL_PORT_COUNT: u16 = 65535 - EPHEMERAL_PORT_START + 1;

/// Pick a random starting port in the ephemeral range
fn random_ephemeral_port() -> u16 {
    let mut buf = [0u8; 2];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
    let offset = u16::from_le_bytes(buf) % EPHEMERAL_PORT_COUNT;
    EPHEMERAL_PORT_START + offset
}

// ── TcpListener ────────────────────────────────────────────────────────────

/// A per-port accept channel for incoming connections.
pub struct TcpListener {
    port: u16,
    rx: mpsc::Receiver<TcpConnection>,
}

impl TcpListener {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Accept an incoming connection on this port.
    pub async fn accept(&mut self) -> Result<TcpConnection> {
        self.rx.recv().await.ok_or(Error::ConnectionClosed)
    }
}

// ── DatagramListener ───────────────────────────────────────────────────────

/// A per-port datagram receiver (connectionless).
pub struct DatagramListener {
    port: u16,
    rx: mpsc::Receiver<(Vec<u8>, Addr)>,
}

impl DatagramListener {
    pub fn port(&self) -> u16 {
        self.port
    }

    pub async fn recv(&mut self) -> Result<(Vec<u8>, Addr)> {
        self.rx.recv().await.ok_or(Error::ConnectionClosed)
    }
}

// ── TcpStack ───────────────────────────────────────────────────────────────

/// The TCP/KEY protocol stack.
///
/// Owns the underlying EncryptedPacketConn, runs a single reader task and
/// a single writer task. Manages connection table and port listeners.
pub struct TcpStack {
    conn: Arc<EncryptedPacketConn>,

    /// Connection table: ConnKey → packet sender for that connection's background task
    connections: Arc<RwLock<HashMap<ConnKey, mpsc::Sender<Packet>>>>,

    /// Port listeners: port → sender for newly accepted connections
    listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<TcpConnection>>>>,

    /// Datagram listeners
    datagram_listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<(Vec<u8>, Addr)>>>>,

    /// Sender for the central writer task
    outgoing: mpsc::Sender<(Vec<u8>, Addr)>,

    /// Ephemeral port allocator
    next_ephemeral_port: AtomicU16,

    cancel: CancellationToken,
}

impl TcpStack {
    pub fn new(conn: Arc<EncryptedPacketConn>) -> Self {
        let connections: Arc<RwLock<HashMap<ConnKey, mpsc::Sender<Packet>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<TcpConnection>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let datagram_listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<(Vec<u8>, Addr)>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let cancel = CancellationToken::new();

        // Spawn the central writer task
        let (outgoing_tx, outgoing_rx) = mpsc::channel(512);
        {
            let conn = conn.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                writer_task(conn, outgoing_rx, cancel).await;
            });
        }

        // Spawn the reader task
        {
            let conn = conn.clone();
            let connections = connections.clone();
            let listeners = listeners.clone();
            let datagram_listeners = datagram_listeners.clone();
            let outgoing_tx = outgoing_tx.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                if let Err(e) = reader_task(
                    conn,
                    connections,
                    listeners,
                    datagram_listeners,
                    outgoing_tx,
                    cancel,
                )
                .await
                {
                    error!("Reader task error: {}", e);
                }
            });
        }

        Self {
            conn,
            connections,
            listeners,
            datagram_listeners,
            outgoing: outgoing_tx,
            next_ephemeral_port: AtomicU16::new(random_ephemeral_port()),
            cancel,
        }
    }

    /// Register a listener for the given port.
    pub async fn listen(&self, port: u16) -> TcpListener {
        let (tx, rx) = mpsc::channel(16);
        self.listeners.write().await.insert(port, tx);
        TcpListener { port, rx }
    }

    /// Register a datagram listener for the given port.
    pub async fn listen_datagram(&self, port: u16) -> DatagramListener {
        let (tx, rx) = mpsc::channel(64);
        self.datagram_listeners.write().await.insert(port, tx);
        DatagramListener { port, rx }
    }

    /// Send a connectionless datagram to a peer on the given port.
    pub async fn send_datagram(&self, peer: &Addr, port: u16, data: Vec<u8>) -> Result<()> {
        if data.len() > MAX_DATA_SIZE {
            return Err(Error::PacketTooLarge(data.len(), MAX_DATA_SIZE));
        }
        let pkt = Packet::datagram(port, data);
        let encoded = pkt.encode()?;
        self.conn.write_to(&encoded, peer).await?;
        Ok(())
    }

    /// Connect to a remote peer on the given port. Auto-assigns ephemeral local port.
    pub async fn connect(&self, remote_key: Addr, remote_port: u16) -> Result<TcpConnection> {
        let local_port = self.allocate_ephemeral_port();
        self.connect_from(local_port, remote_key, remote_port).await
    }

    /// Connect with an explicit local port.
    pub async fn connect_from(
        &self,
        local_port: u16,
        remote_key: Addr,
        remote_port: u16,
    ) -> Result<TcpConnection> {
        let key = ConnKey {
            local_port,
            remote_key,
            remote_port,
        };

        // Check for existing connection
        {
            let conns = self.connections.read().await;
            if conns.contains_key(&key) {
                return Err(Error::ConnectionExists(local_port, remote_port));
            }
        }

        // Create connection in SynSent state
        let (incoming_tx, incoming_rx) = mpsc::channel(64);
        let conn = TcpConnection::new(key, TcpState::SynSent, self.outgoing.clone(), self.cancel.clone());

        // Register in connection table
        self.connections.write().await.insert(key, incoming_tx);

        // Spawn background task
        conn.spawn_background_task(incoming_rx);

        // Send SYN with exponential backoff
        let start = tokio::time::Instant::now();
        let timeout = std::time::Duration::from_secs(10);
        let mut syn_count = 0u32;
        let mut retry_interval_ms = SYN_INITIAL_RETRY_MS;

        let result = loop {
            if syn_count >= MAX_SYN_RETRIES {
                warn!(
                    "connect gave up after {} SYN attempts for {:?}",
                    syn_count, key
                );
                break Err(Error::Timeout);
            }

            match conn.send_syn().await {
                Ok(()) => {
                    syn_count += 1;
                    info!("Sent SYN #{} for {:?} (retry in {}ms)", syn_count, key, retry_interval_ms);
                }
                Err(e) => break Err(e),
            }

            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break Err(Error::Timeout);
            }

            let wait_time = std::cmp::min(
                std::time::Duration::from_millis(retry_interval_ms),
                remaining,
            );

            tokio::select! {
                _ = conn.wait_for_open() => {
                    info!("Connection {:?} established after {} SYNs", key, syn_count);
                    break Ok(conn.clone());
                }
                _ = tokio::time::sleep(wait_time) => {}
                _ = self.cancel.cancelled() => {
                    break Err(Error::ConnectionClosed);
                }
            }

            retry_interval_ms *= 2;
        };

        if result.is_err() {
            self.connections.write().await.remove(&key);
        }

        result
    }

    fn allocate_ephemeral_port(&self) -> u16 {
        allocate_ephemeral_port_from(&self.next_ephemeral_port)
    }

    /// Close all connections and shut down.
    pub async fn close(&self) {
        self.cancel.cancel();
        let mut conns = self.connections.write().await;
        conns.clear();
        self.listeners.write().await.clear();
        self.datagram_listeners.write().await.clear();
        debug!("TcpStack closed");
    }

    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    pub fn local_addr(&self) -> Addr {
        self.conn.local_addr()
    }

    /// Remove a connection from the table (called when connection reaches Closed)
    #[allow(dead_code)]
    pub(crate) async fn remove_connection(&self, key: &ConnKey) {
        self.connections.write().await.remove(key);
    }

    /// Split into a cloneable ConnectHandle. After this, use the handle.
    pub fn split(self) -> ConnectHandle {
        let handle = ConnectHandle {
            conn: self.conn.clone(),
            connections: self.connections.clone(),
            listeners: self.listeners.clone(),
            datagram_listeners: self.datagram_listeners.clone(),
            outgoing: self.outgoing.clone(),
            next_ephemeral_port: Arc::new(AtomicU16::new(
                self.next_ephemeral_port.load(Ordering::Relaxed),
            )),
            cancel: self.cancel.clone(),
        };

        // Keep the stack alive (reader/writer tasks)
        tokio::spawn(async move {
            let _stack = self;
            std::future::pending::<()>().await;
        });

        handle
    }
}

impl Drop for TcpStack {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

// ── ConnectHandle ──────────────────────────────────────────────────────────

/// A cloneable handle for connecting and listening.
#[derive(Clone)]
pub struct ConnectHandle {
    conn: Arc<EncryptedPacketConn>,
    connections: Arc<RwLock<HashMap<ConnKey, mpsc::Sender<Packet>>>>,
    listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<TcpConnection>>>>,
    datagram_listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<(Vec<u8>, Addr)>>>>,
    outgoing: mpsc::Sender<(Vec<u8>, Addr)>,
    next_ephemeral_port: Arc<AtomicU16>,
    cancel: CancellationToken,
}

impl ConnectHandle {
    /// Connect to a remote peer on the given port.
    pub async fn connect(&self, remote_key: Addr, remote_port: u16) -> Result<TcpConnection> {
        let local_port = self.allocate_ephemeral_port();
        self.connect_from(local_port, remote_key, remote_port).await
    }

    pub async fn connect_from(
        &self,
        local_port: u16,
        remote_key: Addr,
        remote_port: u16,
    ) -> Result<TcpConnection> {
        let key = ConnKey {
            local_port,
            remote_key,
            remote_port,
        };

        {
            let conns = self.connections.read().await;
            if conns.contains_key(&key) {
                return Err(Error::ConnectionExists(local_port, remote_port));
            }
        }

        let (incoming_tx, incoming_rx) = mpsc::channel(64);
        let conn = TcpConnection::new(key, TcpState::SynSent, self.outgoing.clone(), self.cancel.clone());

        self.connections.write().await.insert(key, incoming_tx);
        conn.spawn_background_task(incoming_rx);

        // SYN with exponential backoff
        let start = tokio::time::Instant::now();
        let timeout = std::time::Duration::from_secs(10);
        let mut syn_count = 0u32;
        let mut retry_interval_ms = SYN_INITIAL_RETRY_MS;

        let result = loop {
            if syn_count >= MAX_SYN_RETRIES {
                break Err(Error::Timeout);
            }

            match conn.send_syn().await {
                Ok(()) => syn_count += 1,
                Err(e) => break Err(e),
            }

            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break Err(Error::Timeout);
            }

            let wait_time = std::cmp::min(
                std::time::Duration::from_millis(retry_interval_ms),
                remaining,
            );

            tokio::select! {
                _ = conn.wait_for_open() => {
                    break Ok(conn.clone());
                }
                _ = tokio::time::sleep(wait_time) => {}
                _ = self.cancel.cancelled() => {
                    break Err(Error::ConnectionClosed);
                }
            }

            retry_interval_ms *= 2;
        };

        if result.is_err() {
            self.connections.write().await.remove(&key);
        }

        result
    }

    pub async fn listen(&self, port: u16) -> TcpListener {
        let (tx, rx) = mpsc::channel(16);
        self.listeners.write().await.insert(port, tx);
        TcpListener { port, rx }
    }

    pub async fn listen_datagram(&self, port: u16) -> DatagramListener {
        let (tx, rx) = mpsc::channel(64);
        self.datagram_listeners.write().await.insert(port, tx);
        DatagramListener { port, rx }
    }

    pub async fn send_datagram(&self, peer: &Addr, port: u16, data: Vec<u8>) -> Result<()> {
        if data.len() > MAX_DATA_SIZE {
            return Err(Error::PacketTooLarge(data.len(), MAX_DATA_SIZE));
        }
        let pkt = Packet::datagram(port, data);
        let encoded = pkt.encode()?;
        self.conn.write_to(&encoded, peer).await?;
        Ok(())
    }

    pub fn local_addr(&self) -> Addr {
        self.conn.local_addr()
    }

    /// Force-close and remove a connection to a peer.
    pub async fn close_connection(&self, key: ConnKey) {
        self.connections.write().await.remove(&key);
    }

    /// Shut down all connections and listeners.
    pub async fn close_all(&self) {
        self.cancel.cancel();
        self.connections.write().await.clear();
        self.listeners.write().await.clear();
        self.datagram_listeners.write().await.clear();
    }

    fn allocate_ephemeral_port(&self) -> u16 {
        allocate_ephemeral_port_from(&self.next_ephemeral_port)
    }
}

/// Atomically pick the next ephemeral port, always staying within
/// [EPHEMERAL_PORT_START, 65535]. Uses compare_exchange to avoid the
/// race where `fetch_add` wraps through low-numbered ports (which could
/// collide with well-known listeners on the same stack).
fn allocate_ephemeral_port_from(counter: &AtomicU16) -> u16 {
    loop {
        let current = counter.load(Ordering::Relaxed);
        // Defensive: coerce anything out of the ephemeral range back in.
        // Normally current is always in [EPHEMERAL_PORT_START, 65535].
        let port = if current < EPHEMERAL_PORT_START {
            EPHEMERAL_PORT_START
        } else {
            current
        };
        let next = if port == u16::MAX {
            EPHEMERAL_PORT_START
        } else {
            port + 1
        };
        if counter
            .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return port;
        }
    }
}

// ── Reader task ────────────────────────────────────────────────────────────

async fn reader_task(
    conn: Arc<EncryptedPacketConn>,
    connections: Arc<RwLock<HashMap<ConnKey, mpsc::Sender<Packet>>>>,
    listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<TcpConnection>>>>,
    datagram_listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<(Vec<u8>, Addr)>>>>,
    outgoing: mpsc::Sender<(Vec<u8>, Addr)>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            result = conn.read_from(&mut buf) => {
                let (n, remote_key) = result?;
                trace!("Received {} bytes from {}", n, hex::encode(&remote_key.as_ref()[..8]));

                let mut packet = match Packet::decode(&buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        debug!("Decode error from {}: {}", hex::encode(&remote_key.as_ref()[..8]), e);
                        continue;
                    }
                };

                // Datagrams — bypass connection table
                if packet.is_dgram() {
                    let dg = datagram_listeners.read().await;
                    if let Some(tx) = dg.get(&packet.dst_port) {
                        let _ = tx.try_send((packet.data, remote_key));
                    }
                    continue;
                }

                let key = ConnKey {
                    local_port: packet.dst_port,
                    remote_key,
                    remote_port: packet.src_port,
                };

                // Try to route to existing connection
                let sender = {
                    let conns = connections.read().await;
                    conns.get(&key).cloned()
                };

                if let Some(tx) = sender {
                    match tx.send(packet).await {
                        Ok(()) => { continue; }
                        Err(mpsc::error::SendError(returned)) => {
                            // Connection task has exited — remove stale entry
                            // and re-handle the packet as a potential new SYN.
                            debug!("Removing stale connection {:?}", key);
                            connections.write().await.remove(&key);
                            packet = returned;
                        }
                    }
                }

                // No existing connection — handle SYN for new connections
                if packet.is_syn() && !packet.is_ack() {
                    let dst_port = packet.dst_port;

                    // Check listener
                    let has_listener = listeners.read().await.contains_key(&dst_port);
                    if !has_listener {
                        warn!("No listener for port {} from {}", dst_port, hex::encode(&remote_key.as_ref()[..8]));
                        let rst = Packet::rst(dst_port, packet.src_port);
                        if let Ok(data) = rst.encode() {
                            let _ = outgoing.try_send((data, remote_key));
                        }
                        continue;
                    }

                    // Create new connection in SynReceived state
                    let (incoming_tx, incoming_rx) = mpsc::channel(64);
                    let new_conn = TcpConnection::new(
                        key,
                        TcpState::SynReceived,
                        outgoing.clone(),
                        cancel.clone(),
                    );

                    // Set peer's window from SYN
                    new_conn.set_peer_window(packet.window);

                    // Register in connections table
                    connections.write().await.insert(key, incoming_tx);

                    // Spawn background task
                    new_conn.spawn_background_task(incoming_rx);

                    // Send SYN-ACK
                    if let Err(e) = new_conn.send_syn_ack().await {
                        warn!("Failed to send SYN-ACK: {}", e);
                        connections.write().await.remove(&key);
                        continue;
                    }

                    debug!(
                        "New connection {:?} from {}, sent SYN-ACK",
                        key, hex::encode(&remote_key.as_ref()[..8])
                    );

                    // Wait for handshake completion in background, then deliver to listener
                    let listeners_ref = listeners.clone();
                    let connections_ref = connections.clone();
                    let conn_clone = new_conn.clone();
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = conn_clone.wait_for_open() => {
                                let listeners_guard = listeners_ref.read().await;
                                if let Some(tx) = listeners_guard.get(&dst_port) {
                                    if tx.send(conn_clone).await.is_err() {
                                        warn!("Listener channel closed for port {}", dst_port);
                                    }
                                }
                            }
                            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                                // Handshake timeout
                                warn!("SynReceived timeout for {:?}", key);
                                let _ = conn_clone.abort().await;
                                connections_ref.write().await.remove(&key);
                            }
                        }
                    });
                } else if !packet.is_rst() {
                    // Unknown connection, not a SYN — send RST
                    let rst = Packet::rst(packet.dst_port, packet.src_port);
                    if let Ok(data) = rst.encode() {
                        let _ = outgoing.try_send((data, remote_key));
                    }
                }
            }
            _ = cancel.cancelled() => {
                debug!("Reader task cancelled");
                return Ok(());
            }
        }
    }
}

// ── Writer task (single, global) ───────────────────────────────────────────

async fn writer_task(
    conn: Arc<EncryptedPacketConn>,
    mut outgoing: mpsc::Receiver<(Vec<u8>, Addr)>,
    cancel: CancellationToken,
) {
    let mut pkt_count = 0u64;
    let mut err_count = 0u64;

    loop {
        tokio::select! {
            item = outgoing.recv() => {
                match item {
                    Some((data, peer)) => {
                        pkt_count += 1;

                        if let Err(e) = conn.write_to(&data, &peer).await {
                            err_count += 1;
                            warn!(
                                "write_to failed ({} total): {} — continuing",
                                err_count, e
                            );
                            // Transient mesh errors (peer unreachable, link drop) must not
                            // kill the writer — that would silently break every connection
                            // on this stack. Individual connections will retransmit or
                            // time out on their own.
                        }
                    }
                    None => {
                        info!(
                            "Writer task: channel closed (sent {} pkts, {} errs)",
                            pkt_count, err_count
                        );
                        return;
                    }
                }
            }
            _ = cancel.cancelled() => {
                info!(
                    "Writer task cancelled (sent {} pkts, {} errs)",
                    pkt_count, err_count
                );
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ironwood::new_encrypted_packet_conn;

    #[tokio::test]
    async fn test_stack_creation() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let stack = TcpStack::new(conn);
        assert_eq!(stack.connection_count().await, 0);
    }

    #[tokio::test]
    async fn test_stack_local_addr() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let local_addr = conn.local_addr();
        let stack = TcpStack::new(conn);
        assert_eq!(stack.local_addr(), local_addr);
    }

    #[tokio::test]
    async fn test_listen() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let stack = TcpStack::new(conn);
        let listener = stack.listen(42).await;
        assert_eq!(listener.port(), 42);
        assert!(stack.listeners.read().await.contains_key(&42));
    }

    #[tokio::test]
    async fn test_listen_datagram() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let stack = TcpStack::new(conn);
        let dg = stack.listen_datagram(99).await;
        assert_eq!(dg.port(), 99);
        assert!(stack.datagram_listeners.read().await.contains_key(&99));
    }

    #[tokio::test]
    async fn test_datagram_pipeline() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let stack = TcpStack::new(conn);

        let payload = b"hello datagram";
        let sender = Addr::from([0xAB_u8; 32]);
        let port = 42u16;

        let mut listener = stack.listen_datagram(port).await;

        // Simulate encode → decode → route
        let pkt = Packet::datagram(port, payload.to_vec());
        let encoded = pkt.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();
        assert!(decoded.is_dgram());
        assert_eq!(decoded.dst_port, port);

        // Route into listener
        {
            let dg = stack.datagram_listeners.read().await;
            let tx = dg.get(&port).unwrap();
            tx.try_send((decoded.data, sender)).unwrap();
        }

        let (data, addr) = listener.recv().await.unwrap();
        assert_eq!(data, payload);
        assert_eq!(addr, sender);
    }

    #[tokio::test]
    async fn test_ephemeral_port_allocation() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let stack = TcpStack::new(conn);

        let p1 = stack.allocate_ephemeral_port();
        let p2 = stack.allocate_ephemeral_port();
        let p3 = stack.allocate_ephemeral_port();

        // All ports are in the ephemeral range
        assert!(p1 >= EPHEMERAL_PORT_START);
        assert!(p2 >= EPHEMERAL_PORT_START);
        assert!(p3 >= EPHEMERAL_PORT_START);

        // Ports advance by 1, wrapping back to EPHEMERAL_PORT_START after 65535
        let expected_p2 = if p1 == u16::MAX { EPHEMERAL_PORT_START } else { p1 + 1 };
        let expected_p3 = if expected_p2 == u16::MAX { EPHEMERAL_PORT_START } else { expected_p2 + 1 };
        assert_eq!(p2, expected_p2);
        assert_eq!(p3, expected_p3);
    }

    #[test]
    fn test_ephemeral_port_wraparound() {
        // Start the counter near the top to exercise the wrap path.
        let counter = AtomicU16::new(65534);

        let p1 = allocate_ephemeral_port_from(&counter);
        let p2 = allocate_ephemeral_port_from(&counter);
        let p3 = allocate_ephemeral_port_from(&counter);
        let p4 = allocate_ephemeral_port_from(&counter);

        assert_eq!(p1, 65534);
        assert_eq!(p2, 65535);
        assert_eq!(p3, EPHEMERAL_PORT_START);
        assert_eq!(p4, EPHEMERAL_PORT_START + 1);
    }

    #[test]
    fn test_ephemeral_port_out_of_range_is_coerced() {
        // If the counter ever holds a low port, allocator still hands out ephemeral ones.
        let counter = AtomicU16::new(42);
        let p = allocate_ephemeral_port_from(&counter);
        assert!(p >= EPHEMERAL_PORT_START);
    }
}
