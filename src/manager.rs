use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::protocol::{Packet, MAX_DATA_SIZE};
use crate::stream::Stream;
use ironwood::{Addr, EncryptedPacketConn, PacketConn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

/// A per-port accept channel.
///
/// Created by [`StreamManager::listen`] or [`ConnectHandle::listen`].
/// Call [`Listener::accept`] to receive incoming streams on this port.
pub struct Listener {
    port: u16,
    rx: mpsc::Receiver<Arc<Stream>>,
}

impl Listener {
    /// The port this listener is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Accept an incoming stream on this port.
    pub async fn accept(&mut self) -> Result<Stream> {
        self.rx
            .recv()
            .await
            .map(|arc| (*arc).clone())
            .ok_or(Error::ConnectionClosed)
    }
}

/// A per-port datagram receiver.
///
/// Created by [`StreamManager::listen_datagram`] or [`ConnectHandle::listen_datagram`].
/// Call [`DatagramListener::recv`] to receive incoming datagrams on this port.
pub struct DatagramListener {
    port: u16,
    rx: mpsc::Receiver<(Vec<u8>, Addr)>,
}

impl DatagramListener {
    /// The port this datagram listener is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Receive the next datagram on this port.
    ///
    /// Returns `(data, sender_addr)`.
    pub async fn recv(&mut self) -> Result<(Vec<u8>, Addr)> {
        self.rx
            .recv()
            .await
            .ok_or(Error::ConnectionClosed)
    }
}

/// StreamManager manages connections and stream multiplexing
///
/// Wraps an EncryptedPacketConn and provides stream-oriented API.
pub struct StreamManager {
    /// Underlying encrypted packet connection
    conn: Arc<EncryptedPacketConn>,

    /// Active connections (peer address -> Connection)
    connections: Arc<RwLock<HashMap<Addr, Arc<Connection>>>>,

    /// Per-port listener senders
    listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<Arc<Stream>>>>>,

    /// Per-port datagram listener senders
    datagram_listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<(Vec<u8>, Addr)>>>>,

    /// Cancellation token for graceful shutdown
    cancel: CancellationToken,
}

impl StreamManager {
    /// Create a new stream manager
    pub fn new(conn: Arc<EncryptedPacketConn>) -> Self {
        let listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<Arc<Stream>>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let datagram_listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<(Vec<u8>, Addr)>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let manager = Self {
            conn: conn.clone(),
            connections: Arc::new(RwLock::new(HashMap::new())),
            listeners: listeners.clone(),
            datagram_listeners: datagram_listeners.clone(),
            cancel: CancellationToken::new(),
        };

        // Spawn background reader task
        let connections = manager.connections.clone();
        let cancel = manager.cancel.clone();
        tokio::spawn(async move {
            if let Err(e) = reader_task(conn, connections, listeners, datagram_listeners, cancel).await {
                error!("Reader task error: {}", e);
            }
        });

        manager
    }

    /// Register a listener for the given port.
    ///
    /// Returns a [`Listener`] whose `accept()` yields incoming streams on that port.
    /// Streams arriving on ports with no listener are RST'd back to the sender.
    pub async fn listen(&self, port: u16) -> Listener {
        let (tx, rx) = mpsc::channel(16);
        self.listeners.write().await.insert(port, tx);
        Listener { port, rx }
    }

    /// Register a datagram listener for the given port.
    ///
    /// Returns a [`DatagramListener`] whose `recv()` yields incoming datagrams.
    /// Datagrams arriving on ports with no listener are silently dropped.
    pub async fn listen_datagram(&self, port: u16) -> DatagramListener {
        let (tx, rx) = mpsc::channel(64);
        self.datagram_listeners.write().await.insert(port, tx);
        DatagramListener { port, rx }
    }

    /// Send a connectionless datagram to a peer on the given port.
    ///
    /// Bypasses the Connection/Stream machinery entirely — no handshake,
    /// no flow control, no ordering guarantees.
    pub async fn send_datagram(&self, peer: &Addr, port: u16, data: Vec<u8>) -> Result<()> {
        if data.len() > MAX_DATA_SIZE {
            return Err(Error::PacketTooLarge(data.len(), MAX_DATA_SIZE));
        }
        let pkt = Packet::datagram(port, data);
        let encoded = pkt.encode()?;
        self.conn.write_to(&encoded, peer).await?;
        Ok(())
    }

    /// Connect to a peer (or reuse existing connection)
    pub async fn connect(&self, peer: Addr) -> Result<Arc<Connection>> {
        // Check if connection already exists and is alive
        {
            let connections = self.connections.read().await;
            if let Some(conn) = connections.get(&peer) {
                if conn.is_alive() {
                    debug!("Reusing existing connection to peer {:?}", hex::encode(&peer.as_ref()[..8]));
                    return Ok(conn.clone());
                }
            }
        }

        // Remove stale connection if present
        {
            let mut connections = self.connections.write().await;
            if let Some(old) = connections.remove(&peer) {
                debug!("Removing stale connection to peer {:?}", hex::encode(&peer.as_ref()[..8]));
                old.close().await;
            }
        }

        // Create new connection as initiator
        let (outgoing_tx, outgoing_rx) = mpsc::channel(256);
        let connection = Arc::new(Connection::new_initiator(peer, outgoing_tx));

        // Register connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(peer, connection.clone());
        }

        // Spawn writer task for this connection.
        // When the writer task exits, mark the connection dead.
        let conn = self.conn.clone();
        let cancel = self.cancel.clone();
        let conn_ref = connection.clone();
        tokio::spawn(async move {
            if let Err(e) = writer_task(conn, peer, outgoing_rx, cancel).await {
                error!("Writer task error for peer {:?}: {}", hex::encode(&peer.as_ref()[..8]), e);
            }
            conn_ref.mark_dead().await;
        });

        debug!("Created new connection to peer {:?}", hex::encode(&peer.as_ref()[..8]));

        Ok(connection)
    }

    /// Close all connections and shut down
    pub async fn close(&self) {
        self.cancel.cancel();

        // Close all connections
        let connections = {
            let mut connections_lock = self.connections.write().await;
            let current_connections: Vec<_> = connections_lock.values().cloned().collect();
            connections_lock.clear();
            current_connections
        };

        for conn in connections {
            conn.close().await;
        }

        debug!("StreamManager closed");
    }

    /// Get the number of active connections
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Get the local node address
    pub fn local_addr(&self) -> Addr {
        self.conn.local_addr()
    }

    /// Split into a shareable connect handle and move listener state out.
    ///
    /// Use this when you need concurrent connect and listen without shared locking:
    /// - Give `ConnectHandle` to any code that needs to open streams.
    /// - Call `ConnectHandle::listen(port)` to register per-port accept channels.
    ///
    /// After calling `split()`, methods on the original manager should not be used.
    pub fn split(self) -> ConnectHandle {
        let handle = ConnectHandle {
            conn: self.conn.clone(),
            connections: self.connections.clone(),
            listeners: self.listeners.clone(),
            datagram_listeners: self.datagram_listeners.clone(),
            cancel: self.cancel.clone(),
        };

        // Keep the manager alive (its reader_task still runs).
        tokio::spawn(async move {
            let _manager = self; // keeps reader_task alive
            std::future::pending::<()>().await;
        });

        handle
    }
}

/// A cloneable handle for opening new connections and registering listeners.
///
/// All fields are `Arc`-wrapped, so cloning is cheap and safe for concurrent use.
#[derive(Clone)]
pub struct ConnectHandle {
    conn: Arc<EncryptedPacketConn>,
    connections: Arc<RwLock<HashMap<Addr, Arc<Connection>>>>,
    listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<Arc<Stream>>>>>,
    datagram_listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<(Vec<u8>, Addr)>>>>,
    cancel: CancellationToken,
}

impl ConnectHandle {
    /// Connect to a peer (or reuse existing connection).
    pub async fn connect(&self, peer: Addr) -> Result<Arc<Connection>> {
        // Check if connection already exists and is alive
        {
            let connections = self.connections.read().await;
            if let Some(conn) = connections.get(&peer) {
                if conn.is_alive() {
                    debug!("Reusing existing connection to peer {:?}", hex::encode(&peer.as_ref()[..8]));
                    return Ok(conn.clone());
                }
            }
        }

        // Remove stale connection if present
        {
            let mut connections = self.connections.write().await;
            if let Some(old) = connections.remove(&peer) {
                debug!("Removing stale connection to peer {:?}", hex::encode(&peer.as_ref()[..8]));
                old.close().await;
            }
        }

        // Create new connection as initiator
        let (outgoing_tx, outgoing_rx) = mpsc::channel(256);
        let connection = Arc::new(Connection::new_initiator(peer, outgoing_tx));

        // Register connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(peer, connection.clone());
        }

        // Spawn writer task for this connection.
        // When the writer task exits (error or channel close), cancel the
        // connection so that `is_alive()` returns false and future connect
        // calls create a fresh connection instead of reusing a dead one.
        let conn = self.conn.clone();
        let cancel = self.cancel.clone();
        let conn_ref = connection.clone();
        tokio::spawn(async move {
            if let Err(e) = writer_task(conn, peer, outgoing_rx, cancel).await {
                error!("Writer task error for peer {:?}: {}", hex::encode(&peer.as_ref()[..8]), e);
            }
            conn_ref.mark_dead().await;
        });

        debug!("Created new connection to peer {:?}", hex::encode(&peer.as_ref()[..8]));
        Ok(connection)
    }

    /// Register a listener for the given port.
    pub async fn listen(&self, port: u16) -> Listener {
        let (tx, rx) = mpsc::channel(16);
        self.listeners.write().await.insert(port, tx);
        Listener { port, rx }
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

    /// Get the local node address.
    pub fn local_addr(&self) -> Addr {
        self.conn.local_addr()
    }

    /// Force-close and remove a cached connection to a peer.
    pub async fn close_connection(&self, addr: Addr) {
        let conn = {
            let mut guard = self.connections.write().await;
            guard.remove(&addr)
        };
        if let Some(c) = conn {
            c.close().await;
        }
    }
}

/// Background reader task
///
/// Continuously reads packets from the underlying connection and routes them
/// to the appropriate Connection. For new incoming SYN packets, looks up the
/// port listener and sends an RST if no listener is registered.
async fn reader_task(
    conn: Arc<EncryptedPacketConn>,
    connections: Arc<RwLock<HashMap<Addr, Arc<Connection>>>>,
    listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<Arc<Stream>>>>>,
    datagram_listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<(Vec<u8>, Addr)>>>>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            result = conn.read_from(&mut buf) => {
                let (n, peer) = result?;
                debug!("Received {} bytes from peer {}", n, hex::encode(&peer.as_ref()[..8]));

                // Decode packet
                let packet = match Packet::decode(&buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Failed to decode packet from peer {:?}: {}", hex::encode(&peer.as_ref()[..8]), e);
                        continue;
                    }
                };

                // Handle datagrams — bypass all stream/connection routing
                if packet.is_dgram() {
                    let dg_listeners = datagram_listeners.read().await;
                    if let Some(tx) = dg_listeners.get(&packet.port) {
                        let _ = tx.try_send((packet.data, peer));
                    } else {
                        trace!("No datagram listener for port {}, dropping", packet.port);
                    }
                    continue;
                }

                let port = packet.port;

                // Route to connection
                let connection = {
                    let conns = connections.read().await;
                    conns.get(&peer).cloned()
                };

                if let Some(conn_arc) = connection {
                    let is_new_syn = packet.is_syn() && !packet.is_ack();

                    // If it's a new SYN, check listener first
                    if is_new_syn {
                        let has_listener = listeners.read().await.contains_key(&port);
                        if !has_listener {
                            // No listener for this port — send RST
                            warn!("No listener for port {} from peer {:?}, sending RST", port, hex::encode(&peer.as_ref()[..8]));
                            let rst = Packet::rst(port, packet.stream_id);
                            let rst_data = match rst.encode() {
                                Ok(d) => d,
                                Err(_) => continue,
                            };
                            let _ = conn.write_to(&rst_data, &peer).await;
                            continue;
                        }
                    }

                    match conn_arc.handle_packet(packet).await {
                        Err(e) => {
                            warn!("Error handling packet from peer {:?}: {}", hex::encode(&peer.as_ref()[..8]), e);
                        }
                        Ok(true) if is_new_syn => {
                            // New stream was created — pull it from the connection's
                            // internal channel and forward to the port listener.
                            if let Ok(stream) = conn_arc.accept_stream().await {
                                let listeners_guard = listeners.read().await;
                                if let Some(tx) = listeners_guard.get(&port) {
                                    let stream_arc = Arc::new(stream);
                                    if tx.send(stream_arc).await.is_err() {
                                        warn!("Listener channel closed for port {}", port);
                                    }
                                }
                            }
                        }
                        Ok(false) if is_new_syn => {
                            // Duplicate SYN retransmission — SYN-ACK was resent
                            // by handle_packet, no new stream to accept.
                            debug!("Duplicate SYN from peer {:?} port={}, SYN-ACK resent", hex::encode(&peer.as_ref()[..8]), port);
                        }
                        _ => {}
                    }
                } else {
                    // New incoming connection
                    if packet.is_syn() && !packet.is_ack() {
                        // Check if there's a listener for this port
                        let has_listener = listeners.read().await.contains_key(&port);
                        if !has_listener {
                            warn!("No listener for port {} from new peer {:?}, sending RST", port, hex::encode(&peer.as_ref()[..8]));
                            let rst = Packet::rst(port, packet.stream_id);
                            let rst_data = match rst.encode() {
                                Ok(d) => d,
                                Err(_) => continue,
                            };
                            let _ = conn.write_to(&rst_data, &peer).await;
                            continue;
                        }

                        info!("New incoming connection from peer {:?}", hex::encode(&peer.as_ref()[..8]));

                        // Create connection as acceptor
                        let (outgoing_tx, outgoing_rx) = mpsc::channel(256);
                        let connection = Arc::new(Connection::new_acceptor(peer, outgoing_tx));

                        // Register connection
                        {
                            let mut conns = connections.write().await;
                            conns.insert(peer, connection.clone());
                        }

                        // Spawn writer task — mark connection dead on exit
                        let conn_clone = conn.clone();
                        let cancel_clone = cancel.clone();
                        let conn_ref = connection.clone();
                        tokio::spawn(async move {
                            if let Err(e) = writer_task(conn_clone, peer, outgoing_rx, cancel_clone).await {
                                error!("Writer task error for peer {:?}: {}", hex::encode(&peer.as_ref()[..8]), e);
                            }
                            conn_ref.mark_dead().await;
                        });

                        // Handle the SYN packet (creates stream, sends SYN-ACK)
                        match connection.handle_packet(packet).await {
                            Err(e) => {
                                warn!("Error handling SYN packet from peer {:?}: {}", hex::encode(&peer.as_ref()[..8]), e);
                                continue;
                            }
                            Ok(false) => {
                                // Duplicate SYN on a brand-new connection — shouldn't
                                // happen, but handle gracefully.
                                debug!("Duplicate SYN on new connection from {:?}", hex::encode(&peer.as_ref()[..8]));
                                continue;
                            }
                            Ok(true) => {}
                        }

                        // Route the accepted stream to the port listener
                        // The stream was just accepted — fetch it from the connection
                        if let Ok(stream) = connection.accept_stream().await {
                            let listeners_guard = listeners.read().await;
                            if let Some(tx) = listeners_guard.get(&port) {
                                let stream_arc = Arc::new(stream);
                                if tx.send(stream_arc).await.is_err() {
                                    warn!("Listener channel closed for port {}", port);
                                }
                            }
                        }
                    } else {
                        trace!("Received packet from unknown peer {:?}, ignoring", hex::encode(&peer.as_ref()[..8]));
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

/// Background writer task per connection
///
/// Aggregates packets from a connection's streams and writes them to the network.
async fn writer_task(
    conn: Arc<EncryptedPacketConn>,
    peer: Addr,
    mut outgoing: mpsc::Receiver<Packet>,
    cancel: CancellationToken,
) -> Result<()> {
    let peer_hex = hex::encode(&peer.as_ref()[..8]);
    info!("Writer task started for peer {}", peer_hex);
    let mut pkt_count = 0u64;
    loop {
        tokio::select! {
            packet = outgoing.recv() => {
                match packet {
                    Some(pkt) => {
                        let data = pkt.encode()?;
                        pkt_count += 1;
                        if pkt_count <= 5 || pkt.is_syn() || pkt_count % 100 == 0 {
                            info!("Writer sending pkt #{} ({} bytes, flags=0x{:02x}, port={}, stream={}) to {}",
                                pkt_count, data.len(), pkt.flags, pkt.port, pkt.stream_id, peer_hex);
                        }
                        if let Err(e) = conn.write_to(&data, &peer).await {
                            error!("write_to failed for peer {}: {}", peer_hex, e);
                            return Err(e.into());
                        }
                        // Yield after each write so ironwood's internal queues can
                        // drain before the next packet is submitted.  Without this,
                        // rapid-fire writes overflow ironwood's delivery queue and
                        // packets older than 25ms are silently dropped.
                        tokio::task::yield_now().await;
                    }
                    None => {
                        info!("Outgoing channel closed for peer {} (sent {} pkts)", peer_hex, pkt_count);
                        return Ok(());
                    }
                }
            }
            _ = cancel.cancelled() => {
                info!("Writer task cancelled for peer {} (sent {} pkts)", peer_hex, pkt_count);
                return Ok(());
            }
        }
    }
}

impl Drop for StreamManager {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ironwood::new_encrypted_packet_conn;

    #[tokio::test]
    async fn test_manager_creation() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let manager = StreamManager::new(conn);

        assert_eq!(manager.connection_count().await, 0);
    }

    #[tokio::test]
    async fn test_manager_local_addr() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let local_addr = conn.local_addr();

        let manager = StreamManager::new(conn);
        assert_eq!(manager.local_addr(), local_addr);
    }

    #[tokio::test]
    async fn test_manager_listen() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let manager = StreamManager::new(conn);

        let listener = manager.listen(42).await;
        assert_eq!(listener.port(), 42);

        // Verify the listener is registered
        assert!(manager.listeners.read().await.contains_key(&42));
    }

    #[tokio::test]
    async fn test_manager_listen_datagram() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let manager = StreamManager::new(conn);

        let dg_listener = manager.listen_datagram(99).await;
        assert_eq!(dg_listener.port(), 99);

        // Verify the datagram listener is registered
        assert!(manager.datagram_listeners.read().await.contains_key(&99));
    }

    #[tokio::test]
    async fn test_connect_removes_stale_connection() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let manager = StreamManager::new(conn);

        let peer = Addr::from([42u8; 32]);

        // Manually insert a dead connection
        let (tx, _rx) = mpsc::channel(256);
        let dead_conn = Arc::new(Connection::new_initiator(peer, tx));
        dead_conn.mark_dead().await;
        assert!(!dead_conn.is_alive());
        {
            let mut conns = manager.connections.write().await;
            conns.insert(peer, dead_conn.clone());
        }
        assert_eq!(manager.connection_count().await, 1);

        // connect() should detect the stale connection, remove it, and create a new one
        let new_conn = manager.connect(peer).await.unwrap();
        assert!(new_conn.is_alive());
        assert_eq!(manager.connection_count().await, 1);
        // The new connection should be a different Arc (not the dead one)
        assert!(new_conn.is_alive());
    }

    #[tokio::test]
    async fn test_connect_reuses_alive_connection() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let manager = StreamManager::new(conn);

        let peer = Addr::from([7u8; 32]);

        // First connect creates a new connection
        let conn1 = manager.connect(peer).await.unwrap();
        assert!(conn1.is_alive());
        assert_eq!(manager.connection_count().await, 1);

        // Second connect reuses it
        let conn2 = manager.connect(peer).await.unwrap();
        assert_eq!(manager.connection_count().await, 1);
        // Both should be the same Arc
        assert!(Arc::ptr_eq(&conn1, &conn2));
    }

    #[tokio::test]
    async fn test_connect_handle_removes_stale_connection() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let manager = StreamManager::new(conn);
        let handle = manager.split();

        let peer = Addr::from([99u8; 32]);

        // Manually insert a dead connection via the shared map
        let (tx, _rx) = mpsc::channel(256);
        let dead_conn = Arc::new(Connection::new_initiator(peer, tx));
        dead_conn.mark_dead().await;
        {
            let mut conns = handle.connections.write().await;
            conns.insert(peer, dead_conn);
        }

        // connect() should remove it and create a fresh one
        let new_conn = handle.connect(peer).await.unwrap();
        assert!(new_conn.is_alive());
    }

    #[tokio::test]
    async fn test_connect_handle_close_connection() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let manager = StreamManager::new(conn);
        let handle = manager.split();

        let peer = Addr::from([55u8; 32]);

        let connection = handle.connect(peer).await.unwrap();
        assert!(connection.is_alive());

        // close_connection removes and closes it
        handle.close_connection(peer).await;

        // The connection map should no longer contain this peer
        let conns = handle.connections.read().await;
        assert!(!conns.contains_key(&peer));
    }

    #[tokio::test]
    async fn test_connect_handle_close_connection_nonexistent_peer() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let manager = StreamManager::new(conn);
        let handle = manager.split();

        // Should not panic on non-existent peer
        let peer = Addr::from([0u8; 32]);
        handle.close_connection(peer).await;
    }

    #[tokio::test]
    async fn test_writer_task_exit_marks_connection_dead() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let manager = StreamManager::new(conn);

        let peer = Addr::from([11u8; 32]);
        let connection = manager.connect(peer).await.unwrap();
        assert!(connection.is_alive());

        // Close the connection — this cancels the token which makes the writer
        // task exit. After that, mark_dead should also fire. We just verify the
        // connection is no longer alive after close.
        connection.close().await;
        assert!(!connection.is_alive());
    }
}
