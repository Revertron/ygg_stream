use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::protocol::Packet;
use crate::stream::Stream;
use ironwood::{Addr, EncryptedPacketConn, PacketConn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, trace, warn};

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

    /// Cancellation token for graceful shutdown
    cancel: CancellationToken,
}

impl StreamManager {
    /// Create a new stream manager
    pub fn new(conn: Arc<EncryptedPacketConn>) -> Self {
        let listeners: Arc<RwLock<HashMap<u16, mpsc::Sender<Arc<Stream>>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let manager = Self {
            conn: conn.clone(),
            connections: Arc::new(RwLock::new(HashMap::new())),
            listeners: listeners.clone(),
            cancel: CancellationToken::new(),
        };

        // Spawn background reader task
        let connections = manager.connections.clone();
        let cancel = manager.cancel.clone();
        tokio::spawn(async move {
            if let Err(e) = reader_task(conn, connections, listeners, cancel).await {
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

    /// Connect to a peer (or reuse existing connection)
    pub async fn connect(&self, peer: Addr) -> Result<Arc<Connection>> {
        // Check if connection already exists
        {
            let connections = self.connections.read().await;
            if let Some(conn) = connections.get(&peer) {
                if conn.is_alive() {
                    debug!("Reusing existing connection to peer {:?}", &peer.as_ref()[..8]);
                    return Ok(conn.clone());
                }
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

        // Spawn writer task for this connection
        let conn = self.conn.clone();
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            if let Err(e) = writer_task(conn, peer, outgoing_rx, cancel).await {
                error!("Writer task error for peer {:?}: {}", &peer.as_ref()[..8], e);
            }
        });

        debug!("Created new connection to peer {:?}", &peer.as_ref()[..8]);

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
    cancel: CancellationToken,
}

impl ConnectHandle {
    /// Connect to a peer (or reuse existing connection).
    pub async fn connect(&self, peer: Addr) -> Result<Arc<Connection>> {
        // Check if connection already exists
        {
            let connections = self.connections.read().await;
            if let Some(conn) = connections.get(&peer) {
                if conn.is_alive() {
                    debug!("Reusing existing connection to peer {:?}", &peer.as_ref()[..8]);
                    return Ok(conn.clone());
                }
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

        // Spawn writer task for this connection
        let conn = self.conn.clone();
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            if let Err(e) = writer_task(conn, peer, outgoing_rx, cancel).await {
                error!("Writer task error for peer {:?}: {}", &peer.as_ref()[..8], e);
            }
        });

        debug!("Created new connection to peer {:?}", &peer.as_ref()[..8]);
        Ok(connection)
    }

    /// Register a listener for the given port.
    pub async fn listen(&self, port: u16) -> Listener {
        let (tx, rx) = mpsc::channel(16);
        self.listeners.write().await.insert(port, tx);
        Listener { port, rx }
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
    cancel: CancellationToken,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            result = conn.read_from(&mut buf) => {
                let (n, peer) = result?;
                trace!("Received {} bytes from peer {:?}", n, &peer.as_ref()[..8]);

                // Decode packet
                let packet = match Packet::decode(&buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Failed to decode packet from peer {:?}: {}", &peer.as_ref()[..8], e);
                        continue;
                    }
                };

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
                            warn!("No listener for port {} from peer {:?}, sending RST", port, &peer.as_ref()[..8]);
                            let rst = Packet::rst(port, packet.stream_id);
                            let rst_data = match rst.encode() {
                                Ok(d) => d,
                                Err(_) => continue,
                            };
                            let _ = conn.write_to(&rst_data, &peer).await;
                            continue;
                        }
                    }

                    if let Err(e) = conn_arc.handle_packet(packet).await {
                        warn!("Error handling packet from peer {:?}: {}", &peer.as_ref()[..8], e);
                    } else if is_new_syn {
                        // Stream was just created — pull it from the connection's
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
                } else {
                    // New incoming connection
                    if packet.is_syn() && !packet.is_ack() {
                        // Check if there's a listener for this port
                        let has_listener = listeners.read().await.contains_key(&port);
                        if !has_listener {
                            warn!("No listener for port {} from new peer {:?}, sending RST", port, &peer.as_ref()[..8]);
                            let rst = Packet::rst(port, packet.stream_id);
                            let rst_data = match rst.encode() {
                                Ok(d) => d,
                                Err(_) => continue,
                            };
                            let _ = conn.write_to(&rst_data, &peer).await;
                            continue;
                        }

                        debug!("New incoming connection from peer {:?}", &peer.as_ref()[..8]);

                        // Create connection as acceptor
                        let (outgoing_tx, outgoing_rx) = mpsc::channel(256);
                        let connection = Arc::new(Connection::new_acceptor(peer, outgoing_tx));

                        // Register connection
                        {
                            let mut conns = connections.write().await;
                            conns.insert(peer, connection.clone());
                        }

                        // Spawn writer task
                        let conn_clone = conn.clone();
                        let cancel_clone = cancel.clone();
                        tokio::spawn(async move {
                            if let Err(e) = writer_task(conn_clone, peer, outgoing_rx, cancel_clone).await {
                                error!("Writer task error for peer {:?}: {}", &peer.as_ref()[..8], e);
                            }
                        });

                        // Handle the SYN packet (creates stream, sends SYN-ACK)
                        if let Err(e) = connection.handle_packet(packet).await {
                            warn!("Error handling SYN packet from peer {:?}: {}", &peer.as_ref()[..8], e);
                            continue;
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
                        trace!("Received packet from unknown peer {:?}, ignoring", &peer.as_ref()[..8]);
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
    loop {
        tokio::select! {
            packet = outgoing.recv() => {
                match packet {
                    Some(pkt) => {
                        let data = pkt.encode()?;
                        conn.write_to(&data, &peer).await?;
                        trace!("Sent {} bytes to peer {:?} (port={} stream={})", data.len(), &peer.as_ref()[..8], pkt.port, pkt.stream_id);
                    }
                    None => {
                        debug!("Outgoing channel closed for peer {:?}", &peer.as_ref()[..8]);
                        return Ok(());
                    }
                }
            }
            _ = cancel.cancelled() => {
                debug!("Writer task cancelled for peer {:?}", &peer.as_ref()[..8]);
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
}
