//! TCP port forwarding through the Yggdrasil mesh network.
//!
//! Two proxy directions:
//!
//! - [`TcpToYgg`]: binds a local TCP port, forwards each incoming connection
//!   through Yggdrasil to a remote peer's ygg_stream port.
//! - [`YggToTcp`]: listens on a ygg_stream port, forwards each incoming
//!   Yggdrasil stream to a local TCP address.
//!
//! # Example
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use ygg_stream::{AsyncNode, TcpToYgg};
//! use tokio_util::sync::CancellationToken;
//!
//! let node = Arc::new(AsyncNode::new("tcp://peer:1234").await?);
//! let proxy = TcpToYgg::new(
//!     node,
//!     "127.0.0.1:9055".parse()?,
//!     remote_key,
//!     80,
//! );
//! proxy.run(CancellationToken::new()).await?;
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::async_node::AsyncNode;
use crate::stream::Stream;

// ── TcpToYgg (local forward) ────────────────────────────────────────────────

/// Forward local TCP connections to a remote Yggdrasil peer.
///
/// Binds to `bind_addr` and, for each incoming TCP connection, opens a
/// ygg_stream to `remote_key:remote_port` and copies data bidirectionally.
pub struct TcpToYgg {
    node: Arc<AsyncNode>,
    bind_addr: SocketAddr,
    remote_key: [u8; 32],
    remote_port: u16,
}

impl TcpToYgg {
    pub fn new(
        node: Arc<AsyncNode>,
        bind_addr: SocketAddr,
        remote_key: [u8; 32],
        remote_port: u16,
    ) -> Self {
        Self {
            node,
            bind_addr,
            remote_key,
            remote_port,
        }
    }

    /// Run the proxy until `cancel` is triggered.
    pub async fn run(&self, cancel: CancellationToken) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        info!(
            "TcpToYgg: listening on {} -> ygg://{}:{}",
            self.bind_addr,
            hex::encode(&self.remote_key[..8]),
            self.remote_port
        );

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (tcp_stream, peer_addr) = result?;
                    debug!("TcpToYgg: accepted TCP from {}", peer_addr);

                    let node = self.node.clone();
                    let remote_key = self.remote_key;
                    let remote_port = self.remote_port;
                    let cancel = cancel.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_to_ygg(
                            tcp_stream, node, remote_key, remote_port, cancel,
                        ).await {
                            warn!("TcpToYgg: connection from {} failed: {}", peer_addr, e);
                        }
                    });
                }
                _ = cancel.cancelled() => {
                    info!("TcpToYgg: shutting down");
                    return Ok(());
                }
            }
        }
    }
}

// ── YggToTcp (reverse forward) ──────────────────────────────────────────────

/// Forward incoming Yggdrasil streams to a local TCP address.
///
/// Listens on ygg_stream `listen_port` and, for each incoming stream, opens a
/// TCP connection to `target_addr` and copies data bidirectionally.
pub struct YggToTcp {
    node: Arc<AsyncNode>,
    listen_port: u16,
    target_addr: SocketAddr,
}

impl YggToTcp {
    pub fn new(node: Arc<AsyncNode>, listen_port: u16, target_addr: SocketAddr) -> Self {
        Self {
            node,
            listen_port,
            target_addr,
        }
    }

    /// Run the proxy until `cancel` is triggered.
    pub async fn run(&self, cancel: CancellationToken) -> Result<(), String> {
        let mut listener = self.node.listen(self.listen_port).await;
        info!(
            "YggToTcp: listening on ygg port {} -> tcp://{}",
            self.listen_port, self.target_addr
        );

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let stream = result.map_err(|e| e.to_string())?;
                    let peer_key = hex::encode(&stream.peer_addr().as_ref()[..8]);
                    debug!("YggToTcp: accepted stream from peer {}", peer_key);

                    let target_addr = self.target_addr;
                    let cancel = cancel.clone();
                    let peer_key_owned = peer_key.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_ygg_to_tcp(
                            stream, target_addr, cancel,
                        ).await {
                            warn!("YggToTcp: stream from {} failed: {}", peer_key_owned, e);
                        }
                    });
                }
                _ = cancel.cancelled() => {
                    info!("YggToTcp: shutting down");
                    return Ok(());
                }
            }
        }
    }
}

// ── internal handlers ───────────────────────────────────────────────────────

async fn handle_tcp_to_ygg(
    mut tcp: TcpStream,
    node: Arc<AsyncNode>,
    remote_key: [u8; 32],
    remote_port: u16,
    cancel: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn = node
        .connect(&remote_key, remote_port)
        .await
        .map_err(|e| format!("ygg connect: {}", e))?;

    let mut ygg = conn.into_stream();

    debug!(
        "TcpToYgg: connected to {}:{}",
        hex::encode(&remote_key[..8]),
        remote_port
    );

    tokio::select! {
        result = copy_bidirectional(&mut tcp, &mut ygg) => {
            match result {
                Ok((up, down)) => debug!("TcpToYgg: done  up={} down={}", up, down),
                Err(e) => debug!("TcpToYgg: copy error: {}", e),
            }
        }
        _ = cancel.cancelled() => {
            debug!("TcpToYgg: cancelled");
        }
    }

    let _ = ygg.shutdown().await;
    Ok(())
}

async fn handle_ygg_to_tcp(
    mut ygg: Stream,
    target_addr: SocketAddr,
    cancel: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tcp = TcpStream::connect(target_addr).await?;

    debug!("YggToTcp: connected to local {}", target_addr);

    tokio::select! {
        result = copy_bidirectional(&mut ygg, &mut tcp) => {
            match result {
                Ok((down, up)) => debug!("YggToTcp: done  down={} up={}", down, up),
                Err(e) => debug!("YggToTcp: copy error: {}", e),
            }
        }
        _ = cancel.cancelled() => {
            debug!("YggToTcp: cancelled");
        }
    }

    let _ = ygg.shutdown().await;
    Ok(())
}
