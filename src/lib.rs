//! TCP/KEY — TCP-like transport over Yggdrasil mesh network
//!
//! This crate provides TCP semantics over ironwood's `EncryptedPacketConn`,
//! using 32-byte ed25519 public keys instead of IPv4 addresses.
//!
//! - Standard TCP state machine (RFC 793)
//! - Port-based service routing (16-bit ports)
//! - AsyncRead/AsyncWrite on each connection
//! - UniFFI bindings for Kotlin/Swift mobile apps
//!
//! # Architecture
//!
//! ```text
//! Application
//!     ↓
//! TCP/KEY (TcpStack → TcpConnection)
//!     ↓
//! ironwood (encrypted PacketConn, public key addressing)
//! ```

// UniFFI scaffolding — must be in the crate root.
#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!("ygg_stream");

pub mod async_node;
pub mod connection;
pub mod error;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod manager;
pub mod node;
pub mod protocol;

// Re-export main types
pub use async_node::{AsyncConn, AsyncNode};
pub use connection::{ConnKey, TcpConnection, TcpState};
pub use error::{Error, Result};
pub use manager::{ConnectHandle, DatagramListener, TcpListener, TcpStack};
pub use node::{Conn, Node};
pub use ironwood::Addr;
pub use protocol::{Packet, DEFAULT_WINDOW_SIZE, MAX_PACKET_SIZE};
