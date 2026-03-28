use thiserror::Error;

/// Errors that can occur in TCP/KEY operations
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Ironwood error
    #[error("Ironwood error: {0}")]
    Ironwood(#[from] ironwood::Error),

    /// Protocol error (malformed packet, invalid state transition, etc.)
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Connection closed by remote peer
    #[error("Connection closed by peer")]
    ConnectionClosed,

    /// Connection was reset (aborted)
    #[error("Connection reset")]
    ConnectionReset,

    /// Connection already exists
    #[error("Connection already exists: local_port={0} remote_port={1}")]
    ConnectionExists(u16, u16),

    /// No listener registered for port
    #[error("No listener for port {0}")]
    PortNotListened(u16),

    /// Packet too large
    #[error("Packet too large: {0} bytes (max {1})")]
    PacketTooLarge(usize, usize),

    /// Timeout waiting for operation
    #[error("Operation timed out")]
    Timeout,

    /// Flow control violation
    #[error("Flow control violation: attempted to send {0} bytes but window is {1}")]
    FlowControl(usize, usize),
}

pub type Result<T> = std::result::Result<T, Error>;
