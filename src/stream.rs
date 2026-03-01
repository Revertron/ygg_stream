use crate::error::{Error, Result};
use crate::protocol::{Packet, DEFAULT_WINDOW_SIZE, MAX_DATA_SIZE};
use ironwood::Addr;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// SYN sent, waiting for SYN-ACK
    Opening,
    /// Active, can send/receive
    Open,
    /// FIN sent, waiting for peer FIN
    Closing,
    /// Both sides closed
    Closed,
}

/// Individual bidirectional stream
///
/// Implements AsyncRead + AsyncWrite for standard Rust async I/O.
#[derive(Clone)]
pub struct Stream {
    /// Port number
    port: u16,

    /// Stream identifier
    id: u16,

    /// Remote peer address (for debugging/logging)
    peer: Addr,

    /// Receive buffer (data received from peer)
    recv_buf: Arc<Mutex<VecDeque<u8>>>,

    /// Send window (bytes we can send based on peer's last ACK)
    send_window: Arc<AtomicU32>,

    /// Receive window (bytes we can receive - our buffer space)
    recv_window: Arc<AtomicU32>,

    /// Channel to send outgoing packets
    outgoing: mpsc::Sender<Packet>,

    /// Stream state
    state: Arc<Mutex<StreamState>>,

    /// Registered wakers (None = no one waiting)
    read_waker: Arc<Mutex<Option<Waker>>>,
    write_waker: Arc<Mutex<Option<Waker>>>,
    close_waker: Arc<Mutex<Option<Waker>>>,
}

impl Stream {
    /// Create a new stream
    pub fn new(port: u16, id: u16, peer: Addr, outgoing: mpsc::Sender<Packet>) -> Self {
        Self {
            port,
            id,
            peer,
            recv_buf: Arc::new(Mutex::new(VecDeque::new())),
            send_window: Arc::new(AtomicU32::new(DEFAULT_WINDOW_SIZE)),
            recv_window: Arc::new(AtomicU32::new(DEFAULT_WINDOW_SIZE)),
            outgoing,
            state: Arc::new(Mutex::new(StreamState::Opening)),
            read_waker: Arc::new(Mutex::new(None)),
            write_waker: Arc::new(Mutex::new(None)),
            close_waker: Arc::new(Mutex::new(None)),
        }
    }

    /// Get stream ID
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Get port number
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get remote peer address
    pub fn peer_addr(&self) -> Addr {
        self.peer
    }

    /// Get current stream state
    pub async fn state(&self) -> StreamState {
        *self.state.lock().await
    }

    /// Transition stream to Open state (used for acceptor side)
    pub(crate) async fn transition_to_open(&self) {
        let mut state = self.state.lock().await;
        *state = StreamState::Open;
        self.wake_writer();
    }

    /// Handle incoming packet
    pub async fn handle_packet(&self, packet: Packet) -> Result<()> {
        let mut state = self.state.lock().await;

        match *state {
            StreamState::Opening => {
                if packet.is_syn() && packet.is_ack() {
                    // Received SYN-ACK, transition to Open
                    *state = StreamState::Open;
                    // Update send window from SYN-ACK
                    self.send_window.store(packet.window, Ordering::Release);
                    self.wake_writer();
                    Ok(())
                } else {
                    Err(Error::Protocol(format!(
                        "Unexpected packet in Opening state: flags={:02x}",
                        packet.flags
                    )))
                }
            }
            StreamState::Open => {
                if packet.is_rst() {
                    // Stream reset by peer
                    *state = StreamState::Closed;
                    self.wake_reader();  // Instead of read_notify.notify_waiters()
                    self.wake_writer();
                    self.wake_closer();
                    return Err(Error::StreamReset);
                }

                if packet.is_fin() {
                    // Peer initiated close - send FIN back and transition to Closed
                    *state = StreamState::Closed;
                    self.wake_reader();
                    self.wake_closer();

                    // Release the lock before sending FIN
                    drop(state);

                    // Send FIN to acknowledge
                    let fin = Packet::fin(self.port, self.id);
                    let _ = self.outgoing.send(fin).await;

                    return Ok(());
                }

                // Update send window if ACK
                if packet.is_ack() {
                    self.send_window.store(packet.window, Ordering::Release);
                    self.wake_writer();  // Writer might have room now
                }

                // Deliver data if present
                if !packet.data.is_empty() {
                    let mut recv_buf = self.recv_buf.lock().await;
                    recv_buf.extend(&packet.data);

                    // Update our receive window
                    let available = DEFAULT_WINDOW_SIZE.saturating_sub(recv_buf.len() as u32);
                    self.recv_window.store(available, Ordering::Release);

                    // Send ACK with updated window
                    drop(recv_buf); // Release lock before sending
                    self.wake_reader();  // Data available!
                    self.send_ack().await?;
                }

                Ok(())
            }
            StreamState::Closing => {
                if packet.is_fin() {
                    // Both sides closed
                    *state = StreamState::Closed;
                    self.wake_closer();
                }
                Ok(())
            }
            StreamState::Closed => {
                // Ignore packets on closed stream
                Ok(())
            }
        }
    }

    /// Send an ACK packet with current receive window
    async fn send_ack(&self) -> Result<()> {
        let window = self.recv_window.load(Ordering::Acquire);
        let packet = Packet::ack(self.port, self.id, window);
        self.outgoing
            .send(packet)
            .await
            .map_err(|_| Error::ConnectionClosed)?;
        Ok(())
    }

    /// Send a SYN packet to initiate the stream
    pub async fn send_syn(&self) -> Result<()> {
        let packet = Packet::syn(self.port, self.id);
        self.outgoing
            .send(packet)
            .await
            .map_err(|_| Error::ConnectionClosed)?;
        Ok(())
    }

    /// Immediate close (RST)
    pub async fn abort(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if *state == StreamState::Closed {
            return Ok(());
        }

        *state = StreamState::Closed;
        let packet = Packet::rst(self.port, self.id);
        let _ = self.outgoing.send(packet).await;

        self.wake_reader();
        self.wake_writer();
        self.wake_closer();

        Ok(())
    }

    /// Graceful close (FIN)
    pub async fn close(&self) -> Result<()> {
        let mut state = self.state.lock().await;

        match *state {
            StreamState::Closed => return Ok(()),
            StreamState::Closing => {
                // Already closing, wait for completion
                drop(state);
                self.wake_closer();
                return Ok(());
            }
            _ => {}
        }

        *state = StreamState::Closing;
        let packet = Packet::fin(self.port, self.id);
        self.outgoing
            .send(packet)
            .await
            .map_err(|_| Error::ConnectionClosed)?;

        drop(state);

        // Wait for peer's FIN
        self.wake_closer();
        Ok(())
    }

    /// Check if stream is closed
    pub async fn is_closed(&self) -> bool {
        *self.state.lock().await == StreamState::Closed
    }

    /// Wake registered reader if any
    fn wake_reader(&self) {
        if let Ok(mut waker) = self.read_waker.try_lock() {
            if let Some(w) = waker.take() {
                w.wake();
            }
        }
    }

    /// Wake registered writer if any
    fn wake_writer(&self) {
        if let Ok(mut waker) = self.write_waker.try_lock() {
            if let Some(w) = waker.take() {
                w.wake();
            }
        }
    }

    /// Wake registered close waiter if any
    fn wake_closer(&self) {
        if let Ok(mut waker) = self.close_waker.try_lock() {
            if let Some(w) = waker.take() {
                w.wake();
            }
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>,cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Try non-blocking lock on recv_buf
        let mut recv_buf = match this.recv_buf.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        // Data available? Return immediately
        if !recv_buf.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), recv_buf.len());
            let (head, tail) = recv_buf.as_slices();

            if to_read <= head.len() {
                buf.put_slice(&head[..to_read]);
            } else {
                buf.put_slice(head);
                buf.put_slice(&tail[..to_read - head.len()]);
            }
            drop(recv_buf.drain(..to_read));

            if recv_buf.is_empty() {
                recv_buf.shrink_to_fit();
            }

            let available = DEFAULT_WINDOW_SIZE.saturating_sub(recv_buf.len() as u32);
            this.recv_window.store(available, Ordering::Release);

            return Poll::Ready(Ok(()));
        }

        // No data - check state
        drop(recv_buf); // Release lock before checking state

        let state = match this.state.try_lock() {
            Ok(guard) => *guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        match state {
            StreamState::Closed | StreamState::Closing => Poll::Ready(Ok(())),
            _ => {
                // Register waker to be woken when data arrives
                match this.read_waker.try_lock() {
                    Ok(mut waker) => {
                        *waker = Some(cx.waker().clone());
                    }
                    Err(_) => {
                        cx.waker().wake_by_ref();
                    }
                }
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>,cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        let state = match this.state.try_lock() {
            Ok(guard) => *guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if state == StreamState::Closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Stream closed",
            )));
        }

        if state != StreamState::Open {
            // Register waker for when state changes to Open
            match this.write_waker.try_lock() {
                Ok(mut waker) => *waker = Some(cx.waker().clone()),
                Err(_) => cx.waker().wake_by_ref(),
            }
            return Poll::Pending;
        }

        let window = this.send_window.load(Ordering::Acquire);
        if window == 0 {
            // Register waker for when window opens
            match this.write_waker.try_lock() {
                Ok(mut waker) => *waker = Some(cx.waker().clone()),
                Err(_) => cx.waker().wake_by_ref(),
            }
            return Poll::Pending;
        }

        let to_send = buf.len().min(window as usize).min(MAX_DATA_SIZE);
        let data = buf[..to_send].to_vec();
        let window_after = this.recv_window.load(Ordering::Acquire);
        let packet = Packet::data_ack(this.port, this.id, data, window_after);

        this.send_window.fetch_sub(to_send as u32, Ordering::Release);

        match this.outgoing.try_send(packet) {
            Ok(()) => Poll::Ready(Ok(to_send)),
            Err(mpsc::error::TrySendError::Full(_)) => {
                this.send_window.fetch_add(to_send as u32, Ordering::Release);
                // Register waker for when channel has space
                let waker = cx.waker().clone();
                let outgoing = this.outgoing.clone();
                // For channel backpressure, we still need to spawn or use a different mechanism
                // Option: store waker and have a separate task that polls channel readiness
                tokio::spawn(async move {
                    let _ = outgoing.reserve().await;
                    waker.wake();
                });
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "outgoing channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>,cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        let state = match this.state.try_lock() {
            Ok(mut guard) => {
                let current = *guard;
                if current == StreamState::Open {
                    *guard = StreamState::Closing;
                    drop(guard);
                    let packet = Packet::fin(this.port, this.id);
                    let _ = this.outgoing.try_send(packet);
                }
                current
            }
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if state == StreamState::Closed {
            return Poll::Ready(Ok(()));
        }

        // Register waker for close completion
        match this.close_waker.try_lock() {
            Ok(mut waker) => *waker = Some(cx.waker().clone()),
            Err(_) => cx.waker().wake_by_ref(),
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{FLAG_ACK, FLAG_SYN};

    #[tokio::test]
    async fn test_stream_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        assert_eq!(stream.id(), 1);
        assert_eq!(stream.port(), 1);
        assert_eq!(stream.state().await, StreamState::Opening);
        assert_eq!(stream.peer_addr(), Addr::from([0u8; 32]));
    }

    #[tokio::test]
    async fn test_stream_state_transitions() {
        let (tx, _rx) = mpsc::channel(10);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        // Initial state
        assert_eq!(stream.state().await, StreamState::Opening);

        // Receive SYN-ACK -> Open
        let syn_ack = Packet::syn_ack(1, 1);
        stream.handle_packet(syn_ack).await.unwrap();
        assert_eq!(stream.state().await, StreamState::Open);

        // Note: close() waits for peer's FIN, so we can't fully test it in isolation
        // Just verify we can initiate the close
        let close_task = tokio::spawn({
            let stream = stream.clone();
            async move {
                stream.close().await
            }
        });

        // Give it a moment to send FIN
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert_eq!(stream.state().await, StreamState::Closing);

        // Abort the close task since we can't complete it in unit test
        close_task.abort();
    }

    #[tokio::test]
    async fn test_stream_abort() {
        let (tx, mut rx) = mpsc::channel(10);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        // Transition to Open first
        let syn_ack = Packet::syn_ack(1, 1);
        stream.handle_packet(syn_ack).await.unwrap();

        // Abort stream
        stream.abort().await.unwrap();
        assert_eq!(stream.state().await, StreamState::Closed);

        // Should have sent RST packet
        let packet = rx.recv().await.unwrap();
        assert!(packet.is_rst());
        assert_eq!(packet.stream_id, 1);
    }

    #[tokio::test]
    async fn test_stream_data_delivery() {
        let (tx, _rx) = mpsc::channel(10);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        // Transition to Open
        let syn_ack = Packet::syn_ack(1, 1);
        stream.handle_packet(syn_ack).await.unwrap();

        // Deliver data
        let data_packet = Packet::data(1, 1, b"hello".to_vec());
        stream.handle_packet(data_packet).await.unwrap();

        // Check recv_buf has data
        let recv_buf = stream.recv_buf.lock().await;
        assert_eq!(recv_buf.len(), 5);
        let data: Vec<u8> = recv_buf.iter().copied().collect();
        assert_eq!(data, b"hello");
    }

    #[tokio::test]
    async fn test_stream_flow_control() {
        let (tx, _rx) = mpsc::channel(10);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        // Initial send window
        assert_eq!(
            stream.send_window.load(Ordering::Acquire),
            DEFAULT_WINDOW_SIZE
        );

        // Receive ACK with new window
        let ack = Packet {
            port: 1,
            stream_id: 1,
            flags: FLAG_ACK | FLAG_SYN,
            data: Vec::new(),
            window: 1024u32,
        };
        stream.handle_packet(ack).await.unwrap();

        // Window should be updated
        assert_eq!(stream.send_window.load(Ordering::Acquire), 1024);
    }

    #[tokio::test]
    async fn test_stream_reset_on_rst() {
        let (tx, _rx) = mpsc::channel(10);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        // Transition to Open
        let syn_ack = Packet::syn_ack(1, 1);
        stream.handle_packet(syn_ack).await.unwrap();
        assert_eq!(stream.state().await, StreamState::Open);

        // Receive RST
        let rst = Packet::rst(1, 1);
        let result = stream.handle_packet(rst).await;
        assert!(matches!(result, Err(Error::StreamReset)));
        assert_eq!(stream.state().await, StreamState::Closed);
    }
}
