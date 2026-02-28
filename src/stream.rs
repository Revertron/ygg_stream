use crate::error::{Error, Result};
use crate::protocol::{Packet, DEFAULT_WINDOW_SIZE, MAX_DATA_SIZE};
use ironwood::Addr;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex, Notify};
use tracing::{debug, trace};

/// Retransmit timeout in milliseconds.
const RETRANSMIT_TIMEOUT_MS: u64 = 150;

/// Maximum bytes allowed in-flight (sent but not yet ACKed).
/// The Ironwood relay drops packets when queue age exceeds ~25ms.
/// Empirically 64KB keeps us well below the drop threshold while
/// still achieving ~2.5 MB/s throughput over a single relay hop.
const MAX_INFLIGHT: usize = 64 * 1024;


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

/// A segment held for potential retransmission.
#[derive(Clone)]
struct UnackedSegment {
    seq: u32,
    data: Vec<u8>,
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

    /// Receive buffer (data received from peer, in-order)
    recv_buf: Arc<Mutex<VecDeque<u8>>>,

    /// Send window (bytes we can send based on peer's last ACK)
    send_window: Arc<AtomicUsize>,

    /// Receive window (bytes we can receive - our buffer space)
    recv_window: Arc<AtomicUsize>,

    /// Channel to send outgoing packets
    outgoing: mpsc::Sender<Packet>,

    /// Stream state
    state: Arc<Mutex<StreamState>>,

    /// Notify when data arrives for reading
    read_notify: Arc<Notify>,

    /// Notify when window space becomes available for writing
    write_notify: Arc<Notify>,

    /// Notify when stream is closed
    close_notify: Arc<Notify>,

    // ── Reliability fields ────────────────────────────────────────────────

    /// Next byte sequence number to send (sender side)
    next_send_seq: Arc<AtomicU32>,

    /// Highest cumulative ack received from peer (sender side)
    send_ack_seq: Arc<AtomicU32>,

    /// Next expected byte sequence number (receiver side)
    next_recv_seq: Arc<AtomicU32>,

    /// Unacknowledged segments kept for retransmission (sender side)
    unacked: Arc<Mutex<VecDeque<UnackedSegment>>>,

    /// Peer has sent FIN — no more data will arrive.
    /// poll_read returns EOF only when recv_buf is empty AND this is true.
    /// Separated from `state` to avoid losing buffered data on FIN.
    peer_fin: Arc<std::sync::atomic::AtomicBool>,
}

impl Stream {
    /// Create a new stream
    pub fn new(port: u16, id: u16, peer: Addr, outgoing: mpsc::Sender<Packet>) -> Self {
        let stream = Self {
            port,
            id,
            peer,
            recv_buf: Arc::new(Mutex::new(VecDeque::new())),
            send_window: Arc::new(AtomicUsize::new(DEFAULT_WINDOW_SIZE)),
            recv_window: Arc::new(AtomicUsize::new(DEFAULT_WINDOW_SIZE)),
            outgoing: outgoing.clone(),
            state: Arc::new(Mutex::new(StreamState::Opening)),
            read_notify: Arc::new(Notify::new()),
            write_notify: Arc::new(Notify::new()),
            close_notify: Arc::new(Notify::new()),
            next_send_seq: Arc::new(AtomicU32::new(0)),
            send_ack_seq: Arc::new(AtomicU32::new(0)),
            next_recv_seq: Arc::new(AtomicU32::new(0)),
            unacked: Arc::new(Mutex::new(VecDeque::new())),
            peer_fin: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        // Spawn retransmit timer
        {
            let s = stream.clone();
            tokio::spawn(async move {
                s.retransmit_loop().await;
            });
        }

        stream
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
        self.write_notify.notify_one();
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
                    self.write_notify.notify_one();
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
                    self.read_notify.notify_waiters();
                    self.write_notify.notify_waiters();
                    self.close_notify.notify_waiters();
                    return Err(Error::StreamReset);
                }

                if packet.is_fin() {
                    // Peer finished sending — set flag so poll_read returns EOF
                    // after recv_buf is fully drained.  Do NOT set state=Closed
                    // yet: there may still be data in recv_buf that poll_read
                    // hasn't delivered to copy_bidirectional.
                    self.peer_fin.store(true, Ordering::Release);
                    self.read_notify.notify_waiters();
                    self.close_notify.notify_waiters();

                    // Release the lock before sending FIN
                    drop(state);

                    // Send FIN back to acknowledge (non-blocking to prevent deadlock)
                    let fin = Packet::fin(self.port, self.id);
                    let _ = self.outgoing.try_send(fin);

                    return Ok(());
                }

                // Update send window and ack progress if ACK
                if packet.is_ack() {
                    self.send_window.store(packet.window, Ordering::Release);

                    // Remove acked segments from retransmit buffer
                    let ack = packet.ack_seq;
                    let old_ack = self.send_ack_seq.load(Ordering::Acquire);
                    if ack > old_ack {
                        self.send_ack_seq.store(ack, Ordering::Release);
                        let mut unacked = self.unacked.lock().await;
                        while let Some(front) = unacked.front() {
                            let seg_end = front.seq + front.data.len() as u32;
                            if seg_end <= ack {
                                unacked.pop_front();
                            } else {
                                break;
                            }
                        }
                    }

                    self.write_notify.notify_one();
                }

                // Deliver data if present
                if !packet.data.is_empty() {
                    let expected = self.next_recv_seq.load(Ordering::Acquire);
                    let pkt_seq = packet.seq;
                    let pkt_end = pkt_seq + packet.data.len() as u32;
                    trace!("rx data: seq={} len={} expected={}", pkt_seq, packet.data.len(), expected);

                    if pkt_seq == expected {
                        // In-order delivery
                        let mut recv_buf = self.recv_buf.lock().await;
                        recv_buf.extend(&packet.data);
                        self.next_recv_seq.store(pkt_end, Ordering::Release);
                        self.read_notify.notify_one();

                        // Update our receive window
                        let available = DEFAULT_WINDOW_SIZE.saturating_sub(recv_buf.len());
                        self.recv_window.store(available, Ordering::Release);
                        drop(recv_buf);

                        // Send ACK with updated cumulative ack
                        self.send_ack_nonblocking();
                    } else if pkt_seq > expected {
                        // Gap detected — packet arrived out of order or earlier packets lost.
                        // Drop this packet and send a duplicate ACK for expected seq to
                        // trigger retransmission on the sender.
                        trace!("Out-of-order: expected seq={}, got seq={}, dropping", expected, pkt_seq);
                        self.send_ack_nonblocking();
                    } else {
                        // pkt_seq < expected: duplicate — ACK anyway so sender can advance
                        trace!("Duplicate: expected seq={}, got seq={}", expected, pkt_seq);
                        self.send_ack_nonblocking();
                    }
                }

                Ok(())
            }
            StreamState::Closing => {
                if packet.is_ack() {
                    // ACK in Closing state — update ack tracking
                    self.send_window.store(packet.window, Ordering::Release);
                    let ack = packet.ack_seq;
                    let old_ack = self.send_ack_seq.load(Ordering::Acquire);
                    if ack > old_ack {
                        self.send_ack_seq.store(ack, Ordering::Release);
                        let mut unacked = self.unacked.lock().await;
                        while let Some(front) = unacked.front() {
                            let seg_end = front.seq + front.data.len() as u32;
                            if seg_end <= ack {
                                unacked.pop_front();
                            } else {
                                break;
                            }
                        }
                    }
                    self.write_notify.notify_one();
                }
                if packet.is_fin() {
                    // Both sides closed
                    *state = StreamState::Closed;
                    self.peer_fin.store(true, Ordering::Release);
                    self.read_notify.notify_waiters();
                    self.close_notify.notify_waiters();
                }
                Ok(())
            }
            StreamState::Closed => {
                // Ignore packets on closed stream
                Ok(())
            }
        }
    }

    /// Send an ACK packet with cumulative ack_seq and window (non-blocking).
    ///
    /// Uses `try_send` to avoid blocking the reader task when the outgoing
    /// channel is full.  A dropped ACK is acceptable because:
    /// - The peer's next `poll_write` piggybacks an ACK via `data_ack`.
    /// - The retransmit timer will eventually trigger if the sender stalls.
    fn send_ack_nonblocking(&self) {
        let ack_seq = self.next_recv_seq.load(Ordering::Acquire);
        let window = self.recv_window.load(Ordering::Acquire);
        let packet = Packet::ack(self.port, self.id, ack_seq, window);
        match self.outgoing.try_send(packet) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                trace!("send_ack: channel full, dropping ACK (ack_seq={}, window={})", ack_seq, window);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                trace!("send_ack: channel closed");
            }
        }
    }

    /// Retransmit loop — resends unacked segments every RETRANSMIT_TIMEOUT_MS.
    ///
    /// Adaptive retransmit burst size (cwnd 1..8 segments per tick):
    /// - When ACK advances (progress), double cwnd (up to 8).
    /// - When ACK stalls for 2+ ticks, reset cwnd=1.
    ///
    /// In-flight cap is handled statically by MAX_INFLIGHT in poll_write.
    async fn retransmit_loop(&self) {
        let interval = tokio::time::Duration::from_millis(RETRANSMIT_TIMEOUT_MS);
        let mut cwnd: usize = 1;
        let mut prev_ack: u32 = 0;
        let mut stall_ticks: u32 = 0;

        loop {
            tokio::time::sleep(interval).await;

            let state = match self.state.try_lock() {
                Ok(g) => *g,
                Err(_) => {
                    trace!("Retransmit: state lock contention, skipping tick");
                    continue;
                }
            };
            if state == StreamState::Closed {
                debug!("Retransmit loop: stream closed, exiting");
                return;
            }

            let ack_seq = self.send_ack_seq.load(Ordering::Acquire);
            let next_seq = self.next_send_seq.load(Ordering::Acquire);

            // Nothing unacked
            if ack_seq >= next_seq {
                if next_seq > 0 && cwnd > 1 {
                    debug!("Retransmit: all acked, ack_seq={} next_seq={}", ack_seq, next_seq);
                }
                cwnd = 1;
                prev_ack = ack_seq;
                stall_ticks = 0;
                continue;
            }

            // Adaptive retransmit cwnd: track whether ACK is advancing
            if ack_seq > prev_ack {
                stall_ticks = 0;
                cwnd = (cwnd * 2).min(8);
            } else {
                stall_ticks += 1;
                if stall_ticks >= 2 {
                    cwnd = 1;
                }
            }
            prev_ack = ack_seq;

            // Collect segments to retransmit (under lock), then release lock
            let to_resend: Vec<(u32, Vec<u8>)> = {
                let unacked = self.unacked.lock().await;
                unacked.iter()
                    .filter(|seg| seg.seq + seg.data.len() as u32 > ack_seq)
                    .take(cwnd)
                    .map(|seg| (seg.seq, seg.data.clone()))
                    .collect()
            };
            // Lock released here

            if to_resend.is_empty() {
                continue;
            }

            let recv_ack = self.next_recv_seq.load(Ordering::Acquire);
            let window = self.recv_window.load(Ordering::Acquire);

            let mut sent = 0usize;
            for (seq, data) in &to_resend {
                let pkt = Packet::data_ack(
                    self.port, self.id,
                    data.clone(),
                    *seq,
                    recv_ack,
                    window,
                );
                match self.outgoing.try_send(pkt) {
                    Ok(()) => {
                        sent += 1;
                        trace!("retransmit: seq={} len={}", seq, data.len());
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => break,
                    Err(mpsc::error::TrySendError::Closed(_)) => return,
                }

                // Check if ACK advanced while sending
                let new_ack = self.send_ack_seq.load(Ordering::Acquire);
                if new_ack > ack_seq {
                    break;
                }
            }

            if sent > 0 {
                debug!(
                    "Retransmit: sent={} cwnd={} stall={} ack_seq={} next_send={}",
                    sent, cwnd, stall_ticks, ack_seq, next_seq
                );
            }
        }
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

        self.read_notify.notify_waiters();
        self.write_notify.notify_waiters();
        self.close_notify.notify_waiters();

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
                self.close_notify.notified().await;
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
        self.close_notify.notified().await;
        Ok(())
    }

    /// Check if stream is closed
    pub async fn is_closed(&self) -> bool {
        *self.state.lock().await == StreamState::Closed
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Try to lock recv_buf
        let mut recv_buf = match this.recv_buf.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                // Lock contention, register waker and return pending
                this.read_notify.notify_one();
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        // Check if we have data available
        if !recv_buf.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), recv_buf.len());
            let data: Vec<u8> = recv_buf.drain(..to_read).collect();
            buf.put_slice(&data);

            // Update receive window
            let old_window = this.recv_window.load(Ordering::Acquire);
            let available = DEFAULT_WINDOW_SIZE.saturating_sub(recv_buf.len());
            this.recv_window.store(available, Ordering::Release);

            // Send window update ACK when we've freed a significant amount of
            // buffer space. This prevents the sender from stalling at window=0
            // when the receiver is draining data faster than ACKs arrive.
            // Threshold: send update when window crosses the half-mark upward.
            let half = DEFAULT_WINDOW_SIZE / 2;
            if old_window < half && available >= half {
                let ack_seq = this.next_recv_seq.load(Ordering::Acquire);
                let packet = Packet::ack(this.port, this.id, ack_seq, available);
                let _ = this.outgoing.try_send(packet);
            }

            return Poll::Ready(Ok(()));
        }

        // No data available — check if peer has sent FIN or stream is closed
        if this.peer_fin.load(Ordering::Acquire) {
            // Peer sent FIN and recv_buf is empty → EOF
            debug!("poll_read: EOF (peer_fin=true, recv_buf empty)");
            return Poll::Ready(Ok(()));
        }

        let state = match this.state.try_lock() {
            Ok(guard) => *guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        match state {
            StreamState::Closed => {
                // Stream fully closed (RST or both FINs exchanged)
                Poll::Ready(Ok(()))
            }
            _ => {
                // Wait for data
                let waker = cx.waker().clone();
                let notify = this.read_notify.clone();
                tokio::spawn(async move {
                    notify.notified().await;
                    waker.wake();
                });
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Check stream state
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
            // Wait for stream to open
            let waker = cx.waker().clone();
            let notify = this.write_notify.clone();
            tokio::spawn(async move {
                notify.notified().await;
                waker.wake();
            });
            return Poll::Pending;
        }

        // Check available window
        let window = this.send_window.load(Ordering::Acquire);
        if window == 0 {
            // No space available, wait for ACK
            trace!("poll_write: window=0, waiting for ACK");
            let waker = cx.waker().clone();
            let notify = this.write_notify.clone();
            tokio::spawn(async move {
                notify.notified().await;
                waker.wake();
            });
            return Poll::Pending;
        }

        // Limit in-flight data to MAX_INFLIGHT to avoid overwhelming the
        // Ironwood relay (drops packets when queue age exceeds ~25ms).
        let next_seq = this.next_send_seq.load(Ordering::Acquire);
        let ack_seq_val = this.send_ack_seq.load(Ordering::Acquire);
        let in_flight = next_seq.saturating_sub(ack_seq_val) as usize;
        let effective_wnd = window.min(MAX_INFLIGHT);
        let available = effective_wnd.saturating_sub(in_flight);
        if available == 0 {
            trace!("poll_write: in_flight={} >= effective_wnd={}, waiting", in_flight, effective_wnd);
            let waker = cx.waker().clone();
            let notify = this.write_notify.clone();
            tokio::spawn(async move {
                notify.notified().await;
                waker.wake();
            });
            return Poll::Pending;
        }

        // Send what we can within the available window, capped by segment size
        let to_send = buf.len().min(available).min(MAX_DATA_SIZE);
        let data = buf[..to_send].to_vec();

        // Assign sequence number
        let seq = this.next_send_seq.fetch_add(to_send as u32, Ordering::AcqRel);
        let ack_seq = this.next_recv_seq.load(Ordering::Acquire);
        let recv_window = this.recv_window.load(Ordering::Acquire);
        let packet = Packet::data_ack(this.port, this.id, data.clone(), seq, ack_seq, recv_window);

        // Enqueue the packet synchronously via try_send to preserve ordering.
        //
        // The original code used tokio::spawn + outgoing.send() which caused
        // data reordering: two consecutive poll_write calls could spawn tasks
        // that race for the mpsc channel, delivering packets out of order.
        //
        // try_send guarantees that if it succeeds, the packet is already in
        // the channel in FIFO order before we return Ready.
        match this.outgoing.try_send(packet) {
            Ok(()) => {
                // Store segment for potential retransmission
                {
                    // Use try_lock to avoid blocking in poll context
                    if let Ok(mut unacked) = this.unacked.try_lock() {
                        unacked.push_back(UnackedSegment { seq, data });
                    }
                }

                // Packet enqueued — decrease send window and report success
                this.send_window.fetch_sub(to_send, Ordering::Release);
                trace!("poll_write: sent {} bytes seq={}, window now {}", to_send, seq,
                    this.send_window.load(Ordering::Acquire));
                Poll::Ready(Ok(to_send))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel full — revert seq counter since packet was NOT sent
                this.next_send_seq.fetch_sub(to_send as u32, Ordering::AcqRel);

                // Return Pending and wake when space is available.
                // We did NOT consume any bytes from buf, so the caller will
                // retry with the same data.
                trace!("poll_write: channel FULL for {} bytes, returning Pending", to_send);
                let waker = cx.waker().clone();
                let outgoing = this.outgoing.clone();
                tokio::spawn(async move {
                    // reserve() completes when channel has capacity
                    match outgoing.reserve().await {
                        Ok(permit) => drop(permit), // release the reserved slot
                        Err(_) => {} // channel closed, waker will handle it
                    }
                    waker.wake();
                });
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Outgoing channel closed",
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // No internal write buffer; flush is a no-op
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        let state = match this.state.try_lock() {
            Ok(guard) => *guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if state == StreamState::Closed {
            return Poll::Ready(Ok(()));
        }

        // Before sending FIN, wait for all sent data to be acknowledged.
        // Otherwise the peer may FIN back before it receives all our data,
        // and the retransmit loop exits on Closed state.
        let ack_seq = this.send_ack_seq.load(Ordering::Acquire);
        let next_seq = this.next_send_seq.load(Ordering::Acquire);
        if ack_seq < next_seq {
            // Still have unacked data — wait for ACKs
            trace!("poll_shutdown: waiting for ACK (ack={}, next={})", ack_seq, next_seq);
            let waker = cx.waker().clone();
            let notify = this.write_notify.clone();
            tokio::spawn(async move {
                notify.notified().await;
                waker.wake();
            });
            return Poll::Pending;
        }

        // All data acked, now send FIN (if we haven't already)
        if state == StreamState::Open {
            match this.state.try_lock() {
                Ok(mut guard) => {
                    if *guard == StreamState::Open {
                        // If peer already sent FIN, go straight to Closed
                        // (we already sent FIN back in handle_packet).
                        if this.peer_fin.load(Ordering::Acquire) {
                            *guard = StreamState::Closed;
                            drop(guard);
                            return Poll::Ready(Ok(()));
                        }
                        *guard = StreamState::Closing;
                        drop(guard);

                        let packet = Packet::fin(this.port, this.id);
                        let outgoing = this.outgoing.clone();
                        tokio::spawn(async move {
                            let _ = outgoing.send(packet).await;
                        });
                    }
                }
                Err(_) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
        }

        // If peer already sent FIN, we're done
        if this.peer_fin.load(Ordering::Acquire) {
            match this.state.try_lock() {
                Ok(mut guard) => {
                    *guard = StreamState::Closed;
                }
                Err(_) => {}
            }
            return Poll::Ready(Ok(()));
        }

        // Wait for peer's FIN
        let waker = cx.waker().clone();
        let notify = this.close_notify.clone();
        tokio::spawn(async move {
            notify.notified().await;
            waker.wake();
        });
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
            seq: 0,
            ack_seq: 0,
            window: 1024,
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
