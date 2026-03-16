use crate::error::{Error, Result};
use crate::protocol::{
    Packet, DEFAULT_WINDOW_SIZE, MAX_INFLIGHT, RETRANSMIT_TIMEOUT_MS, SEND_CHUNK_SIZE,
};
use ironwood::Addr;
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio::time::{interval, Duration};
use tracing::{debug, trace};

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

/// A buffered, unacknowledged segment kept for potential retransmission
struct UnackedSegment {
    seq: u32,
    data: Vec<u8>,
}

/// Individual bidirectional stream
///
/// Implements AsyncRead + AsyncWrite for standard Rust async I/O.
/// Provides reliable, ordered delivery via sequence numbers, cumulative ACKs,
/// and a retransmit timer that fires every RETRANSMIT_TIMEOUT_MS milliseconds.
#[derive(Clone)]
pub struct Stream {
    /// Port number
    port: u16,

    /// Stream identifier
    id: u16,

    /// Remote peer address (for debugging/logging)
    peer: Addr,

    /// Receive buffer (data received from peer, in order)
    recv_buf: Arc<AsyncMutex<VecDeque<u8>>>,

    /// Send window: bytes we are allowed to send (from peer's last window advertisement)
    send_window: Arc<AtomicU32>,

    /// Receive window: bytes we can still accept (our remaining buffer space)
    recv_window: Arc<AtomicU32>,

    /// Channel to send outgoing packets to the writer task
    outgoing: mpsc::Sender<Packet>,

    /// Stream state (tokio Mutex because handle_packet awaits while holding it)
    state: Arc<AsyncMutex<StreamState>>,

    // --- Reliability fields ---

    /// Next byte sequence number to assign on send
    next_send_seq: Arc<AtomicU32>,

    /// Highest cumulative ACK received from the peer (peer has received everything < this)
    send_ack_seq: Arc<AtomicU32>,

    /// Next expected receive sequence number (we have received everything < this)
    next_recv_seq: Arc<AtomicU32>,

    /// Segments sent but not yet acknowledged; head is the oldest unACKed segment.
    /// Uses std::sync::Mutex: never held across await points, so no async lock needed.
    unacked: Arc<Mutex<VecDeque<UnackedSegment>>>,

    /// True once the peer has sent a FIN (used to return EOF only after recv_buf is drained)
    peer_fin: Arc<AtomicBool>,

    /// Out-of-order receive buffer: packets that arrived ahead of a gap.
    /// Keyed by sequence number. Delivered to recv_buf once the gap fills.
    ooo_buf: Arc<Mutex<BTreeMap<u32, Vec<u8>>>>,

    /// Duplicate ACK counter for fast retransmit (sender side).
    /// Counts consecutive ACKs with the same ack_seq value.
    dup_ack_count: Arc<AtomicU32>,

    /// Last ACK value seen (for dup-ACK detection, sender side).
    last_dup_ack: Arc<AtomicU32>,

    // --- Stored wakers (std::sync::Mutex — fast, no await, no spawned tasks) ---
    read_waker: Arc<Mutex<Option<Waker>>>,
    write_waker: Arc<Mutex<Option<Waker>>>,
    close_waker: Arc<Mutex<Option<Waker>>>,
}

impl Stream {
    /// Create a new stream and immediately spawn its retransmit background task.
    pub fn new(port: u16, id: u16, peer: Addr, outgoing: mpsc::Sender<Packet>) -> Self {
        let stream = Self {
            port,
            id,
            peer,
            recv_buf: Arc::new(AsyncMutex::new(VecDeque::new())),
            send_window: Arc::new(AtomicU32::new(DEFAULT_WINDOW_SIZE as u32)),
            recv_window: Arc::new(AtomicU32::new(DEFAULT_WINDOW_SIZE as u32)),
            outgoing,
            state: Arc::new(AsyncMutex::new(StreamState::Opening)),
            next_send_seq: Arc::new(AtomicU32::new(0)),
            send_ack_seq: Arc::new(AtomicU32::new(0)),
            next_recv_seq: Arc::new(AtomicU32::new(0)),
            unacked: Arc::new(Mutex::new(VecDeque::new())),
            peer_fin: Arc::new(AtomicBool::new(false)),
            ooo_buf: Arc::new(Mutex::new(BTreeMap::new())),
            dup_ack_count: Arc::new(AtomicU32::new(0)),
            last_dup_ack: Arc::new(AtomicU32::new(0)),
            read_waker: Arc::new(Mutex::new(None)),
            write_waker: Arc::new(Mutex::new(None)),
            close_waker: Arc::new(Mutex::new(None)),
        };

        // Spawn the retransmit timer task for this stream
        let s = stream.clone();
        tokio::spawn(async move { s.retransmit_loop().await });

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

    /// Transition stream to Open state (used for acceptor side after SYN-ACK sent)
    pub(crate) async fn transition_to_open(&self) {
        let mut state = self.state.lock().await;
        *state = StreamState::Open;
        self.wake_writer();
    }

    /// Handle incoming packet from the reader task.
    /// Returns `Ok(true)` if the stream transitioned to Closed.
    pub async fn handle_packet(&self, packet: Packet) -> Result<bool> {
        // Check state briefly — only hold the lock for state transitions, not
        // for the data-delivery path (ACK processing + recv_buf writes).
        let cur_state = {
            let mut state = self.state.lock().await;
            match *state {
                StreamState::Opening => {
                    if packet.is_syn() && packet.is_ack() {
                        *state = StreamState::Open;
                        self.send_window.store(packet.window as u32, Ordering::Release);
                        self.wake_writer();
                        return Ok(false);
                    } else {
                        return Err(Error::Protocol(format!(
                            "Unexpected packet in Opening state: flags={:02x}",
                            packet.flags
                        )));
                    }
                }
                StreamState::Closing => {
                    if packet.is_fin() {
                        *state = StreamState::Closed;
                        self.wake_closer();
                    }
                    return Ok(*state == StreamState::Closed);
                }
                StreamState::Closed => return Ok(true),
                StreamState::Open => {
                    if packet.is_rst() {
                        *state = StreamState::Closed;
                        self.wake_reader();
                        self.wake_writer();
                        self.wake_closer();
                        return Err(Error::StreamReset);
                    }
                    if packet.is_fin() {
                        self.peer_fin.store(true, Ordering::Release);
                        self.wake_reader();
                        self.wake_closer();
                        drop(state); // release state lock before I/O
                        let fin = Packet::fin(self.port, self.id);
                        let _ = self.outgoing.try_send(fin);
                        return Ok(false);
                    }
                    StreamState::Open
                }
            }
        };
        // state lock is now DROPPED — the remaining work (ACK processing +
        // data delivery) runs without holding it, so the reader task doesn't
        // block other packets on this lock.
        debug_assert_eq!(cur_state, StreamState::Open);

        // Process cumulative ACK and prune the retransmit buffer
        if packet.is_ack() {
            self.send_window.store(packet.window as u32, Ordering::Release);
            let new_ack = packet.ack_seq;
            let old_ack = self.send_ack_seq.load(Ordering::Acquire);
            if new_ack > old_ack {
                self.send_ack_seq.store(new_ack, Ordering::Release);
                let mut unacked = self.unacked.lock().unwrap();
                while let Some(front) = unacked.front() {
                    let seg_end = front.seq.wrapping_add(front.data.len() as u32);
                    if seg_end <= new_ack {
                        unacked.pop_front();
                    } else {
                        break;
                    }
                }
                self.dup_ack_count.store(0, Ordering::Release);
                self.last_dup_ack.store(new_ack, Ordering::Release);
            } else if new_ack == old_ack && old_ack > 0 {
                let count = self.dup_ack_count.fetch_add(1, Ordering::AcqRel) + 1;
                if count == 3 {
                    let seg = self.unacked.lock().unwrap().front()
                        .map(|s| (s.seq, s.data.clone()));
                    if let Some((seq, data)) = seg {
                        let ack_seq = self.next_recv_seq.load(Ordering::Acquire);
                        let recv_window = self.recv_window.load(Ordering::Acquire) as usize;
                        let pkt = Packet::data_ack(
                            self.port, self.id, data, seq, ack_seq, recv_window,
                        );
                        let _ = self.outgoing.try_send(pkt);
                        debug!(
                            "Stream {}: fast retransmit seq {} after 3 dup-ACKs",
                            self.id, seq
                        );
                    }
                }
            }
            self.wake_writer();
        }

        // Deliver data if present
        if !packet.data.is_empty() {
            let expected = self.next_recv_seq.load(Ordering::Acquire);
            let pkt_seq = packet.seq;

            if pkt_seq == expected {
                let data_len = packet.data.len() as u32;
                let mut recv_buf = self.recv_buf.lock().await;
                recv_buf.extend(&packet.data);
                let mut next_seq = expected.wrapping_add(data_len);

                // Drain consecutive OOO packets
                let mut ooo = self.ooo_buf.lock().unwrap();
                while let Some(data) = ooo.remove(&next_seq) {
                    let len = data.len() as u32;
                    recv_buf.extend(&data);
                    next_seq = next_seq.wrapping_add(len);
                }
                drop(ooo);

                self.next_recv_seq.store(next_seq, Ordering::Release);

                let available = (DEFAULT_WINDOW_SIZE as u32)
                    .saturating_sub(recv_buf.len() as u32);
                self.recv_window.store(available, Ordering::Release);
                drop(recv_buf);

                self.wake_reader();
                self.send_ack_nonblocking();
            } else if pkt_seq > expected {
                let mut ooo = self.ooo_buf.lock().unwrap();
                if ooo.len() < 64 {
                    ooo.insert(pkt_seq, packet.data.clone());
                }
                drop(ooo);
                trace!(
                    "Stream {}: gap — expected seq {}, got {}; buffered OOO, sending dup-ACK",
                    self.id, expected, pkt_seq
                );
                self.send_ack_nonblocking();
            } else {
                self.send_ack_nonblocking();
            }
        }

        Ok(false)
    }

    /// Send an ACK packet non-blockingly.
    /// A dropped ACK is acceptable: the next data packet will piggyback one, or the
    /// retransmit timer will cause a fresh ACK on the next retransmit.
    fn send_ack_nonblocking(&self) {
        let ack_seq = self.next_recv_seq.load(Ordering::Acquire);
        let window = self.recv_window.load(Ordering::Acquire) as usize;
        let packet = Packet::ack(self.port, self.id, ack_seq, window);
        let _ = self.outgoing.try_send(packet);
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
        self.wake_closer();
        Ok(())
    }

    /// Check if stream is closed
    pub async fn is_closed(&self) -> bool {
        *self.state.lock().await == StreamState::Closed
    }

    // --- Waker helpers (std::sync::Mutex — instant, no await, no task spawn) ---

    fn wake_reader(&self) {
        if let Some(w) = self.read_waker.lock().unwrap().take() {
            w.wake();
        }
    }

    fn wake_writer(&self) {
        if let Some(w) = self.write_waker.lock().unwrap().take() {
            w.wake();
        }
    }

    fn wake_closer(&self) {
        if let Some(w) = self.close_waker.lock().unwrap().take() {
            w.wake();
        }
    }

    /// Background retransmit timer task.
    ///
    /// Runs every RETRANSMIT_TIMEOUT_MS ms.  Only retransmits when no ACK
    /// progress has been made (stall detected).  On the first stall tick,
    /// retransmit all unacked segments at once to recover quickly.
    /// cwnd halves on each additional stall tick (multiplicative decrease).
    async fn retransmit_loop(&self) {
        let mut ticker = interval(Duration::from_millis(RETRANSMIT_TIMEOUT_MS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut last_ack: u32 = 0;
        let mut stall_ticks: u32 = 0;
        let mut cwnd: usize = 16;

        loop {
            ticker.tick().await;

            if *self.state.lock().await == StreamState::Closed {
                break;
            }

            let current_ack = self.send_ack_seq.load(Ordering::Acquire);
            if current_ack > last_ack {
                // ACK progress — no retransmission needed
                cwnd = 16;
                stall_ticks = 0;
                last_ack = current_ack;
                continue;
            }

            // No ACK progress — check if there's anything to retransmit
            let unacked_empty = self.unacked.lock().unwrap().is_empty();
            if unacked_empty {
                continue;
            }

            stall_ticks += 1;

            // First stall tick: retransmit aggressively (all unacked)
            // Subsequent ticks: halve cwnd (multiplicative decrease), minimum 1
            if stall_ticks > 1 {
                cwnd = (cwnd / 2).max(1);
            }

            let segments: Vec<(u32, Vec<u8>)> = {
                let unacked = self.unacked.lock().unwrap();
                unacked
                    .iter()
                    .take(cwnd)
                    .map(|s| (s.seq, s.data.clone()))
                    .collect()
            };

            let ack_seq = self.next_recv_seq.load(Ordering::Acquire);
            let recv_window = self.recv_window.load(Ordering::Acquire) as usize;

            debug!(
                "Stream {}: retransmitting {} segment(s) (cwnd={}, stall_ticks={})",
                self.id,
                segments.len(),
                cwnd,
                stall_ticks
            );

            for (seq, data) in segments {
                let pkt = Packet::data_ack(self.port, self.id, data, seq, ack_seq, recv_window);
                let _ = self.outgoing.try_send(pkt);
            }
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Try to drain recv_buf. On try_lock failure, fall through to store the waker
        // and return Pending — handle_packet will call wake_reader() after releasing the lock.
        if let Ok(mut recv_buf) = this.recv_buf.try_lock() {
            if !recv_buf.is_empty() {
                let to_read = buf.remaining().min(recv_buf.len());
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

                let available =
                    (DEFAULT_WINDOW_SIZE as u32).saturating_sub(recv_buf.len() as u32);
                let old_window = this.recv_window.swap(available, Ordering::AcqRel);

                // Proactively send window update when buffer drains past the halfway mark
                let half = (DEFAULT_WINDOW_SIZE / 2) as u32;
                if old_window < half && available >= half {
                    drop(recv_buf);
                    this.send_ack_nonblocking();
                }

                return Poll::Ready(Ok(()));
            }
        }

        // No data (or lock was busy) — check terminal conditions
        if this.peer_fin.load(Ordering::Acquire) {
            return Poll::Ready(Ok(())); // EOF: peer sent FIN and recv_buf is empty
        }

        if let Ok(guard) = this.state.try_lock() {
            if *guard == StreamState::Closed {
                return Poll::Ready(Ok(()));
            }
        }

        // Store waker THEN re-check recv_buf to avoid lost-wakeup race:
        // handle_packet may have written data and called wake_reader() between
        // our empty-buffer check above and this point.
        *this.read_waker.lock().unwrap() = Some(cx.waker().clone());

        // Re-check: if data appeared while we were storing the waker, wake
        // immediately so we don't sleep with data available.
        if let Ok(recv_buf) = this.recv_buf.try_lock() {
            if !recv_buf.is_empty() {
                // Data arrived — wake ourselves and let the next poll drain it
                if let Some(w) = this.read_waker.lock().unwrap().take() {
                    w.wake();
                }
            }
        }
        Poll::Pending
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // On try_lock failure, treat as non-Open and wait — handle_packet will call
        // wake_writer() after releasing the state lock.
        let state = this.state.try_lock().map(|g| *g).unwrap_or(StreamState::Opening);

        if state == StreamState::Closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Stream closed",
            )));
        }

        if state != StreamState::Open {
            *this.write_waker.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }

        // Check flow control: peer's advertised window
        let send_window = this.send_window.load(Ordering::Acquire) as usize;

        // Check in-flight cap: don't exceed MAX_INFLIGHT unACKed bytes
        let next_seq = this.next_send_seq.load(Ordering::Acquire);
        let ack_seq = this.send_ack_seq.load(Ordering::Acquire);
        let in_flight = next_seq.wrapping_sub(ack_seq) as usize;
        let effective_window = send_window.min(MAX_INFLIGHT);
        let can_send = effective_window.saturating_sub(in_flight);

        if can_send == 0 {
            // Store waker THEN re-check to avoid lost-wakeup race:
            // handle_packet may have processed an ACK (updating send_ack_seq
            // and send_window) and called wake_writer() between our check
            // above and this point.
            *this.write_waker.lock().unwrap() = Some(cx.waker().clone());

            // Re-check: if window opened while storing the waker, wake
            // immediately so we don't sleep with send capacity available.
            let send_window2 = this.send_window.load(Ordering::Acquire) as usize;
            let ack_seq2 = this.send_ack_seq.load(Ordering::Acquire);
            let in_flight2 = next_seq.wrapping_sub(ack_seq2) as usize;
            let effective2 = send_window2.min(MAX_INFLIGHT);
            if effective2.saturating_sub(in_flight2) > 0 {
                if let Some(w) = this.write_waker.lock().unwrap().take() {
                    w.wake();
                }
            }
            return Poll::Pending;
        }

        let to_send = buf.len().min(can_send).min(SEND_CHUNK_SIZE);
        let data = buf[..to_send].to_vec();

        // Assign sequence number atomically before sending
        let seq = this
            .next_send_seq
            .fetch_add(to_send as u32, Ordering::AcqRel);

        let ack_seq_val = this.next_recv_seq.load(Ordering::Acquire);
        let recv_window = this.recv_window.load(Ordering::Acquire) as usize;
        let packet =
            Packet::data_ack(this.port, this.id, data.clone(), seq, ack_seq_val, recv_window);

        // Synchronous try_send preserves ordering — no tokio::spawn race
        match this.outgoing.try_send(packet) {
            Ok(()) => {
                // Store in retransmit buffer. std Mutex: fast, no await needed, no spawn.
                this.unacked
                    .lock()
                    .unwrap()
                    .push_back(UnackedSegment { seq, data });
                this.send_window
                    .fetch_sub(to_send as u32, Ordering::Release);
                Poll::Ready(Ok(to_send))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel full — revert seq and wait for capacity
                this.next_send_seq
                    .fetch_sub(to_send as u32, Ordering::AcqRel);
                // The only remaining spawn: waiting for channel capacity (not data).
                // Holds no application data, just a channel Sender clone.
                let waker = cx.waker().clone();
                let outgoing = this.outgoing.clone();
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

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Wait until all sent data has been acknowledged before sending FIN
        let next_seq = this.next_send_seq.load(Ordering::Acquire);
        let ack_seq = this.send_ack_seq.load(Ordering::Acquire);
        if ack_seq < next_seq {
            *this.write_waker.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }

        // All data ACKed — now transition and send FIN.
        // On try_lock failure, fall through to the close_waker wait path.
        let state = if let Ok(mut guard) = this.state.try_lock() {
            let current = *guard;
            if current == StreamState::Open {
                *guard = StreamState::Closing;
                drop(guard);
                // If peer already sent FIN, go straight to Closed
                if this.peer_fin.load(Ordering::Acquire) {
                    if let Ok(mut g) = this.state.try_lock() {
                        *g = StreamState::Closed;
                    }
                    return Poll::Ready(Ok(()));
                }
                let packet = Packet::fin(this.port, this.id);
                let _ = this.outgoing.try_send(packet);
            }
            current
        } else {
            StreamState::Opening // treat lock failure as not-yet-closed
        };

        if state == StreamState::Closed {
            return Poll::Ready(Ok(()));
        }

        *this.close_waker.lock().unwrap() = Some(cx.waker().clone());
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

        assert_eq!(stream.state().await, StreamState::Opening);

        let syn_ack = Packet::syn_ack(1, 1);
        stream.handle_packet(syn_ack).await.unwrap();
        assert_eq!(stream.state().await, StreamState::Open);

        let close_task = tokio::spawn({
            let stream = stream.clone();
            async move { stream.close().await }
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(stream.state().await, StreamState::Closing);

        close_task.abort();
    }

    #[tokio::test]
    async fn test_stream_abort() {
        let (tx, mut rx) = mpsc::channel(10);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        let syn_ack = Packet::syn_ack(1, 1);
        stream.handle_packet(syn_ack).await.unwrap();

        stream.abort().await.unwrap();
        assert_eq!(stream.state().await, StreamState::Closed);

        let packet = rx.recv().await.unwrap();
        assert!(packet.is_rst());
        assert_eq!(packet.stream_id, 1);
    }

    #[tokio::test]
    async fn test_stream_data_delivery() {
        let (tx, _rx) = mpsc::channel(10);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        let syn_ack = Packet::syn_ack(1, 1);
        stream.handle_packet(syn_ack).await.unwrap();

        let mut data_packet = Packet::data(1, 1, b"hello".to_vec());
        data_packet.seq = 0;
        stream.handle_packet(data_packet).await.unwrap();

        let recv_buf = stream.recv_buf.lock().await;
        assert_eq!(recv_buf.len(), 5);
        let data: Vec<u8> = recv_buf.iter().copied().collect();
        assert_eq!(data, b"hello");
    }

    #[tokio::test]
    async fn test_stream_out_of_order_dropped() {
        let (tx, mut rx) = mpsc::channel(32);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        let syn_ack = Packet::syn_ack(1, 1);
        stream.handle_packet(syn_ack).await.unwrap();

        // Out-of-order packet (seq=5, expecting seq=0)
        let mut ooo_packet = Packet::data(1, 1, b"world".to_vec());
        ooo_packet.seq = 5;
        stream.handle_packet(ooo_packet).await.unwrap();

        // recv_buf should be empty (dropped)
        let recv_buf = stream.recv_buf.lock().await;
        assert!(recv_buf.is_empty());
        drop(recv_buf);

        // Should have sent a dup-ACK for seq=0
        let ack = rx.recv().await.unwrap();
        assert!(ack.is_ack());
        assert_eq!(ack.ack_seq, 0);
    }

    #[tokio::test]
    async fn test_stream_flow_control() {
        let (tx, _rx) = mpsc::channel(10);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        assert_eq!(
            stream.send_window.load(Ordering::Acquire),
            DEFAULT_WINDOW_SIZE as u32
        );

        let ack = Packet {
            port: 1,
            stream_id: 1,
            flags: FLAG_ACK | FLAG_SYN,
            seq: 0,
            ack_seq: 0,
            window: 1024,
            data: Vec::new(),
        };
        stream.handle_packet(ack).await.unwrap();

        assert_eq!(stream.send_window.load(Ordering::Acquire), 1024);
    }

    #[tokio::test]
    async fn test_stream_reset_on_rst() {
        let (tx, _rx) = mpsc::channel(10);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        let syn_ack = Packet::syn_ack(1, 1);
        stream.handle_packet(syn_ack).await.unwrap();
        assert_eq!(stream.state().await, StreamState::Open);

        let rst = Packet::rst(1, 1);
        let result = stream.handle_packet(rst).await;
        assert!(matches!(result, Err(Error::StreamReset)));
        assert_eq!(stream.state().await, StreamState::Closed);
    }

    #[tokio::test]
    async fn test_ack_prunes_unacked_queue() {
        let (tx, _rx) = mpsc::channel(32);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        let syn_ack = Packet::syn_ack(1, 1);
        stream.handle_packet(syn_ack).await.unwrap();

        {
            let mut unacked = stream.unacked.lock().unwrap();
            unacked.push_back(UnackedSegment { seq: 0, data: vec![0u8; 5] });
            unacked.push_back(UnackedSegment { seq: 5, data: vec![0u8; 5] });
        }
        stream.next_send_seq.store(10, Ordering::Release);

        let ack_pkt = Packet::ack(1, 1, 10, DEFAULT_WINDOW_SIZE);
        stream.handle_packet(ack_pkt).await.unwrap();

        let unacked = stream.unacked.lock().unwrap();
        assert!(unacked.is_empty(), "unacked queue should be empty after ACK");
    }

    #[tokio::test]
    async fn test_fin_does_not_drop_recv_buf() {
        let (tx, _rx) = mpsc::channel(32);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        let syn_ack = Packet::syn_ack(1, 1);
        stream.handle_packet(syn_ack).await.unwrap();

        let mut data_pkt = Packet::data(1, 1, b"buffered".to_vec());
        data_pkt.seq = 0;
        stream.handle_packet(data_pkt).await.unwrap();

        let fin_pkt = Packet::fin(1, 1);
        stream.handle_packet(fin_pkt).await.unwrap();

        assert_eq!(stream.state().await, StreamState::Open);
        assert!(stream.peer_fin.load(Ordering::Acquire));

        let recv_buf = stream.recv_buf.lock().await;
        assert_eq!(recv_buf.len(), 8);
    }
}
