use crate::error::{Error, Result};
use crate::protocol::{
    Packet, CLOCK_GRANULARITY_MS, DEFAULT_WINDOW_SIZE, INITIAL_CWND, INITIAL_RTO_MS,
    MAX_INFLIGHT, MAX_RTO_MS, MAX_STALL_MS, MIN_RTO_MS, SEND_CHUNK_SIZE,
};
use ironwood::Addr;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::Instant;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio::time::Duration;
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

/// Jacobson/Karels RTT estimator (RFC 6298) with Karn's algorithm.
struct RttEstimator {
    /// Smoothed RTT in microseconds, or None if no sample yet.
    srtt_us: Option<u64>,
    /// RTT variation in microseconds.
    rttvar_us: u64,
    /// Computed RTO in milliseconds.
    rto_ms: u64,
    /// Sequence numbers that have been retransmitted (Karn's algorithm:
    /// don't update RTT estimates from retransmitted segments).
    retransmitted_seqs: HashSet<u32>,
}

impl RttEstimator {
    fn new() -> Self {
        Self {
            srtt_us: None,
            rttvar_us: 0,
            rto_ms: INITIAL_RTO_MS,
            retransmitted_seqs: HashSet::new(),
        }
    }

    /// Feed an RTT sample and recompute RTO (RFC 6298 Section 2).
    fn update(&mut self, sample_us: u64) {
        match self.srtt_us {
            None => {
                // First measurement: SRTT = R, RTTVAR = R/2
                self.srtt_us = Some(sample_us);
                self.rttvar_us = sample_us / 2;
            }
            Some(srtt) => {
                // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|   (beta = 1/4)
                let diff = if srtt > sample_us { srtt - sample_us } else { sample_us - srtt };
                self.rttvar_us = (self.rttvar_us * 3 / 4) + (diff / 4);
                // SRTT = (1 - alpha) * SRTT + alpha * R              (alpha = 1/8)
                self.srtt_us = Some((srtt * 7 / 8) + (sample_us / 8));
            }
        }
        // RTO = SRTT + max(G, 4 * RTTVAR)
        let srtt_ms = self.srtt_us.unwrap() / 1000;
        let rttvar_ms = self.rttvar_us / 1000;
        let k_rttvar = (4 * rttvar_ms).max(CLOCK_GRANULARITY_MS);
        self.rto_ms = (srtt_ms + k_rttvar).clamp(MIN_RTO_MS, MAX_RTO_MS);
    }

    /// Current RTO in milliseconds.
    fn rto(&self) -> u64 {
        self.rto_ms
    }

    /// Mark a seq as retransmitted (Karn's algorithm).
    fn mark_retransmitted(&mut self, seq: u32) {
        self.retransmitted_seqs.insert(seq);
    }

    /// Check if a seq was retransmitted (and remove the mark).
    fn was_retransmitted(&mut self, seq: u32) -> bool {
        self.retransmitted_seqs.remove(&seq)
    }

    /// Discard retransmit marks for segments fully ACKed below `ack_seq`.
    fn clear_retransmitted_up_to(&mut self, ack_seq: u32) {
        self.retransmitted_seqs.retain(|&seq| seq >= ack_seq);
    }
}

/// A buffered, unacknowledged segment kept for potential retransmission
struct UnackedSegment {
    seq: u32,
    data: Vec<u8>,
    sent_at: Instant,
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

    /// Congestion window in bytes (TCP Reno style). Starts at INITIAL_CWND.
    cwnd: Arc<AtomicU32>,

    /// Slow-start threshold in bytes. Once cwnd >= ssthresh, growth becomes linear.
    ssthresh: Arc<AtomicU32>,

    /// RTT estimator (Jacobson/Karels, RFC 6298). Shared between handle_packet
    /// (produces RTT samples on ACK) and retransmit_loop (reads computed RTO).
    /// Uses std::sync::Mutex — never held across await points.
    rtt: Arc<Mutex<RttEstimator>>,

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
            cwnd: Arc::new(AtomicU32::new(INITIAL_CWND as u32)),
            ssthresh: Arc::new(AtomicU32::new(MAX_INFLIGHT as u32)),
            rtt: Arc::new(Mutex::new(RttEstimator::new())),
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
                // Capture the oldest segment's timing before pruning (for RTT measurement)
                let oldest_sample = unacked.front()
                    .filter(|seg| seg.seq.wrapping_add(seg.data.len() as u32) <= new_ack)
                    .map(|seg| (seg.seq, seg.sent_at));
                while let Some(front) = unacked.front() {
                    let seg_end = front.seq.wrapping_add(front.data.len() as u32);
                    if seg_end <= new_ack {
                        unacked.pop_front();
                    } else {
                        break;
                    }
                }
                drop(unacked); // release before taking rtt lock

                // RTT sample (Karn's algorithm: skip retransmitted segments)
                if let Some((seq, sent_at)) = oldest_sample {
                    let mut rtt = self.rtt.lock().unwrap();
                    if !rtt.was_retransmitted(seq) {
                        let sample_us = sent_at.elapsed().as_micros() as u64;
                        rtt.update(sample_us);
                        trace!(
                            "Stream {}: RTT sample {}us, new RTO={}ms",
                            self.id, sample_us, rtt.rto()
                        );
                    }
                    rtt.clear_retransmitted_up_to(new_ack);
                }

                self.dup_ack_count.store(0, Ordering::Release);
                self.last_dup_ack.store(new_ack, Ordering::Release);

                // Grow congestion window (TCP Reno)
                let cwnd_val = self.cwnd.load(Ordering::Acquire);
                let ssthresh_val = self.ssthresh.load(Ordering::Acquire);
                let new_cwnd = if cwnd_val < ssthresh_val {
                    // Slow start: grow by one segment per ACK (doubles per RTT)
                    cwnd_val + SEND_CHUNK_SIZE as u32
                } else {
                    // Congestion avoidance: grow ~1 segment per RTT
                    cwnd_val + (SEND_CHUNK_SIZE as u32 * SEND_CHUNK_SIZE as u32) / cwnd_val.max(1)
                };
                self.cwnd.store(new_cwnd.min(MAX_INFLIGHT as u32), Ordering::Release);
            } else if new_ack == old_ack && old_ack > 0 && packet.data.is_empty() {
                // Only count dup-ACKs from standalone ACK packets (no data).
                // Data packets carry a piggybacked ack_seq that may be stale
                // simply because the sender is busy transmitting — not because
                // our data was lost.  Counting those as dup-ACKs causes false
                // fast-retransmits and cwnd collapse when a peer sends many
                // requests in quick succession (e.g. 10 subscribes at once).
                let count = self.dup_ack_count.fetch_add(1, Ordering::AcqRel) + 1;
                if count == 3 {
                    // Multiplicative decrease on triple dup-ACK
                    let cwnd_val = self.cwnd.load(Ordering::Acquire);
                    let half = (cwnd_val / 2).max(SEND_CHUNK_SIZE as u32);
                    self.ssthresh.store(half, Ordering::Release);
                    self.cwnd.store(half, Ordering::Release);

                    let seg = self.unacked.lock().unwrap().front()
                        .map(|s| (s.seq, s.data.clone()));
                    if let Some((seq, data)) = seg {
                        self.rtt.lock().unwrap().mark_retransmitted(seq);
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
    /// Uses the RTT-based RTO from the Jacobson/Karels estimator (RFC 6298).
    /// Applies exponential backoff on consecutive stalls, capped at MAX_RTO_MS.
    /// Gives up and closes the stream after MAX_STALL_MS of total stall time.
    async fn retransmit_loop(&self) {
        let mut last_ack: u32 = 0;
        let mut rto_ms: u64 = INITIAL_RTO_MS;
        let mut total_stall_ms: u64 = 0;
        let mut cwnd_collapsed = false;

        loop {
            tokio::time::sleep(Duration::from_millis(rto_ms)).await;

            if *self.state.lock().await == StreamState::Closed {
                break;
            }

            let current_ack = self.send_ack_seq.load(Ordering::Acquire);
            if current_ack > last_ack {
                // ACK progress — use the RTT-based RTO
                last_ack = current_ack;
                total_stall_ms = 0;
                cwnd_collapsed = false;
                rto_ms = self.rtt.lock().unwrap().rto();
                continue;
            }

            // No ACK progress — check if there's anything to retransmit
            let unacked_empty = self.unacked.lock().unwrap().is_empty();
            if unacked_empty {
                // Nothing in flight — use RTT-based RTO, wait for new data
                rto_ms = self.rtt.lock().unwrap().rto();
                total_stall_ms = 0;
                cwnd_collapsed = false;
                continue;
            }

            total_stall_ms += rto_ms;

            // Give up after MAX_STALL_MS of no progress
            if total_stall_ms >= MAX_STALL_MS {
                debug!(
                    "Stream {} (port {}): giving up after {}ms with no ACK progress, closing",
                    self.id, self.port, total_stall_ms
                );
                let mut state = self.state.lock().await;
                *state = StreamState::Closed;
                let rst = Packet::rst(self.port, self.id);
                let _ = self.outgoing.try_send(rst);
                self.wake_reader();
                self.wake_writer();
                self.wake_closer();
                break;
            }

            // Collapse cwnd once per stall episode (not on every tick)
            if !cwnd_collapsed {
                cwnd_collapsed = true;
                let cwnd_val = self.cwnd.load(Ordering::Acquire);
                let half = (cwnd_val / 2).max(SEND_CHUNK_SIZE as u32);
                self.ssthresh.store(half, Ordering::Release);
                self.cwnd.store(SEND_CHUNK_SIZE as u32, Ordering::Release);
            }

            let cwnd_val = self.cwnd.load(Ordering::Acquire) as usize;
            let seg_count = (cwnd_val / SEND_CHUNK_SIZE).max(1);

            let segments: Vec<(u32, Vec<u8>)> = {
                let unacked = self.unacked.lock().unwrap();
                unacked
                    .iter()
                    .take(seg_count)
                    .map(|s| (s.seq, s.data.clone()))
                    .collect()
            };

            // Mark retransmitted segments for Karn's algorithm
            {
                let mut rtt = self.rtt.lock().unwrap();
                for &(seq, _) in &segments {
                    rtt.mark_retransmitted(seq);
                }
            }

            let ack_seq = self.next_recv_seq.load(Ordering::Acquire);
            let recv_window = self.recv_window.load(Ordering::Acquire) as usize;

            debug!(
                "Stream {} (port {}): retransmitting {} seg(s) (cwnd={}, rto={}ms, stalled={}ms)",
                self.id,
                self.port,
                segments.len(),
                cwnd_val,
                rto_ms,
                total_stall_ms
            );

            for (seq, data) in segments {
                let pkt = Packet::data_ack(self.port, self.id, data, seq, ack_seq, recv_window);
                let _ = self.outgoing.try_send(pkt);
            }

            // Exponential backoff (RFC 6298 Section 5.5)
            rto_ms = (rto_ms * 2).min(MAX_RTO_MS);
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>,cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
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
            debug!("Stream {} (port {}): poll_read EOF — peer sent FIN", this.id, this.port);
            return Poll::Ready(Ok(())); // EOF: peer sent FIN and recv_buf is empty
        }

        if let Ok(guard) = this.state.try_lock() {
            if *guard == StreamState::Closed {
                debug!("Stream {} (port {}): poll_read EOF — state is Closed (RST or FIN exchange)", this.id, this.port);
                return Poll::Ready(Ok(()));
            }
        }

        // Connection dead (writer task gone) — treat as EOF
        if this.outgoing.is_closed() {
            debug!("Stream {} (port {}): poll_read EOF — outgoing channel closed (writer task dead)", this.id, this.port);
            return Poll::Ready(Ok(()));
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

        // Re-check: channel may have closed while we were storing the waker
        if this.outgoing.is_closed() {
            if let Some(w) = this.read_waker.lock().unwrap().take() {
                w.wake();
            }
        }

        Poll::Pending
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>,cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
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
        let cwnd_val = this.cwnd.load(Ordering::Acquire) as usize;
        let effective_window = send_window.min(cwnd_val);
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
            let cwnd_val2 = this.cwnd.load(Ordering::Acquire) as usize;
            let effective2 = send_window2.min(cwnd_val2);
            if effective2.saturating_sub(in_flight2) > 0 || this.outgoing.is_closed() {
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
                    .push_back(UnackedSegment { seq, data, sent_at: Instant::now() });
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

    fn poll_shutdown(self: Pin<&mut Self>,cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // If the outgoing channel is closed (writer task dead / connection gone),
        // we can never send FIN or receive ACKs — just transition to Closed.
        if this.outgoing.is_closed() {
            if let Ok(mut g) = this.state.try_lock() {
                *g = StreamState::Closed;
            }
            return Poll::Ready(Ok(()));
        }

        // Wait until all sent data has been acknowledged before sending FIN
        let next_seq = this.next_send_seq.load(Ordering::Acquire);
        let ack_seq = this.send_ack_seq.load(Ordering::Acquire);
        if ack_seq < next_seq {
            *this.write_waker.lock().unwrap() = Some(cx.waker().clone());
            // Re-check: channel may have closed while we stored the waker
            if this.outgoing.is_closed() {
                if let Some(w) = this.write_waker.lock().unwrap().take() {
                    w.wake();
                }
            }
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
        // Re-check: channel may have closed while we stored the waker
        if this.outgoing.is_closed() {
            if let Some(w) = this.close_waker.lock().unwrap().take() {
                w.wake();
            }
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
        assert_eq!(
            stream.cwnd.load(Ordering::Acquire),
            INITIAL_CWND as u32
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
            unacked.push_back(UnackedSegment { seq: 0, data: vec![0u8; 5], sent_at: Instant::now() });
            unacked.push_back(UnackedSegment { seq: 5, data: vec![0u8; 5], sent_at: Instant::now() });
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

    #[tokio::test]
    async fn test_cwnd_slow_start_growth() {
        let (tx, _rx) = mpsc::channel(32);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        let syn_ack = Packet::syn_ack(1, 1);
        stream.handle_packet(syn_ack).await.unwrap();

        // Simulate sending data and receiving ACKs
        let chunk = SEND_CHUNK_SIZE as u32;
        stream.next_send_seq.store(chunk * 4, Ordering::Release);

        assert_eq!(stream.cwnd.load(Ordering::Acquire), INITIAL_CWND as u32);

        // First ACK: cwnd should grow by SEND_CHUNK_SIZE (slow start)
        {
            let mut unacked = stream.unacked.lock().unwrap();
            unacked.push_back(UnackedSegment { seq: 0, data: vec![0u8; SEND_CHUNK_SIZE], sent_at: Instant::now() });
            unacked.push_back(UnackedSegment { seq: chunk, data: vec![0u8; SEND_CHUNK_SIZE], sent_at: Instant::now() });
        }
        let ack1 = Packet::ack(1, 1, chunk, DEFAULT_WINDOW_SIZE);
        stream.handle_packet(ack1).await.unwrap();
        assert_eq!(
            stream.cwnd.load(Ordering::Acquire),
            INITIAL_CWND as u32 + chunk,
            "cwnd should grow by one segment in slow start"
        );

        // Second ACK: cwnd should grow by another SEND_CHUNK_SIZE
        let ack2 = Packet::ack(1, 1, chunk * 2, DEFAULT_WINDOW_SIZE);
        stream.handle_packet(ack2).await.unwrap();
        assert_eq!(
            stream.cwnd.load(Ordering::Acquire),
            INITIAL_CWND as u32 + chunk * 2,
            "cwnd should grow by one segment per ACK in slow start"
        );
    }

    #[tokio::test]
    async fn test_cwnd_fast_retransmit_halves() {
        let (tx, mut rx) = mpsc::channel(32);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        let syn_ack = Packet::syn_ack(1, 1);
        stream.handle_packet(syn_ack).await.unwrap();

        let chunk = SEND_CHUNK_SIZE as u32;
        // Grow cwnd first via ACKs
        stream.next_send_seq.store(chunk * 8, Ordering::Release);
        {
            let mut unacked = stream.unacked.lock().unwrap();
            for i in 0..8 {
                unacked.push_back(UnackedSegment {
                    seq: chunk * i,
                    data: vec![0u8; SEND_CHUNK_SIZE],
                    sent_at: Instant::now(),
                });
            }
        }
        // ACK first 4 segments to grow cwnd
        for i in 1..=4 {
            let ack = Packet::ack(1, 1, chunk * i, DEFAULT_WINDOW_SIZE);
            stream.handle_packet(ack).await.unwrap();
        }
        let cwnd_before = stream.cwnd.load(Ordering::Acquire);
        assert!(cwnd_before > INITIAL_CWND as u32);

        // Now send 3 duplicate ACKs for chunk*4 (already acked up to chunk*4)
        for _ in 0..3 {
            let dup_ack = Packet::ack(1, 1, chunk * 4, DEFAULT_WINDOW_SIZE);
            stream.handle_packet(dup_ack).await.unwrap();
        }

        let cwnd_after = stream.cwnd.load(Ordering::Acquire);
        let expected_half = (cwnd_before / 2).max(chunk);
        assert_eq!(cwnd_after, expected_half, "cwnd should be halved after 3 dup-ACKs");
        assert_eq!(
            stream.ssthresh.load(Ordering::Acquire),
            expected_half,
            "ssthresh should equal halved cwnd"
        );

        // Drain the fast-retransmit packet from the channel
        let retransmit_pkt = rx.recv().await.unwrap();
        assert!(retransmit_pkt.is_ack());
    }

    #[tokio::test]
    async fn test_cwnd_timeout_resets() {
        let (tx, _rx) = mpsc::channel(32);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        let chunk = SEND_CHUNK_SIZE as u32;

        // Set cwnd to a larger value to simulate an established connection
        stream.cwnd.store(chunk * 8, Ordering::Release);
        stream.ssthresh.store(MAX_INFLIGHT as u32, Ordering::Release);

        // Simulate what retransmit_loop does on first stall tick:
        // ssthresh = cwnd/2, cwnd = SEND_CHUNK_SIZE
        let cwnd_val = stream.cwnd.load(Ordering::Acquire);
        let half = (cwnd_val / 2).max(chunk);
        stream.ssthresh.store(half, Ordering::Release);
        stream.cwnd.store(chunk, Ordering::Release);

        assert_eq!(
            stream.cwnd.load(Ordering::Acquire),
            chunk,
            "cwnd should reset to one segment on timeout"
        );
        assert_eq!(
            stream.ssthresh.load(Ordering::Acquire),
            chunk * 4,
            "ssthresh should be half of previous cwnd"
        );
    }

    // --- RTT estimator tests ---

    #[test]
    fn test_rtt_estimator_initial_state() {
        let rtt = RttEstimator::new();
        assert_eq!(rtt.rto(), INITIAL_RTO_MS);
        assert!(rtt.srtt_us.is_none());
    }

    #[test]
    fn test_rtt_estimator_first_sample() {
        let mut rtt = RttEstimator::new();
        // 300ms sample
        rtt.update(300_000);
        assert_eq!(rtt.srtt_us, Some(300_000));
        assert_eq!(rtt.rttvar_us, 150_000); // R/2

        // RTO = SRTT + max(G, 4*RTTVAR) = 300 + max(50, 600) = 900ms
        assert_eq!(rtt.rto(), 900);
    }

    #[test]
    fn test_rtt_estimator_multiple_samples() {
        let mut rtt = RttEstimator::new();
        // First: 300ms
        rtt.update(300_000);
        assert_eq!(rtt.rto(), 900);

        // Second: 280ms — SRTT should converge, RTTVAR should shrink
        rtt.update(280_000);
        // RTTVAR = 3/4 * 150000 + 1/4 * |300000-280000| = 112500 + 5000 = 117500
        assert_eq!(rtt.rttvar_us, 117500);
        // SRTT = 7/8 * 300000 + 1/8 * 280000 = 262500 + 35000 = 297500
        assert_eq!(rtt.srtt_us, Some(297500));

        // RTO = 297 + max(50, 4*117) = 297 + 468 = 765
        assert_eq!(rtt.rto(), 765);
    }

    #[test]
    fn test_rtt_estimator_min_floor() {
        let mut rtt = RttEstimator::new();
        // Very fast: 1ms RTT
        rtt.update(1_000);
        // SRTT = 1ms, RTTVAR = 0.5ms
        // RTO = 1 + max(50, 4*0) = 1 + 50 = 51 → clamped to MIN_RTO_MS = 200
        assert_eq!(rtt.rto(), MIN_RTO_MS);
    }

    #[test]
    fn test_rtt_estimator_max_cap() {
        let mut rtt = RttEstimator::new();
        // Extremely high: 10 seconds
        rtt.update(10_000_000);
        // RTO would be huge, capped at MAX_RTO_MS
        assert_eq!(rtt.rto(), MAX_RTO_MS);
    }

    #[test]
    fn test_karn_algorithm() {
        let mut rtt = RttEstimator::new();
        rtt.mark_retransmitted(0);
        rtt.mark_retransmitted(100);

        assert!(rtt.was_retransmitted(0));
        // Second call returns false (removed on first check)
        assert!(!rtt.was_retransmitted(0));
        assert!(rtt.was_retransmitted(100));
    }

    #[test]
    fn test_karn_clear_up_to() {
        let mut rtt = RttEstimator::new();
        rtt.mark_retransmitted(0);
        rtt.mark_retransmitted(100);
        rtt.mark_retransmitted(200);

        rtt.clear_retransmitted_up_to(150);
        // 0 and 100 should be cleared, 200 should remain
        assert!(!rtt.was_retransmitted(0));
        assert!(!rtt.was_retransmitted(100));
        assert!(rtt.was_retransmitted(200));
    }

    #[tokio::test]
    async fn test_rtt_sample_from_ack() {
        let (tx, _rx) = mpsc::channel(32);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        let syn_ack = Packet::syn_ack(1, 1);
        stream.handle_packet(syn_ack).await.unwrap();

        // Simulate sending a segment
        let sent_at = Instant::now();
        {
            let mut unacked = stream.unacked.lock().unwrap();
            unacked.push_back(UnackedSegment {
                seq: 0,
                data: vec![0u8; 100],
                sent_at,
            });
        }
        stream.next_send_seq.store(100, Ordering::Release);

        // Wait a bit so the RTT sample is measurable
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Send ACK that covers the segment
        let ack = Packet::ack(1, 1, 100, DEFAULT_WINDOW_SIZE);
        stream.handle_packet(ack).await.unwrap();

        // RTT estimator should have a sample now
        let rtt = stream.rtt.lock().unwrap();
        assert!(rtt.srtt_us.is_some(), "RTT estimator should have a sample");
        let srtt_ms = rtt.srtt_us.unwrap() / 1000;
        assert!(srtt_ms >= 10, "SRTT should be at least 10ms, got {}ms", srtt_ms);
    }

    #[tokio::test]
    async fn test_rtt_skips_retransmitted_segment() {
        let (tx, _rx) = mpsc::channel(32);
        let stream = Stream::new(1, 1, Addr::from([0u8; 32]), tx);

        let syn_ack = Packet::syn_ack(1, 1);
        stream.handle_packet(syn_ack).await.unwrap();

        // Simulate a retransmitted segment
        {
            let mut unacked = stream.unacked.lock().unwrap();
            unacked.push_back(UnackedSegment {
                seq: 0,
                data: vec![0u8; 100],
                sent_at: Instant::now(),
            });
        }
        stream.next_send_seq.store(100, Ordering::Release);
        stream.rtt.lock().unwrap().mark_retransmitted(0);

        // ACK it
        let ack = Packet::ack(1, 1, 100, DEFAULT_WINDOW_SIZE);
        stream.handle_packet(ack).await.unwrap();

        // RTT estimator should NOT have a sample (Karn's algorithm)
        let rtt = stream.rtt.lock().unwrap();
        assert!(rtt.srtt_us.is_none(), "RTT should not be updated from retransmitted segment");
    }
}
