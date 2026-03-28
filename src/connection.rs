use crate::error::{Error, Result};
use crate::protocol::{
    Packet, CLOCK_GRANULARITY_MS, DEFAULT_WINDOW_SIZE, INITIAL_CWND, INITIAL_RTO_MS,
    MAX_INFLIGHT, MAX_RTO_MS, MAX_STALL_MS, MIN_RTO_MS, SEND_CHUNK_SIZE,
};
use ironwood::Addr;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Notify};
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

// ── Connection identification ──────────────────────────────────────────────

/// Unique identifier for a TCP/KEY connection.
/// Analogous to TCP's 4-tuple (src_ip, src_port, dst_ip, dst_port),
/// but local key is implicit (we only have one identity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnKey {
    pub local_port: u16,
    pub remote_key: Addr,
    pub remote_port: u16,
}

// ── TCP state machine (full RFC 793) ───────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// Passive open, waiting for SYN (transient)
    Listen,
    /// Active open: SYN sent, waiting SYN-ACK
    SynSent,
    /// SYN received, SYN-ACK sent, waiting ACK
    SynReceived,
    /// Data transfer (3-way handshake complete)
    Established,
    /// We sent FIN, waiting ACK of FIN or peer's FIN
    FinWait1,
    /// Our FIN ACKed, waiting peer's FIN
    FinWait2,
    /// Peer sent FIN, we can still send
    CloseWait,
    /// Both sides sent FIN simultaneously, waiting ACK
    Closing,
    /// In CloseWait, sent FIN, waiting final ACK
    LastAck,
    /// Both FINs exchanged, wait 2*MSL before cleanup
    TimeWait,
    /// Terminal
    Closed,
}

impl TcpState {
    pub fn is_established(&self) -> bool {
        *self == TcpState::Established
    }

    /// Can we still send data in this state?
    pub fn can_send(&self) -> bool {
        matches!(self, TcpState::Established | TcpState::CloseWait)
    }

    /// Is this a terminal or near-terminal state?
    pub fn is_closed_or_closing(&self) -> bool {
        matches!(
            self,
            TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::Closing
                | TcpState::LastAck
                | TcpState::TimeWait
                | TcpState::Closed
        )
    }
}

// ── RTT estimator (Jacobson/Karels, RFC 6298) ──────────────────────────────

pub(crate) struct RttEstimator {
    srtt_us: Option<u64>,
    rttvar_us: u64,
    rto_ms: u64,
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

    fn update(&mut self, sample_us: u64) {
        match self.srtt_us {
            None => {
                self.srtt_us = Some(sample_us);
                self.rttvar_us = sample_us / 2;
            }
            Some(srtt) => {
                let diff = if srtt > sample_us {
                    srtt - sample_us
                } else {
                    sample_us - srtt
                };
                self.rttvar_us = (self.rttvar_us * 3 / 4) + (diff / 4);
                self.srtt_us = Some((srtt * 7 / 8) + (sample_us / 8));
            }
        }
        let srtt_ms = self.srtt_us.unwrap() / 1000;
        let rttvar_ms = self.rttvar_us / 1000;
        let k_rttvar = (4 * rttvar_ms).max(CLOCK_GRANULARITY_MS);
        self.rto_ms = (srtt_ms + k_rttvar).clamp(MIN_RTO_MS, MAX_RTO_MS);
    }

    fn rto(&self) -> u64 {
        self.rto_ms
    }

    fn mark_retransmitted(&mut self, seq: u32) {
        self.retransmitted_seqs.insert(seq);
    }

    fn was_retransmitted(&mut self, seq: u32) -> bool {
        self.retransmitted_seqs.remove(&seq)
    }

    fn clear_retransmitted_up_to(&mut self, ack_seq: u32) {
        self.retransmitted_seqs.retain(|&seq| seq >= ack_seq);
    }
}

// ── Unacknowledged segment ─────────────────────────────────────────────────

pub(crate) struct UnackedSegment {
    seq: u32,
    data: Vec<u8>,
    sent_at: Instant,
}

// ── Connection inner state (behind one Mutex) ──────────────────────────────

pub(crate) struct ConnInner {
    pub state: TcpState,
    // Receive
    pub recv_buf: VecDeque<u8>,
    pub ooo_buf: BTreeMap<u32, Vec<u8>>,
    pub next_recv_seq: u32,
    pub recv_window: u32,
    pub peer_fin: bool,
    // Send
    pub next_send_seq: u32,
    pub send_ack_seq: u32,
    pub send_window: u32,
    pub unacked: VecDeque<UnackedSegment>,
    // FIN tracking: sequence number consumed by our FIN
    pub fin_seq: Option<u32>,
    // Congestion control
    pub cwnd: u32,
    pub ssthresh: u32,
    pub dup_ack_count: u32,
    pub last_dup_ack: u32,
    // RTT
    pub rtt: RttEstimator,
    // Wakers
    pub read_waker: Option<Waker>,
    pub write_waker: Option<Waker>,
    pub close_waker: Option<Waker>,
}

impl ConnInner {
    fn new(state: TcpState) -> Self {
        Self {
            state,
            recv_buf: VecDeque::new(),
            ooo_buf: BTreeMap::new(),
            next_recv_seq: 0,
            recv_window: DEFAULT_WINDOW_SIZE,
            peer_fin: false,
            next_send_seq: 0,
            send_ack_seq: 0,
            send_window: DEFAULT_WINDOW_SIZE,
            unacked: VecDeque::new(),
            fin_seq: None,
            cwnd: INITIAL_CWND,
            ssthresh: MAX_INFLIGHT,
            dup_ack_count: 0,
            last_dup_ack: 0,
            rtt: RttEstimator::new(),
            read_waker: None,
            write_waker: None,
            close_waker: None,
        }
    }

    fn wake_reader(&mut self) {
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
    }

    fn wake_writer(&mut self) {
        if let Some(w) = self.write_waker.take() {
            w.wake();
        }
    }

    fn wake_closer(&mut self) {
        if let Some(w) = self.close_waker.take() {
            w.wake();
        }
    }

    fn wake_all(&mut self) {
        self.wake_reader();
        self.wake_writer();
        self.wake_closer();
    }
}

// ── TcpConnection ──────────────────────────────────────────────────────────

/// A single TCP/KEY connection, identified by (local_port, remote_key, remote_port).
///
/// Implements AsyncRead + AsyncWrite. All mutable state is behind a single
/// std::sync::Mutex (never held across await points).
#[derive(Clone)]
pub struct TcpConnection {
    key: ConnKey,
    pub(crate) inner: Arc<Mutex<ConnInner>>,
    /// Sends encoded packets to the central writer task
    outgoing: mpsc::Sender<(Vec<u8>, Addr)>,
    /// Notified when connection transitions to Established
    pub(crate) open_notify: Arc<Notify>,
    cancel: CancellationToken,
}

impl TcpConnection {
    /// Create a new connection. Does NOT spawn the background task — caller must
    /// call `spawn_background_task` separately after registering the incoming channel.
    ///
    /// `parent_cancel` is the stack's token — used to create a child token so that
    /// stack shutdown propagates, but dropping this connection does NOT kill the stack.
    pub(crate) fn new(
        key: ConnKey,
        state: TcpState,
        outgoing: mpsc::Sender<(Vec<u8>, Addr)>,
        parent_cancel: CancellationToken,
    ) -> Self {
        Self {
            key,
            inner: Arc::new(Mutex::new(ConnInner::new(state))),
            outgoing,
            open_notify: Arc::new(Notify::new()),
            cancel: parent_cancel.child_token(),
        }
    }

    /// Spawn the background task that processes incoming packets and runs retransmit timer.
    pub(crate) fn spawn_background_task(&self, incoming: mpsc::Receiver<Packet>) {
        let inner = self.inner.clone();
        let outgoing = self.outgoing.clone();
        let key = self.key;
        let open_notify = self.open_notify.clone();
        let cancel = self.cancel.clone();

        tokio::spawn(async move {
            connection_task(inner, incoming, outgoing, key, open_notify, cancel).await;
        });
    }

    pub fn key(&self) -> ConnKey {
        self.key
    }

    pub fn local_port(&self) -> u16 {
        self.key.local_port
    }

    pub fn remote_key(&self) -> Addr {
        self.key.remote_key
    }

    pub fn remote_port(&self) -> u16 {
        self.key.remote_port
    }

    pub fn state(&self) -> TcpState {
        self.inner.lock().unwrap().state
    }

    pub fn is_alive(&self) -> bool {
        let state = self.inner.lock().unwrap().state;
        matches!(
            state,
            TcpState::SynSent | TcpState::SynReceived | TcpState::Established | TcpState::CloseWait
        )
    }

    /// Wait until connection reaches Established state.
    pub async fn wait_for_open(&self) {
        loop {
            // Register the notification future BEFORE checking state to avoid
            // a race where the background task notifies between our check and
            // the await — that would lose the notification and hang forever.
            let notified = self.open_notify.notified();
            let state = self.inner.lock().unwrap().state;
            if state == TcpState::Established || state == TcpState::Closed {
                return;
            }
            notified.await;
        }
    }

    /// Set the peer's advertised receive window
    pub(crate) fn set_peer_window(&self, window: u32) {
        self.inner.lock().unwrap().send_window = window;
    }

    /// Send a SYN packet
    pub(crate) async fn send_syn(&self) -> Result<()> {
        let packet = Packet::syn(self.key.local_port, self.key.remote_port);
        self.send_packet(packet).await
    }

    /// Send a SYN-ACK packet
    pub(crate) async fn send_syn_ack(&self) -> Result<()> {
        let packet = Packet::syn_ack(self.key.local_port, self.key.remote_port);
        self.send_packet(packet).await
    }

    /// Abort the connection immediately (RST)
    pub async fn abort(&self) -> Result<()> {
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.state == TcpState::Closed {
                return Ok(());
            }
            inner.state = TcpState::Closed;
            inner.wake_all();
        }

        let packet = Packet::rst(self.key.local_port, self.key.remote_port);
        let _ = self.send_packet(packet).await;
        Ok(())
    }

    /// Graceful close (sends FIN). Called from poll_shutdown or directly.
    pub async fn close(&self) -> Result<()> {
        let fin_seq = {
            let mut inner = self.inner.lock().unwrap();
            match inner.state {
                TcpState::Closed | TcpState::TimeWait => return Ok(()),
                TcpState::FinWait1 | TcpState::FinWait2 | TcpState::Closing | TcpState::LastAck => {
                    return Ok(());
                }
                TcpState::Established => {
                    // FIN consumes one sequence number
                    let seq = inner.next_send_seq;
                    inner.next_send_seq = seq.wrapping_add(1);
                    inner.fin_seq = Some(seq);
                    inner.state = TcpState::FinWait1;
                    seq
                }
                TcpState::CloseWait => {
                    let seq = inner.next_send_seq;
                    inner.next_send_seq = seq.wrapping_add(1);
                    inner.fin_seq = Some(seq);
                    inner.state = TcpState::LastAck;
                    seq
                }
                _ => return Ok(()),
            }
        };

        let packet = Packet::fin(self.key.local_port, self.key.remote_port, fin_seq);
        let _ = self.send_packet(packet).await;
        Ok(())
    }

    /// Encode and send a packet to the writer task
    async fn send_packet(&self, packet: Packet) -> Result<()> {
        let data = packet.encode()?;
        self.outgoing
            .send((data, self.key.remote_key))
            .await
            .map_err(|_| Error::ConnectionClosed)
    }

    /// Try-send a packet (non-blocking). Used from poll_write and ack paths.
    fn try_send_packet(&self, packet: Packet) -> Result<()> {
        let data = packet.encode()?;
        let _ = self.outgoing.try_send((data, self.key.remote_key));
        Ok(())
    }

    /// Send an ACK non-blockingly
    #[allow(dead_code)]
    fn send_ack_nonblocking(&self, inner: &ConnInner) {
        let packet = Packet::ack(
            self.key.local_port,
            self.key.remote_port,
            inner.next_recv_seq,
            inner.recv_window,
        );
        let _ = self.try_send_packet(packet);
    }
}

// ── Background connection task ─────────────────────────────────────────────

async fn connection_task(
    inner: Arc<Mutex<ConnInner>>,
    mut incoming: mpsc::Receiver<Packet>,
    outgoing: mpsc::Sender<(Vec<u8>, Addr)>,
    key: ConnKey,
    open_notify: Arc<Notify>,
    cancel: CancellationToken,
) {
    let mut last_ack: u32 = 0;
    let mut rto_ms: u64 = INITIAL_RTO_MS;
    let mut total_stall_ms: u64 = 0;
    let mut cwnd_collapsed = false;

    loop {
        tokio::select! {
            packet = incoming.recv() => {
                match packet {
                    Some(pkt) => {
                        handle_incoming_packet(
                            &inner, &outgoing, &key, &open_notify, pkt,
                        );
                    }
                    None => {
                        // Channel closed — connection dead
                        let mut g = inner.lock().unwrap();
                        g.state = TcpState::Closed;
                        g.wake_all();
                        break;
                    }
                }

                // Reset retransmit state on ACK progress
                let current_ack = inner.lock().unwrap().send_ack_seq;
                if current_ack > last_ack {
                    last_ack = current_ack;
                    total_stall_ms = 0;
                    cwnd_collapsed = false;
                    rto_ms = inner.lock().unwrap().rtt.rto();
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(rto_ms)) => {
                // Retransmit timer fired
                let state = inner.lock().unwrap().state;
                if state == TcpState::Closed {
                    break;
                }
                if state == TcpState::TimeWait {
                    // TimeWait expiry
                    let mut g = inner.lock().unwrap();
                    g.state = TcpState::Closed;
                    g.wake_all();
                    break;
                }

                let current_ack = inner.lock().unwrap().send_ack_seq;
                if current_ack > last_ack {
                    last_ack = current_ack;
                    total_stall_ms = 0;
                    cwnd_collapsed = false;
                    rto_ms = inner.lock().unwrap().rtt.rto();
                    continue;
                }

                let unacked_empty = inner.lock().unwrap().unacked.is_empty();
                if unacked_empty {
                    rto_ms = inner.lock().unwrap().rtt.rto();
                    total_stall_ms = 0;
                    cwnd_collapsed = false;
                    continue;
                }

                total_stall_ms += rto_ms;

                if total_stall_ms >= MAX_STALL_MS {
                    debug!(
                        "Connection {:?}: giving up after {}ms stall",
                        key, total_stall_ms
                    );
                    let mut g = inner.lock().unwrap();
                    g.state = TcpState::Closed;
                    g.wake_all();

                    let rst = Packet::rst(key.local_port, key.remote_port);
                    if let Ok(data) = rst.encode() {
                        let _ = outgoing.try_send((data, key.remote_key));
                    }
                    break;
                }

                // Collapse cwnd once per stall episode
                if !cwnd_collapsed {
                    cwnd_collapsed = true;
                    let mut g = inner.lock().unwrap();
                    let half = (g.cwnd / 2).max(SEND_CHUNK_SIZE as u32);
                    g.ssthresh = half;
                    g.cwnd = SEND_CHUNK_SIZE as u32;
                }

                // Retransmit segments
                let (segments, ack_seq, recv_window) = {
                    let g = inner.lock().unwrap();
                    let cwnd_val = g.cwnd as usize;
                    let seg_count = (cwnd_val / SEND_CHUNK_SIZE).max(1);
                    let segs: Vec<(u32, Vec<u8>)> = g
                        .unacked
                        .iter()
                        .take(seg_count)
                        .map(|s| (s.seq, s.data.clone()))
                        .collect();
                    (segs, g.next_recv_seq, g.recv_window)
                };

                {
                    let mut g = inner.lock().unwrap();
                    for &(seq, _) in &segments {
                        g.rtt.mark_retransmitted(seq);
                    }
                }

                debug!(
                    "Connection {:?}: retransmitting {} seg(s) (rto={}ms, stalled={}ms)",
                    key, segments.len(), rto_ms, total_stall_ms
                );

                for (seq, data) in segments {
                    let pkt = Packet::data_ack(
                        key.local_port, key.remote_port, data, seq, ack_seq, recv_window,
                    );
                    if let Ok(encoded) = pkt.encode() {
                        let _ = outgoing.try_send((encoded, key.remote_key));
                    }
                }

                rto_ms = (rto_ms * 2).min(MAX_RTO_MS);
            }
            _ = cancel.cancelled() => {
                let mut g = inner.lock().unwrap();
                g.state = TcpState::Closed;
                g.wake_all();
                break;
            }
        }
    }
}

/// Process a single incoming packet, updating ConnInner state.
fn handle_incoming_packet(
    inner: &Arc<Mutex<ConnInner>>,
    outgoing: &mpsc::Sender<(Vec<u8>, Addr)>,
    key: &ConnKey,
    open_notify: &Arc<Notify>,
    packet: Packet,
) {
    let mut g = inner.lock().unwrap();

    match g.state {
        TcpState::SynSent => {
            // Expecting SYN-ACK
            if packet.is_syn() && packet.is_ack() {
                g.send_window = packet.window;
                g.state = TcpState::Established;
                g.wake_writer();
                drop(g);
                open_notify.notify_waiters();
                // Send ACK (3rd leg of handshake)
                let ack = Packet::ack(key.local_port, key.remote_port, 0, DEFAULT_WINDOW_SIZE);
                if let Ok(data) = ack.encode() {
                    let _ = outgoing.try_send((data, key.remote_key));
                }
                return;
            }
            if packet.is_rst() {
                g.state = TcpState::Closed;
                g.wake_all();
                drop(g);
                open_notify.notify_waiters();
                return;
            }
            return;
        }
        TcpState::SynReceived => {
            if packet.is_rst() {
                g.state = TcpState::Closed;
                g.wake_all();
                drop(g);
                open_notify.notify_waiters();
                return;
            }
            // ACK completes 3-way handshake
            if packet.is_ack() && !packet.is_syn() {
                g.send_window = packet.window;
                g.state = TcpState::Established;
                g.wake_writer();
                // If packet has data, fall through to data processing
                if packet.data.is_empty() {
                    drop(g);
                    open_notify.notify_waiters();
                    return;
                }
                // Notify open, then process data below
                open_notify.notify_waiters();
                // Fall through to Established data processing
            } else {
                // Duplicate SYN — resend SYN-ACK
                drop(g);
                let syn_ack = Packet::syn_ack(key.local_port, key.remote_port);
                if let Ok(data) = syn_ack.encode() {
                    let _ = outgoing.try_send((data, key.remote_key));
                }
                return;
            }
        }
        TcpState::Established => {
            if packet.is_rst() {
                g.state = TcpState::Closed;
                g.wake_all();
                return;
            }
            if packet.is_fin() {
                g.peer_fin = true;
                g.state = TcpState::CloseWait;
                g.wake_reader();
                g.wake_closer();
                // Send ACK for FIN
                let ack = Packet::ack(
                    key.local_port, key.remote_port,
                    g.next_recv_seq, g.recv_window,
                );
                drop(g);
                if let Ok(data) = ack.encode() {
                    let _ = outgoing.try_send((data, key.remote_key));
                }
                return;
            }
        }
        TcpState::FinWait1 => {
            if packet.is_rst() {
                g.state = TcpState::Closed;
                g.wake_all();
                return;
            }
            // Check if peer ACKs our FIN
            let fin_acked = g.fin_seq.is_some_and(|fs| {
                let fin_end = fs.wrapping_add(1);
                packet.is_ack() && packet.ack_seq >= fin_end
            });
            if packet.is_fin() && fin_acked {
                // Simultaneous close with ACK — go to TimeWait
                g.peer_fin = true;
                g.state = TcpState::TimeWait;
                g.wake_closer();
                let ack = Packet::ack(
                    key.local_port, key.remote_port,
                    g.next_recv_seq, g.recv_window,
                );
                drop(g);
                if let Ok(data) = ack.encode() {
                    let _ = outgoing.try_send((data, key.remote_key));
                }
                return;
            }
            if packet.is_fin() {
                // Simultaneous close (no ACK of our FIN yet)
                g.peer_fin = true;
                g.state = TcpState::Closing;
                g.wake_closer();
                let ack = Packet::ack(
                    key.local_port, key.remote_port,
                    g.next_recv_seq, g.recv_window,
                );
                drop(g);
                if let Ok(data) = ack.encode() {
                    let _ = outgoing.try_send((data, key.remote_key));
                }
                return;
            }
            if fin_acked {
                g.state = TcpState::FinWait2;
                g.wake_closer();
                // Fall through to process ACK/data
            }
        }
        TcpState::FinWait2 => {
            if packet.is_rst() {
                g.state = TcpState::Closed;
                g.wake_all();
                return;
            }
            if packet.is_fin() {
                g.peer_fin = true;
                g.state = TcpState::TimeWait;
                g.wake_reader();
                g.wake_closer();
                let ack = Packet::ack(
                    key.local_port, key.remote_port,
                    g.next_recv_seq, g.recv_window,
                );
                drop(g);
                if let Ok(data) = ack.encode() {
                    let _ = outgoing.try_send((data, key.remote_key));
                }
                return;
            }
        }
        TcpState::CloseWait => {
            if packet.is_rst() {
                g.state = TcpState::Closed;
                g.wake_all();
                return;
            }
            // Can still process ACKs for data we sent
        }
        TcpState::Closing => {
            if packet.is_rst() {
                g.state = TcpState::Closed;
                g.wake_all();
                return;
            }
            // Waiting for ACK of our FIN
            let fin_acked = g.fin_seq.is_some_and(|fs| {
                let fin_end = fs.wrapping_add(1);
                packet.is_ack() && packet.ack_seq >= fin_end
            });
            if fin_acked {
                g.state = TcpState::TimeWait;
                g.wake_closer();
            }
            return;
        }
        TcpState::LastAck => {
            if packet.is_rst() {
                g.state = TcpState::Closed;
                g.wake_all();
                return;
            }
            let fin_acked = g.fin_seq.is_some_and(|fs| {
                let fin_end = fs.wrapping_add(1);
                packet.is_ack() && packet.ack_seq >= fin_end
            });
            if fin_acked {
                g.state = TcpState::Closed;
                g.wake_all();
            }
            return;
        }
        TcpState::TimeWait | TcpState::Closed | TcpState::Listen => {
            return;
        }
    }

    // === ACK processing (for Established, FinWait1, FinWait2, CloseWait) ===
    if packet.is_ack() {
        g.send_window = packet.window;
        let new_ack = packet.ack_seq;
        let old_ack = g.send_ack_seq;

        if new_ack > old_ack {
            g.send_ack_seq = new_ack;

            // Capture RTT sample from oldest fully-ACKed segment
            let oldest_sample = g.unacked.front()
                .filter(|seg| seg.seq.wrapping_add(seg.data.len() as u32) <= new_ack)
                .map(|seg| (seg.seq, seg.sent_at));

            // Prune ACKed segments
            while let Some(front) = g.unacked.front() {
                let seg_end = front.seq.wrapping_add(front.data.len() as u32);
                if seg_end <= new_ack {
                    g.unacked.pop_front();
                } else {
                    break;
                }
            }

            // RTT sample (Karn's algorithm)
            if let Some((seq, sent_at)) = oldest_sample {
                if !g.rtt.was_retransmitted(seq) {
                    let sample_us = sent_at.elapsed().as_micros() as u64;
                    g.rtt.update(sample_us);
                    trace!("Connection {:?}: RTT {}us, RTO={}ms", key, sample_us, g.rtt.rto());
                }
                g.rtt.clear_retransmitted_up_to(new_ack);
            }

            g.dup_ack_count = 0;
            g.last_dup_ack = new_ack;

            // Congestion window growth (TCP Reno)
            let new_cwnd = if g.cwnd < g.ssthresh {
                g.cwnd + SEND_CHUNK_SIZE as u32
            } else {
                g.cwnd + (SEND_CHUNK_SIZE as u32 * SEND_CHUNK_SIZE as u32) / g.cwnd.max(1)
            };
            g.cwnd = new_cwnd.min(MAX_INFLIGHT);
        } else if new_ack == old_ack && old_ack > 0 && packet.data.is_empty() {
            // Duplicate ACK (standalone ACK only)
            g.dup_ack_count += 1;
            if g.dup_ack_count == 3 {
                // Fast retransmit
                let half = (g.cwnd / 2).max(SEND_CHUNK_SIZE as u32);
                g.ssthresh = half;
                g.cwnd = half;

                let seg = g.unacked.front().map(|s| (s.seq, s.data.clone()));
                if let Some((seq, data)) = seg {
                    g.rtt.mark_retransmitted(seq);
                    let pkt = Packet::data_ack(
                        key.local_port, key.remote_port,
                        data, seq, g.next_recv_seq, g.recv_window,
                    );
                    drop(g);
                    if let Ok(encoded) = pkt.encode() {
                        let _ = outgoing.try_send((encoded, key.remote_key));
                    }
                    // Re-lock for wake_writer below
                    let mut g = inner.lock().unwrap();
                    g.wake_writer();
                    debug!("Connection {:?}: fast retransmit seq {}", key, seq);
                    return;
                }
            }
        }
        g.wake_writer();
    }

    // === Data delivery ===
    if !packet.data.is_empty() {
        let expected = g.next_recv_seq;
        let pkt_seq = packet.seq;

        if pkt_seq == expected {
            let data_len = packet.data.len() as u32;
            g.recv_buf.extend(&packet.data);
            let mut next_seq = expected.wrapping_add(data_len);

            // Drain consecutive OOO packets
            while let Some(data) = g.ooo_buf.remove(&next_seq) {
                let len = data.len() as u32;
                g.recv_buf.extend(&data);
                next_seq = next_seq.wrapping_add(len);
            }

            g.next_recv_seq = next_seq;
            g.recv_window = DEFAULT_WINDOW_SIZE.saturating_sub(g.recv_buf.len() as u32);
            g.wake_reader();

            // Send ACK
            let ack = Packet::ack(
                key.local_port, key.remote_port,
                g.next_recv_seq, g.recv_window,
            );
            drop(g);
            if let Ok(data) = ack.encode() {
                let _ = outgoing.try_send((data, key.remote_key));
            }
        } else if pkt_seq > expected {
            // Out-of-order
            if g.ooo_buf.len() < 64 {
                g.ooo_buf.insert(pkt_seq, packet.data);
            }
            trace!("Connection {:?}: OOO expected {}, got {}", key, expected, pkt_seq);
            // Send dup-ACK
            let ack = Packet::ack(
                key.local_port, key.remote_port,
                g.next_recv_seq, g.recv_window,
            );
            drop(g);
            if let Ok(data) = ack.encode() {
                let _ = outgoing.try_send((data, key.remote_key));
            }
        } else {
            // Old/duplicate data — send ACK anyway
            let ack = Packet::ack(
                key.local_port, key.remote_port,
                g.next_recv_seq, g.recv_window,
            );
            drop(g);
            if let Ok(data) = ack.encode() {
                let _ = outgoing.try_send((data, key.remote_key));
            }
        }
    }
}

// ── AsyncRead ──────────────────────────────────────────────────────────────

impl AsyncRead for TcpConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut inner = this.inner.lock().unwrap();

        if !inner.recv_buf.is_empty() {
            let to_read = buf.remaining().min(inner.recv_buf.len());
            let (head, tail) = inner.recv_buf.as_slices();

            if to_read <= head.len() {
                buf.put_slice(&head[..to_read]);
            } else {
                buf.put_slice(head);
                buf.put_slice(&tail[..to_read - head.len()]);
            }
            drop(inner.recv_buf.drain(..to_read));

            if inner.recv_buf.is_empty() {
                inner.recv_buf.shrink_to_fit();
            }

            let available = DEFAULT_WINDOW_SIZE.saturating_sub(inner.recv_buf.len() as u32);
            let old_window = inner.recv_window;
            inner.recv_window = available;

            // Proactive window update when buffer drains past halfway
            let half = DEFAULT_WINDOW_SIZE / 2;
            if old_window < half && available >= half {
                let ack = Packet::ack(
                    this.key.local_port,
                    this.key.remote_port,
                    inner.next_recv_seq,
                    inner.recv_window,
                );
                drop(inner);
                let _ = this.try_send_packet(ack);
            }

            return Poll::Ready(Ok(()));
        }

        // No data — check terminal conditions
        if inner.peer_fin {
            return Poll::Ready(Ok(())); // EOF
        }

        if inner.state == TcpState::Closed || inner.state == TcpState::TimeWait {
            return Poll::Ready(Ok(())); // EOF
        }

        if this.outgoing.is_closed() {
            return Poll::Ready(Ok(())); // Writer dead
        }

        inner.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

// ── AsyncWrite ─────────────────────────────────────────────────────────────

impl AsyncWrite for TcpConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut inner = this.inner.lock().unwrap();

        if inner.state == TcpState::Closed || inner.state == TcpState::TimeWait {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "Connection closed")));
        }

        if !inner.state.can_send() {
            inner.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        // Flow control
        let send_window = inner.send_window as usize;
        let next_seq = inner.next_send_seq;
        let ack_seq = inner.send_ack_seq;
        let in_flight = next_seq.wrapping_sub(ack_seq) as usize;
        let cwnd_val = inner.cwnd as usize;
        let effective_window = send_window.min(cwnd_val);
        let can_send = effective_window.saturating_sub(in_flight);

        if can_send == 0 {
            inner.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let to_send = buf.len().min(can_send).min(SEND_CHUNK_SIZE);
        let data = buf[..to_send].to_vec();

        let seq = inner.next_send_seq;
        inner.next_send_seq = seq.wrapping_add(to_send as u32);

        let ack_seq_val = inner.next_recv_seq;
        let recv_window = inner.recv_window;

        let packet = Packet::data_ack(
            this.key.local_port,
            this.key.remote_port,
            data.clone(),
            seq,
            ack_seq_val,
            recv_window,
        );

        drop(inner);

        match this.try_send_packet(packet) {
            Ok(()) => {
                let mut inner = this.inner.lock().unwrap();
                inner.unacked.push_back(UnackedSegment {
                    seq,
                    data,
                    sent_at: Instant::now(),
                });
                Poll::Ready(Ok(to_send))
            }
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "outgoing channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Graceful shutdown: waits for all sent data to be ACKed, sends FIN,
    /// then returns immediately. The FIN exchange completes in the background.
    ///
    /// This matches the semantics of TCP's `close()` — it initiates the close
    /// but doesn't block until TimeWait/Closed. Blocking until the peer sends
    /// FIN would deadlock if both sides call `shutdown()` sequentially.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.outgoing.is_closed() {
            let mut inner = this.inner.lock().unwrap();
            inner.state = TcpState::Closed;
            return Poll::Ready(Ok(()));
        }

        let mut inner = this.inner.lock().unwrap();

        match inner.state {
            TcpState::Closed | TcpState::TimeWait
            | TcpState::FinWait1 | TcpState::FinWait2
            | TcpState::Closing | TcpState::LastAck => {
                // FIN already sent (or connection already closed) — done
                return Poll::Ready(Ok(()));
            }
            TcpState::Established | TcpState::CloseWait => {
                // Wait for all data to be ACKed before sending FIN
                let next_seq = inner.next_send_seq;
                let ack_seq = inner.send_ack_seq;
                if ack_seq < next_seq {
                    inner.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }

                // All data ACKed — send FIN
                let seq = inner.next_send_seq;
                inner.next_send_seq = seq.wrapping_add(1);
                inner.fin_seq = Some(seq);

                if inner.state == TcpState::CloseWait {
                    inner.state = TcpState::LastAck;
                } else {
                    inner.state = TcpState::FinWait1;
                    if inner.peer_fin {
                        inner.state = TcpState::Closing;
                    }
                }

                let src = this.key.local_port;
                let dst = this.key.remote_port;
                drop(inner);

                let fin = Packet::fin(src, dst, seq);
                let _ = this.try_send_packet(fin);

                // FIN sent — return immediately. The state machine completes
                // in the background task (FinWait1→FinWait2→TimeWait→Closed).
                return Poll::Ready(Ok(()));
            }
            _ => {
                // SynSent, SynReceived, Listen — not ready to close
                inner.close_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        // If this is the last reference (Arc strong count == 1 for inner),
        // cancel the background task
        if Arc::strong_count(&self.inner) <= 2 {
            self.cancel.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Create a wired pair of connections for testing.
    /// Returns (client, server, relay_handles).
    fn create_connection_pair() -> (
        TcpConnection,
        TcpConnection,
        tokio::task::JoinHandle<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let client_addr = Addr::from([1u8; 32]);
        let server_addr = Addr::from([2u8; 32]);

        // Shared "wire" channels
        let (c2s_tx, mut c2s_rx) = mpsc::channel::<(Vec<u8>, Addr)>(64);
        let (s2c_tx, mut s2c_rx) = mpsc::channel::<(Vec<u8>, Addr)>(64);

        // Per-connection incoming channels
        let (client_in_tx, client_in_rx) = mpsc::channel::<Packet>(64);
        let (server_in_tx, server_in_rx) = mpsc::channel::<Packet>(64);

        let client_key = ConnKey {
            local_port: 49152,
            remote_key: server_addr,
            remote_port: 80,
        };
        let server_key = ConnKey {
            local_port: 80,
            remote_key: client_addr,
            remote_port: 49152,
        };

        let cancel = CancellationToken::new();

        let client = TcpConnection::new(client_key, TcpState::SynSent, c2s_tx, cancel.clone());
        let server = TcpConnection::new(server_key, TcpState::Listen, s2c_tx, cancel.clone());

        client.spawn_background_task(client_in_rx);
        server.spawn_background_task(server_in_rx);

        // Relay: client → server
        let server_in_tx_c = server_in_tx.clone();
        let relay_c2s = tokio::spawn(async move {
            while let Some((data, _addr)) = c2s_rx.recv().await {
                if let Ok(pkt) = Packet::decode(&data) {
                    let _ = server_in_tx_c.send(pkt).await;
                }
            }
        });

        // Relay: server → client
        let client_in_tx_c = client_in_tx.clone();
        let relay_s2c = tokio::spawn(async move {
            while let Some((data, _addr)) = s2c_rx.recv().await {
                if let Ok(pkt) = Packet::decode(&data) {
                    let _ = client_in_tx_c.send(pkt).await;
                }
            }
        });

        (client, server, relay_c2s, relay_s2c)
    }

    #[tokio::test]
    async fn test_three_way_handshake() {
        let (client, server, r1, r2) = create_connection_pair();

        // Server: transition to SynReceived and send SYN-ACK
        {
            let mut g = server.inner.lock().unwrap();
            g.state = TcpState::SynReceived;
        }
        let _ = server.send_syn_ack().await;

        // Client: send SYN
        let _ = client.send_syn().await;

        // Wait for handshake
        tokio::time::timeout(Duration::from_secs(5), client.wait_for_open())
            .await
            .expect("Client handshake should complete");

        // Give server time to process the ACK
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(client.state(), TcpState::Established);
        assert_eq!(server.state(), TcpState::Established);

        r1.abort();
        r2.abort();
    }

    #[tokio::test]
    async fn test_data_exchange() {
        let (client, server, r1, r2) = create_connection_pair();

        // Fast-track to Established
        {
            let mut g = client.inner.lock().unwrap();
            g.state = TcpState::Established;
        }
        {
            let mut g = server.inner.lock().unwrap();
            g.state = TcpState::Established;
        }

        let mut c = client.clone();
        let mut s = server.clone();

        // Client → Server
        c.write_all(b"hello").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut buf = vec![0u8; 64];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // Server → Client
        s.write_all(b"world").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let n = c.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");

        r1.abort();
        r2.abort();
    }

    #[test]
    fn test_conn_key_hash() {
        use std::collections::HashMap;

        let key1 = ConnKey {
            local_port: 80,
            remote_key: Addr::from([1u8; 32]),
            remote_port: 49152,
        };
        let key2 = ConnKey {
            local_port: 80,
            remote_key: Addr::from([2u8; 32]),
            remote_port: 49152,
        };

        let mut map = HashMap::new();
        map.insert(key1, "conn1");
        map.insert(key2, "conn2");
        assert_eq!(map.len(), 2);
        assert_eq!(map[&key1], "conn1");
        assert_eq!(map[&key2], "conn2");
    }

    #[test]
    fn test_tcp_state_properties() {
        assert!(TcpState::Established.can_send());
        assert!(TcpState::CloseWait.can_send());
        assert!(!TcpState::FinWait1.can_send());
        assert!(!TcpState::Closed.can_send());

        assert!(TcpState::Established.is_established());
        assert!(!TcpState::SynSent.is_established());
    }
}
