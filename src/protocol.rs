use crate::error::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

/// Protocol flags
pub const FLAG_SYN: u8 = 0x01; // Open stream
pub const FLAG_ACK: u8 = 0x02; // Acknowledge
pub const FLAG_FIN: u8 = 0x04; // Close stream gracefully
pub const FLAG_RST: u8 = 0x08; // Reset stream (abort)
pub const FLAG_DGRAM: u8 = 0x10; // Connectionless datagram

/// Default flow control window size (512 KB)
pub const DEFAULT_WINDOW_SIZE: usize = 512 * 1024;

/// Maximum packet size (64 KB - 1 byte)
pub const MAX_PACKET_SIZE: usize = 65535;

/// Packet header size:
/// [port+stream_id:u32][flags:u8][seq:u32][ack_seq:u32][window:u32][length:u16]
/// = 4 + 1 + 4 + 4 + 4 + 2 = 19 bytes
pub const HEADER_SIZE: usize = 19;

/// Yggdrasil overhead
pub const HEADER_YGGDRASIL: usize = 131;

/// Maximum data payload per packet (accounting for header + Yggdrasil overhead)
pub const MAX_DATA_SIZE: usize = MAX_PACKET_SIZE - HEADER_SIZE - HEADER_YGGDRASIL;

/// Preferred send chunk size.  Smaller than MAX_DATA_SIZE to reduce queuing
/// delay at the ironwood layer (which drops packets queued longer than 25 ms).
/// 16 KiB keeps per-packet transmission time well under that budget while
/// keeping header overhead below 1 %.
pub const SEND_CHUNK_SIZE: usize = 16 * 1024;

/// Maximum in-flight bytes before sender blocks (512 KB)
pub const MAX_INFLIGHT: usize = 512 * 1024;

/// Initial congestion window (2 segments = 32 KB)
pub const INITIAL_CWND: usize = 2 * SEND_CHUNK_SIZE;

/// Initial RTO in milliseconds before any RTT samples are available.
/// 500 ms is a sane default for mesh networks where RTT is typically 200-500 ms+.
pub const INITIAL_RTO_MS: u64 = 500;

/// Minimum RTO floor in milliseconds.
/// Mesh networks have higher latency than LAN; this prevents the computed
/// RTO from being too aggressive even with very fast RTT samples.
pub const MIN_RTO_MS: u64 = 200;

/// Clock granularity for RTO calculation in milliseconds (RFC 6298 recommends >= 100 ms;
/// we use 50 ms since tokio timers have sub-ms precision).
pub const CLOCK_GRANULARITY_MS: u64 = 50;

/// Maximum retransmit timeout in milliseconds (cap for exponential backoff)
pub const MAX_RTO_MS: u64 = 5_000;

/// Maximum total stall time before giving up (30 seconds)
pub const MAX_STALL_MS: u64 = 30_000;

/// Minimum inter-packet interval in milliseconds (pacing).
/// Ironwood drops packets queued longer than 25 ms, so spacing consecutive
/// packets by at least 10 ms keeps the queue well under that budget.
pub const PACING_INTERVAL_MS: u64 = 10;

/// Protocol packet
///
/// Wire format:
/// ```text
/// [port:u16 << 16 | stream_id:u16 : u32][flags: u8][seq: u32][ack_seq: u32][window: u32][length: u16][data: bytes]
/// ```
///
/// - `seq`:     byte-level sequence number of the first byte in `data` (0 for control packets)
/// - `ack_seq`: cumulative acknowledgment — "I have received all bytes up to this seq" (0 if no ACK)
/// - `window`:  receiver's available buffer space in bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Port number (high 16 bits of the wire u32)
    pub port: u16,

    /// Stream identifier (low 16 bits of the wire u32)
    pub stream_id: u16,

    /// Control flags (SYN, ACK, FIN, RST)
    pub flags: u8,

    /// Byte-level sequence number of the first data byte (0 for control packets)
    pub seq: u32,

    /// Cumulative ACK: peer has received all bytes up to (not including) this seq
    pub ack_seq: u32,

    /// Receiver's available window size (for flow control)
    pub window: usize,

    /// Data payload
    pub data: Vec<u8>,
}

impl Packet {
    /// Create a new packet
    pub fn new(port: u16, stream_id: u16, flags: u8, data: Vec<u8>) -> Self {
        Self {
            port,
            stream_id,
            flags,
            seq: 0,
            ack_seq: 0,
            window: DEFAULT_WINDOW_SIZE,
            data,
        }
    }

    /// Create a SYN packet to open a stream
    pub fn syn(port: u16, stream_id: u16) -> Self {
        Self::new(port, stream_id, FLAG_SYN, Vec::new())
    }

    /// Create a SYN-ACK packet
    pub fn syn_ack(port: u16, stream_id: u16) -> Self {
        Self::new(port, stream_id, FLAG_SYN | FLAG_ACK, Vec::new())
    }

    /// Create a data packet
    pub fn data(port: u16, stream_id: u16, data: Vec<u8>) -> Self {
        Self::new(port, stream_id, 0, data)
    }

    /// Create a data + ACK packet with sequence numbers
    pub fn data_ack(port: u16, stream_id: u16, data: Vec<u8>, seq: u32, ack_seq: u32, window: usize) -> Self {
        Self {
            port,
            stream_id,
            flags: FLAG_ACK,
            seq,
            ack_seq,
            window,
            data,
        }
    }

    /// Create a FIN packet to close a stream
    pub fn fin(port: u16, stream_id: u16) -> Self {
        Self::new(port, stream_id, FLAG_FIN, Vec::new())
    }

    /// Create a RST packet to reset a stream
    pub fn rst(port: u16, stream_id: u16) -> Self {
        Self::new(port, stream_id, FLAG_RST, Vec::new())
    }

    /// Create a datagram packet (connectionless, no stream_id)
    pub fn datagram(port: u16, data: Vec<u8>) -> Self {
        Self::new(port, 0, FLAG_DGRAM, data)
    }

    /// Create an ACK packet with cumulative ack_seq and window update
    pub fn ack(port: u16, stream_id: u16, ack_seq: u32, window: usize) -> Self {
        Self {
            port,
            stream_id,
            flags: FLAG_ACK,
            seq: 0,
            ack_seq,
            window,
            data: Vec::new(),
        }
    }

    /// Check if packet has SYN flag
    pub fn is_syn(&self) -> bool {
        self.flags & FLAG_SYN != 0
    }

    /// Check if packet has ACK flag
    pub fn is_ack(&self) -> bool {
        self.flags & FLAG_ACK != 0
    }

    /// Check if packet has FIN flag
    pub fn is_fin(&self) -> bool {
        self.flags & FLAG_FIN != 0
    }

    /// Check if packet has RST flag
    pub fn is_rst(&self) -> bool {
        self.flags & FLAG_RST != 0
    }

    /// Check if packet is a datagram
    pub fn is_dgram(&self) -> bool {
        self.flags & FLAG_DGRAM != 0
    }

    /// Encode packet to bytes
    ///
    /// Format: [(port << 16 | stream_id): u32][flags: u8][seq: u32][ack_seq: u32][window: u32][length: u16][data]
    pub fn encode(&self) -> Result<Vec<u8>> {
        let data_len = self.data.len();
        if data_len > MAX_DATA_SIZE {
            return Err(Error::PacketTooLarge(data_len, MAX_DATA_SIZE));
        }

        let mut buf = BytesMut::with_capacity(HEADER_SIZE + data_len);

        // Write combined port + stream_id (4 bytes, big-endian)
        let combined = ((self.port as u32) << 16) | (self.stream_id as u32);
        buf.put_u32(combined);

        // Write flags (1 byte)
        buf.put_u8(self.flags);

        // Write seq (4 bytes, big-endian)
        buf.put_u32(self.seq);

        // Write ack_seq (4 bytes, big-endian)
        buf.put_u32(self.ack_seq);

        // Write window (4 bytes, big-endian)
        buf.put_u32(self.window as u32);

        // Write length (2 bytes, big-endian)
        buf.put_u16(data_len as u16);

        // Write data payload
        buf.put_slice(&self.data);

        Ok(buf.to_vec())
    }

    /// Decode packet from bytes
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE {
            return Err(Error::Protocol(format!(
                "Packet too short: {} bytes (expected at least {}) [{}]",
                buf.len(),
                HEADER_SIZE,
                hex::encode(&buf[..buf.len()])
            )));
        }

        let mut cursor = std::io::Cursor::new(buf);

        // Read combined port + stream_id (4 bytes, big-endian)
        let combined = cursor.get_u32();
        let port = (combined >> 16) as u16;
        let stream_id = (combined & 0xFFFF) as u16;

        // Read flags (1 byte)
        let flags = cursor.get_u8();

        // Read seq (4 bytes, big-endian)
        let seq = cursor.get_u32();

        // Read ack_seq (4 bytes, big-endian)
        let ack_seq = cursor.get_u32();

        // Read window (4 bytes, big-endian)
        let window = cursor.get_u32() as usize;

        // Read length (2 bytes, big-endian)
        let length = cursor.get_u16() as usize;

        // Validate length matches remaining data
        let remaining = buf.len() - HEADER_SIZE;
        if length != remaining {
            return Err(Error::Protocol(format!(
                "Length mismatch: header says {} bytes, but {} bytes available",
                length, remaining
            )));
        }

        // Read data payload
        let data = buf[HEADER_SIZE..].to_vec();

        Ok(Self {
            port,
            stream_id,
            flags,
            seq,
            ack_seq,
            window,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_encode_decode() {
        let packet = Packet::new(5, 42, FLAG_SYN | FLAG_ACK, b"hello".to_vec());
        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();

        assert_eq!(decoded.port, 5);
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.flags, FLAG_SYN | FLAG_ACK);
        assert_eq!(decoded.data, b"hello");
        assert_eq!(decoded.seq, 0);
        assert_eq!(decoded.ack_seq, 0);
    }

    #[test]
    fn test_packet_port_stream_id_encoding() {
        // Verify the combined encoding: (port << 16) | stream_id
        let packet = Packet::syn(0x1234, 0xABCD);
        let encoded = packet.encode().unwrap();
        // First 4 bytes should be 0x1234ABCD
        assert_eq!(encoded[0], 0x12);
        assert_eq!(encoded[1], 0x34);
        assert_eq!(encoded[2], 0xAB);
        assert_eq!(encoded[3], 0xCD);

        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(decoded.port, 0x1234);
        assert_eq!(decoded.stream_id, 0xABCD);
    }

    #[test]
    fn test_packet_syn() {
        let packet = Packet::syn(1, 123);
        assert_eq!(packet.port, 1);
        assert_eq!(packet.stream_id, 123);
        assert!(packet.is_syn());
        assert!(!packet.is_ack());
        assert!(!packet.is_fin());
        assert!(!packet.is_rst());
        assert!(packet.data.is_empty());
    }

    #[test]
    fn test_packet_syn_ack() {
        let packet = Packet::syn_ack(2, 456);
        assert_eq!(packet.port, 2);
        assert_eq!(packet.stream_id, 456);
        assert!(packet.is_syn());
        assert!(packet.is_ack());
        assert!(!packet.is_fin());
        assert!(!packet.is_rst());
    }

    #[test]
    fn test_packet_data() {
        let packet = Packet::data(3, 789, b"test data".to_vec());
        assert_eq!(packet.port, 3);
        assert_eq!(packet.stream_id, 789);
        assert!(!packet.is_syn());
        assert!(!packet.is_ack());
        assert!(!packet.is_fin());
        assert!(!packet.is_rst());
        assert_eq!(packet.data, b"test data");
    }

    #[test]
    fn test_packet_data_ack_with_seq() {
        let packet = Packet::data_ack(1, 2, b"payload".to_vec(), 100, 200, 32768);
        assert_eq!(packet.seq, 100);
        assert_eq!(packet.ack_seq, 200);
        assert_eq!(packet.window, 32768);
        assert!(packet.is_ack());

        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(decoded.seq, 100);
        assert_eq!(decoded.ack_seq, 200);
        assert_eq!(decoded.window, 32768);
        assert_eq!(decoded.data, b"payload");
    }

    #[test]
    fn test_packet_ack_with_ack_seq() {
        let packet = Packet::ack(1, 2, 1024, 65536);
        assert_eq!(packet.ack_seq, 1024);
        assert_eq!(packet.window, 65536);
        assert!(packet.is_ack());
        assert!(packet.data.is_empty());

        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(decoded.ack_seq, 1024);
        assert_eq!(decoded.window, 65536);
    }

    #[test]
    fn test_packet_fin() {
        let packet = Packet::fin(1, 111);
        assert_eq!(packet.stream_id, 111);
        assert!(packet.is_fin());
        assert!(!packet.is_syn());
        assert!(!packet.is_ack());
        assert!(!packet.is_rst());
    }

    #[test]
    fn test_packet_rst() {
        let packet = Packet::rst(1, 222);
        assert_eq!(packet.stream_id, 222);
        assert!(packet.is_rst());
        assert!(!packet.is_syn());
        assert!(!packet.is_ack());
        assert!(!packet.is_fin());
    }

    #[test]
    fn test_packet_too_large() {
        let data = vec![0u8; MAX_DATA_SIZE + 1];
        let packet = Packet::new(0, 1, 0, data);
        assert!(matches!(
            packet.encode(),
            Err(Error::PacketTooLarge(_, _))
        ));
    }

    #[test]
    fn test_decode_invalid_length() {
        // Create packet with mismatched length field
        let mut buf = BytesMut::new();
        buf.put_u32(1); // combined port+stream_id
        buf.put_u8(0);  // flags
        buf.put_u32(0); // seq
        buf.put_u32(0); // ack_seq
        buf.put_u32(0); // window
        buf.put_u16(100); // length says 100 bytes
        buf.put_slice(b"short"); // but only 5 bytes of data

        assert!(matches!(
            Packet::decode(&buf),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn test_decode_too_short() {
        let buf = vec![0u8; 3]; // Less than HEADER_SIZE
        assert!(matches!(
            Packet::decode(&buf),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn test_packet_with_large_data() {
        let data = vec![0xAB; 1000];
        let packet = Packet::data(10, 999, data.clone());
        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();

        assert_eq!(decoded.port, 10);
        assert_eq!(decoded.stream_id, 999);
        assert_eq!(decoded.data.len(), 1000);
        assert_eq!(decoded.data, data);
    }

    #[test]
    fn test_packet_empty_data() {
        let packet = Packet::new(1, 1, FLAG_ACK, Vec::new());
        let encoded = packet.encode().unwrap();
        assert_eq!(encoded.len(), HEADER_SIZE);

        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(decoded.port, 1);
        assert_eq!(decoded.stream_id, 1);
        assert!(decoded.is_ack());
        assert!(decoded.data.is_empty());
    }

    #[test]
    fn test_packet_datagram() {
        let packet = Packet::datagram(100, b"dgram payload".to_vec());
        assert_eq!(packet.port, 100);
        assert_eq!(packet.stream_id, 0);
        assert!(packet.is_dgram());
        assert!(!packet.is_syn());
        assert!(!packet.is_ack());
        assert!(!packet.is_fin());
        assert!(!packet.is_rst());
        assert_eq!(packet.data, b"dgram payload");
    }

    #[test]
    fn test_packet_datagram_encode_decode() {
        let packet = Packet::datagram(42, b"hello datagram".to_vec());
        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();

        assert_eq!(decoded.port, 42);
        assert_eq!(decoded.stream_id, 0);
        assert!(decoded.is_dgram());
        assert_eq!(decoded.data, b"hello datagram");
    }

    #[test]
    fn test_packet_zero_port() {
        let packet = Packet::syn(0, 1);
        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(decoded.port, 0);
        assert_eq!(decoded.stream_id, 1);
    }

    #[test]
    fn test_header_size() {
        // Verify the fixed header is exactly 19 bytes
        let packet = Packet::new(1, 1, FLAG_ACK, Vec::new());
        let encoded = packet.encode().unwrap();
        assert_eq!(encoded.len(), HEADER_SIZE);
        assert_eq!(HEADER_SIZE, 19);
    }
}
