use crate::error::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

/// Protocol flags
pub const FLAG_SYN: u8 = 0x01;
pub const FLAG_ACK: u8 = 0x02;
pub const FLAG_FIN: u8 = 0x04;
pub const FLAG_RST: u8 = 0x08;
pub const FLAG_DGRAM: u8 = 0x10;

/// Default flow control window size (512 KB)
pub const DEFAULT_WINDOW_SIZE: u32 = 512 * 1024;

/// Maximum packet size (64 KB - 1 byte)
pub const MAX_PACKET_SIZE: usize = 65535;

/// Packet header size: [src_port:u16][dst_port:u16][seq:u32][ack_seq:u32][flags_window:u32] = 16
pub const HEADER_SIZE: usize = 16;

/// Yggdrasil overhead
pub const HEADER_YGGDRASIL: usize = 131;

/// Maximum data payload per packet
pub const MAX_DATA_SIZE: usize = MAX_PACKET_SIZE - HEADER_SIZE - HEADER_YGGDRASIL;

/// Preferred send chunk size (16 KiB). Keeps per-packet transmission time
/// well under ironwood's 25 ms queue budget.
pub const SEND_CHUNK_SIZE: usize = 16384;

/// Maximum in-flight bytes before sender blocks (512 KB)
pub const MAX_INFLIGHT: u32 = 512 * 1024;

/// Initial congestion window (2 segments = 32 KB)
pub const INITIAL_CWND: u32 = 2 * SEND_CHUNK_SIZE as u32;

/// Initial RTO in milliseconds
pub const INITIAL_RTO_MS: u64 = 500;

/// Minimum RTO floor in milliseconds
pub const MIN_RTO_MS: u64 = 200;

/// Clock granularity for RTO calculation (RFC 6298)
pub const CLOCK_GRANULARITY_MS: u64 = 50;

/// Maximum retransmit timeout in milliseconds
pub const MAX_RTO_MS: u64 = 5_000;

/// Maximum SYN retransmissions
pub const MAX_SYN_RETRIES: u32 = 5;

/// Initial SYN retry interval in milliseconds
pub const SYN_INITIAL_RETRY_MS: u64 = 1_000;

/// Maximum total stall time before giving up (30 seconds)
pub const MAX_STALL_MS: u64 = 30_000;

/// Minimum inter-packet interval in milliseconds (pacing)
pub const PACING_INTERVAL_MS: u64 = 10;

/// Maximum window value (24-bit: 16 MB - 1)
pub const MAX_WINDOW: u32 = 0x00FF_FFFF;

/// TimeWait duration in milliseconds (2 seconds for mesh network)
pub const TIME_WAIT_MS: u64 = 2_000;

/// TCP/KEY protocol packet.
///
/// Wire format (16 bytes header):
/// ```text
///  0       8       16      24      32
/// +-------+-------+-------+-------+
/// |  src_port(16) |  dst_port(16) |   bytes 0-3
/// +-------+-------+-------+-------+
/// |         sequence number        |   bytes 4-7
/// +-------+-------+-------+-------+
/// |       acknowledgment number    |   bytes 8-11
/// +-------+-------+-------+-------+
/// | flags(8) |    window(24)      |   bytes 12-15
/// +-------+-------+-------+-------+
/// |            payload...          |
/// ```
///
/// No length field — payload length = total bytes - 16.
/// Addressing provided by Yggdrasil layer (public keys).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub flags: u8,
    /// Receiver's available window (24-bit on wire, max 16 MB)
    pub window: u32,
    pub data: Vec<u8>,
}

impl Packet {
    pub fn new(src_port: u16, dst_port: u16, flags: u8, data: Vec<u8>) -> Self {
        Self {
            src_port,
            dst_port,
            flags,
            seq: 0,
            ack_seq: 0,
            window: DEFAULT_WINDOW_SIZE,
            data,
        }
    }

    /// Create a SYN packet (connection initiation)
    pub fn syn(src_port: u16, dst_port: u16) -> Self {
        Self::new(src_port, dst_port, FLAG_SYN, Vec::new())
    }

    /// Create a SYN-ACK packet
    pub fn syn_ack(src_port: u16, dst_port: u16) -> Self {
        Self::new(src_port, dst_port, FLAG_SYN | FLAG_ACK, Vec::new())
    }

    /// Create a data+ACK packet with sequence numbers and window
    pub fn data_ack(src_port: u16, dst_port: u16, data: Vec<u8>, seq: u32, ack_seq: u32, window: u32) -> Self {
        Self {
            src_port,
            dst_port,
            flags: FLAG_ACK,
            seq,
            ack_seq,
            window,
            data,
        }
    }

    /// Create a FIN packet
    pub fn fin(src_port: u16, dst_port: u16, seq: u32) -> Self {
        Self {
            src_port,
            dst_port,
            flags: FLAG_FIN,
            seq,
            ack_seq: 0,
            window: 0,
            data: Vec::new(),
        }
    }

    /// Create a RST packet
    pub fn rst(src_port: u16, dst_port: u16) -> Self {
        Self::new(src_port, dst_port, FLAG_RST, Vec::new())
    }

    /// Create a datagram packet (connectionless)
    pub fn datagram(dst_port: u16, data: Vec<u8>) -> Self {
        Self::new(0, dst_port, FLAG_DGRAM, data)
    }

    /// Create an ACK-only packet
    pub fn ack(src_port: u16, dst_port: u16, ack_seq: u32, window: u32) -> Self {
        Self {
            src_port,
            dst_port,
            flags: FLAG_ACK,
            seq: 0,
            ack_seq,
            window,
            data: Vec::new(),
        }
    }

    pub fn is_syn(&self) -> bool {
        self.flags & FLAG_SYN != 0
    }
    pub fn is_ack(&self) -> bool {
        self.flags & FLAG_ACK != 0
    }
    pub fn is_fin(&self) -> bool {
        self.flags & FLAG_FIN != 0
    }
    pub fn is_rst(&self) -> bool {
        self.flags & FLAG_RST != 0
    }
    pub fn is_dgram(&self) -> bool {
        self.flags & FLAG_DGRAM != 0
    }

    /// Encode packet to bytes (16-byte header + payload)
    pub fn encode(&self) -> Result<Vec<u8>> {
        let data_len = self.data.len();
        if data_len > MAX_DATA_SIZE {
            return Err(Error::PacketTooLarge(data_len, MAX_DATA_SIZE));
        }

        let mut buf = BytesMut::with_capacity(HEADER_SIZE + data_len);

        buf.put_u16(self.src_port);
        buf.put_u16(self.dst_port);
        buf.put_u32(self.seq);
        buf.put_u32(self.ack_seq);

        // Pack flags (high byte) + window (lower 24 bits)
        let flags_window = ((self.flags as u32) << 24) | (self.window & MAX_WINDOW);
        buf.put_u32(flags_window);

        buf.put_slice(&self.data);

        Ok(buf.to_vec())
    }

    /// Decode packet from bytes. Payload length = buf.len() - HEADER_SIZE.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE {
            return Err(Error::Protocol(format!(
                "Packet too short: {} bytes (min {})",
                buf.len(),
                HEADER_SIZE
            )));
        }

        let mut cursor = std::io::Cursor::new(buf);

        let src_port = cursor.get_u16();
        let dst_port = cursor.get_u16();
        let seq = cursor.get_u32();
        let ack_seq = cursor.get_u32();

        let flags_window = cursor.get_u32();
        let flags = (flags_window >> 24) as u8;
        let window = flags_window & MAX_WINDOW;

        let data = buf[HEADER_SIZE..].to_vec();

        Ok(Self {
            src_port,
            dst_port,
            seq,
            ack_seq,
            flags,
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

        assert_eq!(decoded.src_port, 5);
        assert_eq!(decoded.dst_port, 42);
        assert_eq!(decoded.flags, FLAG_SYN | FLAG_ACK);
        assert_eq!(decoded.data, b"hello");
        assert_eq!(decoded.seq, 0);
        assert_eq!(decoded.ack_seq, 0);
    }

    #[test]
    fn test_packet_port_encoding() {
        let packet = Packet::syn(0x1234, 0xABCD);
        let encoded = packet.encode().unwrap();
        // src_port: 0x12, 0x34
        assert_eq!(encoded[0], 0x12);
        assert_eq!(encoded[1], 0x34);
        // dst_port: 0xAB, 0xCD
        assert_eq!(encoded[2], 0xAB);
        assert_eq!(encoded[3], 0xCD);

        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(decoded.src_port, 0x1234);
        assert_eq!(decoded.dst_port, 0xABCD);
    }

    #[test]
    fn test_packet_syn() {
        let packet = Packet::syn(100, 80);
        assert_eq!(packet.src_port, 100);
        assert_eq!(packet.dst_port, 80);
        assert!(packet.is_syn());
        assert!(!packet.is_ack());
        assert!(!packet.is_fin());
        assert!(!packet.is_rst());
        assert!(packet.data.is_empty());
    }

    #[test]
    fn test_packet_syn_ack() {
        let packet = Packet::syn_ack(100, 80);
        assert!(packet.is_syn());
        assert!(packet.is_ack());
    }

    #[test]
    fn test_packet_data_ack() {
        let packet = Packet::data_ack(100, 80, b"payload".to_vec(), 42, 200, 32768);
        assert_eq!(packet.seq, 42);
        assert_eq!(packet.ack_seq, 200);
        assert_eq!(packet.window, 32768);
        assert!(packet.is_ack());

        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(decoded.seq, 42);
        assert_eq!(decoded.ack_seq, 200);
        assert_eq!(decoded.window, 32768);
        assert_eq!(decoded.data, b"payload");
    }

    #[test]
    fn test_packet_ack() {
        let packet = Packet::ack(100, 80, 1024, 65536);
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
        let packet = Packet::fin(100, 80, 999);
        assert!(packet.is_fin());
        assert_eq!(packet.seq, 999);
    }

    #[test]
    fn test_packet_rst() {
        let packet = Packet::rst(100, 80);
        assert!(packet.is_rst());
    }

    #[test]
    fn test_packet_too_large() {
        let data = vec![0u8; MAX_DATA_SIZE + 1];
        let packet = Packet::new(0, 1, 0, data);
        assert!(matches!(packet.encode(), Err(Error::PacketTooLarge(_, _))));
    }

    #[test]
    fn test_decode_too_short() {
        let buf = vec![0u8; 3];
        assert!(matches!(Packet::decode(&buf), Err(Error::Protocol(_))));
    }

    #[test]
    fn test_packet_with_large_data() {
        let data = vec![0xAB; 1000];
        let packet = Packet::new(10, 999, 0, data.clone());
        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();

        assert_eq!(decoded.src_port, 10);
        assert_eq!(decoded.dst_port, 999);
        assert_eq!(decoded.data, data);
    }

    #[test]
    fn test_packet_empty_data() {
        let packet = Packet::new(1, 1, FLAG_ACK, Vec::new());
        let encoded = packet.encode().unwrap();
        assert_eq!(encoded.len(), HEADER_SIZE);

        let decoded = Packet::decode(&encoded).unwrap();
        assert!(decoded.data.is_empty());
    }

    #[test]
    fn test_packet_datagram() {
        let packet = Packet::datagram(100, b"dgram payload".to_vec());
        assert_eq!(packet.dst_port, 100);
        assert!(packet.is_dgram());
    }

    #[test]
    fn test_packet_datagram_encode_decode() {
        let packet = Packet::datagram(42, b"hello datagram".to_vec());
        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();

        assert_eq!(decoded.dst_port, 42);
        assert!(decoded.is_dgram());
        assert_eq!(decoded.data, b"hello datagram");
    }

    #[test]
    fn test_header_size() {
        let packet = Packet::new(1, 1, FLAG_ACK, Vec::new());
        let encoded = packet.encode().unwrap();
        assert_eq!(encoded.len(), HEADER_SIZE);
        assert_eq!(HEADER_SIZE, 16);
    }

    #[test]
    fn test_flags_window_packing() {
        // Verify flags and window are packed correctly
        let packet = Packet {
            src_port: 0,
            dst_port: 0,
            seq: 0,
            ack_seq: 0,
            flags: 0xFF,
            window: MAX_WINDOW,
            data: Vec::new(),
        };
        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(decoded.flags, 0xFF);
        assert_eq!(decoded.window, MAX_WINDOW);
    }

    #[test]
    fn test_window_truncation() {
        // Window values above 24-bit max should be truncated
        let packet = Packet {
            src_port: 0,
            dst_port: 0,
            seq: 0,
            ack_seq: 0,
            flags: FLAG_ACK,
            window: 0xFFFF_FFFF,
            data: Vec::new(),
        };
        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(decoded.flags, FLAG_ACK);
        assert_eq!(decoded.window, MAX_WINDOW);
    }

    #[test]
    fn test_no_length_field() {
        // Payload length is derived from total size - header
        let data = b"variable length data".to_vec();
        let packet = Packet::new(1, 2, 0, data.clone());
        let encoded = packet.encode().unwrap();
        assert_eq!(encoded.len(), HEADER_SIZE + data.len());

        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(decoded.data, data);
    }
}
