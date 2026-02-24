use crate::error::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

/// Protocol flags
pub const FLAG_SYN: u8 = 0x01; // Open stream
pub const FLAG_ACK: u8 = 0x02; // Acknowledge
pub const FLAG_FIN: u8 = 0x04; // Close stream gracefully
pub const FLAG_RST: u8 = 0x08; // Reset stream (abort)
pub const FLAG_DGRAM: u8 = 0x10; // Connectionless datagram

/// Default flow control window size (256 KB)
pub const DEFAULT_WINDOW_SIZE: usize = 256 * 1024;

/// Maximum packet size (64 KB - 1 byte)
pub const MAX_PACKET_SIZE: usize = 65535;

/// Maximum data payload per packet (accounting for 7-byte header)
pub const MAX_DATA_SIZE: usize = MAX_PACKET_SIZE - 7;

/// Packet header size (stream_id + flags + length)
pub const HEADER_SIZE: usize = 7;

/// Protocol packet
///
/// Wire format:
/// ```text
/// [port:u16 << 16 | stream_id:u16 : u32][flags: u8][length: u16][data: bytes]
/// ```
///
/// The 4-byte combined field encodes `(port << 16) | stream_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Port number (high 16 bits of the wire u32)
    pub port: u16,

    /// Stream identifier (low 16 bits of the wire u32)
    pub stream_id: u16,

    /// Control flags (SYN, ACK, FIN, RST)
    pub flags: u8,

    /// Data payload
    pub data: Vec<u8>,

    /// Receiver's available window size (for flow control)
    /// Encoded in flags byte when ACK flag is set
    pub window: usize,
}

impl Packet {
    /// Create a new packet
    pub fn new(port: u16, stream_id: u16, flags: u8, data: Vec<u8>) -> Self {
        Self {
            port,
            stream_id,
            flags,
            data,
            window: DEFAULT_WINDOW_SIZE,
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

    /// Create a data + ACK packet
    pub fn data_ack(port: u16, stream_id: u16, data: Vec<u8>, window: usize) -> Self {
        Self {
            port,
            stream_id,
            flags: FLAG_ACK,
            data,
            window,
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

    /// Create an ACK packet with window update
    pub fn ack(port: u16, stream_id: u16, window: usize) -> Self {
        Self {
            port,
            stream_id,
            flags: FLAG_ACK,
            data: Vec::new(),
            window,
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
    /// Format: [(port << 16 | stream_id): u32][flags: u8][length: u16][data]
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
            data,
            window: DEFAULT_WINDOW_SIZE,
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
        buf.put_u8(0); // flags
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
}
