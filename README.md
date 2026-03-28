# ygg_stream: TCP/KEY Protocol for Yggdrasil

A TCP-like transport protocol for the Yggdrasil mesh network. Uses 32-byte ed25519 public keys instead of IPv4 addresses — hence **TCP/KEY**.

## Features

- **Standard TCP semantics** — 3-way handshake, reliable ordered delivery, graceful shutdown (full RFC 793 state machine)
- **Port-based routing** — 16-bit ports, just like TCP/IP. Multiple services on a single node
- **AsyncRead + AsyncWrite** — each connection is a standard Rust async byte stream
- **Congestion control** — TCP Reno (slow start, congestion avoidance, fast retransmit)
- **RTT estimation** — Jacobson/Karels algorithm (RFC 6298) with Karn's algorithm
- **Flow control** — 24-bit window (up to 16 MB), 512 KB default
- **Connectionless datagrams** — fire-and-forget messages with port routing, no handshake
- **No additional encryption** — leverages Yggdrasil's existing encryption at the PacketConn layer
- **Mobile bindings** — UniFFI for Kotlin/Swift (Android/iOS)

## Wire Protocol

16-byte header, no length field (derived from Yggdrasil packet size):

```
 0       8       16      24      32
+-------+-------+-------+-------+
|  src_port(16) |  dst_port(16) |   bytes 0-3
+-------+-------+-------+-------+
|         sequence number        |   bytes 4-7
+-------+-------+-------+-------+
|       acknowledgment number    |   bytes 8-11
+-------+-------+-------+-------+
| flags(8) |    window(24)      |   bytes 12-15
+-------+-------+-------+-------+
|            payload...          |
```

**Flags**: SYN (0x01), ACK (0x02), FIN (0x04), RST (0x08), DGRAM (0x10)

Addressing is provided by Yggdrasil's network layer — each peer is identified by its 32-byte ed25519 public key. No addresses appear in the header.

## Architecture

```
Application
    ↓
TCP/KEY (TcpStack → TcpConnection)
    ↓
ironwood (encrypted PacketConn, public key addressing)
    ↓
Yggdrasil mesh network (TCP/TLS links)
```

A connection is identified by a 3-tuple: `(local_port, remote_key, remote_port)` — analogous to TCP's 4-tuple, but with the local key implicit.

## Quick Start

### Server

```rust
use ygg_stream::{TcpStack, TcpConnection};
use ironwood::{new_encrypted_packet_conn, PacketConn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let conn = new_encrypted_packet_conn(signing_key, Default::default());

    let stack = TcpStack::new(conn);
    let mut listener = stack.listen(80).await;

    loop {
        let mut conn = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            loop {
                let n = conn.read(&mut buf).await?;
                if n == 0 { break; }
                conn.write_all(&buf[..n]).await?;
            }
            Ok::<_, std::io::Error>(())
        });
    }
}
```

### Client

```rust
let stack = TcpStack::new(conn);
let mut connection = stack.connect(peer_addr, 80).await?;

connection.write_all(b"Hello, Yggdrasil!").await?;
let mut buf = vec![0u8; 1024];
let n = connection.read(&mut buf).await?;
println!("Response: {}", String::from_utf8_lossy(&buf[..n]));

connection.shutdown().await?;
```

## High-Level API

For applications that don't need to wire up `Core` + `TcpStack` manually:

| Type | Environment | I/O style |
|------|-------------|-----------|
| `AsyncNode` / `AsyncConn` | Inside a tokio runtime | `async fn` |
| `Node` / `Conn` | Blocking / FFI (Android) | Blocking (`block_on`) |

Both expose: `connect(pubkey, port)`, `accept(port)`, `listen(port)`, `send_datagram`, `recv_datagram`, peer management, and network introspection.

### AsyncNode

```rust
let node = AsyncNode::new("tcp://1.2.3.4:1234").await?;

// Client
let conn = node.connect(&peer_key, 80).await?;
conn.write(b"hello").await?;
let mut buf = vec![0u8; 1024];
let n = conn.read(&mut buf).await?;
conn.close().await;

// Server
let conn = node.accept(80).await?;
```

### Node (blocking / FFI)

```rust
let node = Node::new("tcp://1.2.3.4:1234")?;
let conn = node.connect(&peer_key, 80)?;
conn.write(b"hello")?;
conn.close();
```

> **Note**: Do not use `Node`/`Conn` from inside a tokio runtime — `block_on()` will panic. Use `AsyncNode`/`AsyncConn` instead.

## Full Yggdrasil Node

```rust
use yggdrasil::config::Config;
use yggdrasil::core::Core;
use ygg_stream::TcpStack;

let mut config = Config::default();
config.listen = vec!["tcp://0.0.0.0:1234".to_string()];
config.peers = vec!["tcp://peer.example.com:1234".to_string()];

let core = Core::new(signing_key, config);
core.init_links().await;
core.start().await;

let stack = TcpStack::new(core.packet_conn());
let mut listener = stack.listen(80).await;
let conn = listener.accept().await?;
```

## Datagrams

Connectionless messages, routed by port. No handshake, no ordering, no flow control.

```rust
// Send
stack.send_datagram(&peer_addr, 42, b"ping".to_vec()).await?;

// Receive
let mut dg = stack.listen_datagram(42).await;
let (data, sender) = dg.recv().await?;
```

## Multiple Services

```rust
let mut chat = stack.listen(1).await;
let mut files = stack.listen(2).await;

tokio::spawn(async move {
    loop { let conn = chat.accept().await?; /* handle chat */ }
});
tokio::spawn(async move {
    loop { let conn = files.accept().await?; /* handle files */ }
});
```

## Connection Lifecycle

```
Client                          Server
  |                               |
  |--- SYN (src=ephemeral,dst) -->|  SynSent → SynReceived
  |<-- SYN-ACK --------------------|
  |--- ACK ----------------------->|  Established ← Established
  |                               |
  |<== DATA (AsyncRead/Write) ===>|
  |                               |
  |--- FIN ----------------------->|  FinWait1 → CloseWait
  |<-- ACK -----------------------|  FinWait2
  |<-- FIN -----------------------|  TimeWait ← LastAck
  |--- ACK ----------------------->|  (2s) → Closed ← Closed
```

## Running Examples

```bash
# Echo server
cargo run --example echo

# Client (needs peer's hex public key)
cargo run --example client <peer_public_key_hex>

# Full Yggdrasil node
cargo run --example full_node --features full-node server
cargo run --example full_node --features full-node client tcp://127.0.0.1:1234 <key>
```

## Performance

- **Header overhead**: 16 bytes per packet
- **Max payload**: ~65,385 bytes per packet
- **Default window**: 512 KB
- **Pacing**: 10 ms inter-packet interval (matches ironwood's queue budget)
- **Congestion window**: starts at 32 KB, grows via TCP Reno

## Testing

```bash
cargo test --lib    # 28 unit tests
cargo test          # All tests
```

## Contributing

Contributions are not very welcome! Please don't feel free to submit issues or pull requests.
Ensure your code follows the project's own style guidelines and passes all tests.

## License

Mozilla Public License 2.0 (MPL-2.0). See [LICENSE](LICENSE).
