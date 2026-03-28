//! Simple client example (TCP/KEY)

use ed25519_dalek::SigningKey;
use ironwood::{new_encrypted_packet_conn, Addr, PacketConn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info;
use ygg_stream::TcpStack;

const ECHO_PORT: u16 = 1;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info,ygg_stream=debug,ironwood=info")
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <peer_public_key_hex>", args[0]);
        std::process::exit(1);
    }

    let peer_hex = &args[1];
    let peer_bytes = hex::decode(peer_hex)?;
    if peer_bytes.len() != 32 {
        eprintln!("Error: Peer key must be 32 bytes (64 hex characters)");
        std::process::exit(1);
    }

    let mut peer_key = [0u8; 32];
    peer_key.copy_from_slice(&peer_bytes);
    let peer_addr = Addr::from(peer_key);

    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let conn = new_encrypted_packet_conn(signing_key, Default::default());
    let local_addr = conn.local_addr();

    info!("Client started");
    info!("Local address: {}", local_addr);
    info!("Connecting to peer: {}", peer_addr);

    let stack = TcpStack::new(conn);

    // Connect to peer on the echo port
    let mut connection = stack.connect(peer_addr, ECHO_PORT).await?;
    info!("Connected to peer on port {}", ECHO_PORT);

    // Send a message
    let message = b"Hello, Yggdrasil!";
    info!("Sending message: {}", String::from_utf8_lossy(message));
    connection.write_all(message).await?;
    connection.flush().await?;

    // Read response
    let mut buf = vec![0u8; 1024];
    let n = connection.read(&mut buf).await?;
    info!("Received response: {}", String::from_utf8_lossy(&buf[..n]));

    // Close gracefully
    connection.shutdown().await?;
    info!("Connection closed");

    stack.close().await;

    Ok(())
}
