//! Complete Yggdrasil node with TCP/KEY echo service
//!
//! This example shows how to integrate ygg_stream with a full Yggdrasil node
//! that has TCP/TLS listeners and peer connections.

use ed25519_dalek::SigningKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error};
use yggdrasil::config::Config;
use yggdrasil::core::Core;
use ygg_stream::TcpStack;

const YGG_NODE: &str = "tcp://192.168.44.77:7743";

/// Default port for the echo service
const ECHO_PORT: u16 = 1;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info,ygg_stream=debug,yggdrasil=info,ironwood=info")
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("server");

    // Create configuration
    let mut config = Config::default();
    config.peers = vec![YGG_NODE.to_string()];

    // Generate signing key (in production, load from config)
    let signing_key = SigningKey::generate(&mut rand::thread_rng());

    // Create Yggdrasil core
    let core = Core::new(signing_key, config);

    info!("Your IPv6 address: {}", core.address());
    info!("Your IPv6 subnet: {}", core.subnet());
    info!("Your public key: {}", hex::encode(core.public_key()));

    // Initialize links and start listening/connecting
    core.init_links().await;
    core.start().await;

    info!("Yggdrasil node started successfully");

    // Give connections time to establish
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    info!("Yggdrasil routing should be ready");

    // Create TcpStack using the Yggdrasil core's packet connection
    let stack = TcpStack::new(core.packet_conn());

    if mode == "server" {
        info!("TcpStack ready - listening on port {} for incoming connections...", ECHO_PORT);
        run_server(&stack).await?;
    } else {
        info!("TcpStack ready - will connect to peer");

        // In client mode, we need to know the server's public key
        let server_pubkey = args.get(2)
            .ok_or("Usage: full_node client SERVER_PUBLIC_KEY_HEX")?;

        run_client(&stack, server_pubkey).await?;
    }

    stack.close().await;

    Ok(())
}

async fn run_server(stack: &TcpStack) -> Result<(), Box<dyn std::error::Error>> {
    let mut listener = stack.listen(ECHO_PORT).await;

    loop {
        match listener.accept().await {
            Ok(mut conn) => {
                let peer = conn.remote_key();
                info!("Accepted connection from peer {} on port {}", peer, ECHO_PORT);

                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    loop {
                        match conn.read(&mut buf).await {
                            Ok(0) => {
                                info!("Connection closed by peer");
                                break;
                            }
                            Ok(n) => {
                                info!("Received {} bytes", n);

                                // Echo back
                                if let Err(e) = conn.write_all(&buf[..n]).await {
                                    error!("Write error: {}", e);
                                    break;
                                }
                                if let Err(e) = conn.flush().await {
                                    error!("Flush error: {}", e);
                                    break;
                                }

                                info!("Echoed {} bytes", n);
                            }
                            Err(e) => {
                                error!("Read error: {}", e);
                                break;
                            }
                        }
                    }
                });
            }
            Err(e) => {
                error!("Error accepting connection: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn run_client(stack: &TcpStack, server_pubkey_hex: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Decode server public key
    let pubkey_bytes = hex::decode(server_pubkey_hex)?;
    if pubkey_bytes.len() != 32 {
        return Err("Server public key must be 32 bytes (64 hex chars)".into());
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&pubkey_bytes);
    let server_addr = ironwood::Addr::from(pubkey);

    info!("Connecting to server with public key {}", server_pubkey_hex);

    // Connect to server on the echo port
    let mut connection = stack.connect(server_addr, ECHO_PORT).await?;
    info!("Connected to server on port {}", ECHO_PORT);

    // Send some messages
    for i in 1..=5 {
        let message = format!("Hello from client, message {}", i);
        info!("Sending: {}", message);

        connection.write_all(message.as_bytes()).await?;
        connection.flush().await?;

        // Read response
        let mut buf = vec![0u8; 1024];
        let n = connection.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);
        info!("Received: {}", response);

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    // Close gracefully
    connection.shutdown().await?;
    info!("Connection closed gracefully");

    Ok(())
}
