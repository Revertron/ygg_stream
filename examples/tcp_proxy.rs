//! TCP proxy through Yggdrasil mesh network.
//!
//! Two modes:
//!
//!   **forward** — binds a local TCP port and tunnels each connection through
//!   Yggdrasil to a remote peer.
//!
//!   **reverse** — listens on a ygg_stream port and forwards each incoming
//!   Yggdrasil stream to a local TCP address.
//!
//! # Usage
//!
//! ```text
//! # Forward local:9055 → ygg → remote peer port 80
//! tcp_proxy forward --peer tcp://1.2.3.4:1234 \
//!     --bind 127.0.0.1:9055 \
//!     --remote-key <64_hex_chars> \
//!     --remote-port 80
//!
//! # Reverse: accept ygg streams on port 80, forward to local 127.0.0.1:8080
//! tcp_proxy reverse --peer tcp://1.2.3.4:1234 \
//!     --listen-port 80 \
//!     --target 127.0.0.1:8080
//! ```
//!
//! # Test with curl
//!
//! ```text
//! # Node B (server side):
//! python3 -m http.server 8080 &
//! cargo run --example tcp_proxy -- reverse \
//!     --peer tcp://bootstrap:1234 --listen-port 80 --target 127.0.0.1:8080
//!
//! # Node A (client side):
//! cargo run --example tcp_proxy -- forward \
//!     --peer tcp://bootstrap:1234 --bind 127.0.0.1:9055 \
//!     --remote-key <NODE_B_KEY> --remote-port 80
//!
//! curl http://127.0.0.1:9055/
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tokio_util::sync::CancellationToken;
use tracing::info;
use ygg_stream::{AsyncNode, TcpToYgg, YggToTcp};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,ygg_stream=debug".parse().unwrap())
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match mode {
        "forward" => run_forward(&args).await,
        "reverse" => run_reverse(&args).await,
        _ => {
            print_usage();
            Ok(())
        }
    }
}

fn print_usage() {
    eprintln!("TCP proxy through Yggdrasil mesh network");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  tcp_proxy forward --peer <uri> --bind <addr:port> --remote-key <hex> --remote-port <port> [--key <hex>]");
    eprintln!("  tcp_proxy reverse --peer <uri> --listen-port <port> --target <addr:port> [--key <hex>]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --peer          Yggdrasil peer URI (e.g. tcp://1.2.3.4:1234)");
    eprintln!("  --bind          Local TCP address to bind (forward mode)");
    eprintln!("  --remote-key    Remote peer's ed25519 public key (64 hex chars)");
    eprintln!("  --remote-port   Remote ygg_stream port");
    eprintln!("  --listen-port   ygg_stream port to listen on (reverse mode)");
    eprintln!("  --target        Local TCP address to forward to (reverse mode)");
    eprintln!("  --key           Signing key (64 hex chars). Keeps public key stable across restarts.");
    eprintln!("                  If omitted, a random key is generated and printed for you to save.");
    eprintln!();
    eprintln!("Examples:");
    eprintln!();
    eprintln!("  # Generate a key once, then reuse it:");
    eprintln!("  tcp_proxy reverse --peer tcp://1.2.3.4:1234 --listen-port 80 --target 127.0.0.1:8080");
    eprintln!("  # logs: Signing key (save this): a1b2c3...  Public key: d4e5f6...");
    eprintln!();
    eprintln!("  # Next time, pass --key to keep the same public key:");
    eprintln!("  tcp_proxy reverse --peer tcp://1.2.3.4:1234 --listen-port 80 --target 127.0.0.1:8080 \\");
    eprintln!("      --key a1b2c3...");
    eprintln!();
    eprintln!("  # Forward local:9055 through Yggdrasil to remote peer's port 80:");
    eprintln!("  tcp_proxy forward --peer tcp://1.2.3.4:1234 \\");
    eprintln!("      --bind 127.0.0.1:9055 --remote-key d4e5f6... --remote-port 80");
    eprintln!();
    eprintln!("  # SOCKS5 proxy through Yggdrasil (remote side runs microsocks):");
    eprintln!("  tcp_proxy forward --peer tcp://1.2.3.4:1234 \\");
    eprintln!("      --bind 127.0.0.1:9080 --remote-key abcd...1234 --remote-port 1080");
    eprintln!("  curl -x socks5h://127.0.0.1:9080 http://example.com");
}

/// Create an AsyncNode using --key (if provided) or a fresh random key.
/// Prints both signing key and public key so the user can save them.
///
/// --peer is optional; if omitted, the node starts with no peers.
async fn create_node(args: &[String]) -> Result<Arc<AsyncNode>, Box<dyn std::error::Error>> {
    let peers: Vec<String> = match get_arg(args, "--peer") {
        Ok(uri) if !uri.is_empty() => vec![uri],
        _ => vec![],
    };

    let node = if let Ok(key_hex) = get_arg(args, "--key") {
        let key_bytes = hex::decode(&key_hex)?;
        if key_bytes.len() != 32 {
            return Err("--key must be exactly 64 hex characters (32 bytes)".into());
        }
        info!("Using provided signing key");
        Arc::new(AsyncNode::new_with_key(&key_bytes, peers).await?)
    } else {
        let sk = SigningKey::generate(&mut OsRng);
        let sk_hex = hex::encode(sk.to_bytes());
        info!("Signing key (save this): {}", sk_hex);
        Arc::new(AsyncNode::new_with_key(&sk.to_bytes(), peers).await?)
    };

    info!("Public key: {}", hex::encode(node.public_key()));
    Ok(node)
}

async fn run_forward(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr: SocketAddr = get_arg(args, "--bind")?.parse()?;
    let remote_key_hex = get_arg(args, "--remote-key")?;
    let remote_port: u16 = get_arg(args, "--remote-port")?.parse()?;

    let remote_key_bytes = hex::decode(&remote_key_hex)?;
    if remote_key_bytes.len() != 32 {
        return Err("--remote-key must be exactly 64 hex characters (32 bytes)".into());
    }
    let mut remote_key = [0u8; 32];
    remote_key.copy_from_slice(&remote_key_bytes);

    let node = create_node(args).await?;

    let cancel = CancellationToken::new();
    let cancel_signal = cancel.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Ctrl+C received, shutting down...");
        cancel_signal.cancel();
    });

    let proxy = TcpToYgg::new(node.clone(), bind_addr, remote_key, remote_port);
    proxy.run(cancel).await?;

    node.close().await;
    Ok(())
}

async fn run_reverse(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let listen_port: u16 = get_arg(args, "--listen-port")?.parse()?;
    let target_addr: SocketAddr = get_arg(args, "--target")?.parse()?;

    let node = create_node(args).await?;

    let cancel = CancellationToken::new();
    let cancel_signal = cancel.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Ctrl+C received, shutting down...");
        cancel_signal.cancel();
    });

    let proxy = YggToTcp::new(node.clone(), listen_port, target_addr);
    proxy.run(cancel).await?;

    node.close().await;
    Ok(())
}

fn get_arg(args: &[String], name: &str) -> Result<String, String> {
    let pos = args
        .iter()
        .position(|a| a == name)
        .ok_or_else(|| format!("missing argument: {}", name))?;
    args.get(pos + 1)
        .cloned()
        .ok_or_else(|| format!("missing value for {}", name))
}
