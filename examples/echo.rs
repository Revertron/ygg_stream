//! Simple echo server example (TCP/KEY)

use ed25519_dalek::SigningKey;
use ironwood::{new_encrypted_packet_conn, PacketConn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error};
use ygg_stream::TcpStack;

const ECHO_PORT: u16 = 1;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info,ygg_stream=debug,ironwood=info")
        .init();

    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let conn = new_encrypted_packet_conn(signing_key, Default::default());
    let local_addr = conn.local_addr();

    info!("Echo server started");
    info!("Local address: {}", local_addr);

    let stack = TcpStack::new(conn);
    let mut listener = stack.listen(ECHO_PORT).await;

    info!("Listening on port {} for connections...", ECHO_PORT);

    loop {
        match listener.accept().await {
            Ok(conn) => {
                let peer = conn.remote_key();
                info!("Accepted connection from peer {} on port {}", peer, ECHO_PORT);

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(conn).await {
                        error!("Connection error: {}", e);
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

async fn handle_connection(mut conn: ygg_stream::TcpConnection) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; 1024];

    loop {
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            info!("Connection closed by peer");
            break;
        }

        info!("Received {} bytes", n);
        conn.write_all(&buf[..n]).await?;
        conn.flush().await?;
        info!("Echoed {} bytes", n);
    }

    Ok(())
}
