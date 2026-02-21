// Integration tests using real TCP connections via Yggdrasil Core

use ed25519_dalek::SigningKey;
use ironwood::PacketConn;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yggdrasil::config::Config;
use yggdrasil::core::Core;
use ygg_stream::StreamManager;

/// Default port used in tests
const TEST_PORT: u16 = 1;

/// Helper to create a Yggdrasil node with TCP listener on a specific port
async fn create_node_with_listener(port: u16) -> Arc<Core> {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());

    let mut config = Config::default();
    config.listen = vec![format!("tcp://127.0.0.1:{}", port)];

    let core = Core::new(signing_key, config);
    core.init_links().await;
    core.start().await;

    // Give the listener time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    core
}

/// Helper to create a Yggdrasil node that connects to another node
async fn create_node_with_peer(peer_addr: &str) -> Arc<Core> {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());

    let mut config = Config::default();
    config.peers = vec![peer_addr.to_string()];

    let core = Core::new(signing_key, config);
    core.init_links().await;
    core.start().await;

    // Give the connection time to establish at the TCP level
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    core
}

/// Full bidirectional stream data transfer test.
///
/// open_stream() now retransmits SYN every 500ms until SYN-ACK is received,
/// so no fixed routing sleep is needed - the timing is handled automatically.
#[tokio::test]
async fn test_tcp_connectivity_and_streams() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("info,ygg_stream=debug")
        .try_init();

    let port1 = 19001;

    let core1 = create_node_with_listener(port1).await;
    let addr1 = core1.packet_conn().local_addr();

    let peer_uri = format!("tcp://127.0.0.1:{}", port1);
    let core2 = create_node_with_peer(&peer_uri).await;

    let manager1 = StreamManager::new(core1.packet_conn());
    let manager2 = StreamManager::new(core2.packet_conn());

    // Register a listener on manager1 for TEST_PORT
    let mut listener1 = manager1.listen(TEST_PORT).await;

    // open_stream() sends SYN every 500ms and blocks until SYN-ACK is received.
    let connection2 = manager2.connect(addr1).await.unwrap();
    let mut stream2 = connection2.open_stream(TEST_PORT).await.unwrap();

    // Accept the incoming stream on node 1 via the listener
    let mut stream1 = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        listener1.accept()
    )
    .await
    .expect("Timeout accepting stream on node 1")
    .unwrap();

    // Bidirectional data transfer
    let msg_a = b"Hello from node 2!";
    stream2.write_all(msg_a).await.unwrap();
    stream2.flush().await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        stream1.read(&mut buf)
    )
    .await
    .expect("Timeout reading on node 1")
    .unwrap();
    assert_eq!(&buf[..n], msg_a);

    let msg_b = b"Hello back from node 1!";
    stream1.write_all(msg_b).await.unwrap();
    stream1.flush().await.unwrap();

    buf.clear();
    buf.resize(1024, 0);
    let n = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        stream2.read(&mut buf)
    )
    .await
    .expect("Timeout reading on node 2")
    .unwrap();
    assert_eq!(&buf[..n], msg_b);

    // Clean shutdown
    stream1.shutdown().await.unwrap();
    stream2.shutdown().await.unwrap();
    manager1.close().await;
    manager2.close().await;
}

/// Verify multiple streams can be opened on a single connection.
#[tokio::test]
async fn test_tcp_multiple_streams() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("info")
        .try_init();

    let port1 = 19002;

    let core1 = create_node_with_listener(port1).await;
    let addr1 = core1.packet_conn().local_addr();

    let peer_uri = format!("tcp://127.0.0.1:{}", port1);
    let core2 = create_node_with_peer(&peer_uri).await;

    let manager1 = StreamManager::new(core1.packet_conn());
    let manager2 = StreamManager::new(core2.packet_conn());

    // Register a listener so SYNs are accepted
    let _listener1 = manager1.listen(TEST_PORT).await;

    let connection2 = manager2.connect(addr1).await.unwrap();

    let stream1 = connection2.open_stream(TEST_PORT).await.unwrap();
    let stream2 = connection2.open_stream(TEST_PORT).await.unwrap();
    let stream3 = connection2.open_stream(TEST_PORT).await.unwrap();

    // Verify stream IDs are unique and odd (node 2 is the initiator)
    assert_ne!(stream1.id(), stream2.id());
    assert_ne!(stream2.id(), stream3.id());
    assert_ne!(stream1.id(), stream3.id());
    assert_eq!(stream1.id() % 2, 1);
    assert_eq!(stream2.id() % 2, 1);
    assert_eq!(stream3.id() % 2, 1);

    manager1.close().await;
    manager2.close().await;
}

/// Verify streams can be opened and data exchanged in both directions concurrently.
#[tokio::test]
async fn test_tcp_bidirectional_multiple_streams() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("info,ygg_stream=debug")
        .try_init();

    let port1 = 19003;

    let core1 = create_node_with_listener(port1).await;
    let addr1 = core1.packet_conn().local_addr();

    let peer_uri = format!("tcp://127.0.0.1:{}", port1);
    let core2 = create_node_with_peer(&peer_uri).await;

    let manager1 = StreamManager::new(core1.packet_conn());
    let manager2 = StreamManager::new(core2.packet_conn());

    // Both sides listen on TEST_PORT
    let mut listener1 = manager1.listen(TEST_PORT).await;
    let mut listener2 = manager2.listen(TEST_PORT).await;

    // Node 2 opens a stream to node 1
    let connection2 = manager2.connect(addr1).await.unwrap();
    let mut stream_2to1 = connection2.open_stream(TEST_PORT).await.unwrap();

    // Accept the stream on node 1 via listener
    let mut stream_from_2 = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        listener1.accept()
    )
    .await
    .expect("Timeout accepting stream on node 1")
    .unwrap();

    // Node 1 opens a stream back to node 2 (reuses existing connection)
    let addr2 = core2.packet_conn().local_addr();
    let connection1 = manager1.connect(addr2).await.unwrap();
    let mut stream_1to2 = connection1.open_stream(TEST_PORT).await.unwrap();

    // Accept the stream from node 1 on node 2 via listener
    let mut stream_from_1 = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        listener2.accept()
    )
    .await
    .expect("Timeout accepting stream on node 2")
    .unwrap();

    // Send data in both directions
    let msg1 = b"Message from node 1";
    let msg2 = b"Message from node 2";

    stream_1to2.write_all(msg1).await.unwrap();
    stream_1to2.flush().await.unwrap();
    stream_2to1.write_all(msg2).await.unwrap();
    stream_2to1.flush().await.unwrap();

    // Verify data arrived
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        stream_from_2.read(&mut buf)
    )
    .await
    .expect("Timeout reading msg2 on node 1")
    .unwrap();
    assert_eq!(&buf[..n], msg2);

    buf.clear();
    buf.resize(1024, 0);
    let n = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        stream_from_1.read(&mut buf)
    )
    .await
    .expect("Timeout reading msg1 on node 2")
    .unwrap();
    assert_eq!(&buf[..n], msg1);

    manager1.close().await;
    manager2.close().await;
}
