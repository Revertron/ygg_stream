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

/// Verify connectionless datagram send/receive works.
#[tokio::test]
async fn test_tcp_datagram_send_recv() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("info,ygg_stream=debug")
        .try_init();

    let port1 = 19004;

    let core1 = create_node_with_listener(port1).await;
    let addr1 = core1.packet_conn().local_addr();

    let peer_uri = format!("tcp://127.0.0.1:{}", port1);
    let core2 = create_node_with_peer(&peer_uri).await;
    let addr2 = core2.packet_conn().local_addr();

    // Wait 2 seconds before the nodes establish routing
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let manager1 = StreamManager::new(core1.packet_conn());
    let manager2 = StreamManager::new(core2.packet_conn());

    // Node 1 listens for datagrams on TEST_PORT
    let mut dg_listener1 = manager1.listen_datagram(TEST_PORT).await;

    // Send several datagrams so ironwood has a chance to establish the route
    let msg = b"hello datagram!";
    for _ in 0..10 {
        let _ = manager2.send_datagram(&addr1, TEST_PORT, msg.to_vec()).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }

    // Receive at least one datagram on node 1
    let (data, sender) = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        dg_listener1.recv(),
    )
    .await
    .expect("Timeout receiving datagram on node 1")
    .unwrap();

    assert_eq!(data, msg);
    assert_eq!(sender, addr2);

    // Clean shutdown
    manager1.close().await;
    manager2.close().await;
}

/// Verify that a stale (dead) connection is automatically replaced on reconnect.
///
/// This tests the new behavior where `connect()` detects a dead connection
/// (is_alive() == false), removes it, and creates a fresh one.
#[tokio::test]
async fn test_tcp_stale_connection_reconnect() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("info,ygg_stream=debug")
        .try_init();

    let port1 = 19005;

    let core1 = create_node_with_listener(port1).await;
    let addr1 = core1.packet_conn().local_addr();

    let peer_uri = format!("tcp://127.0.0.1:{}", port1);
    let core2 = create_node_with_peer(&peer_uri).await;

    let manager1 = StreamManager::new(core1.packet_conn());
    let manager2 = StreamManager::new(core2.packet_conn());

    let mut listener1 = manager1.listen(TEST_PORT).await;

    // First connection & stream
    let connection2a = manager2.connect(addr1).await.unwrap();
    assert!(connection2a.is_alive());
    let mut stream2a = connection2a.open_stream(TEST_PORT).await.unwrap();

    let mut stream1a = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        listener1.accept(),
    )
    .await
    .expect("Timeout accepting first stream")
    .unwrap();

    // Exchange data on first stream
    stream2a.write_all(b"first").await.unwrap();
    stream2a.flush().await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        stream1a.read(&mut buf),
    )
    .await
    .expect("Timeout reading first stream")
    .unwrap();
    assert_eq!(&buf[..n], b"first");

    // Kill the first connection by closing it
    connection2a.close().await;
    assert!(!connection2a.is_alive());

    // Reconnect — connect() should create a fresh connection
    let connection2b = manager2.connect(addr1).await.unwrap();
    assert!(connection2b.is_alive());

    let mut stream2b = connection2b.open_stream(TEST_PORT).await.unwrap();

    let mut stream1b = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        listener1.accept(),
    )
    .await
    .expect("Timeout accepting second stream after reconnect")
    .unwrap();

    // Exchange data on second stream
    stream2b.write_all(b"second").await.unwrap();
    stream2b.flush().await.unwrap();

    buf.clear();
    buf.resize(64, 0);
    let n = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        stream1b.read(&mut buf),
    )
    .await
    .expect("Timeout reading second stream")
    .unwrap();
    assert_eq!(&buf[..n], b"second");

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

/// Stress test: multiple clients connect to one server simultaneously,
/// each exchanging 3 request/response messages over a dedicated stream.
#[tokio::test]
async fn test_tcp_concurrent_clients() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("info,ygg_stream=debug")
        .try_init();

    const NUM_CLIENTS: usize = 5;
    const NUM_MESSAGES: usize = 3;
    const SERVER_TCP_PORT: u16 = 19006;

    // ── server node ───────────────────────────────────────────────────
    let server_core = create_node_with_listener(SERVER_TCP_PORT).await;
    let server_addr = server_core.packet_conn().local_addr();
    let server_manager = Arc::new(StreamManager::new(server_core.packet_conn()));
    let mut server_listener = server_manager.listen(TEST_PORT).await;

    // Server task: accept streams and echo back each message with a prefix.
    let server_mgr = server_manager.clone();
    let server_handle = tokio::spawn(async move {
        let mut handles = Vec::new();

        for _ in 0..NUM_CLIENTS {
            let mut stream = tokio::time::timeout(
                tokio::time::Duration::from_secs(30),
                server_listener.accept(),
            )
            .await
            .expect("Server timed out accepting a client")
            .unwrap();

            // Handle each client in its own task
            handles.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                for _ in 0..NUM_MESSAGES {
                    // Read client request
                    let n = tokio::time::timeout(
                        tokio::time::Duration::from_secs(10),
                        stream.read(&mut buf),
                    )
                    .await
                    .expect("Server timed out reading")
                    .unwrap();
                    assert!(n > 0, "Server got 0-byte read");

                    // Echo back with "reply:" prefix
                    let mut reply = b"reply:".to_vec();
                    reply.extend_from_slice(&buf[..n]);
                    stream.write_all(&reply).await.unwrap();
                    stream.flush().await.unwrap();
                }
            }));
        }

        // Wait for all per-client handlers to finish
        for h in handles {
            h.await.expect("Server handler panicked");
        }

        server_mgr.close().await;
    });

    // ── client nodes ──────────────────────────────────────────────────
    let peer_uri = format!("tcp://127.0.0.1:{}", SERVER_TCP_PORT);
    let mut client_handles = Vec::new();

    for client_id in 0..NUM_CLIENTS {
        let peer_uri = peer_uri.clone();

        let handle = tokio::spawn(async move {
            let client_core = create_node_with_peer(&peer_uri).await;
            let client_manager = StreamManager::new(client_core.packet_conn());

            let connection = tokio::time::timeout(
                tokio::time::Duration::from_secs(15),
                client_manager.connect(server_addr),
            )
            .await
            .unwrap_or_else(|_| panic!("Client {} timed out connecting", client_id))
            .unwrap();

            let mut stream = tokio::time::timeout(
                tokio::time::Duration::from_secs(15),
                connection.open_stream(TEST_PORT),
            )
            .await
            .unwrap_or_else(|_| panic!("Client {} timed out opening stream", client_id))
            .unwrap();

            let mut buf = vec![0u8; 1024];
            for msg_idx in 0..NUM_MESSAGES {
                let msg = format!("client{}:msg{}", client_id, msg_idx);
                stream.write_all(msg.as_bytes()).await.unwrap();
                stream.flush().await.unwrap();

                let n = tokio::time::timeout(
                    tokio::time::Duration::from_secs(10),
                    stream.read(&mut buf),
                )
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "Client {} timed out reading reply for msg {}",
                        client_id, msg_idx
                    )
                })
                .unwrap();
                assert!(n > 0, "Client {} got 0-byte read for msg {}", client_id, msg_idx);

                let expected = format!("reply:{}", msg);
                assert_eq!(
                    &buf[..n],
                    expected.as_bytes(),
                    "Client {} message {} mismatch",
                    client_id,
                    msg_idx,
                );
            }

            stream.shutdown().await.unwrap();
            client_manager.close().await;
        });

        client_handles.push(handle);
    }

    // Wait for all clients
    for (i, h) in client_handles.into_iter().enumerate() {
        h.await.unwrap_or_else(|e| panic!("Client {} panicked: {:?}", i, e));
    }

    // Wait for server
    tokio::time::timeout(tokio::time::Duration::from_secs(10), server_handle)
        .await
        .expect("Server timed out finishing")
        .expect("Server panicked");
}
