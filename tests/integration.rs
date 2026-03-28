// Integration tests using real TCP connections via Yggdrasil Core

use ed25519_dalek::SigningKey;
use ironwood::PacketConn;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;
use yggdrasil::config::Config;
use yggdrasil::core::Core;
use ygg_stream::TcpStack;

/// Default port used in tests
const TEST_PORT: u16 = 1;

/// Find a free TCP port by briefly binding to :0, then returning the assigned port.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Helper to create a Yggdrasil node with TCP listener on a free port.
/// Returns (core, tcp_port).
async fn create_node_with_listener() -> (Arc<Core>, u16) {
    let tcp_port = free_port();
    let signing_key = SigningKey::generate(&mut rand::thread_rng());

    let mut config = Config::default();
    config.listen = vec![format!("tcp://127.0.0.1:{}", tcp_port)];

    let core = Core::new(signing_key, config);
    core.init_links().await;
    core.start().await;

    // Give the listener time to start
    tokio::time::sleep(Duration::from_millis(5000)).await;

    (core, tcp_port)
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
    tokio::time::sleep(Duration::from_millis(5000)).await;

    core
}

/// Full bidirectional data transfer test.
#[tokio::test]
async fn test_tcp_connectivity() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("info,ygg_stream=debug")
        .try_init();

    let (core1, tcp_port) = create_node_with_listener().await;
    let addr1 = core1.packet_conn().local_addr();

    let peer_uri = format!("tcp://127.0.0.1:{}", tcp_port);
    let core2 = create_node_with_peer(&peer_uri).await;

    let stack1 = TcpStack::new(core1.packet_conn());
    let stack2 = TcpStack::new(core2.packet_conn());

    let mut listener1 = stack1.listen(TEST_PORT).await;

    let mut conn2 = stack2.connect(addr1, TEST_PORT).await.unwrap();

    let mut conn1 = tokio::time::timeout(
        Duration::from_secs(5),
        listener1.accept(),
    )
    .await
    .expect("Timeout accepting connection on node 1")
    .unwrap();

    // Node 2 → Node 1
    let msg_a = b"Hello from node 2!";
    conn2.write_all(msg_a).await.unwrap();
    conn2.flush().await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), conn1.read(&mut buf))
        .await
        .expect("Timeout reading on node 1")
        .unwrap();
    assert_eq!(&buf[..n], msg_a);

    // Node 1 → Node 2
    let msg_b = b"Hello back from node 1!";
    conn1.write_all(msg_b).await.unwrap();
    conn1.flush().await.unwrap();

    buf.clear();
    buf.resize(1024, 0);
    let n = tokio::time::timeout(Duration::from_secs(5), conn2.read(&mut buf))
        .await
        .expect("Timeout reading on node 2")
        .unwrap();
    assert_eq!(&buf[..n], msg_b);

    conn1.shutdown().await.unwrap();
    conn2.shutdown().await.unwrap();
    stack1.close().await;
    stack2.close().await;
}

/// Verify multiple connections can be opened to the same peer on different ports.
#[tokio::test]
async fn test_tcp_multiple_connections() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("info")
        .try_init();

    let (core1, tcp_port) = create_node_with_listener().await;
    let addr1 = core1.packet_conn().local_addr();

    let peer_uri = format!("tcp://127.0.0.1:{}", tcp_port);
    let core2 = create_node_with_peer(&peer_uri).await;

    let stack1 = TcpStack::new(core1.packet_conn());
    let stack2 = TcpStack::new(core2.packet_conn());

    let mut listener_port1 = stack1.listen(1).await;
    let mut listener_port2 = stack1.listen(2).await;
    let mut listener_port3 = stack1.listen(3).await;

    let mut conn_a = stack2.connect(addr1, 1).await.unwrap();
    let mut conn_b = stack2.connect(addr1, 2).await.unwrap();
    let mut conn_c = stack2.connect(addr1, 3).await.unwrap();

    let mut srv_a = tokio::time::timeout(Duration::from_secs(5), listener_port1.accept())
        .await.expect("Timeout accepting conn a").unwrap();
    let mut srv_b = tokio::time::timeout(Duration::from_secs(5), listener_port2.accept())
        .await.expect("Timeout accepting conn b").unwrap();
    let mut srv_c = tokio::time::timeout(Duration::from_secs(5), listener_port3.accept())
        .await.expect("Timeout accepting conn c").unwrap();

    conn_a.write_all(b"aaa").await.unwrap();
    conn_b.write_all(b"bbb").await.unwrap();
    conn_c.write_all(b"ccc").await.unwrap();
    conn_a.flush().await.unwrap();
    conn_b.flush().await.unwrap();
    conn_c.flush().await.unwrap();

    let mut buf = vec![0u8; 64];

    let n = tokio::time::timeout(Duration::from_secs(5), srv_a.read(&mut buf))
        .await.expect("Timeout reading a").unwrap();
    assert_eq!(&buf[..n], b"aaa");

    let n = tokio::time::timeout(Duration::from_secs(5), srv_b.read(&mut buf))
        .await.expect("Timeout reading b").unwrap();
    assert_eq!(&buf[..n], b"bbb");

    let n = tokio::time::timeout(Duration::from_secs(5), srv_c.read(&mut buf))
        .await.expect("Timeout reading c").unwrap();
    assert_eq!(&buf[..n], b"ccc");

    stack1.close().await;
    stack2.close().await;
}

/// Verify connectionless datagram send/receive works.
#[tokio::test]
async fn test_tcp_datagram_send_recv() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("info,ygg_stream=debug")
        .try_init();

    let (core1, tcp_port) = create_node_with_listener().await;
    let addr1 = core1.packet_conn().local_addr();

    let peer_uri = format!("tcp://127.0.0.1:{}", tcp_port);
    let core2 = create_node_with_peer(&peer_uri).await;
    let addr2 = core2.packet_conn().local_addr();

    tokio::time::sleep(Duration::from_secs(2)).await;

    let stack1 = TcpStack::new(core1.packet_conn());
    let stack2 = TcpStack::new(core2.packet_conn());

    let mut dg_listener1 = stack1.listen_datagram(TEST_PORT).await;

    let msg = b"hello datagram!";
    for _ in 0..10 {
        let _ = stack2.send_datagram(&addr1, TEST_PORT, msg.to_vec()).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let (data, sender) = tokio::time::timeout(
        Duration::from_secs(5),
        dg_listener1.recv(),
    )
    .await
    .expect("Timeout receiving datagram on node 1")
    .unwrap();

    assert_eq!(data, msg);
    assert_eq!(sender, addr2);

    stack1.close().await;
    stack2.close().await;
}

/// Verify that after closing a connection, a new one can be established.
#[tokio::test]
async fn test_tcp_reconnect_after_close() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("info,ygg_stream=debug")
        .try_init();

    let (core1, tcp_port) = create_node_with_listener().await;
    let addr1 = core1.packet_conn().local_addr();

    let peer_uri = format!("tcp://127.0.0.1:{}", tcp_port);
    let core2 = create_node_with_peer(&peer_uri).await;

    let stack1 = TcpStack::new(core1.packet_conn());
    let stack2 = TcpStack::new(core2.packet_conn());

    let mut listener1 = stack1.listen(TEST_PORT).await;

    // First connection
    let mut conn2a = stack2.connect(addr1, TEST_PORT).await.unwrap();

    let mut conn1a = tokio::time::timeout(Duration::from_secs(5), listener1.accept())
        .await
        .expect("Timeout accepting first connection")
        .unwrap();

    conn2a.write_all(b"first").await.unwrap();
    conn2a.flush().await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), conn1a.read(&mut buf))
        .await
        .expect("Timeout reading first connection")
        .unwrap();
    assert_eq!(&buf[..n], b"first");

    // Close first connection
    conn2a.shutdown().await.unwrap();
    sleep(Duration::from_secs(1)).await;

    // Open second connection (new ephemeral port)
    let mut conn2b = stack2.connect(addr1, TEST_PORT).await.unwrap();

    let mut conn1b = tokio::time::timeout(Duration::from_secs(5), listener1.accept())
        .await
        .expect("Timeout accepting second connection")
        .unwrap();

    conn2b.write_all(b"second").await.unwrap();
    conn2b.flush().await.unwrap();

    buf.clear();
    buf.resize(64, 0);
    let n = tokio::time::timeout(Duration::from_secs(5), conn1b.read(&mut buf))
        .await
        .expect("Timeout reading second connection")
        .unwrap();
    assert_eq!(&buf[..n], b"second");

    stack1.close().await;
    stack2.close().await;
}

/// Verify connections can be opened in both directions between two nodes.
#[tokio::test]
async fn test_tcp_bidirectional_connections() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("info,ygg_stream=debug")
        .try_init();

    let (core1, tcp_port) = create_node_with_listener().await;
    let addr1 = core1.packet_conn().local_addr();

    let peer_uri = format!("tcp://127.0.0.1:{}", tcp_port);
    let core2 = create_node_with_peer(&peer_uri).await;
    let addr2 = core2.packet_conn().local_addr();

    let stack1 = TcpStack::new(core1.packet_conn());
    let stack2 = TcpStack::new(core2.packet_conn());

    let mut listener1 = stack1.listen(TEST_PORT).await;
    let mut listener2 = stack2.listen(TEST_PORT).await;

    // Node 2 → Node 1
    let mut conn_2to1 = stack2.connect(addr1, TEST_PORT).await.unwrap();
    let mut conn_from_2 = tokio::time::timeout(Duration::from_secs(5), listener1.accept())
        .await
        .expect("Timeout accepting on node 1")
        .unwrap();

    // Node 1 → Node 2
    let mut conn_1to2 = stack1.connect(addr2, TEST_PORT).await.unwrap();
    let mut conn_from_1 = tokio::time::timeout(Duration::from_secs(5), listener2.accept())
        .await
        .expect("Timeout accepting on node 2")
        .unwrap();

    let msg1 = b"Message from node 1";
    let msg2 = b"Message from node 2";

    conn_1to2.write_all(msg1).await.unwrap();
    conn_1to2.flush().await.unwrap();
    conn_2to1.write_all(msg2).await.unwrap();
    conn_2to1.flush().await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), conn_from_2.read(&mut buf))
        .await
        .expect("Timeout reading msg2 on node 1")
        .unwrap();
    assert_eq!(&buf[..n], msg2);

    buf.clear();
    buf.resize(1024, 0);
    let n = tokio::time::timeout(Duration::from_secs(5), conn_from_1.read(&mut buf))
        .await
        .expect("Timeout reading msg1 on node 2")
        .unwrap();
    assert_eq!(&buf[..n], msg1);

    stack1.close().await;
    stack2.close().await;
}

/// Stress test: multiple clients connect to one server simultaneously,
/// each exchanging 3 request/response messages.
#[tokio::test]
async fn test_tcp_concurrent_clients() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("info,ygg_stream=debug")
        .try_init();

    const NUM_CLIENTS: usize = 5;
    const NUM_MESSAGES: usize = 3;

    // ── server node ───────────────────────────────────────────────────
    let (server_core, server_tcp_port) = create_node_with_listener().await;
    let server_addr = server_core.packet_conn().local_addr();
    let server_stack = Arc::new(TcpStack::new(server_core.packet_conn()));
    let mut server_listener = server_stack.listen(TEST_PORT).await;

    let server_stk = server_stack.clone();
    let server_handle = tokio::spawn(async move {
        let mut handles = Vec::new();

        for _ in 0..NUM_CLIENTS {
            let mut conn = tokio::time::timeout(
                Duration::from_secs(30),
                server_listener.accept(),
            )
            .await
            .expect("Server timed out accepting a client")
            .unwrap();

            handles.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                for _ in 0..NUM_MESSAGES {
                    let n = tokio::time::timeout(
                        Duration::from_secs(10),
                        conn.read(&mut buf),
                    )
                    .await
                    .expect("Server timed out reading")
                    .unwrap();
                    assert!(n > 0, "Server got 0-byte read");

                    let mut reply = b"reply:".to_vec();
                    reply.extend_from_slice(&buf[..n]);
                    conn.write_all(&reply).await.unwrap();
                    conn.flush().await.unwrap();
                }
            }));
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        for h in handles {
            h.await.expect("Server handler panicked");
        }

        server_stk.close().await;
    });

    // ── client nodes ──────────────────────────────────────────────────
    let peer_uri = format!("tcp://127.0.0.1:{}", server_tcp_port);
    let mut client_handles = Vec::new();

    for client_id in 0..NUM_CLIENTS {
        let peer_uri = peer_uri.clone();

        let handle = tokio::spawn(async move {
            let client_core = create_node_with_peer(&peer_uri).await;
            let client_stack = TcpStack::new(client_core.packet_conn());

            let mut conn = tokio::time::timeout(
                Duration::from_secs(15),
                client_stack.connect(server_addr, TEST_PORT),
            )
            .await
            .unwrap_or_else(|_| panic!("Client {} timed out connecting", client_id))
            .unwrap();

            let mut buf = vec![0u8; 1024];
            for msg_idx in 0..NUM_MESSAGES {
                let msg = format!("client{}:msg{}", client_id, msg_idx);
                conn.write_all(msg.as_bytes()).await.unwrap();
                conn.flush().await.unwrap();

                let n = tokio::time::timeout(
                    Duration::from_secs(10),
                    conn.read(&mut buf),
                )
                .await
                .unwrap_or_else(|_| {
                    panic!("Client {} timed out reading reply for msg {}", client_id, msg_idx)
                })
                .unwrap();
                assert!(n > 0, "Client {} got 0-byte read for msg {}", client_id, msg_idx);

                let expected = format!("reply:{}", msg);
                assert_eq!(
                    &buf[..n],
                    expected.as_bytes(),
                    "Client {} message {} mismatch",
                    client_id,
                    msg_idx
                );
            }

            conn.shutdown().await.unwrap();
            client_stack.close().await;
        });

        client_handles.push(handle);
    }

    for (i, h) in client_handles.into_iter().enumerate() {
        h.await.unwrap_or_else(|e| panic!("Client {} panicked: {:?}", i, e));
    }

    tokio::time::timeout(Duration::from_secs(10), server_handle)
        .await
        .expect("Server timed out finishing")
        .expect("Server panicked");
}
