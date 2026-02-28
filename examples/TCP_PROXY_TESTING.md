# tcp_proxy — Testing Guide

TCP port forwarding through Yggdrasil mesh network.

## Build

```bash
cd /home/exp113/life/projects/mimir/ygg_stream
cargo build --example tcp_proxy --release
```

## Key Management

### First run — generate and save key

```bash
cargo run --release --example tcp_proxy -- reverse \
    --peer tcp://bootstrap:1234 \
    --listen-port 80 --target 127.0.0.1:8080
```

Output:
```
INFO Signing key (save this): a1b2c3d4...  # 64 hex — PRIVATE, save securely
INFO Public key: d4e5f6a7...               # 64 hex — share with clients
```

### Subsequent runs — reuse key

```bash
cargo run --release --example tcp_proxy -- reverse \
    --peer tcp://bootstrap:1234 \
    --listen-port 80 --target 127.0.0.1:8080 \
    --key a1b2c3d4...
```

Public key stays the same across restarts.

## CLI Reference

```
tcp_proxy forward --peer <uri> --bind <addr:port> --remote-key <hex> --remote-port <port> [--key <hex>]
tcp_proxy reverse --peer <uri> --listen-port <port> --target <addr:port> [--key <hex>]
```

| Flag | Description |
|------|-------------|
| `--peer` | Yggdrasil peer URI (`tcp://1.2.3.4:1234`) |
| `--bind` | Local TCP address to listen on (forward mode) |
| `--remote-key` | Remote peer's public key, 64 hex chars |
| `--remote-port` | Remote ygg_stream port |
| `--listen-port` | ygg_stream port to accept connections on (reverse mode) |
| `--target` | Local TCP address to forward to (reverse mode) |
| `--key` | Signing key, 64 hex chars. Keeps identity stable between restarts |

## Test Scenarios

All scenarios require two nodes connected to the same Yggdrasil network.
Replace `<BOOTSTRAP>` with your Yggdrasil peer URI and `<NODE_B_KEY>` with the
public key printed by Node B at startup.

### A: HTTP server

```bash
# --- Node B (server) ---
python3 -m http.server 8080 &

cargo run --release --example tcp_proxy -- reverse \
    --peer tcp://<BOOTSTRAP> \
    --listen-port 80 \
    --target 127.0.0.1:8080 \
    --key <NODE_B_SIGNING_KEY>
# prints: Public key: <NODE_B_KEY>

# --- Node A (client) ---
cargo run --release --example tcp_proxy -- forward \
    --peer tcp://<BOOTSTRAP> \
    --bind 127.0.0.1:9055 \
    --remote-key <NODE_B_KEY> \
    --remote-port 80

# --- Test ---
curl -v http://127.0.0.1:9055/
```

### B: HTTPS tunnel

```bash
# --- Node B ---
# nginx/apache with HTTPS on port 443
cargo run --release --example tcp_proxy -- reverse \
    --peer tcp://<BOOTSTRAP> \
    --listen-port 443 \
    --target 127.0.0.1:443 \
    --key <NODE_B_SIGNING_KEY>

# --- Node A ---
cargo run --release --example tcp_proxy -- forward \
    --peer tcp://<BOOTSTRAP> \
    --bind 127.0.0.1:9443 \
    --remote-key <NODE_B_KEY> \
    --remote-port 443

# --- Test ---
curl -k https://127.0.0.1:9443/
```

### C: SOCKS5 proxy

```bash
# --- Node B ---
# Install: apt install microsocks  OR  cargo install microsocks
microsocks -p 1080 &

cargo run --release --example tcp_proxy -- reverse \
    --peer tcp://<BOOTSTRAP> \
    --listen-port 1080 \
    --target 127.0.0.1:1080 \
    --key <NODE_B_SIGNING_KEY>

# --- Node A ---
cargo run --release --example tcp_proxy -- forward \
    --peer tcp://<BOOTSTRAP> \
    --bind 127.0.0.1:9080 \
    --remote-key <NODE_B_KEY> \
    --remote-port 1080

# --- Test ---
curl -x socks5h://127.0.0.1:9080 http://example.com
curl -x socks5h://127.0.0.1:9080 https://example.com

# Firefox: Settings -> Network -> Manual proxy -> SOCKS Host: 127.0.0.1:9080, SOCKS v5
```

### D: SSH

```bash
# --- Node B ---
# sshd must be running on port 22
cargo run --release --example tcp_proxy -- reverse \
    --peer tcp://<BOOTSTRAP> \
    --listen-port 22 \
    --target 127.0.0.1:22 \
    --key <NODE_B_SIGNING_KEY>

# --- Node A ---
cargo run --release --example tcp_proxy -- forward \
    --peer tcp://<BOOTSTRAP> \
    --bind 127.0.0.1:2222 \
    --remote-key <NODE_B_KEY> \
    --remote-port 22

# --- Test ---
ssh -p 2222 user@127.0.0.1
scp -P 2222 file.txt user@127.0.0.1:/tmp/
```

### E: Multiple services on one node

Run several reverse proxies with the same key but different ports:

```bash
# --- Node B ---
cargo run --release --example tcp_proxy -- reverse \
    --peer tcp://<BOOTSTRAP> --listen-port 80 --target 127.0.0.1:8080 --key <KEY> &

cargo run --release --example tcp_proxy -- reverse \
    --peer tcp://<BOOTSTRAP> --listen-port 22 --target 127.0.0.1:22 --key <KEY> &

cargo run --release --example tcp_proxy -- reverse \
    --peer tcp://<BOOTSTRAP> --listen-port 1080 --target 127.0.0.1:1080 --key <KEY> &
```

Note: each instance starts its own Yggdrasil node. For production use,
share a single node (requires code changes to accept `Arc<AsyncNode>`).

## Troubleshooting

| Problem | Likely cause |
|---------|--------------|
| `ygg connect: Operation timed out` | Peer unreachable. Check `--peer` URI, firewall, Yggdrasil routing |
| `Connection refused` on curl | `--bind` address/port mismatch, or forward proxy not running |
| `Connection refused` in YggToTcp logs | `--target` service not running on Node B |
| Public key changes on restart | Forgot `--key`. Save signing key from first run |
| Slow first connection | Normal. Yggdrasil routing needs 1-10 seconds to converge |
