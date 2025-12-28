<div align="center">

# Tonnet Relay

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![TON](https://img.shields.io/badge/TON-Network-0088CC?logo=telegram)](https://ton.org/)

**Onion routing relay node for TON blockchain**

[Installation](#installation) · [Usage](#usage) · [Configuration](#configuration) · [Join Network](#join-the-network)

</div>

---

## Overview

Tonnet Relay is a node in the Tonnet anonymity network. Traffic is routed through 3 relays with layered encryption. Each relay only knows its immediate neighbors, never the full path.

Built natively on TON protocols (ADNL, RLDP, DHT), it provides:

- **True anonymity**: no single relay knows both source and destination
- **Layered encryption**: ChaCha20-Poly1305 at each hop, X25519 key exchange
- **Decentralized**: run your own relay, strengthen the network
- **TON-native**: direct integration with TON DNS and RLDP HTTP

---

## Features

| Feature | Description |
|---------|-------------|
| **3-Hop Circuits** | Traffic routes through Entry, Middle, and Exit relays for maximum privacy |
| **Garlic Encryption** | ChaCha20-Poly1305 with X25519 key exchange at each hop |
| **Exit Node Mode** | Relay can act as exit node to reach actual TON sites |
| **UDP Tunnel Mode** | High-performance UDP-based packet forwarding between relays |
| **DHT Integration** | Automatic peer discovery via TON's distributed hash table |
| **Prometheus Metrics** | Built-in monitoring with `/metrics` endpoint |
| **Circuit Management** | Create, extend, and destroy circuits dynamically |

---

## Architecture

Traffic flows through 3 relays: **Client → Entry → Middle → Exit → TON Site**

Each hop has its own encryption layer (ChaCha20-Poly1305). The client encrypts data for all 3 hops in reverse order: `[[[payload]K3]K2]K1`. Each relay decrypts one layer and forwards to the next.

### Circuit Flow

1. Client establishes shared keys with each relay via X25519 key exchange
2. Client sends request encrypted in 3 layers
3. Each relay peels one layer and forwards
4. Exit node resolves `.ton` domain via DHT and fetches via RLDP
5. Response travels back through the circuit with encryption added at each hop

---

## Installation

```bash
curl -L https://github.com/TONresistor/tonnet-relay/releases/latest/download/tonnet-relay-linux-amd64 -o tonnet-relay
chmod +x tonnet-relay
```

---

## Usage

```bash
# Initialize configuration and generate keys
./tonnet-relay init

# This creates:
#   ~/.tonnet-relay/config.json     - Node configuration
#   ~/.tonnet-relay/keys/relay.key  - Ed25519 private key
#   ~/.tonnet-relay/peers.json      - Known peers list

# Start as a regular relay (entry/middle node)
./tonnet-relay start

# Start as an exit node (requires global config)
./tonnet-relay start --exit --global-config /path/to/mainnet.json

# View node info (public key, connection address)
./tonnet-relay info
```

---

## Configuration

Configuration file: `~/.tonnet-relay/config.json`

```json
{
  "node": {
    "name": "my-relay",
    "listen_addr": "0.0.0.0",
    "port": 9001,
    "udp_port": 9002,
    "max_connections": 100,
    "max_circuits_per_peer": 10
  },
  "keys": {
    "private_key_path": "./keys/relay.key"
  },
  "peers": {
    "file": "./peers.json",
    "bootstrap": [
      "abc123...@relay1.example.com:9001",
      "def456...@relay2.example.com:9001"
    ],
    "max_peers": 50,
    "health_check_interval": 30
  },
  "relay": {
    "enabled": true,
    "max_bandwidth_mbps": 100,
    "circuit_timeout": 300,
    "forward_timeout": 10
  },
  "exit": {
    "enabled": false,
    "global_config_path": "/path/to/mainnet.json"
  },
  "metrics": {
    "enabled": true,
    "port": 9090,
    "path": "/metrics"
  },
  "logging": {
    "level": "info",
    "format": "json",
    "file": "./logs/relay.log"
  }
}
```

### Configuration Options

| Section | Option | Default | Description |
|---------|--------|---------|-------------|
| `node.port` | int | `9001` | ADNL listen port |
| `node.udp_port` | int | `9002` | UDP tunnel port |
| `node.max_connections` | int | `100` | Maximum peer connections |
| `relay.circuit_timeout` | int | `300` | Circuit idle timeout (seconds) |
| `exit.enabled` | bool | `false` | Enable exit node mode |
| `metrics.enabled` | bool | `true` | Enable Prometheus metrics |

---

## How It Works

### Garlic Encryption

Each data packet is encrypted in layers (like a garlic bulb). Each relay decrypts one layer with its shared key and forwards to the next hop.

### Key Exchange

X25519 Diffie-Hellman establishes shared keys at circuit creation. Client sends `CircuitCreate` with its public key, relay responds with `CircuitCreated` containing the relay's public key. Both derive the same shared key via `SHA256(X25519(priv, other_pub))`.

### Exit Node Operation

The exit relay connects to actual TON sites:

1. Resolves `.ton` domain via TON DNS smart contracts
2. Looks up site's ADNL address in DHT
3. Connects via RLDP (Reliable Large Datagram Protocol)
4. Fetches HTTP response and sends back through circuit

### Protocol Messages

| Message | Purpose |
|---------|---------|
| `CircuitCreate` | Establish circuit with first relay |
| `CircuitExtend` | Extend circuit through existing hop |
| `CircuitRelay` | Forward encrypted command through circuit |
| `Data` | Send/receive encrypted payload |
| `DataChunk` | Chunked transfer for large responses |
| `StreamConnect` | Open connection to destination |
| `StreamData` | HTTP request/response data |

---

## CLI Reference

```bash
tonnet-relay [command]

Commands:
  init        Initialize a new relay node
  start       Start the relay server
  info        Show node info (pubkey, address)
  version     Show version

Flags:
  --config string      Config file path
  --config-dir string  Config directory (default ~/.tonnet-relay)
  --log-level string   Log level: debug|info|warn|error (default "info")

Start Flags:
  --port int           Listen port (default 9001)
  --metrics            Enable Prometheus metrics (default true)
  --metrics-port int   Metrics port (default 9090)
  --exit               Enable exit node for TON sites
  --global-config      Path to TON global config
```

---

## Security Considerations

### Privacy Guarantees

| Relay | Knows Client | Knows Destination | Knows Content |
|-------|--------------|-------------------|---------------|
| Entry | IP only | No | No |
| Middle | No | No | No |
| Exit | No | Yes | Decrypted at exit |

### Threat Model

- **Traffic Analysis**: Correlating entry/exit timing could deanonymize users
- **Malicious Relays**: A single malicious relay cannot break anonymity
- **Colluding Relays**: All 3 relays colluding could identify user-destination pairs
- **Exit Node Sniffing**: Exit nodes see decrypted traffic (use HTTPS where possible)

### Best Practices

1. **Use diverse relays** - Don't use relays from the same operator
2. **Rotate circuits** - Periodically create new circuits
3. **Run your own relay** - Contribute to network diversity
4. **Monitor metrics** - Watch for anomalous traffic patterns

---

## Metrics & Monitoring

Prometheus metrics available at `http://localhost:9090/metrics`:

```
tonnet_connections_total    - Total peer connections
tonnet_circuits_total       - Total active circuits
tonnet_bytes_received_total - Total bytes received
tonnet_bytes_sent_total     - Total bytes sent
```

---

## Docker

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o tonnet-relay ./cmd/tonnet-relay

FROM alpine:latest
COPY --from=builder /app/tonnet-relay /usr/local/bin/
EXPOSE 9001 9002/udp 9090
ENTRYPOINT ["tonnet-relay"]
CMD ["start"]
```

```bash
# Build image
docker build -t tonnet-relay .

# Run relay
docker run -d \
  --name tonnet-relay \
  -p 9001:9001 \
  -p 9002:9002/udp \
  -p 9090:9090 \
  -v ~/.tonnet-relay:/root/.tonnet-relay \
  tonnet-relay

# Run as exit node
docker run -d \
  --name tonnet-exit \
  -p 9001:9001 \
  -p 9002:9002/udp \
  -v ~/.tonnet-relay:/root/.tonnet-relay \
  -v /path/to/mainnet.json:/etc/ton/mainnet.json \
  tonnet-relay start --exit --global-config /etc/ton/mainnet.json
```

---

## Development

### Building from Source

```bash
git clone https://github.com/TONresistor/tonnet-relay.git
cd tonnet-relay
go mod download
make build
make test
```

### Project Structure

- `cmd/tonnet-relay` - Main relay daemon
- `internal/relay` - Core relay server and routing engine
- `internal/tunnel` - Garlic encryption and UDP packet handling
- `internal/exit` - Exit node with RLDP HTTP transport
- `internal/protocol` - TL message definitions

---

## Join the Network

Help the network by running your own relay:

1. Run `./tonnet-relay info` to get your pubkey
2. Submit PR to [tonnet-directory](https://github.com/TONresistor/tonnet-directory)

---

## Contributing

Contributions are welcome!

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

---

## Acknowledgments

- **[tonutils-go](https://github.com/xssnick/tonutils-go)** - Foundation for TON protocol interactions
- **[TON Foundation](https://ton.org)** - TON Network and documentation
- **Tor Project** - Inspiration for onion routing architecture

---

## Related

- [tonnet-proxy](https://github.com/TONresistor/tonnet-proxy) - Client proxy

## License

MIT
