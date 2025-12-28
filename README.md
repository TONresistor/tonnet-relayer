# Tonnet Relay

Onion routing relay node for the TON blockchain. Part of the Tonnet anonymity network.

## What is Tonnet?

Tonnet is an anonymity layer for TON Network, similar to Tor but built on TON protocols (ADNL, RLDP, DHT). It routes traffic through 3-hop encrypted circuits so no single node can link users to their destinations.

```
Client -> Entry -> Middle -> Exit -> TON Site
            |         |        |
         sees IP   sees      sees
         not dest  nothing   dest not IP
```

## This Repository

**tonnet-relay** is the server component that operators run to contribute relay capacity to the network.

Looking for the client? See [tonnet-proxy](https://github.com/TONresistor/tonnet-proxy).

## Requirements

- Linux server with public IP
- Ports 9001 (TCP) and 9002 (UDP) open
- Go 1.21+ (for building from source)

## Installation

### From Releases

```bash
# Download latest release
curl -L https://github.com/TONresistor/tonnet-relay/releases/latest/download/tonnet-relay-linux-amd64 -o tonnet-relay
chmod +x tonnet-relay
sudo mv tonnet-relay /usr/local/bin/
```

### From Source

```bash
git clone https://github.com/TONresistor/tonnet-relay.git
cd tonnet-relay
make build
sudo mv bin/tonnet-relay /usr/local/bin/
```

## Quick Start

```bash
# 1. Initialize (creates keys and config)
tonnet-relay init

# 2. Start relay
tonnet-relay start

# 3. Check your node info
tonnet-relay info
```

## Running as Exit Node

Exit nodes can resolve `.ton` domains and fetch TON sites. They require the TON global config:

```bash
# Download TON mainnet config
curl -o ~/.tonnet-relay/global-config.json https://ton.org/global-config.json

# Start with exit capability
tonnet-relay start --exit --global-config ~/.tonnet-relay/global-config.json
```

## Configuration

Config file: `~/.tonnet-relay/config.json`

```json
{
  "node": {
    "external_ip": "YOUR_SERVER_IP",
    "port": 9001,
    "udp_port": 9002
  },
  "exit": {
    "enabled": true,
    "global_config_path": "/root/.tonnet-relay/global-config.json"
  }
}
```

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 9001 | TCP | ADNL client connections |
| 9002 | UDP | Relay-to-relay forwarding |
| 9090 | HTTP | Prometheus metrics |

## CLI Commands

```
tonnet-relay init          Initialize new relay node
tonnet-relay start         Start the relay server
tonnet-relay stop          Stop the relay server
tonnet-relay info          Show node pubkey and address
tonnet-relay status        Show relay status
tonnet-relay version       Show version
```

## Deployment

### Systemd

```ini
# /etc/systemd/system/tonnet-relay.service
[Unit]
Description=Tonnet Relay
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tonnet-relay start --exit --global-config /root/.tonnet-relay/global-config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable tonnet-relay
sudo systemctl start tonnet-relay
```

## Join the Network

To add your relay to the public directory, submit a PR to [tonnet-directory](https://github.com/TONresistor/tonnet-directory) with your node info:

```json
{
  "name": "my-relay",
  "pubkey": "<your-pubkey-from-tonnet-relay-info>",
  "address": "<your-ip>:9001",
  "roles": ["entry", "middle", "exit"]
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      tonnet-relay                       │
├─────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌───────────┐  │
│  │  ADNL   │  │  UDP    │  │ Circuit │  │   Exit    │  │
│  │ Server  │  │ Tunnel  │  │ Engine  │  │  Handler  │  │
│  │ :9001   │  │ :9002   │  │         │  │ (RLDP)    │  │
│  └────┬────┘  └────┬────┘  └────┬────┘  └─────┬─────┘  │
│       │            │            │              │        │
│       └────────────┴─────┬──────┴──────────────┘        │
│                          │                              │
│                    ┌─────┴─────┐                        │
│                    │  Crypto   │                        │
│                    │ ChaCha20  │                        │
│                    │  X25519   │                        │
│                    └───────────┘                        │
└─────────────────────────────────────────────────────────┘
```

## Security

- Each relay only knows the previous and next hop
- Traffic is encrypted with ChaCha20-Poly1305
- Keys are negotiated per-circuit using X25519
- Exit nodes see destination but not client IP

## License

MIT
