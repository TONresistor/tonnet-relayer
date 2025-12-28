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

## Installation

```bash
curl -L https://github.com/TONresistor/tonnet-relay/releases/latest/download/tonnet-relay-linux-amd64 -o tonnet-relay
chmod +x tonnet-relay
```

## Usage

```bash
# Initialize
./tonnet-relay init

# Start relay
./tonnet-relay start

# Start as exit node
./tonnet-relay start --exit --global-config ~/.tonnet-relay/global-config.json

# Show node info
./tonnet-relay info
```

## Configuration

`~/.tonnet-relay/config.json`

| Option | Default | Description |
|--------|---------|-------------|
| `node.port` | 9001 | ADNL listen port |
| `node.udp_port` | 9002 | UDP tunnel port |
| `exit.enabled` | false | Enable exit mode |

## Join the Network

1. Run `./tonnet-relay info` to get your pubkey
2. Submit PR to [tonnet-directory](https://github.com/TONresistor/tonnet-directory)

## Related

- [tonnet-proxy](https://github.com/TONresistor/tonnet-proxy) - Client proxy

## License

MIT
