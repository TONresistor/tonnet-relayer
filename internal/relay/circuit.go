package relay

import (
	"net"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
)

// Circuit represents an active relay circuit
type Circuit struct {
	ID        []byte
	CreatedAt time.Time
	SharedKey []byte    // Shared key with previous hop
	RelayPub  []byte    // Our X25519 public key (for idempotent responses)
	PrevHop   adnl.Peer // Connection to previous relay/client
	NextHop   adnl.Peer // Connection to next relay (nil if exit) - ADNL based

	// Tunnel-related fields for UDP-based garlic routing
	TunnelKeyHash  [32]byte     // Key hash for this circuit's tunnel midpoint
	NextHopUDPAddr *net.UDPAddr // UDP address of next relay (for UDP-based routing)
	PrevHopUDPAddr *net.UDPAddr // UDP address of previous relay (for UDP responses)

	StreamCount int
	BytesIn     uint64
	BytesOut    uint64
}

// IsExit returns true if this relay is the exit node for this circuit
func (c *Circuit) IsExit() bool {
	return c.NextHop == nil && c.NextHopUDPAddr == nil
}

// GetID returns the circuit ID (implements exit.Circuit interface)
func (c *Circuit) GetID() []byte {
	return c.ID
}

// GetSharedKey returns the shared key for this circuit (implements exit.Circuit interface)
func (c *Circuit) GetSharedKey() []byte {
	return c.SharedKey
}

// GetPrevHop returns the ADNL peer of the previous hop (implements exit.Circuit interface)
func (c *Circuit) GetPrevHop() adnl.Peer {
	return c.PrevHop
}

// GetPrevHopUDPAddr returns the UDP address of the previous hop (implements exit.Circuit interface)
func (c *Circuit) GetPrevHopUDPAddr() *net.UDPAddr {
	return c.PrevHopUDPAddr
}

// GetTunnelKeyHash returns the tunnel key hash for this circuit (implements exit.Circuit interface)
func (c *Circuit) GetTunnelKeyHash() [32]byte {
	return c.TunnelKeyHash
}

// Age returns how long the circuit has been active
func (c *Circuit) Age() time.Duration {
	return time.Since(c.CreatedAt)
}

// Stats returns circuit statistics
func (c *Circuit) Stats() CircuitStats {
	return CircuitStats{
		BytesIn:     c.BytesIn,
		BytesOut:    c.BytesOut,
		StreamCount: c.StreamCount,
		Age:         c.Age(),
	}
}

// CircuitStats holds circuit statistics
type CircuitStats struct {
	BytesIn     uint64
	BytesOut    uint64
	StreamCount int
	Age         time.Duration
}
