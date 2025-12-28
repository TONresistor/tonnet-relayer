package peer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/TONresistor/tonnet-relay/internal/config"
	"github.com/xssnick/tonutils-go/adnl"
	"go.uber.org/zap"
)

// Info contains information about a peer
type Info struct {
	ADNLID     []byte    `json:"adnl_id"`
	Addresses  []Address `json:"addresses"`
	AddedAt    time.Time `json:"added_at"`
	LastSeen   time.Time `json:"last_seen"`
	TrustLevel string    `json:"trust_level"`
	Latency    int       `json:"latency_ms"`
	Online     bool      `json:"-"`
}

// Address contains an IP and port
type Address struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// Manager manages peer connections
type Manager struct {
	config *config.PeersConfig
	peers  map[string]*Info    // ADNL ID hex -> Info
	conns  map[string]adnl.Peer // ADNL ID hex -> connection
	mu     sync.RWMutex
	logger *zap.Logger
}

// NewManager creates a new peer manager
func NewManager(cfg *config.PeersConfig, logger *zap.Logger) *Manager {
	return &Manager{
		config: cfg,
		peers:  make(map[string]*Info),
		conns:  make(map[string]adnl.Peer),
		logger: logger,
	}
}

// LoadFromFile loads peers from the configured file
func (m *Manager) LoadFromFile() error {
	data, err := os.ReadFile(m.config.File)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var peerFile struct {
		Peers []*Info `json:"peers"`
	}

	if err := json.Unmarshal(data, &peerFile); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, p := range peerFile.Peers {
		m.peers[hex.EncodeToString(p.ADNLID)] = p
	}

	m.logger.Info("loaded peers", zap.Int("count", len(peerFile.Peers)))
	return nil
}

// SaveToFile saves peers to the configured file
func (m *Manager) SaveToFile() error {
	m.mu.RLock()
	peers := make([]*Info, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	m.mu.RUnlock()

	data, err := json.MarshalIndent(struct {
		Peers []*Info `json:"peers"`
	}{Peers: peers}, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.config.File, data, 0644)
}

// AddPeer adds a new peer
func (m *Manager) AddPeer(info *Info) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := hex.EncodeToString(info.ADNLID)
	if _, exists := m.peers[id]; !exists {
		info.AddedAt = time.Now()
		m.peers[id] = info
		m.logger.Debug("peer added", zap.String("id", id))
	}
}

// RemovePeer removes a peer
func (m *Manager) RemovePeer(adnlID []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := hex.EncodeToString(adnlID)
	delete(m.peers, id)
	delete(m.conns, id)
	m.logger.Debug("peer removed", zap.String("id", id))
}

// GetPeer returns a peer by ADNL ID
func (m *Manager) GetPeer(adnlID []byte) (*Info, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	id := hex.EncodeToString(adnlID)
	info, ok := m.peers[id]
	return info, ok
}

// GetPeers returns up to maxCount online peers
func (m *Manager) GetPeers(maxCount int) []*Info {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Info, 0, maxCount)
	for _, p := range m.peers {
		if p.Online {
			result = append(result, p)
			if len(result) >= maxCount {
				break
			}
		}
	}
	return result
}

// GetAllPeers returns all peers
func (m *Manager) GetAllPeers() []*Info {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Info, 0, len(m.peers))
	for _, p := range m.peers {
		result = append(result, p)
	}
	return result
}

// SetConnection stores a connection for a peer
func (m *Manager) SetConnection(adnlID []byte, conn adnl.Peer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := hex.EncodeToString(adnlID)
	m.conns[id] = conn

	if info, ok := m.peers[id]; ok {
		info.Online = true
		info.LastSeen = time.Now()
	}
}

// GetConnection returns the connection for a peer
func (m *Manager) GetConnection(adnlID []byte) (adnl.Peer, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	id := hex.EncodeToString(adnlID)
	conn, ok := m.conns[id]
	return conn, ok
}

// RemoveConnection removes a connection
func (m *Manager) RemoveConnection(adnlID []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := hex.EncodeToString(adnlID)
	delete(m.conns, id)

	if info, ok := m.peers[id]; ok {
		info.Online = false
	}
}

// HealthCheck pings all known peers
func (m *Manager) HealthCheck(ctx context.Context) {
	m.mu.RLock()
	peers := make([]*Info, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	m.mu.RUnlock()

	for _, peer := range peers {
		go m.checkPeer(ctx, peer)
	}
}

// checkPeer pings a single peer
func (m *Manager) checkPeer(ctx context.Context, peer *Info) {
	id := hex.EncodeToString(peer.ADNLID)

	m.mu.RLock()
	conn, ok := m.conns[id]
	m.mu.RUnlock()

	if !ok {
		m.mu.Lock()
		if info, exists := m.peers[id]; exists {
			info.Online = false
		}
		m.mu.Unlock()
		return
	}

	// Ping the peer
	start := time.Now()
	if err := pingPeer(ctx, conn); err != nil {
		m.mu.Lock()
		if info, exists := m.peers[id]; exists {
			info.Online = false
		}
		m.mu.Unlock()
		return
	}

	latency := time.Since(start)

	m.mu.Lock()
	if info, exists := m.peers[id]; exists {
		info.Online = true
		info.Latency = int(latency.Milliseconds())
		info.LastSeen = time.Now()
	}
	m.mu.Unlock()
}

// pingPeer sends a ping to a peer
func pingPeer(ctx context.Context, conn adnl.Peer) error {
	// TODO: Implement actual ping using protocol.Ping
	return nil
}

// Count returns the number of known peers
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.peers)
}

// OnlineCount returns the number of online peers
func (m *Manager) OnlineCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, p := range m.peers {
		if p.Online {
			count++
		}
	}
	return count
}
