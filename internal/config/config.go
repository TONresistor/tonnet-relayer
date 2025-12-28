package config

// Config represents the relay configuration
type Config struct {
	Node    NodeConfig    `json:"node"`
	Keys    KeysConfig    `json:"keys"`
	Peers   PeersConfig   `json:"peers"`
	Relay   RelayConfig   `json:"relay"`
	Exit    ExitConfig    `json:"exit"`
	Metrics MetricsConfig `json:"metrics"`
	Logging LoggingConfig `json:"logging"`
}

// ExitConfig contains exit node settings
type ExitConfig struct {
	Enabled          bool   `json:"enabled"`
	GlobalConfigPath string `json:"global_config_path"` // Path to TON global config (mainnet.json)
}

// NodeConfig contains node settings
type NodeConfig struct {
	Name               string `json:"name"`
	ListenAddr         string `json:"listen_addr"`
	Port               int    `json:"port"`
	UDPPort            int    `json:"udp_port"`            // UDP port for tunnel packets (default: 9002)
	MaxConnections     int    `json:"max_connections"`
	MaxCircuitsPerPeer int    `json:"max_circuits_per_peer"`
}

// KeysConfig contains key paths
type KeysConfig struct {
	PrivateKeyPath string `json:"private_key_path"`
}

// PeersConfig contains peer settings
type PeersConfig struct {
	File                string   `json:"file"`
	Bootstrap           []string `json:"bootstrap"`
	MaxPeers            int      `json:"max_peers"`
	HealthCheckInterval int      `json:"health_check_interval"`
}

// RelayConfig contains relay settings
type RelayConfig struct {
	Enabled         bool `json:"enabled"`
	MaxBandwidthMbps int  `json:"max_bandwidth_mbps"`
	CircuitTimeout  int  `json:"circuit_timeout"`
	ForwardTimeout  int  `json:"forward_timeout"`
}

// MetricsConfig contains metrics settings
type MetricsConfig struct {
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port"`
	Path    string `json:"path"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
	File   string `json:"file"`
}
