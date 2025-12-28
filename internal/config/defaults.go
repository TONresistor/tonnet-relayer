package config

// Default returns the default configuration
func Default() *Config {
	return &Config{
		Node: NodeConfig{
			Name:               "tonnet-relay",
			ListenAddr:         "0.0.0.0",
			Port:               9001,
			UDPPort:            9002, // Default UDP port for tunnel packets
			MaxConnections:     100,
			MaxCircuitsPerPeer: 10,
		},
		Keys: KeysConfig{
			PrivateKeyPath: "./keys/relay.key",
		},
		Peers: PeersConfig{
			File:                "./peers.json",
			Bootstrap:           []string{},
			MaxPeers:            50,
			HealthCheckInterval: 30,
		},
		Relay: RelayConfig{
			Enabled:         true,
			MaxBandwidthMbps: 100,
			CircuitTimeout:  300,
			ForwardTimeout:  10,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Port:    9090,
			Path:    "/metrics",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			File:   "./logs/relay.log",
		},
	}
}
