package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Load reads configuration from a JSON file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	cfg := Default()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

// Save writes configuration to a JSON file
func Save(cfg *Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// Initialize creates the config directory and generates default files
func Initialize(dir string) error {
	// Create directories
	dirs := []string{
		dir,
		filepath.Join(dir, "keys"),
		filepath.Join(dir, "logs"),
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", d, err)
		}
	}

	// Generate private key
	keyPath := filepath.Join(dir, "keys", "relay.key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		if err := generateKey(keyPath); err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
		}
	}

	// Create default config
	cfgPath := filepath.Join(dir, "config.json")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		cfg := Default()
		cfg.Keys.PrivateKeyPath = keyPath
		cfg.Peers.File = filepath.Join(dir, "peers.json")
		cfg.Logging.File = filepath.Join(dir, "logs", "relay.log")

		if err := Save(cfg, cfgPath); err != nil {
			return err
		}
	}

	// Create empty peers file
	peersPath := filepath.Join(dir, "peers.json")
	if _, err := os.Stat(peersPath); os.IsNotExist(err) {
		emptyPeers := struct {
			Peers []interface{} `json:"peers"`
		}{Peers: []interface{}{}}

		data, _ := json.MarshalIndent(emptyPeers, "", "  ")
		if err := os.WriteFile(peersPath, data, 0644); err != nil {
			return fmt.Errorf("failed to create peers file: %w", err)
		}
	}

	return nil
}

// generateKey generates a new ed25519 private key and saves it
func generateKey(path string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	hexKey := hex.EncodeToString(priv.Seed())

	if err := os.WriteFile(path, []byte(hexKey), 0600); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	return nil
}

// LoadKey loads an ed25519 private key from a file
func LoadKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key: %w", err)
	}

	seed, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid key size: %d", len(seed))
	}

	return ed25519.NewKeyFromSeed(seed), nil
}
