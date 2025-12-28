package peer

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseAddress parses a peer address in format: pubkey_hex@ip:port
// Example: abc123def456...@192.168.1.100:9001
// Returns: "ip:port", pubkey, error
func ParseAddress(addr string) (string, ed25519.PublicKey, error) {
	parts := strings.SplitN(addr, "@", 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("invalid address format, expected pubkey@ip:port: %s", addr)
	}

	pubKeyHex := parts[0]
	ipPort := parts[1]

	// Decode public key (64 hex chars = 32 bytes)
	if len(pubKeyHex) != 64 {
		return "", nil, fmt.Errorf("invalid pubkey length, expected 64 hex chars: %d", len(pubKeyHex))
	}

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", nil, fmt.Errorf("invalid pubkey hex: %w", err)
	}

	// Validate ip:port format
	if !strings.Contains(ipPort, ":") {
		return "", nil, fmt.Errorf("invalid ip:port format: %s", ipPort)
	}

	return ipPort, ed25519.PublicKey(pubKeyBytes), nil
}

// FormatAddress formats a peer address from components
// Returns: pubkey_hex@ip:port
func FormatAddress(pubKey ed25519.PublicKey, ip string, port int) string {
	return fmt.Sprintf("%s@%s:%d", hex.EncodeToString(pubKey), ip, port)
}

// FormatAddressFromInfo formats a peer address from Info struct
func FormatAddressFromInfo(info *Info) string {
	if len(info.Addresses) == 0 {
		return ""
	}
	addr := info.Addresses[0]
	return FormatAddress(info.ADNLID, addr.IP, addr.Port)
}
