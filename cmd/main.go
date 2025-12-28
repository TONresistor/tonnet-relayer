package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/TONresistor/tonnet-relay/internal/config"
	"github.com/TONresistor/tonnet-relay/internal/relay"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var version = "dev"

const banner = `
▗▄▄▄▖▗▄▖ ▗▖  ▗▖▗▖  ▗▖▗▄▄▄▖▗▄▄▄▖    ▗▄▄▖ ▗▄▄▄▖▗▖    ▗▄▖▗▖  ▗▖▗▄▄▄▖▗▄▄▖
  █ ▐▌ ▐▌▐▛▚▖▐▌▐▛▚▖▐▌▐▌     █      ▐▌ ▐▌▐▌   ▐▌   ▐▌ ▐▌▝▚▞▘ ▐▌   ▐▌ ▐▌
  █ ▐▌ ▐▌▐▌ ▝▜▌▐▌ ▝▜▌▐▛▀▀▘  █      ▐▛▀▚▖▐▛▀▀▘▐▌   ▐▛▀▜▌ ▐▌  ▐▛▀▀▘▐▛▀▚▖
  █ ▝▚▄▞▘▐▌  ▐▌▐▌  ▐▌▐▙▄▄▖  █      ▐▌ ▐▌▐▙▄▄▖▐▙▄▄▖▐▌ ▐▌ ▐▌  ▐▙▄▄▖▐▌ ▐▌

              Onion Routing Node for TON Blockchain
`

var (
	cfgFile   string
	logLevel  string
	configDir string
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "tonnet-relay",
	Short: "Tonnet relay node",
	Long:  "Relay node for the Tonnet network. Provides garlic routing for privacy.",
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new relay node",
	RunE:  runInit,
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the relay server",
	RunE:  runStart,
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the relay server",
	RunE:  runStop,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show relay status",
	RunE:  runStatus,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("tonnet-relay %s\n", version)
	},
}

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show node info (pubkey, address)",
	RunE:  runInfo,
}

var peersCmd = &cobra.Command{
	Use:   "peers",
	Short: "Manage peers",
}

var peersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List known peers",
	RunE:  runPeersList,
}

var peersAddCmd = &cobra.Command{
	Use:   "add [adnl://id@ip:port]",
	Short: "Add a peer",
	Args:  cobra.ExactArgs(1),
	RunE:  runPeersAdd,
}

var peersRemoveCmd = &cobra.Command{
	Use:   "remove [adnl-id]",
	Short: "Remove a peer",
	Args:  cobra.ExactArgs(1),
	RunE:  runPeersRemove,
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	RunE:  runConfigShow,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path")
	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", "", "config directory (default ~/.tonnet-relay)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level: debug|info|warn|error")

	startCmd.Flags().Int("port", 9001, "listen port")
	startCmd.Flags().Int("max-peers", 100, "max peer connections")
	startCmd.Flags().Bool("metrics", true, "enable Prometheus metrics")
	startCmd.Flags().Int("metrics-port", 9090, "metrics port")
	startCmd.Flags().Bool("daemon", false, "run as daemon")
	startCmd.Flags().Bool("exit", false, "enable exit node for TON sites")
	startCmd.Flags().String("global-config", "", "path to TON global config (mainnet.json)")

	peersCmd.AddCommand(peersListCmd, peersAddCmd, peersRemoveCmd)
	configCmd.AddCommand(configShowCmd)

	rootCmd.AddCommand(initCmd, startCmd, stopCmd, statusCmd, versionCmd, infoCmd, peersCmd, configCmd)
}

func getConfigDir() string {
	if configDir != "" {
		return configDir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".tonnet-relay"
	}
	return filepath.Join(home, ".tonnet-relay")
}

func runInit(cmd *cobra.Command, args []string) error {
	dir := getConfigDir()

	fmt.Printf("Initializing relay node in %s\n", dir)

	if err := config.Initialize(dir); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}

	fmt.Println("Relay node initialized.")
	fmt.Printf("  Config:      %s/config.json\n", dir)
	fmt.Printf("  Private key: %s/keys/relay.key\n", dir)
	fmt.Printf("  Peers:       %s/peers.json\n", dir)
	fmt.Println("\nRun 'tonnet-relay start' to start the relay.")

	return nil
}

func runStart(cmd *cobra.Command, args []string) error {
	fmt.Println(banner)
	fmt.Printf("  Version: %s\n\n", version)

	logger, err := createLogger()
	if err != nil {
		return err
	}
	defer logger.Sync()

	dir := getConfigDir()
	cfgPath := cfgFile
	if cfgPath == "" {
		cfgPath = filepath.Join(dir, "config.json")
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Override with flags
	if port, _ := cmd.Flags().GetInt("port"); port != 0 {
		cfg.Node.Port = port
	}
	if maxPeers, _ := cmd.Flags().GetInt("max-peers"); maxPeers != 0 {
		cfg.Node.MaxConnections = maxPeers
	}
	if metrics, _ := cmd.Flags().GetBool("metrics"); !metrics {
		cfg.Metrics.Enabled = false
	}
	if metricsPort, _ := cmd.Flags().GetInt("metrics-port"); metricsPort != 0 {
		cfg.Metrics.Port = metricsPort
	}

	server, err := relay.NewServer(cfg, logger)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	// Setup exit node if enabled
	exitEnabled, _ := cmd.Flags().GetBool("exit")
	globalConfigPath, _ := cmd.Flags().GetString("global-config")

	if exitEnabled || cfg.Exit.Enabled {
		// Determine global config path
		cfgPath := globalConfigPath
		if cfgPath == "" {
			cfgPath = cfg.Exit.GlobalConfigPath
		}
		if cfgPath == "" {
			cfgPath = filepath.Join(getConfigDir(), "global-config.json")
		}

		if err := server.SetupExitNode(cfgPath); err != nil {
			return fmt.Errorf("failed to setup exit node: %w", err)
		}
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("shutting down...")
	return server.Stop()
}

func runStop(cmd *cobra.Command, args []string) error {
	dir := getConfigDir()
	pidFile := filepath.Join(dir, "relay.pid")

	data, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("relay not running or pid file not found")
	}

	var pid int
	if _, err := fmt.Sscanf(string(data), "%d", &pid); err != nil {
		return fmt.Errorf("invalid pid file")
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("process not found: %w", err)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to stop relay: %w", err)
	}

	fmt.Println("Relay stopped.")
	return nil
}

func runStatus(cmd *cobra.Command, args []string) error {
	dir := getConfigDir()
	statusFile := filepath.Join(dir, "status.json")

	data, err := os.ReadFile(statusFile)
	if err != nil {
		fmt.Println("Relay status: not running")
		return nil
	}

	fmt.Println(string(data))
	return nil
}

func runPeersList(cmd *cobra.Command, args []string) error {
	dir := getConfigDir()
	peersFile := filepath.Join(dir, "peers.json")

	data, err := os.ReadFile(peersFile)
	if err != nil {
		fmt.Println("No peers configured.")
		return nil
	}

	fmt.Println(string(data))
	return nil
}

func runPeersAdd(cmd *cobra.Command, args []string) error {
	// TODO: Parse ADNL URL and add to peers.json
	fmt.Printf("Adding peer: %s\n", args[0])
	return nil
}

func runPeersRemove(cmd *cobra.Command, args []string) error {
	// TODO: Remove from peers.json
	fmt.Printf("Removing peer: %s\n", args[0])
	return nil
}

func runConfigShow(cmd *cobra.Command, args []string) error {
	dir := getConfigDir()
	cfgPath := cfgFile
	if cfgPath == "" {
		cfgPath = filepath.Join(dir, "config.json")
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("config not found: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func runInfo(cmd *cobra.Command, args []string) error {
	dir := getConfigDir()
	cfgPath := cfgFile
	if cfgPath == "" {
		cfgPath = filepath.Join(dir, "config.json")
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("config not found: %w", err)
	}

	// Load private key and derive public key
	privKey, err := config.LoadKey(cfg.Keys.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load key: %w", err)
	}
	pubKey := privKey.Public().(ed25519.PublicKey)
	pubKeyHex := hex.EncodeToString(pubKey)

	// Get external IP
	externalIP := cfg.Node.ListenAddr
	if externalIP == "0.0.0.0" || externalIP == "" {
		// Try to detect external IP
		if ip := getOutboundIP(); ip != "" {
			externalIP = ip
		} else {
			externalIP = "<your-ip>"
		}
	}

	fmt.Println("Tonnet Relay Info")
	fmt.Println("=================")
	fmt.Printf("Version:  %s\n", version)
	fmt.Printf("Port:     %d\n", cfg.Node.Port)
	fmt.Printf("PubKey:   %s\n", pubKeyHex)
	fmt.Println()
	fmt.Println("Connection address (for other relays):")
	fmt.Printf("  %s@%s:%d\n", pubKeyHex, externalIP, cfg.Node.Port)

	return nil
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func createLogger() (*zap.Logger, error) {
	var cfg zap.Config

	switch logLevel {
	case "debug":
		cfg = zap.NewDevelopmentConfig()
	default:
		cfg = zap.NewProductionConfig()
	}

	switch logLevel {
	case "debug":
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "warn":
		cfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		cfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	return cfg.Build()
}
