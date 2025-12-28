package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/TONresistor/tonnet-relay/internal/config"
	"github.com/TONresistor/tonnet-relay/internal/exit"
	"github.com/TONresistor/tonnet-relay/internal/metrics"
	"github.com/TONresistor/tonnet-relay/internal/peer"
	"github.com/TONresistor/tonnet-relay/internal/protocol"
	"github.com/TONresistor/tonnet-relay/internal/tunnel"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/tl"
	"go.uber.org/zap"
)

// Server is the main relay server
type Server struct {
	config  *config.Config
	gateway *adnl.Gateway
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey

	engine    *Engine
	peers     *peer.Manager
	metrics   *metrics.Collector
	proxyNode *tunnel.ProxyNode // UDP tunnel proxy node
	udpConn   net.PacketConn    // UDP listener for tunnel packets

	logger *zap.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewServer creates a new relay server
func NewServer(cfg *config.Config, logger *zap.Logger) (*Server, error) {
	privKey, err := config.LoadKey(cfg.Keys.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		config:  cfg,
		privKey: privKey,
		pubKey:  privKey.Public().(ed25519.PublicKey),
		logger:  logger,
		ctx:     ctx,
		cancel:  cancel,
	}

	// Initialize tunnel keyring and proxy node
	keyring := tunnel.NewKeyring()
	keyring.AddKey(privKey)
	s.proxyNode = tunnel.NewProxyNode(keyring)
	s.proxyNode.SetLogger(logger)

	s.engine = NewEngine(s)
	s.peers = peer.NewManager(&cfg.Peers, logger)
	s.metrics = metrics.NewCollector()

	return s, nil
}

// SetupExitNode configures the server as an exit node for TON sites
func (s *Server) SetupExitNode(globalCfgPath string) error {
	exitNode, err := exit.NewExitNode(s.privKey, globalCfgPath, s.logger)
	if err != nil {
		return fmt.Errorf("create exit node: %w", err)
	}

	// Set UDP sender callback so exit node can send responses back through tunnel
	exitNode.SetUDPSender(func(addr *net.UDPAddr, data []byte) error {
		if s.udpConn == nil {
			return fmt.Errorf("UDP connection not available")
		}
		_, err := s.udpConn.WriteTo(data, addr)
		return err
	})

	s.engine.SetExitNode(exitNode)
	s.logger.Info("exit node enabled for TON sites")
	return nil
}

// Start starts the relay server
func (s *Server) Start() error {
	s.gateway = adnl.NewGateway(s.privKey)

	listenAddr := fmt.Sprintf("%s:%d", s.config.Node.ListenAddr, s.config.Node.Port)

	// Start server mode (handles both incoming and outgoing connections)
	if err := s.gateway.StartServer(listenAddr); err != nil {
		return fmt.Errorf("failed to start ADNL server: %w", err)
	}

	s.gateway.SetConnectionHandler(s.handleConnection)

	s.logger.Info("relay server started",
		zap.String("addr", listenAddr),
		zap.String("adnl_id", hex.EncodeToString(s.pubKey)),
	)

	// Start UDP listener for tunnel packets
	if err := s.startUDPListener(); err != nil {
		s.logger.Warn("failed to start UDP tunnel listener", zap.Error(err))
	}

	// Start background tasks
	s.wg.Add(1)
	go s.runHealthCheck()

	if s.config.Metrics.Enabled {
		s.wg.Add(1)
		go s.runMetricsServer()
	}

	// Load peers from file
	if err := s.peers.LoadFromFile(); err != nil {
		s.logger.Warn("failed to load peers", zap.Error(err))
	}

	// Connect to bootstrap peers
	for _, addr := range s.config.Peers.Bootstrap {
		go s.connectToPeer(addr)
	}

	return nil
}

// Stop stops the relay server
func (s *Server) Stop() error {
	s.logger.Info("stopping relay server")
	s.cancel()

	if s.gateway != nil {
		s.gateway.Close()
	}

	// Close UDP listener
	if s.udpConn != nil {
		s.udpConn.Close()
	}

	// Close proxy node
	if s.proxyNode != nil {
		s.proxyNode.Close()
	}

	s.wg.Wait()

	// Save peers
	if err := s.peers.SaveToFile(); err != nil {
		s.logger.Warn("failed to save peers", zap.Error(err))
	}

	return nil
}

// startUDPListener starts the UDP listener for tunnel packets
func (s *Server) startUDPListener() error {
	udpPort := s.config.Node.UDPPort
	if udpPort == 0 {
		udpPort = 9002 // Default UDP port
	}

	udpAddr := fmt.Sprintf("%s:%d", s.config.Node.ListenAddr, udpPort)

	conn, err := net.ListenPacket("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", udpAddr, err)
	}

	s.udpConn = conn
	s.proxyNode.SetConnection(conn)

	s.logger.Info("UDP tunnel listener started",
		zap.String("addr", udpAddr),
	)

	// Start UDP receive loop
	s.wg.Add(1)
	go s.runUDPReceiver()

	return nil
}

// runUDPReceiver handles incoming UDP tunnel packets
func (s *Server) runUDPReceiver() {
	defer s.wg.Done()

	buf := make([]byte, 65536)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Set read deadline to allow periodic context checks
		s.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, srcAddr, err := s.udpConn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Just a timeout, check context and retry
			}
			if s.ctx.Err() != nil {
				return // Context cancelled, exit gracefully
			}
			s.logger.Debug("UDP read error", zap.Error(err))
			continue
		}

		// Copy data for async processing
		data := make([]byte, n)
		copy(data, buf[:n])

		// Process packet asynchronously
		go s.handleUDPPacket(data, srcAddr)
	}
}

// handleUDPPacket processes an incoming UDP tunnel packet
func (s *Server) handleUDPPacket(data []byte, srcAddr net.Addr) {
	s.metrics.AddBytesReceived(uint64(len(data)))

	// Check if this is a control packet (ping/pong/register)
	if tunnel.IsControlPacket(data) {
		if err := s.handleTunnelControlPacket(data, srcAddr); err != nil {
			s.logger.Debug("failed to handle control packet",
				zap.Error(err),
				zap.String("src", srcAddr.String()))
		}
		return
	}

	// Check if this is a relay protocol packet (CircuitCreate/CircuitCreated)
	// These come wrapped in TunnelPacketContents
	if s.handleRelayProtocolPacket(data, srcAddr) {
		return
	}

	// Route to proxy node for decryption and forwarding
	if err := s.proxyNode.ReceivePacket(data, srcAddr); err != nil {
		s.logger.Debug("failed to handle tunnel packet",
			zap.Error(err),
			zap.String("src", srcAddr.String()))
	}
}

// handleRelayProtocolPacket checks if the UDP packet contains a relay protocol message
// (CircuitCreate or CircuitCreated) and handles it appropriately.
// Returns true if the packet was handled as a relay protocol message.
func (s *Server) handleRelayProtocolPacket(data []byte, srcAddr net.Addr) bool {
	// Try to parse as TunnelPacketContents
	var tunnelPacket tunnel.TunnelPacketContents
	if err := tunnelPacket.Parse(data); err != nil {
		// Not a TunnelPacketContents, might be raw encrypted data
		return false
	}

	// Check if it has a message payload
	if tunnelPacket.Flags&tunnel.FlagHasMessage == 0 || len(tunnelPacket.Message) < 4 {
		return false
	}

	message := tunnelPacket.Message

	// Try to parse as CircuitCreate (incoming request from another relay)
	var circuitCreate protocol.CircuitCreate
	if _, err := tl.Parse(&circuitCreate, message, true); err == nil {
		s.logger.Info("received CircuitCreate via UDP",
			zap.String("circuit_id", hex.EncodeToString(circuitCreate.CircuitID)[:16]),
			zap.String("src", srcAddr.String()))

		// Handle the CircuitCreate and send response
		s.handleUDPCircuitCreate(&circuitCreate, srcAddr)
		return true
	}

	// Try to parse as CircuitCreated (response to our extend request)
	var circuitCreated protocol.CircuitCreated
	if _, err := tl.Parse(&circuitCreated, message, true); err == nil {
		s.logger.Info("received CircuitCreated via UDP",
			zap.String("circuit_id", hex.EncodeToString(circuitCreated.CircuitID)[:16]),
			zap.String("src", srcAddr.String()))

		// Route to pending extend handler
		s.handleUDPCircuitCreated(&circuitCreated, srcAddr)
		return true
	}

	// Try to parse as CircuitExtend (relayed from previous hop)
	var circuitExtend protocol.CircuitExtend
	if _, err := tl.Parse(&circuitExtend, message, true); err == nil {
		s.logger.Info("received CircuitExtend via UDP",
			zap.String("circuit_id", hex.EncodeToString(circuitExtend.CircuitID)[:16]),
			zap.String("src", srcAddr.String()))

		// Handle the extend and send response
		s.handleUDPCircuitExtend(&circuitExtend, srcAddr)
		return true
	}

	// Try to parse as Data (forwarded data through circuit)
	var dataMsg protocol.Data
	if _, err := tl.Parse(&dataMsg, message, true); err == nil {
		s.logger.Debug("received Data via UDP",
			zap.String("circuit_id", hex.EncodeToString(dataMsg.CircuitID)[:16]),
			zap.Int("stream_id", dataMsg.StreamID),
			zap.String("src", srcAddr.String()))

		// Handle via engine (will decrypt and forward or process at exit)
		if err := s.engine.handleDataFromUDP(&dataMsg, srcAddr); err != nil {
			s.logger.Error("failed to handle UDP data",
				zap.Error(err),
				zap.String("circuit_id", hex.EncodeToString(dataMsg.CircuitID)[:16]))
		}
		return true
	}

	// Try to parse as DataChunk (chunked response for large data)
	var chunkMsg protocol.DataChunk
	if _, err := tl.Parse(&chunkMsg, message, true); err == nil {
		s.logger.Debug("received DataChunk via UDP",
			zap.String("circuit_id", hex.EncodeToString(chunkMsg.CircuitID)[:16]),
			zap.Int("stream_id", chunkMsg.StreamID),
			zap.Int("chunk", chunkMsg.ChunkIndex+1),
			zap.Int("total", chunkMsg.TotalChunks),
			zap.String("src", srcAddr.String()))

		// Handle via engine (forward as-is, don't decrypt)
		if err := s.engine.handleDataChunkFromUDP(&chunkMsg, srcAddr); err != nil {
			s.logger.Error("failed to handle UDP chunk",
				zap.Error(err),
				zap.String("circuit_id", hex.EncodeToString(chunkMsg.CircuitID)[:16]))
		}
		return true
	}

	return false
}

// handleUDPCircuitCreate handles a CircuitCreate request received via UDP
// and sends the CircuitCreated response back via UDP
func (s *Server) handleUDPCircuitCreate(req *protocol.CircuitCreate, srcAddr net.Addr) {
	// Check if circuit already exists (idempotency)
	if existing, ok := s.engine.circuits.Load(string(req.CircuitID)); ok {
		circuit := existing.(*Circuit)
		s.logger.Info("circuit already exists (UDP), returning cached response",
			zap.String("circuit_id", hex.EncodeToString(req.CircuitID)[:16]),
		)
		s.sendUDPCircuitCreated(req.CircuitID, circuit.RelayPub, hashKey(circuit.SharedKey), srcAddr)
		return
	}

	// Generate ephemeral keypair for this circuit
	relayPriv, relayPub := generateX25519Keypair()

	// Compute shared secret with client
	sharedKey := computeSharedKey(relayPriv, req.ClientKey)

	// Create circuit - for UDP-based circuits, PrevHop is nil but we track the source address
	circuit := &Circuit{
		ID:        req.CircuitID,
		CreatedAt: time.Now(),
		SharedKey: sharedKey,
		RelayPub:  relayPub,
		PrevHop:   nil, // No ADNL peer for UDP-based circuits
	}

	// Store the source UDP address for sending responses back
	if udpAddr, ok := srcAddr.(*net.UDPAddr); ok {
		circuit.PrevHopUDPAddr = udpAddr
		s.logger.Debug("storing prev hop UDP addr", zap.String("addr", udpAddr.String()))
	}

	s.engine.circuits.Store(string(req.CircuitID), circuit)
	s.metrics.IncrCircuits()

	s.logger.Info("circuit created (UDP), sending response",
		zap.String("circuit_id", hex.EncodeToString(req.CircuitID)[:16]),
		zap.String("relay_key", hex.EncodeToString(relayPub)[:16]),
	)

	// Send response via UDP
	s.sendUDPCircuitCreated(req.CircuitID, relayPub, hashKey(sharedKey), srcAddr)
}

// sendUDPCircuitCreated sends a CircuitCreated response via UDP
func (s *Server) sendUDPCircuitCreated(circuitID, relayKey, keyHash []byte, destAddr net.Addr) {
	resp := &protocol.CircuitCreated{
		CircuitID: circuitID,
		RelayKey:  relayKey,
		KeyHash:   keyHash,
	}

	// Serialize the response
	tlData, err := tl.Serialize(resp, true)
	if err != nil {
		s.logger.Error("failed to serialize CircuitCreated", zap.Error(err))
		return
	}

	// Wrap in TunnelPacketContents
	tunnelPacket := tunnel.NewTunnelPacket(tlData, nil)
	packetData, err := tunnelPacket.Serialize()
	if err != nil {
		s.logger.Error("failed to serialize tunnel packet", zap.Error(err))
		return
	}

	// Send via UDP
	if s.udpConn != nil {
		_, err = s.udpConn.WriteTo(packetData, destAddr)
		if err != nil {
			s.logger.Error("failed to send CircuitCreated via UDP",
				zap.Error(err),
				zap.String("dest", destAddr.String()))
		} else {
			s.logger.Debug("sent CircuitCreated via UDP",
				zap.String("circuit_id", hex.EncodeToString(circuitID)[:16]),
				zap.String("dest", destAddr.String()))
		}
	}
}

// handleUDPCircuitCreated routes a CircuitCreated response to the pending extend handler
func (s *Server) handleUDPCircuitCreated(resp *protocol.CircuitCreated, srcAddr net.Addr) {
	circuitID := string(resp.CircuitID)
	pendingI, ok := s.engine.pendingExtends.Load(circuitID)
	if !ok {
		s.logger.Debug("received CircuitCreated via UDP for unknown circuit",
			zap.String("circuit_id", hex.EncodeToString(resp.CircuitID)[:16]),
			zap.String("src", srcAddr.String()))
		return
	}

	pending := pendingI.(*pendingExtend)

	// Verify the response is from the expected relay (optional security check)
	if pending.nextRelayAddr != nil {
		expectedAddr := pending.nextRelayAddr.String()
		actualAddr := srcAddr.String()
		if expectedAddr != actualAddr {
			s.logger.Warn("CircuitCreated from unexpected source",
				zap.String("expected", expectedAddr),
				zap.String("actual", actualAddr))
			// Continue anyway - NAT might change the port
		}
	}

	s.logger.Info("routing CircuitCreated to pending extend handler",
		zap.String("circuit_id", hex.EncodeToString(resp.CircuitID)[:16]),
		zap.String("relay_key", hex.EncodeToString(resp.RelayKey)[:16]),
	)

	// Send response to waiting goroutine
	select {
	case pending.responseChan <- resp:
		// Response delivered
	default:
		s.logger.Warn("response channel full or closed for UDP CircuitCreated")
	}
}

// handleUDPCircuitExtend handles a CircuitExtend received via UDP (relayed from prev hop)
// This processes the extend and sends CircuitCreated response back
func (s *Server) handleUDPCircuitExtend(req *protocol.CircuitExtend, srcAddr net.Addr) {
	// 1. Look up the circuit
	circuitI, ok := s.engine.circuits.Load(string(req.CircuitID))
	if !ok {
		s.logger.Warn("circuit not found for UDP extend",
			zap.String("circuit_id", hex.EncodeToString(req.CircuitID)[:16]),
		)
		return
	}
	circuit := circuitI.(*Circuit)

	// 2. Decrypt the extend payload with circuit's shared key
	decrypted, err := decryptPayload(req.Encrypted, circuit.SharedKey)
	if err != nil {
		s.logger.Error("failed to decrypt extend payload (UDP)",
			zap.Error(err),
			zap.String("circuit_id", hex.EncodeToString(req.CircuitID)[:16]),
		)
		return
	}

	// 3. Parse the extend payload (format: addr_len(2) + addr + client_key(32))
	if len(decrypted) < 34 {
		s.logger.Error("extend payload too short",
			zap.Int("len", len(decrypted)),
		)
		return
	}

	addrLen := int(decrypted[0])<<8 | int(decrypted[1])
	if len(decrypted) < 2+addrLen+32 {
		s.logger.Error("extend payload invalid length",
			zap.Int("addr_len", addrLen),
			zap.Int("total_len", len(decrypted)),
		)
		return
	}

	nextAddr := string(decrypted[2 : 2+addrLen])
	clientKey := decrypted[2+addrLen : 2+addrLen+32]

	s.logger.Info("UDP extend - decrypted payload",
		zap.String("circuit_id", hex.EncodeToString(req.CircuitID)[:16]),
		zap.String("next_addr", nextAddr),
		zap.String("client_key", hex.EncodeToString(clientKey)[:16]),
	)

	// 4. Convert next address to UDP address
	nextUDPAddr, err := parseToUDPAddr(nextAddr)
	if err != nil {
		s.logger.Error("failed to parse next relay address",
			zap.Error(err),
			zap.String("next_addr", nextAddr),
		)
		return
	}

	// 5. Send CircuitCreate to next relay via UDP
	circuitCreate := &protocol.CircuitCreate{
		CircuitID: req.CircuitID, // Use same circuit ID
		ClientKey: clientKey,
	}

	createBytes, err := tl.Serialize(circuitCreate, true)
	if err != nil {
		s.logger.Error("failed to serialize CircuitCreate", zap.Error(err))
		return
	}

	packet := tunnel.NewTunnelPacket(createBytes, nil)
	packetBytes, err := packet.Serialize()
	if err != nil {
		s.logger.Error("failed to wrap CircuitCreate", zap.Error(err))
		return
	}

	// Create response channel - use full CircuitID as key
	responseChan := make(chan *protocol.CircuitCreated, 1)
	circuitIDKey := string(req.CircuitID)

	s.engine.pendingExtends.Store(circuitIDKey, &pendingExtend{
		responseChan:  responseChan,
		nextRelayAddr: nextUDPAddr,
		createdAt:     time.Now(),
	})
	defer s.engine.pendingExtends.Delete(circuitIDKey)

	// Send via UDP
	_, err = s.udpConn.WriteTo(packetBytes, nextUDPAddr)
	if err != nil {
		s.logger.Error("failed to send CircuitCreate to next relay (UDP extend)",
			zap.Error(err),
			zap.String("dest", nextUDPAddr.String()),
		)
		return
	}

	s.logger.Info("UDP extend - sent CircuitCreate to next relay, waiting for response",
		zap.String("circuit_id", hex.EncodeToString(req.CircuitID)[:16]),
		zap.String("dest", nextUDPAddr.String()),
	)

	// 6. Wait for response
	select {
	case createResp := <-responseChan:
		// Store the next hop address in the circuit
		circuit.NextHopUDPAddr = nextUDPAddr

		s.logger.Info("UDP extend - received CircuitCreated, sending response back",
			zap.String("circuit_id", hex.EncodeToString(req.CircuitID)[:16]),
			zap.String("relay_key", hex.EncodeToString(createResp.RelayKey)[:16]),
		)

		// Send CircuitCreated back to the source (prev relay)
		s.sendUDPCircuitCreated(req.CircuitID, createResp.RelayKey, createResp.KeyHash, srcAddr)

	case <-time.After(10 * time.Second):
		s.logger.Error("timeout waiting for CircuitCreated from next relay (UDP extend)",
			zap.String("circuit_id", hex.EncodeToString(req.CircuitID)[:16]),
		)
	}
}

// handleTunnelControlPacket handles tunnel control packets (ping/pong/register)
func (s *Server) handleTunnelControlPacket(data []byte, srcAddr net.Addr) error {
	packet, err := tunnel.ParseControlPacket(data)
	if err != nil {
		return err
	}

	switch p := packet.(type) {
	case *tunnel.ControlPacketPing:
		// Respond with pong
		pong := &tunnel.ControlPacketPong{ID: p.ID}
		_, err := s.udpConn.WriteTo(pong.Serialize(), srcAddr)
		return err

	case *tunnel.ControlPacketPong:
		// Record pong response (could be used for latency tracking)
		s.logger.Debug("received pong",
			zap.String("src", srcAddr.String()))
		return nil

	case *tunnel.ControlPacketRegister:
		// Client registering its address
		s.logger.Debug("received register",
			zap.String("src", srcAddr.String()),
			zap.Int32("ip", p.IP),
			zap.Int32("port", p.Port))
		return nil
	}

	return nil
}

// handleConnection handles new ADNL connections
func (s *Server) handleConnection(client adnl.Peer) error {
	peerID := client.GetID()
	s.logger.Debug("new connection", zap.String("peer", hex.EncodeToString(peerID)))

	s.metrics.IncrConnections()

	// Store incoming connection in PeerManager for reuse
	// This is critical for bidirectional communication - we want to use the same
	// peer object for both incoming queries and outgoing queries to avoid
	// creating duplicate connections that cause response routing issues
	s.peers.SetConnection(peerID, client)
	s.logger.Info("stored incoming connection",
		zap.String("peer_id", hex.EncodeToString(peerID)[:16]+"..."))

	// Register handlers
	client.SetQueryHandler(func(msg *adnl.MessageQuery) error {
		return s.engine.HandleQuery(client, msg)
	})

	client.SetCustomMessageHandler(func(msg *adnl.MessageCustom) error {
		return s.engine.HandleMessage(client, msg)
	})

	client.SetDisconnectHandler(func(addr string, key ed25519.PublicKey) {
		s.metrics.DecrConnections()
		s.peers.RemoveConnection(key)
		s.engine.HandleDisconnect(key)
		s.logger.Debug("peer disconnected", zap.String("addr", addr))
	})

	return nil
}

// connectToPeer connects to a peer by ADNL address
// Format: pubkey_hex@ip:port (e.g., abc123...@192.168.1.100:9001)
func (s *Server) connectToPeer(addr string) error {
	s.logger.Debug("connecting to peer", zap.String("addr", addr))

	// Parse address
	peerAddr, pubKey, err := peer.ParseAddress(addr)
	if err != nil {
		s.logger.Error("failed to parse peer address", zap.Error(err), zap.String("addr", addr))
		return err
	}

	// Connect via ADNL gateway
	p, err := s.gateway.RegisterClient(peerAddr, pubKey)
	if err != nil {
		s.logger.Error("failed to connect to peer", zap.Error(err), zap.String("addr", peerAddr))
		return err
	}

	// Set handlers for this outgoing connection
	p.SetQueryHandler(func(msg *adnl.MessageQuery) error {
		return s.engine.HandleQuery(p, msg)
	})

	p.SetCustomMessageHandler(func(msg *adnl.MessageCustom) error {
		return s.engine.HandleMessage(p, msg)
	})

	p.SetDisconnectHandler(func(addr string, key ed25519.PublicKey) {
		s.metrics.DecrConnections()
		s.peers.RemoveConnection(key)
		s.logger.Debug("peer disconnected", zap.String("addr", addr))
	})

	// Store connection
	s.peers.SetConnection(pubKey, p)
	s.metrics.IncrConnections()

	s.logger.Info("connected to peer",
		zap.String("addr", peerAddr),
		zap.String("pubkey", hex.EncodeToString(pubKey)[:16]+"..."),
	)

	return nil
}

// ConnectToPeer is the public method to connect to a peer
func (s *Server) ConnectToPeer(addr string) error {
	return s.connectToPeer(addr)
}

// GetGateway returns the ADNL gateway
func (s *Server) GetGateway() *adnl.Gateway {
	return s.gateway
}

// runHealthCheck runs periodic health checks on peers
func (s *Server) runHealthCheck() {
	defer s.wg.Done()

	interval := time.Duration(s.config.Peers.HealthCheckInterval) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.peers.HealthCheck(s.ctx)
		}
	}
}

// runMetricsServer runs the Prometheus metrics HTTP server
func (s *Server) runMetricsServer() {
	defer s.wg.Done()

	addr := fmt.Sprintf(":%d", s.config.Metrics.Port)
	mux := http.NewServeMux()
	mux.Handle(s.config.Metrics.Path, s.metrics.Handler())

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		<-s.ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	s.logger.Info("metrics server started", zap.String("addr", addr))
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		s.logger.Error("metrics server error", zap.Error(err))
	}
}

// GetLogger returns the server logger
func (s *Server) GetLogger() *zap.Logger {
	return s.logger
}

// GetMetrics returns the metrics collector
func (s *Server) GetMetrics() *metrics.Collector {
	return s.metrics
}

// GetProxyNode returns the tunnel proxy node
func (s *Server) GetProxyNode() *tunnel.ProxyNode {
	return s.proxyNode
}

// GetUDPConn returns the UDP connection for tunnel packets
func (s *Server) GetUDPConn() net.PacketConn {
	return s.udpConn
}
