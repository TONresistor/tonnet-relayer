package exit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/dht"
	rldphttp "github.com/xssnick/tonutils-go/adnl/rldp/http"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/dns"
	"go.uber.org/zap"

	"github.com/TONresistor/tonnet-relay/internal/protocol"
	"github.com/TONresistor/tonnet-relay/internal/tunnel"
)

// Circuit is an interface that represents the circuit information needed by the exit node.
// This interface is implemented by relay.Circuit to avoid import cycles.
type Circuit interface {
	// GetID returns the circuit ID
	GetID() []byte
	// GetSharedKey returns the shared key for this circuit
	GetSharedKey() []byte
	// GetPrevHop returns the ADNL peer of the previous hop (can be nil)
	GetPrevHop() adnl.Peer
	// GetPrevHopUDPAddr returns the UDP address of the previous hop (can be nil)
	GetPrevHopUDPAddr() *net.UDPAddr
	// GetTunnelKeyHash returns the tunnel key hash for this circuit
	GetTunnelKeyHash() [32]byte
}

// StreamState represents the state of a stream
type StreamState int

const (
	StreamStatePending StreamState = iota
	StreamStateConnected
	StreamStateClosed
	StreamStateError
)

// UDPSender is a callback function for sending UDP packets
type UDPSender func(addr *net.UDPAddr, data []byte) error

// ExitNode handles exit node functionality for TON site proxying
type ExitNode struct {
	httpClient *http.Client  // Uses rldphttp.Transport from tonutils-go
	gateway    *adnl.Gateway // Gateway for DHT (client mode)
	dnsClient  *dns.Client   // For domain validation
	logger     *zap.Logger

	// Active streams
	streams sync.Map // streamID -> *Stream

	// UDP sender callback (set by Server)
	udpSender UDPSender
}

// Stream represents an active stream to a TON site
type Stream struct {
	ID       int
	Host     string
	Port     int
	State    StreamState
	Circuit  Circuit
	Response chan []byte
}

// NewExitNode creates a new exit node using tonutils-go's battle-tested RLDP transport
// privKey is the relay's private key for ADNL connections
// globalCfgPath is the path to TON global config (e.g., mainnet.json)
func NewExitNode(privKey ed25519.PrivateKey, globalCfgPath string, logger *zap.Logger) (*ExitNode, error) {
	// Load global config
	globalCfg, err := liteclient.GetConfigFromFile(globalCfgPath)
	if err != nil {
		return nil, fmt.Errorf("load global config from %s: %w", globalCfgPath, err)
	}

	// 1. Create ADNL gateway in CLIENT mode for DHT
	gateway := adnl.NewGateway(privKey)
	if err := gateway.StartClient(); err != nil {
		return nil, fmt.Errorf("start ADNL gateway: %w", err)
	}

	// 2. Initialize DHT client
	dhtClient, err := dht.NewClientFromConfig(gateway, globalCfg)
	if err != nil {
		gateway.Close()
		return nil, fmt.Errorf("init DHT: %w", err)
	}

	// 3. Initialize Liteserver connection pool for DNS
	pool := liteclient.NewConnectionPool()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := pool.AddConnectionsFromConfig(ctx, globalCfg); err != nil {
		gateway.Close()
		return nil, fmt.Errorf("connect to liteservers: %w", err)
	}

	// 4. Initialize DNS resolver
	api := ton.NewAPIClient(pool)
	root, err := dns.GetRootContractAddr(ctx, api)
	if err != nil {
		gateway.Close()
		return nil, fmt.Errorf("get DNS root: %w", err)
	}
	dnsClient := dns.NewDNSClient(api, root)

	// 5. Create RLDP HTTP transport (tonutils-go handles everything correctly)
	transport := rldphttp.NewTransport(dhtClient, dnsClient, privKey)

	logger.Info("exit node initialized",
		zap.String("global_config", globalCfgPath),
	)

	return &ExitNode{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   60 * time.Second,
		},
		gateway:   gateway,
		dnsClient: dnsClient,
		logger:    logger,
	}, nil
}

// HandleStreamConnect handles a stream connection request
func (e *ExitNode) HandleStreamConnect(circuit Circuit, req *protocol.StreamConnect) error {
	e.logger.Debug("stream connect",
		zap.Int("stream_id", req.StreamID),
		zap.String("host", req.Host),
		zap.Int("port", req.Port),
	)

	stream := &Stream{
		ID:       req.StreamID,
		Host:     req.Host,
		Port:     req.Port,
		State:    StreamStatePending,
		Circuit:  circuit,
		Response: make(chan []byte, 10),
	}

	e.streams.Store(req.StreamID, stream)

	// Validate domain format (actual resolution happens on first request)
	if !isValidTONDomain(req.Host) {
		stream.State = StreamStateError
		return e.sendStreamConnected(circuit, req.StreamID, false, "invalid domain format")
	}

	// For .ton domains, do a quick DNS check to validate the domain exists
	if strings.HasSuffix(req.Host, ".ton") || strings.HasSuffix(req.Host, ".t.me") {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		domain, err := e.dnsClient.Resolve(ctx, req.Host)
		if err != nil {
			stream.State = StreamStateError
			return e.sendStreamConnected(circuit, req.StreamID, false, fmt.Sprintf("DNS resolution failed: %v", err))
		}

		siteRecord, _ := domain.GetSiteRecord()
		if siteRecord == nil {
			stream.State = StreamStateError
			return e.sendStreamConnected(circuit, req.StreamID, false, "no site record found")
		}
	}

	stream.State = StreamStateConnected
	return e.sendStreamConnected(circuit, req.StreamID, true, "")
}

// isValidTONDomain checks if the domain is a valid TON domain
func isValidTONDomain(host string) bool {
	return strings.HasSuffix(host, ".ton") ||
		strings.HasSuffix(host, ".adnl") ||
		strings.HasSuffix(host, ".t.me")
}

// HandleStreamData handles data on a stream (HTTP request)
func (e *ExitNode) HandleStreamData(circuit Circuit, streamID int, data []byte) error {
	streamI, ok := e.streams.Load(streamID)
	if !ok {
		return fmt.Errorf("stream %d not found", streamID)
	}
	stream := streamI.(*Stream)

	if stream.State != StreamStateConnected {
		return fmt.Errorf("stream %d not connected (state=%d)", streamID, stream.State)
	}

	// Parse HTTP request from raw bytes
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return fmt.Errorf("parse HTTP request: %w", err)
	}

	// Prepare request for http.Client
	// The rldphttp.Transport expects a proper http.Request with URL scheme set
	req.URL.Scheme = "http"
	req.URL.Host = stream.Host
	req.Host = stream.Host
	req.RequestURI = "" // Must be empty for http.Client

	e.logger.Debug("RLDP HTTP request",
		zap.String("method", req.Method),
		zap.String("host", stream.Host),
		zap.String("path", req.URL.Path),
	)

	// Execute request via RLDP transport
	// The tonutils-go transport handles:
	// - DNS resolution
	// - DHT lookup
	// - ADNL connection with proper handshake
	// - GetCapabilities exchange
	// - RLDP v1/v2 negotiation
	// - Request/response streaming
	resp, err := e.httpClient.Do(req)
	if err != nil {
		e.logger.Error("RLDP request failed",
			zap.Error(err),
			zap.String("host", stream.Host),
		)
		return e.sendErrorResponse(circuit, streamID, err)
	}
	defer resp.Body.Close()

	e.logger.Debug("RLDP HTTP response",
		zap.Int("status", resp.StatusCode),
		zap.String("host", stream.Host),
	)

	// Serialize HTTP response
	var respBuf bytes.Buffer
	if err := resp.Write(&respBuf); err != nil {
		return fmt.Errorf("serialize response: %w", err)
	}

	// Wrap in StreamData before sending
	streamData := &protocol.StreamData{
		StreamID: streamID,
		Data:     respBuf.Bytes(),
	}
	payload, err := tl.Serialize(streamData, true)
	if err != nil {
		return fmt.Errorf("serialize stream data: %w", err)
	}

	return e.sendResponseToCircuit(circuit, streamID, payload)
}

// sendErrorResponse sends an HTTP 502 error response through the circuit
func (e *ExitNode) sendErrorResponse(circuit Circuit, streamID int, originalErr error) error {
	errorBody := fmt.Sprintf("RLDP Error: %v", originalErr)
	errorResp := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		len(errorBody), errorBody)

	streamData := &protocol.StreamData{
		StreamID: streamID,
		Data:     []byte(errorResp),
	}
	payload, err := tl.Serialize(streamData, true)
	if err != nil {
		return err
	}
	return e.sendResponseToCircuit(circuit, streamID, payload)
}

// MaxChunkPayload is the max plaintext size per chunk (~6KB to stay within ADNL 8KB limit)
// ADNL has 1024 MTU × 8 parts = 8192 bytes, minus overhead for TL and encryption
const MaxChunkPayload = 6000

// sendResponseToCircuit sends an encrypted response via the tunnel
// For large responses (>MaxChunkPayload), it chunks the data and sends DataChunk messages
func (e *ExitNode) sendResponseToCircuit(circuit Circuit, streamID int, data []byte) error {
	// Small response: send as single Data message
	if len(data) <= MaxChunkPayload {
		return e.sendSingleResponse(circuit, streamID, data)
	}

	// Large response: chunk it
	e.logger.Debug("chunking large response",
		zap.Int("total_size", len(data)),
		zap.Int("chunk_size", MaxChunkPayload),
	)

	totalChunks := (len(data) + MaxChunkPayload - 1) / MaxChunkPayload

	for i := 0; i < totalChunks; i++ {
		start := i * MaxChunkPayload
		end := start + MaxChunkPayload
		if end > len(data) {
			end = len(data)
		}
		chunkData := data[start:end]

		// Encrypt this chunk separately
		encrypted, err := encryptPayload(chunkData, circuit.GetSharedKey())
		if err != nil {
			return fmt.Errorf("encrypt chunk %d: %w", i, err)
		}

		chunkMsg := &protocol.DataChunk{
			CircuitID:   circuit.GetID(),
			StreamID:    streamID,
			ChunkIndex:  i,
			TotalChunks: totalChunks,
			Data:        encrypted,
		}

		e.logger.Debug("sending chunk",
			zap.Int("chunk", i+1),
			zap.Int("total", totalChunks),
			zap.Int("size", len(encrypted)),
		)

		if err := e.sendChunk(circuit, chunkMsg); err != nil {
			return fmt.Errorf("send chunk %d: %w", i, err)
		}
	}

	return nil
}

// sendSingleResponse sends a single Data message (for small responses)
func (e *ExitNode) sendSingleResponse(circuit Circuit, streamID int, data []byte) error {
	encrypted, err := encryptPayload(data, circuit.GetSharedKey())
	if err != nil {
		return err
	}

	dataMsg := &protocol.Data{
		CircuitID: circuit.GetID(),
		StreamID:  streamID,
		Data:      encrypted,
	}

	prevHopUDPAddr := circuit.GetPrevHopUDPAddr()
	if prevHopUDPAddr != nil {
		dataBytes, err := tl.Serialize(dataMsg, true)
		if err != nil {
			return err
		}
		return e.sendUDP(prevHopUDPAddr, dataBytes)
	}

	prevHop := circuit.GetPrevHop()
	if prevHop != nil {
		return prevHop.SendCustomMessage(context.Background(), dataMsg)
	}

	return fmt.Errorf("no return path for circuit")
}

// sendChunk sends a single DataChunk message
func (e *ExitNode) sendChunk(circuit Circuit, chunk *protocol.DataChunk) error {
	prevHopUDPAddr := circuit.GetPrevHopUDPAddr()
	if prevHopUDPAddr != nil {
		dataBytes, err := tl.Serialize(chunk, true)
		if err != nil {
			return err
		}
		return e.sendUDP(prevHopUDPAddr, dataBytes)
	}

	prevHop := circuit.GetPrevHop()
	if prevHop != nil {
		return prevHop.SendCustomMessage(context.Background(), chunk)
	}

	return fmt.Errorf("no return path for circuit")
}

// sendStreamConnected sends a connection confirmation
func (e *ExitNode) sendStreamConnected(circuit Circuit, streamID int, success bool, errMsg string) error {
	resp := &protocol.StreamConnected{
		StreamID: streamID,
		Success:  success,
		Error:    errMsg,
	}

	payload, err := tl.Serialize(resp, true)
	if err != nil {
		return err
	}

	e.logger.Debug("sending stream connected response",
		zap.Int("stream_id", streamID),
		zap.Bool("success", success),
		zap.String("error", errMsg),
	)

	// Send via circuit - sendResponseToCircuit handles encryption
	return e.sendResponseToCircuit(circuit, streamID, payload)
}

// HandleStreamClose closes a stream
func (e *ExitNode) HandleStreamClose(streamID int) {
	if stream, ok := e.streams.LoadAndDelete(streamID); ok {
		s := stream.(*Stream)
		s.State = StreamStateClosed
		close(s.Response)
	}
}

// sendUDP sends a packet via UDP wrapped in TunnelPacketContents format
func (e *ExitNode) sendUDP(addr *net.UDPAddr, data []byte) error {
	if e.udpSender == nil {
		return fmt.Errorf("UDP sender not configured")
	}

	// Wrap in TunnelPacketContents for compatibility with relay handlers
	tunnelPacket := tunnel.NewTunnelPacket(data, nil)
	packetData, err := tunnelPacket.Serialize()
	if err != nil {
		return fmt.Errorf("serialize tunnel packet: %w", err)
	}

	e.logger.Debug("sending UDP response",
		zap.String("addr", addr.String()),
		zap.Int("data_len", len(packetData)),
	)

	return e.udpSender(addr, packetData)
}

// SetUDPSender sets the callback function for sending UDP packets
func (e *ExitNode) SetUDPSender(sender UDPSender) {
	e.udpSender = sender
}

// Close shuts down the exit node
func (e *ExitNode) Close() {
	if e.gateway != nil {
		e.gateway.Close()
	}
}
