package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/TONresistor/tonnet-relay/internal/exit"
	"github.com/TONresistor/tonnet-relay/internal/protocol"
	"github.com/TONresistor/tonnet-relay/internal/tunnel"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/tl"
	"go.uber.org/zap"
)

// pendingExtend tracks a pending circuit extension request
type pendingExtend struct {
	responseChan chan *protocol.CircuitCreated
	queryID      []byte
	peer         adnl.Peer
	createdAt    time.Time
	// UDP-based extend fields
	nextRelayAddr *net.UDPAddr // UDP address of the next relay for responses
}

// Engine handles relay protocol logic
type Engine struct {
	server         *Server
	circuits       sync.Map // circuit_id (string) -> *Circuit
	pendingExtends sync.Map // circuit_id (string) -> *pendingExtend
	exitNode       *exit.ExitNode // nil if not exit node
	isExit         bool
}

// NewEngine creates a new relay engine
func NewEngine(server *Server) *Engine {
	return &Engine{
		server: server,
	}
}

// SetExitNode configures the engine with an exit node for handling exit traffic
func (e *Engine) SetExitNode(exitNode *exit.ExitNode) {
	e.exitNode = exitNode
	e.isExit = exitNode != nil
}

// HandleQuery handles ADNL query messages
func (e *Engine) HandleQuery(peer adnl.Peer, msg *adnl.MessageQuery) error {
	ctx := context.Background()
	logger := e.server.GetLogger()

	// Handle both pointer and value types from TL deserialization
	switch data := msg.Data.(type) {
	case *protocol.Hello:
		return e.handleHello(ctx, peer, msg.ID, data)
	case protocol.Hello:
		return e.handleHello(ctx, peer, msg.ID, &data)

	case *protocol.CircuitCreate:
		return e.handleCircuitCreate(ctx, peer, msg.ID, data)
	case protocol.CircuitCreate:
		return e.handleCircuitCreate(ctx, peer, msg.ID, &data)

	case *protocol.Ping:
		return e.handlePing(ctx, peer, msg.ID, data)
	case protocol.Ping:
		return e.handlePing(ctx, peer, msg.ID, &data)

	case *protocol.GetPeers:
		return e.handleGetPeers(ctx, peer, msg.ID, data)
	case protocol.GetPeers:
		return e.handleGetPeers(ctx, peer, msg.ID, &data)

	case *protocol.CircuitExtend:
		return e.handleCircuitExtendQuery(ctx, peer, msg.ID, data)
	case protocol.CircuitExtend:
		return e.handleCircuitExtendQuery(ctx, peer, msg.ID, &data)

	case *protocol.CircuitRelay:
		return e.handleCircuitRelay(ctx, peer, msg.ID, data)
	case protocol.CircuitRelay:
		return e.handleCircuitRelay(ctx, peer, msg.ID, &data)

	default:
		logger.Warn("unknown query type", zap.Any("type", fmt.Sprintf("%T", data)))
		return peer.Answer(ctx, msg.ID, &protocol.Error{
			Code:    400,
			Message: "unknown query type",
		})
	}
}

// HandleMessage handles ADNL custom messages
func (e *Engine) HandleMessage(peer adnl.Peer, msg *adnl.MessageCustom) error {
	switch data := msg.Data.(type) {
	case *protocol.Data:
		return e.handleData(peer, data)
	case protocol.Data:
		return e.handleData(peer, &data)

	case *protocol.DataChunk:
		return e.handleDataChunk(peer, data)
	case protocol.DataChunk:
		return e.handleDataChunk(peer, &data)

	case *protocol.CircuitExtend:
		return e.handleCircuitExtend(peer, data)
	case protocol.CircuitExtend:
		return e.handleCircuitExtend(peer, &data)

	case *protocol.CircuitDestroy:
		return e.handleCircuitDestroy(peer, data)
	case protocol.CircuitDestroy:
		return e.handleCircuitDestroy(peer, &data)

	// Handle CircuitCreated as CustomMessage for relay-to-relay async responses
	case *protocol.CircuitCreated:
		return e.handleCircuitCreatedAsync(peer, data)
	case protocol.CircuitCreated:
		return e.handleCircuitCreatedAsync(peer, &data)

	// Handle CircuitCreate as CustomMessage for relay-to-relay async requests
	case *protocol.CircuitCreate:
		return e.handleCircuitCreateAsync(peer, data)
	case protocol.CircuitCreate:
		return e.handleCircuitCreateAsync(peer, &data)

	default:
		return nil
	}
}

// handleCircuitCreateAsync handles CircuitCreate as a CustomMessage (relay-to-relay)
// and responds with CircuitCreated via SendCustomMessage instead of Answer
func (e *Engine) handleCircuitCreateAsync(peer adnl.Peer, req *protocol.CircuitCreate) error {
	logger := e.server.GetLogger()
	metrics := e.server.GetMetrics()

	logger.Info("handleCircuitCreateAsync called (relay-to-relay)",
		zap.String("circuit_id", hex.EncodeToString(req.CircuitID)[:16]),
		zap.String("peer_id", hex.EncodeToString(peer.GetID())[:16]),
	)

	// Check if circuit already exists (idempotency)
	if existing, ok := e.circuits.Load(string(req.CircuitID)); ok {
		circuit := existing.(*Circuit)
		logger.Info("circuit already exists, returning cached response",
			zap.String("circuit_id", hex.EncodeToString(req.CircuitID)[:16]),
		)
		return peer.SendCustomMessage(context.Background(), &protocol.CircuitCreated{
			CircuitID: req.CircuitID,
			RelayKey:  circuit.RelayPub,
			KeyHash:   hashKey(circuit.SharedKey),
		})
	}

	// Generate ephemeral keypair for this circuit
	relayPriv, relayPub := generateX25519Keypair()

	// Compute shared secret with client
	sharedKey := computeSharedKey(relayPriv, req.ClientKey)

	// Create circuit
	circuit := &Circuit{
		ID:        req.CircuitID,
		CreatedAt: time.Now(),
		SharedKey: sharedKey,
		RelayPub:  relayPub,
		PrevHop:   peer,
	}

	e.circuits.Store(string(req.CircuitID), circuit)
	metrics.IncrCircuits()

	logger.Info("circuit created (async), sending CustomMessage response",
		zap.String("circuit_id", hex.EncodeToString(req.CircuitID)[:16]),
		zap.String("relay_key", hex.EncodeToString(relayPub)[:16]),
	)

	// Send response via SendCustomMessage (not Answer)
	return peer.SendCustomMessage(context.Background(), &protocol.CircuitCreated{
		CircuitID: req.CircuitID,
		RelayKey:  relayPub,
		KeyHash:   hashKey(sharedKey),
	})
}

// handleCircuitCreatedAsync handles async CircuitCreated responses from next relay
func (e *Engine) handleCircuitCreatedAsync(peer adnl.Peer, resp *protocol.CircuitCreated) error {
	logger := e.server.GetLogger()

	circuitID := string(resp.CircuitID)
	pendingI, ok := e.pendingExtends.Load(circuitID)
	if !ok {
		logger.Debug("received CircuitCreated for unknown circuit (may be Query response)",
			zap.String("circuit_id", hex.EncodeToString(resp.CircuitID)[:16]))
		return nil // Not an error - might be a Query response handled elsewhere
	}

	pending := pendingI.(*pendingExtend)
	logger.Info("received async CircuitCreated response",
		zap.String("circuit_id", hex.EncodeToString(resp.CircuitID)[:16]),
		zap.String("relay_key", hex.EncodeToString(resp.RelayKey)[:16]),
	)

	// Send response to waiting goroutine
	select {
	case pending.responseChan <- resp:
		// Response delivered
	default:
		logger.Warn("response channel full or closed")
	}

	return nil
}

// HandleDisconnect cleans up when a peer disconnects
func (e *Engine) HandleDisconnect(key ed25519.PublicKey) {
	keyHex := hex.EncodeToString(key)

	e.circuits.Range(func(k, v interface{}) bool {
		circuit := v.(*Circuit)

		prevID := ""
		if circuit.PrevHop != nil {
			prevID = hex.EncodeToString(circuit.PrevHop.GetID())
		}

		nextID := ""
		if circuit.NextHop != nil {
			nextID = hex.EncodeToString(circuit.NextHop.GetID())
		}

		if prevID == keyHex || nextID == keyHex {
			e.circuits.Delete(k)
			e.server.GetMetrics().DecrCircuits()
		}

		return true
	})
}

// handleHello handles hello handshake
func (e *Engine) handleHello(ctx context.Context, peer adnl.Peer, queryID []byte, req *protocol.Hello) error {
	logger := e.server.GetLogger()
	logger.Debug("received hello",
		zap.String("node_id", hex.EncodeToString(req.NodeID)),
		zap.Int("version", req.Version),
	)

	return peer.Answer(ctx, queryID, &protocol.HelloAck{
		NodeID:  e.server.pubKey,
		Version: protocol.Version,
	})
}

// handleCircuitCreate handles circuit creation
func (e *Engine) handleCircuitCreate(ctx context.Context, peer adnl.Peer, queryID []byte, req *protocol.CircuitCreate) error {
	logger := e.server.GetLogger()
	metrics := e.server.GetMetrics()

	logger.Info("DEBUG: handleCircuitCreate called",
		zap.String("circuit_id", hex.EncodeToString(req.CircuitID)[:16]),
		zap.String("query_id", hex.EncodeToString(queryID)[:16]),
		zap.String("peer_id", hex.EncodeToString(peer.GetID())[:16]),
		zap.Int64("timestamp_ns", time.Now().UnixNano()),
	)

	// Check if circuit already exists (idempotency for ADNL retries)
	if existing, ok := e.circuits.Load(string(req.CircuitID)); ok {
		circuit := existing.(*Circuit)
		logger.Info("DEBUG: circuit already exists, returning cached response",
			zap.String("circuit_id", hex.EncodeToString(req.CircuitID)[:16]),
		)
		err := peer.Answer(ctx, queryID, &protocol.CircuitCreated{
			CircuitID: req.CircuitID,
			RelayKey:  circuit.RelayPub,
			KeyHash:   hashKey(circuit.SharedKey),
		})
		logger.Info("DEBUG: Answer sent (cached)",
			zap.Bool("success", err == nil),
			zap.Int64("timestamp_ns", time.Now().UnixNano()),
		)
		return err
	}

	// Generate ephemeral keypair for this circuit
	relayPriv, relayPub := generateX25519Keypair()

	// Compute shared secret with client
	sharedKey := computeSharedKey(relayPriv, req.ClientKey)

	// Create circuit
	circuit := &Circuit{
		ID:        req.CircuitID,
		CreatedAt: time.Now(),
		SharedKey: sharedKey,
		RelayPub:  relayPub, // Store for idempotent responses
		PrevHop:   peer,
	}

	e.circuits.Store(string(req.CircuitID), circuit)
	metrics.IncrCircuits()

	logger.Info("DEBUG: circuit created, sending Answer",
		zap.String("circuit_id", hex.EncodeToString(req.CircuitID)[:16]),
		zap.String("shared_key_hash", hex.EncodeToString(hashKey(sharedKey))[:16]),
		zap.String("relay_key", hex.EncodeToString(relayPub)[:16]),
		zap.Int64("timestamp_ns", time.Now().UnixNano()),
	)

	err := peer.Answer(ctx, queryID, &protocol.CircuitCreated{
		CircuitID: req.CircuitID,
		RelayKey:  relayPub,
		KeyHash:   hashKey(sharedKey),
	})

	logger.Info("DEBUG: Answer sent",
		zap.Bool("success", err == nil),
		zap.Int64("timestamp_ns", time.Now().UnixNano()),
	)
	if err != nil {
		logger.Error("DEBUG: Answer failed", zap.Error(err))
	}

	return err
}

// handlePing handles ping requests
func (e *Engine) handlePing(ctx context.Context, peer adnl.Peer, queryID []byte, req *protocol.Ping) error {
	return peer.Answer(ctx, queryID, &protocol.Pong{
		Nonce: req.Nonce,
	})
}

// handleGetPeers handles peer discovery requests
func (e *Engine) handleGetPeers(ctx context.Context, peer adnl.Peer, queryID []byte, req *protocol.GetPeers) error {
	peers := e.server.peers.GetPeers(req.MaxCount)

	peerInfos := make([]*protocol.PeerInfo, 0, len(peers))
	for _, p := range peers {
		if len(p.Addresses) > 0 {
			peerInfos = append(peerInfos, &protocol.PeerInfo{
				ADNLID:   p.ADNLID,
				IP:       p.Addresses[0].IP,
				Port:     p.Addresses[0].Port,
				Capacity: 100, // TODO: Get actual capacity
			})
		}
	}

	return peer.Answer(ctx, queryID, &protocol.Peers{
		Peers: peerInfos,
	})
}

// handleData handles data relay through established circuits
func (e *Engine) handleData(peer adnl.Peer, data *protocol.Data) error {
	logger := e.server.GetLogger()
	metrics := e.server.GetMetrics()

	circuitI, ok := e.circuits.Load(string(data.CircuitID))
	if !ok {
		logger.Warn("unknown circuit", zap.String("circuit_id", hex.EncodeToString(data.CircuitID)))
		return fmt.Errorf("unknown circuit: %x", data.CircuitID)
	}
	circuit := circuitI.(*Circuit)

	// Update metrics
	circuit.BytesIn += uint64(len(data.Data))
	metrics.AddBytesReceived(uint64(len(data.Data)))

	// Decrypt one layer using simple ChaCha20-Poly1305
	decrypted, err := decryptPayload(data.Data, circuit.SharedKey)
	if err != nil {
		logger.Error("failed to decrypt layer", zap.Error(err))
		return err
	}

	logger.Debug("decrypted data layer",
		zap.String("circuit_id", hex.EncodeToString(data.CircuitID)[:16]),
		zap.Int("decrypted_len", len(decrypted)),
		zap.Bool("is_exit", circuit.IsExit()),
	)

	// Check if we are the exit node (no next hop configured)
	if circuit.NextHop == nil && circuit.NextHopUDPAddr == nil {
		// We are the exit node
		if e.isExit && e.exitNode != nil {
			// Route to exit node handler for TON site proxying
			return e.handleExitData(circuit, decrypted)
		}
		// Fallback: forward to destination (legacy behavior)
		return e.forwardToDestination(circuit, decrypted)
	}

	// Forward to next relay via UDP tunnel
	if circuit.NextHopUDPAddr != nil {
		circuit.BytesOut += uint64(len(decrypted))
		metrics.AddBytesSent(uint64(len(decrypted)))

		// Wrap decrypted data in protocol.Data message
		forwardData := &protocol.Data{
			CircuitID: data.CircuitID,
			StreamID:  data.StreamID,
			Data:      decrypted,
		}

		dataBytes, err := tl.Serialize(forwardData, true)
		if err != nil {
			return fmt.Errorf("serialize data: %w", err)
		}

		// Wrap in tunnel packet and send via UDP
		tunnelPacket := tunnel.NewTunnelPacket(dataBytes, nil)
		packetData, err := tunnelPacket.Serialize()
		if err != nil {
			return fmt.Errorf("serialize tunnel packet: %w", err)
		}

		conn := e.server.GetUDPConn()
		if conn == nil {
			return fmt.Errorf("UDP connection not available")
		}

		logger.Debug("forwarding data via UDP",
			zap.String("circuit_id", hex.EncodeToString(data.CircuitID)[:16]),
			zap.String("dest", circuit.NextHopUDPAddr.String()),
		)

		_, err = conn.WriteTo(packetData, circuit.NextHopUDPAddr)
		return err
	}

	// Forward via ADNL (legacy)
	if circuit.NextHop != nil {
		circuit.BytesOut += uint64(len(decrypted))
		metrics.AddBytesSent(uint64(len(decrypted)))

		return circuit.NextHop.SendCustomMessage(context.Background(), &protocol.Data{
			CircuitID: data.CircuitID,
			StreamID:  data.StreamID,
			Data:      decrypted,
		})
	}

	return nil
}

// sendDataViaUDP wraps data in TunnelPacketContents and sends via UDP (DRY helper)
func (e *Engine) sendDataViaUDP(circuitID []byte, streamID int, data []byte, dest *net.UDPAddr) error {
	if dest == nil {
		return fmt.Errorf("no destination address")
	}

	conn := e.server.GetUDPConn()
	if conn == nil {
		return fmt.Errorf("UDP connection not available")
	}

	msg := &protocol.Data{CircuitID: circuitID, StreamID: streamID, Data: data}
	msgBytes, err := tl.Serialize(msg, true)
	if err != nil {
		return fmt.Errorf("serialize data: %w", err)
	}

	packet := tunnel.NewTunnelPacket(msgBytes, nil)
	packetData, err := packet.Serialize()
	if err != nil {
		return fmt.Errorf("serialize tunnel packet: %w", err)
	}

	_, err = conn.WriteTo(packetData, dest)
	return err
}

// handleDataFromUDP handles data received via UDP tunnel
// Supports bidirectional routing: forward (to exit) and response (from exit)
func (e *Engine) handleDataFromUDP(data *protocol.Data, srcAddr net.Addr) error {
	logger := e.server.GetLogger()
	metrics := e.server.GetMetrics()

	circuitI, ok := e.circuits.Load(string(data.CircuitID))
	if !ok {
		logger.Warn("unknown circuit (UDP)", zap.String("circuit_id", hex.EncodeToString(data.CircuitID)[:16]))
		return fmt.Errorf("unknown circuit: %x", data.CircuitID[:8])
	}
	circuit := circuitI.(*Circuit)

	// Store the previous hop UDP address if not set (for responses)
	if circuit.PrevHopUDPAddr == nil {
		if udpAddr, ok := srcAddr.(*net.UDPAddr); ok {
			circuit.PrevHopUDPAddr = udpAddr
		}
	}

	// Update metrics
	circuit.BytesIn += uint64(len(data.Data))
	metrics.AddBytesReceived(uint64(len(data.Data)))

	// Detect direction FIRST: is this a response from NextHop?
	isFromNextHop := circuit.NextHopUDPAddr != nil && srcAddr.String() == circuit.NextHopUDPAddr.String()

	// Response from NextHop → forward to PrevHop WITHOUT decrypting
	// (responses are encrypted with client-exit key, not our key)
	if isFromNextHop {
		logger.Debug("forwarding response (no decrypt)",
			zap.String("circuit_id", hex.EncodeToString(data.CircuitID)[:16]),
			zap.Int("data_len", len(data.Data)),
			zap.String("src", srcAddr.String()),
		)

		circuit.BytesOut += uint64(len(data.Data))
		metrics.AddBytesSent(uint64(len(data.Data)))

		// Try ADNL first, then UDP
		if circuit.PrevHop != nil {
			logger.Debug("sending response via ADNL to client",
				zap.String("circuit_id", hex.EncodeToString(data.CircuitID)[:16]),
				zap.Int("stream_id", data.StreamID),
			)
			err := circuit.PrevHop.SendCustomMessage(context.Background(), &protocol.Data{
				CircuitID: data.CircuitID,
				StreamID:  data.StreamID,
				Data:      data.Data, // Forward as-is, don't decrypt
			})
			if err != nil {
				logger.Error("failed to send response via ADNL", zap.Error(err))
			} else {
				logger.Debug("response sent via ADNL successfully")
			}
			return err
		}
		if circuit.PrevHopUDPAddr != nil {
			logger.Debug("forwarding response to prev hop", zap.String("dest", circuit.PrevHopUDPAddr.String()))
			return e.sendDataViaUDP(data.CircuitID, data.StreamID, data.Data, circuit.PrevHopUDPAddr)
		}
		return fmt.Errorf("no previous hop for response")
	}

	// Request from PrevHop → decrypt and forward/handle
	decrypted, err := decryptPayload(data.Data, circuit.SharedKey)
	if err != nil {
		logger.Error("failed to decrypt layer (UDP)", zap.Error(err))
		return err
	}

	logger.Debug("decrypted data layer (UDP)",
		zap.String("circuit_id", hex.EncodeToString(data.CircuitID)[:16]),
		zap.Int("decrypted_len", len(decrypted)),
		zap.String("src", srcAddr.String()),
	)

	// Check if we are the exit node (no next hop)
	if circuit.NextHop == nil && circuit.NextHopUDPAddr == nil {
		if e.isExit && e.exitNode != nil {
			return e.handleExitData(circuit, decrypted)
		}
		return e.forwardToDestination(circuit, decrypted)
	}

	// Forward request to NextHop
	circuit.BytesOut += uint64(len(decrypted))
	metrics.AddBytesSent(uint64(len(decrypted)))
	logger.Debug("forwarding data to next hop", zap.String("dest", circuit.NextHopUDPAddr.String()))
	return e.sendDataViaUDP(data.CircuitID, data.StreamID, decrypted, circuit.NextHopUDPAddr)
}

// handleDataChunkFromUDP handles DataChunk messages received via UDP
// These are chunked responses from exit node - forward as-is without decrypting
func (e *Engine) handleDataChunkFromUDP(chunk *protocol.DataChunk, srcAddr net.Addr) error {
	logger := e.server.GetLogger()

	circuitI, ok := e.circuits.Load(string(chunk.CircuitID))
	if !ok {
		return fmt.Errorf("circuit not found: %s", hex.EncodeToString(chunk.CircuitID)[:16])
	}
	circuit := circuitI.(*Circuit)

	circuit.BytesIn += uint64(len(chunk.Data))

	// DataChunk is always a response from NextHop → forward to PrevHop without decrypting
	logger.Debug("forwarding chunk (no decrypt)",
		zap.String("circuit_id", hex.EncodeToString(chunk.CircuitID)[:16]),
		zap.Int("chunk", chunk.ChunkIndex+1),
		zap.Int("total", chunk.TotalChunks),
		zap.Int("data_len", len(chunk.Data)),
	)

	circuit.BytesOut += uint64(len(chunk.Data))

	// Forward to PrevHop via ADNL or UDP
	if circuit.PrevHop != nil {
		logger.Debug("sending chunk via ADNL to client",
			zap.String("circuit_id", hex.EncodeToString(chunk.CircuitID)[:16]),
			zap.Int("chunk", chunk.ChunkIndex+1),
		)
		err := circuit.PrevHop.SendCustomMessage(context.Background(), chunk)
		if err != nil {
			logger.Error("failed to send chunk via ADNL", zap.Error(err))
		} else {
			logger.Debug("chunk sent via ADNL successfully")
		}
		return err
	}
	if circuit.PrevHopUDPAddr != nil {
		logger.Debug("forwarding chunk to prev hop", zap.String("dest", circuit.PrevHopUDPAddr.String()))
		return e.sendDataChunkViaUDP(chunk, circuit.PrevHopUDPAddr)
	}

	return fmt.Errorf("no previous hop for chunk")
}

// handleDataChunk handles DataChunk messages received via ADNL
// These are chunked responses - forward as-is without decrypting
func (e *Engine) handleDataChunk(peer adnl.Peer, chunk *protocol.DataChunk) error {
	logger := e.server.GetLogger()

	circuitI, ok := e.circuits.Load(string(chunk.CircuitID))
	if !ok {
		return fmt.Errorf("circuit not found: %s", hex.EncodeToString(chunk.CircuitID)[:16])
	}
	circuit := circuitI.(*Circuit)

	circuit.BytesIn += uint64(len(chunk.Data))

	logger.Debug("received chunk via ADNL, forwarding (no decrypt)",
		zap.String("circuit_id", hex.EncodeToString(chunk.CircuitID)[:16]),
		zap.Int("chunk", chunk.ChunkIndex+1),
		zap.Int("total", chunk.TotalChunks),
	)

	circuit.BytesOut += uint64(len(chunk.Data))

	// Forward to PrevHop via ADNL or UDP
	if circuit.PrevHop != nil {
		return circuit.PrevHop.SendCustomMessage(context.Background(), chunk)
	}
	if circuit.PrevHopUDPAddr != nil {
		return e.sendDataChunkViaUDP(chunk, circuit.PrevHopUDPAddr)
	}

	return fmt.Errorf("no previous hop for chunk")
}

// sendDataChunkViaUDP sends a DataChunk message via UDP
func (e *Engine) sendDataChunkViaUDP(chunk *protocol.DataChunk, dest *net.UDPAddr) error {
	if dest == nil {
		return fmt.Errorf("no destination address")
	}

	conn := e.server.GetUDPConn()
	if conn == nil {
		return fmt.Errorf("UDP connection not available")
	}

	data, err := tl.Serialize(chunk, true)
	if err != nil {
		return fmt.Errorf("serialize chunk: %w", err)
	}

	tunnelPacket := tunnel.NewTunnelPacket(data, nil)
	packetData, err := tunnelPacket.Serialize()
	if err != nil {
		return fmt.Errorf("serialize tunnel packet: %w", err)
	}

	_, err = conn.WriteTo(packetData, dest)
	return err
}

// handleCircuitExtendQuery handles circuit extension as a query
// Uses UDP tunnel transport for relay-to-relay communication instead of ADNL SendCustomMessage
// This avoids issues with ADNL ephemeral session keys causing response routing problems
func (e *Engine) handleCircuitExtendQuery(ctx context.Context, peer adnl.Peer, queryID []byte, data *protocol.CircuitExtend) error {
	logger := e.server.GetLogger()

	// 1. Look up the circuit
	circuitI, ok := e.circuits.Load(string(data.CircuitID))
	if !ok {
		logger.Error("circuit not found for extend",
			zap.String("circuit_id", hex.EncodeToString(data.CircuitID)))
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    404,
			Message: "unknown circuit",
		})
	}
	circuit := circuitI.(*Circuit)
	logger.Info("circuit extend lookup",
		zap.String("circuit_id", hex.EncodeToString(data.CircuitID)),
		zap.String("stored_key_hash", hex.EncodeToString(hashKey(circuit.SharedKey))[:16]),
	)

	// 2. Decrypt the encrypted payload using circuit's shared key
	if len(data.Encrypted) < 12+16 {
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    400,
			Message: "encrypted payload too short",
		})
	}

	nonce := data.Encrypted[:12]
	ciphertext := data.Encrypted[12:]

	logger.Debug("decrypt attempt",
		zap.String("circuit_id", hex.EncodeToString(data.CircuitID)),
		zap.String("shared_key", hex.EncodeToString(circuit.SharedKey)[:16]),
		zap.Int("encrypted_len", len(data.Encrypted)),
	)

	plaintext, err := decryptLayer(ciphertext, circuit.SharedKey, nonce)
	if err != nil {
		logger.Error("failed to decrypt extend payload", zap.Error(err),
			zap.String("key_hash", hex.EncodeToString(hashKey(circuit.SharedKey))[:16]))
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    401,
			Message: "decryption failed",
		})
	}

	// 3. Parse the ExtendPayload (simple format: addr_len(2) + addr + client_key(32))
	if len(plaintext) < 2 {
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    400,
			Message: "invalid extend payload",
		})
	}

	addrLen := int(plaintext[0])<<8 | int(plaintext[1])
	if len(plaintext) < 2+addrLen+32 {
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    400,
			Message: "truncated extend payload",
		})
	}

	nextAddr := string(plaintext[2 : 2+addrLen])
	clientKey := plaintext[2+addrLen : 2+addrLen+32]

	logger.Info("circuit extend - decrypted successfully",
		zap.String("circuit_id", hex.EncodeToString(data.CircuitID)),
		zap.String("next_relay", hex.EncodeToString(data.NextRelay)[:16]),
		zap.String("next_addr", nextAddr),
	)

	// 4. Get UDP connection for sending to next relay
	udpConn := e.server.GetUDPConn()
	if udpConn == nil {
		logger.Error("UDP connection not available for circuit extension")
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    503,
			Message: "UDP tunnel not available",
		})
	}

	// 5. Parse the next relay address and convert to UDP address (port 9002)
	nextUDPAddr, err := parseToUDPAddr(nextAddr)
	if err != nil {
		logger.Error("failed to parse next relay address",
			zap.String("addr", nextAddr),
			zap.Error(err))
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    400,
			Message: "invalid next relay address: " + err.Error(),
		})
	}

	logger.Info("sending CircuitCreate via UDP tunnel",
		zap.String("circuit_id", hex.EncodeToString(data.CircuitID)[:16]),
		zap.String("udp_addr", nextUDPAddr.String()),
		zap.String("client_key", hex.EncodeToString(clientKey)[:16]),
	)

	// 6. Serialize the CircuitCreate request using TL format
	createReq := &protocol.CircuitCreate{
		CircuitID: data.CircuitID,
		ClientKey: clientKey,
	}

	tlData, err := tl.Serialize(createReq, true) // boxed = true for TL constructor ID
	if err != nil {
		logger.Error("failed to serialize CircuitCreate", zap.Error(err))
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    500,
			Message: "failed to serialize request",
		})
	}

	// 7. Wrap in TunnelPacketContents for proper UDP tunnel format
	tunnelPacket := tunnel.NewTunnelPacket(tlData, nil)
	packetData, err := tunnelPacket.Serialize()
	if err != nil {
		logger.Error("failed to serialize tunnel packet", zap.Error(err))
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    500,
			Message: "failed to serialize tunnel packet",
		})
	}

	// 8. Create response channel and register pending request with UDP address
	responseChan := make(chan *protocol.CircuitCreated, 1)
	pending := &pendingExtend{
		responseChan:  responseChan,
		queryID:       queryID,
		peer:          peer,
		createdAt:     time.Now(),
		nextRelayAddr: nextUDPAddr,
	}
	e.pendingExtends.Store(string(data.CircuitID), pending)
	defer e.pendingExtends.Delete(string(data.CircuitID))

	// 9. Send the packet via UDP to the next relay
	_, err = udpConn.WriteTo(packetData, nextUDPAddr)
	if err != nil {
		logger.Error("failed to send CircuitCreate via UDP", zap.Error(err))
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    502,
			Message: "failed to send to next relay: " + err.Error(),
		})
	}

	logger.Info("CircuitCreate sent via UDP, waiting for response",
		zap.String("circuit_id", hex.EncodeToString(data.CircuitID)[:16]),
		zap.String("dest_addr", nextUDPAddr.String()))

	// 10. Wait for response with timeout
	select {
	case createResp := <-responseChan:
		logger.Info("SUCCESS: received CircuitCreated via UDP from next relay",
			zap.String("relay_key", hex.EncodeToString(createResp.RelayKey)[:16]),
			zap.String("key_hash", hex.EncodeToString(createResp.KeyHash)[:16]),
		)

		// 11. Store the next hop UDP address in the circuit
		// Note: For UDP-based routing, we don't use ADNL Peer objects
		// Instead, we track the UDP address for future data forwarding
		circuit.NextHopUDPAddr = nextUDPAddr

		logger.Info("circuit extended via UDP - sending response",
			zap.String("circuit_id", hex.EncodeToString(data.CircuitID)),
			zap.String("next_addr", nextAddr),
		)

		// 12. Return CircuitExtended with next relay's key info
		return peer.Answer(ctx, queryID, &protocol.CircuitExtended{
			CircuitID: data.CircuitID,
			RelayKey:  createResp.RelayKey,
			KeyHash:   createResp.KeyHash,
		})

	case <-time.After(10 * time.Second):
		logger.Error("timeout waiting for CircuitCreated via UDP from next relay",
			zap.String("circuit_id", hex.EncodeToString(data.CircuitID)[:16]),
		)
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    504,
			Message: "timeout waiting for next relay response",
		})
	}
}

// parseToUDPAddr converts an ADNL address (ip:port) to a UDP address
// The UDP port is typically 9002 (one more than ADNL port 9001)
func parseToUDPAddr(adnlAddr string) (*net.UDPAddr, error) {
	// Parse the address
	host, portStr, err := net.SplitHostPort(adnlAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %w", err)
	}

	// Parse the port
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	// Convert to UDP port (ADNL port + 1, e.g., 9001 -> 9002)
	udpPort := port + 1

	// Handle IPv4 addresses that might be formatted as IPv6
	ip := net.ParseIP(host)
	if ip == nil {
		// Try to resolve hostname
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("cannot resolve host: %s", host)
		}
		ip = ips[0]
	}

	// Prefer IPv4 if available
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}

	return &net.UDPAddr{
		IP:   ip,
		Port: udpPort,
	}, nil
}

// handleCircuitRelay forwards a command through the circuit to the next hop
// Used for multi-hop (3+) operations: client -> relay1 -> relay2 -> relay3
// The encrypted payload is decrypted by this hop, then forwarded to the next hop
func (e *Engine) handleCircuitRelay(ctx context.Context, peer adnl.Peer, queryID []byte, data *protocol.CircuitRelay) error {
	logger := e.server.GetLogger()

	circuitID := string(data.CircuitID)

	logger.Info("circuit relay received",
		zap.String("circuit_id", hex.EncodeToString(data.CircuitID)[:16]),
		zap.Int("encrypted_len", len(data.Encrypted)),
	)

	// 1. Look up the circuit
	circuitI, ok := e.circuits.Load(circuitID)
	if !ok {
		logger.Warn("circuit not found for relay",
			zap.String("circuit_id", hex.EncodeToString(data.CircuitID)[:16]),
		)
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    404,
			Message: "circuit not found",
		})
	}
	circuit := circuitI.(*Circuit)

	// 2. Decrypt the payload with the circuit's shared key
	decrypted, err := decryptPayload(data.Encrypted, circuit.SharedKey)
	if err != nil {
		logger.Error("failed to decrypt relay payload",
			zap.Error(err),
			zap.String("circuit_id", hex.EncodeToString(data.CircuitID)[:16]),
		)
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    400,
			Message: "decryption failed",
		})
	}

	// 3. Parse the inner TL message
	var innerMsg any
	_, err = tl.Parse(&innerMsg, decrypted, true)
	if err != nil {
		logger.Error("failed to parse inner relay message",
			zap.Error(err),
			zap.String("circuit_id", hex.EncodeToString(data.CircuitID)[:16]),
		)
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    400,
			Message: "invalid inner message",
		})
	}

	// 4. Check if we have a next hop to forward to
	if circuit.NextHopUDPAddr == nil {
		logger.Error("no next hop for relay",
			zap.String("circuit_id", hex.EncodeToString(data.CircuitID)[:16]),
		)
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    400,
			Message: "no next hop configured",
		})
	}

	// 5. Handle the inner message based on type
	switch inner := innerMsg.(type) {
	case *protocol.CircuitExtend:
		return e.handleRelayedExtend(ctx, peer, queryID, data.CircuitID, circuit, inner)
	case protocol.CircuitExtend:
		return e.handleRelayedExtend(ctx, peer, queryID, data.CircuitID, circuit, &inner)
	default:
		logger.Warn("unsupported inner message type for relay",
			zap.String("type", fmt.Sprintf("%T", innerMsg)),
		)
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    400,
			Message: fmt.Sprintf("unsupported relay message: %T", innerMsg),
		})
	}
}

// handleRelayedExtend handles a CircuitExtend that was relayed through the circuit
func (e *Engine) handleRelayedExtend(ctx context.Context, peer adnl.Peer, queryID []byte, circuitID []byte, circuit *Circuit, extend *protocol.CircuitExtend) error {
	logger := e.server.GetLogger()

	logger.Info("forwarding relayed CircuitExtend to next hop via UDP",
		zap.String("circuit_id", hex.EncodeToString(circuitID)[:16]),
		zap.String("next_hop", circuit.NextHopUDPAddr.String()),
	)

	// Get UDP connection
	conn := e.server.GetUDPConn()
	if conn == nil {
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    500,
			Message: "UDP connection not available",
		})
	}

	// Serialize the CircuitExtend for the next relay
	extendBytes, err := tl.Serialize(extend, true)
	if err != nil {
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    500,
			Message: "failed to serialize extend request",
		})
	}

	// Wrap in TunnelPacketContents for UDP transport
	packet := tunnel.NewTunnelPacket(extendBytes, nil)
	packetBytes, err := packet.Serialize()
	if err != nil {
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    500,
			Message: "failed to wrap extend request",
		})
	}

	// Create response channel for CircuitCreated (from next hop processing the extend)
	responseChan := make(chan *protocol.CircuitCreated, 1)
	circuitIDKey := string(extend.CircuitID) // Use full CircuitID as key

	// Store pending request - the next hop will send CircuitCreated (not CircuitExtended)
	e.pendingExtends.Store(circuitIDKey, &pendingExtend{
		responseChan:  responseChan,
		nextRelayAddr: circuit.NextHopUDPAddr,
		createdAt:     time.Now(),
	})
	defer e.pendingExtends.Delete(circuitIDKey)

	// Send via UDP
	_, err = conn.WriteTo(packetBytes, circuit.NextHopUDPAddr)
	if err != nil {
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    500,
			Message: "failed to send to next hop",
		})
	}

	logger.Info("relayed CircuitExtend sent via UDP, waiting for CircuitCreated response",
		zap.String("circuit_id", hex.EncodeToString(circuitID)[:16]),
		zap.String("dest", circuit.NextHopUDPAddr.String()),
	)

	// Wait for response with timeout
	select {
	case createResp := <-responseChan:
		// Convert CircuitCreated to CircuitExtended for the client
		resp := &protocol.CircuitExtended{
			CircuitID: extend.CircuitID,
			RelayKey:  createResp.RelayKey,
			KeyHash:   createResp.KeyHash,
		}
		// Encrypt response with circuit's shared key
		respBytes, err := tl.Serialize(resp, true)
		if err != nil {
			return peer.Answer(ctx, queryID, &protocol.Error{
				Code:    500,
				Message: "failed to serialize response",
			})
		}

		encryptedResp, err := encryptPayload(respBytes, circuit.SharedKey)
		if err != nil {
			return peer.Answer(ctx, queryID, &protocol.Error{
				Code:    500,
				Message: "failed to encrypt response",
			})
		}

		return peer.Answer(ctx, queryID, &protocol.CircuitRelayResponse{
			CircuitID: circuitID,
			Encrypted: encryptedResp,
		})

	case <-time.After(10 * time.Second):
		return peer.Answer(ctx, queryID, &protocol.Error{
			Code:    504,
			Message: "timeout waiting for relay response",
		})
	}
}

// handleCircuitExtend handles circuit extension (legacy custom message, deprecated)
func (e *Engine) handleCircuitExtend(peer adnl.Peer, data *protocol.CircuitExtend) error {
	// Deprecated: use handleCircuitExtendQuery instead
	return nil
}

// handleCircuitDestroy handles circuit teardown
func (e *Engine) handleCircuitDestroy(peer adnl.Peer, data *protocol.CircuitDestroy) error {
	logger := e.server.GetLogger()
	metrics := e.server.GetMetrics()

	circuitID := string(data.CircuitID)
	if _, ok := e.circuits.LoadAndDelete(circuitID); ok {
		metrics.DecrCircuits()
		logger.Debug("circuit destroyed",
			zap.String("circuit_id", hex.EncodeToString(data.CircuitID)),
		)
	}

	return nil
}

// forwardToDestination forwards decrypted data to the final destination
func (e *Engine) forwardToDestination(circuit *Circuit, data []byte) error {
	// TODO: Implement RLDP forwarding to destination
	e.server.GetLogger().Debug("forward to destination",
		zap.Int("data_len", len(data)),
	)
	return nil
}

// handleExitData handles decrypted data at the exit node
func (e *Engine) handleExitData(circuit *Circuit, data []byte) error {
	logger := e.server.GetLogger()

	if e.exitNode == nil {
		return fmt.Errorf("exit node not configured")
	}

	// Parse the message type
	var msg any
	_, err := tl.Parse(&msg, data, true)
	if err != nil {
		logger.Error("failed to parse exit data message", zap.Error(err))
		return fmt.Errorf("parse message: %w", err)
	}

	switch m := msg.(type) {
	case *protocol.StreamConnect:
		logger.Debug("exit: handling StreamConnect",
			zap.Int("stream_id", m.StreamID),
			zap.String("host", m.Host),
			zap.Int("port", m.Port),
		)
		return e.exitNode.HandleStreamConnect(circuit, m)

	case protocol.StreamConnect:
		logger.Debug("exit: handling StreamConnect",
			zap.Int("stream_id", m.StreamID),
			zap.String("host", m.Host),
			zap.Int("port", m.Port),
		)
		return e.exitNode.HandleStreamConnect(circuit, &m)

	case *protocol.StreamData:
		logger.Debug("exit: handling StreamData",
			zap.Int("stream_id", m.StreamID),
			zap.Int("data_len", len(m.Data)),
		)
		return e.exitNode.HandleStreamData(circuit, m.StreamID, m.Data)

	case protocol.StreamData:
		logger.Debug("exit: handling StreamData",
			zap.Int("stream_id", m.StreamID),
			zap.Int("data_len", len(m.Data)),
		)
		return e.exitNode.HandleStreamData(circuit, m.StreamID, m.Data)

	case *protocol.StreamClose:
		logger.Debug("exit: handling StreamClose",
			zap.Int("stream_id", m.StreamID),
		)
		e.exitNode.HandleStreamClose(m.StreamID)
		return nil

	case protocol.StreamClose:
		logger.Debug("exit: handling StreamClose",
			zap.Int("stream_id", m.StreamID),
		)
		e.exitNode.HandleStreamClose(m.StreamID)
		return nil

	default:
		logger.Warn("unknown message type at exit node",
			zap.String("type", fmt.Sprintf("%T", msg)),
		)
		return fmt.Errorf("unknown message type at exit: %T", msg)
	}
}

// GetCircuit retrieves a circuit by ID
func (e *Engine) GetCircuit(id []byte) (*Circuit, bool) {
	v, ok := e.circuits.Load(string(id))
	if !ok {
		return nil, false
	}
	return v.(*Circuit), true
}

// GetCircuitCount returns the number of active circuits
func (e *Engine) GetCircuitCount() int {
	count := 0
	e.circuits.Range(func(k, v interface{}) bool {
		count++
		return true
	})
	return count
}

// RegisterTunnelMidpoint creates and registers a tunnel midpoint for a circuit
// This allows the circuit to receive data via UDP tunnel packets
func (e *Engine) RegisterTunnelMidpoint(circuit *Circuit, senderPubKey ed25519.PublicKey, nextHopAddr net.Addr) error {
	proxyNode := e.server.GetProxyNode()
	if proxyNode == nil {
		return fmt.Errorf("proxy node not initialized")
	}

	// Generate ephemeral keys for this midpoint
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("generate midpoint key: %w", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	// Create midpoint configuration
	cfg := tunnel.MidpointConfig{
		PrivateKey:  priv,
		PublicKey:   pub,
		SenderKey:   senderPubKey,
		NextHopAddr: nextHopAddr,
	}

	midpoint, err := tunnel.NewTunnelMidpoint(cfg)
	if err != nil {
		return fmt.Errorf("create midpoint: %w", err)
	}

	// Set the UDP connection
	if conn := e.server.GetUDPConn(); conn != nil {
		midpoint.SetConnection(conn)
	}

	// Register with proxy node
	proxyNode.AddMidpoint(midpoint)

	// Store midpoint reference in circuit (for cleanup)
	keyHash := midpoint.KeyHash()
	circuit.TunnelKeyHash = keyHash

	e.server.GetLogger().Info("registered tunnel midpoint",
		zap.String("circuit_id", hex.EncodeToString(circuit.ID)[:16]),
		zap.String("key_hash", hex.EncodeToString(keyHash[:])[:16]),
	)

	return nil
}

// UnregisterTunnelMidpoint removes the tunnel midpoint for a circuit
func (e *Engine) UnregisterTunnelMidpoint(circuit *Circuit) {
	proxyNode := e.server.GetProxyNode()
	if proxyNode == nil {
		return
	}

	// Remove from proxy node if we have a key hash
	var emptyHash [32]byte
	if circuit.TunnelKeyHash != emptyHash {
		proxyNode.RemoveMidpoint(circuit.TunnelKeyHash)
	}
}

// SendViaTunnel sends data through the UDP tunnel to a specific address
func (e *Engine) SendViaTunnel(data []byte, destAddr net.Addr) error {
	conn := e.server.GetUDPConn()
	if conn == nil {
		return fmt.Errorf("UDP connection not available")
	}

	_, err := conn.WriteTo(data, destAddr)
	return err
}

// BuildTunnelPacket creates an encrypted tunnel packet for a route
func (e *Engine) BuildTunnelPacket(payload []byte, route *tunnel.Route, senderPrivKey ed25519.PrivateKey) ([]byte, error) {
	return tunnel.BuildOnionPacket(payload, route, senderPrivKey)
}
