// pcc2k-agent — the single Go binary that runs on every managed host
// and connects outbound to the WSS gateway.
//
// Phase 1 scope (today):
//   - WSS dial + handshake (agent.hello → session.proof) per
//     fleethub/docs/AGENT-PROTOCOL.md
//   - HMAC-signed inventory.report
//   - Heartbeat loop
//   - Linux inventory collection
//
// Phase 1 dev shortcuts (tracked):
//   - No mTLS (gateway accepts plain ws today; agent honors --insecure)
//   - Enrollment token via --token / PCC2K_AGENT_TOKEN env (production
//     stores in encrypted local cache per HIPAA-READY §1)
//   - One namespace: inventory.* + agent.heartbeat
//
// Phases 2-5 add scripts.*, software.*, patches.* etc.

package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/hkdf"
)

const protocolVersion = "1.0"

func main() {
	// Windows: when SCM started us, hand off to the service handler
	// before any flag parsing. The flags-pulled-from-config-file path
	// runs inside runAsService().
	if isWindowsService() {
		runAsService()
		return
	}

	// Subcommands (Windows-only effects, but the dispatch is shared).
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			if err := installService(os.Args[2:]); err != nil {
				fatal("install: %v", err)
			}
			return
		case "uninstall":
			if err := uninstallService(); err != nil {
				fatal("uninstall: %v", err)
			}
			return
		case "start":
			if err := startServiceCmd(); err != nil {
				fatal("start: %v", err)
			}
			return
		case "stop":
			if err := stopServiceCmd(); err != nil {
				fatal("stop: %v", err)
			}
			return
		}
	}

	runConsole()
}

func runConsole() {
	var (
		gatewayURL = flag.String("gateway", envDefault("PCC2K_GATEWAY_URL", "ws://127.0.0.1:3012/agent/v1"), "WSS gateway URL")
		token      = flag.String("token", os.Getenv("PCC2K_AGENT_TOKEN"), "enrollment token (or PCC2K_AGENT_TOKEN env)")
		agentID    = flag.String("agent-id", envDefault("PCC2K_AGENT_ID", ""), "Op_Agent.id (must match server-side)")
		clientName = flag.String("client", envDefault("PCC2K_CLIENT_NAME", "PCC2K (Internal)"), "TH_Client.name")
		hostname   = flag.String("hostname", envDefault("PCC2K_HOSTNAME", ""), "hostname to report (default = os.Hostname())")
		role       = flag.String("role", envDefault("PCC2K_ROLE", "server"), "free-form role tag (workstation/server/laptop/...)")
		once       = flag.Bool("once", false, "send one inventory.report and exit (smoke test mode)")
		insecure   = flag.Bool("insecure", false, "allow plain ws:// (dev only — production must use wss://)")
	)
	flag.Parse()

	if *token == "" {
		fatal("missing --token (or PCC2K_AGENT_TOKEN)")
	}
	if *agentID == "" {
		fatal("missing --agent-id (or PCC2K_AGENT_ID)")
	}

	hn := *hostname
	if hn == "" {
		h, _ := os.Hostname()
		hn = h
	}

	parsed, err := url.Parse(*gatewayURL)
	if err != nil {
		fatal("invalid --gateway URL: %v", err)
	}
	if parsed.Scheme == "ws" && !*insecure {
		fatal("plain ws:// requires --insecure (production must use wss://)")
	}

	cfg := agentConfig{
		gatewayURL: *gatewayURL,
		token:      *token,
		agentID:    *agentID,
		clientName: *clientName,
		hostname:   hn,
		role:       *role,
	}

	if *once {
		if err := runOnce(cfg); err != nil {
			fatal("once: %v", err)
		}
		return
	}

	runReconnectLoop(context.Background(), cfg)
}

// runReconnectLoop is the same supervisor loop runConsole() uses, but
// also called by the SCM service handler. Returns when ctx is
// cancelled — the service handler signals shutdown by cancelling.
func runReconnectLoop(ctx context.Context, cfg agentConfig) {
	for {
		if ctx.Err() != nil {
			return
		}
		err := runSession(cfg)
		if err != nil {
			log.Printf("session ended: %v — reconnecting in 5s", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

type agentConfig struct {
	gatewayURL string
	token      string
	agentID    string
	clientName string
	hostname   string
	role       string
}

type session struct {
	cfg          agentConfig
	conn         *websocket.Conn
	proofKey     []byte
	sessionKey   []byte
	heartbeatSec int

	// Bidirectional I/O state — see session_io.go.
	writeMu          sync.Mutex
	pendingMu        sync.Mutex
	pendingResponses map[string]chan *inboundFrame
}

func runOnce(cfg agentConfig) error {
	s, err := dialAndHandshake(cfg)
	if err != nil {
		return err
	}
	defer s.conn.Close()
	s.startIO()
	if _, err := s.sendInventoryReport(); err != nil {
		return fmt.Errorf("inventory.report: %w", err)
	}
	log.Println("once: inventory.report sent OK")
	return nil
}

func runSession(cfg agentConfig) error {
	s, err := dialAndHandshake(cfg)
	if err != nil {
		return err
	}
	defer s.conn.Close()

	// Spin up the reader goroutine. From here on out we never call
	// conn.ReadJSON directly — the reader demuxes everything and feeds
	// either a pending-response channel or an inbound dispatcher.
	readerDone := s.startIO()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("signal received, closing session")
		cancel()
	}()

	if _, err := s.sendInventoryReport(); err != nil {
		return fmt.Errorf("first inventory.report: %w", err)
	}
	log.Println("session: initial inventory.report OK")

	heartbeatTicker := time.NewTicker(time.Duration(s.heartbeatSec) * time.Second)
	defer heartbeatTicker.Stop()
	inventoryTicker := time.NewTicker(15 * time.Minute)
	defer inventoryTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-readerDone:
			// Reader exited — connection is dead. Trigger reconnect.
			return fmt.Errorf("reader exited")
		case <-heartbeatTicker.C:
			if _, err := s.sendHeartbeat(); err != nil {
				return fmt.Errorf("heartbeat: %w", err)
			}
		case <-inventoryTicker.C:
			if _, err := s.sendInventoryReport(); err != nil {
				return fmt.Errorf("periodic inventory: %w", err)
			}
		}
	}
}

func dialAndHandshake(cfg agentConfig) (*session, error) {
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 15 * time.Second
	conn, _, err := dialer.Dial(cfg.gatewayURL, nil)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	proofKey := hmacSha256([]byte(cfg.token), []byte("pcc2k.proof.v1"))

	hello := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "h-1",
		"method":  "agent.hello",
		"params": map[string]interface{}{
			"agentId":     cfg.agentID,
			"version":     "0.1.0-go",
			"os":          detectFamily(),
			"osVersion":   runtimeOSVersion(),
			"hostname":    cfg.hostname,
			"clientName":  cfg.clientName,
			"capabilities": []string{"agent", "inventory", "alerts"},
			"protocolMin": protocolVersion,
			"protocolMax": protocolVersion,
		},
	}
	if err := conn.WriteJSON(hello); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write hello: %w", err)
	}

	var challenge struct {
		Method string `json:"method"`
		Params struct {
			NonceS string `json:"nonceS"`
		} `json:"params"`
	}
	if err := conn.ReadJSON(&challenge); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read challenge: %w", err)
	}
	if challenge.Method != "session.challenge" {
		conn.Close()
		return nil, fmt.Errorf("unexpected method %q (want session.challenge)", challenge.Method)
	}
	nonceS, err := base64.StdEncoding.DecodeString(challenge.Params.NonceS)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("decode nonceS: %w", err)
	}

	nonceA := make([]byte, 32)
	if _, err := rand.Read(nonceA); err != nil {
		conn.Close()
		return nil, fmt.Errorf("rand nonceA: %w", err)
	}

	proofInput := append(append(append([]byte{}, nonceS...), nonceA...), []byte(cfg.agentID)...)
	proof := hmacSha256(proofKey, proofInput)

	proofFrame := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "h-2",
		"method":  "session.proof",
		"params": map[string]interface{}{
			"nonceA": base64.StdEncoding.EncodeToString(nonceA),
			"nonceS": base64.StdEncoding.EncodeToString(nonceS),
			"proof":  base64.StdEncoding.EncodeToString(proof),
		},
	}
	if err := conn.WriteJSON(proofFrame); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write proof: %w", err)
	}

	var accept struct {
		ID     string `json:"id"`
		Result struct {
			ProtocolVersion      string   `json:"protocolVersion"`
			ServerTime           string   `json:"serverTime"`
			AcceptedCapabilities []string `json:"acceptedCapabilities"`
			HeartbeatSec         int      `json:"heartbeatSec"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := conn.ReadJSON(&accept); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read accept: %w", err)
	}
	if accept.Error != nil {
		conn.Close()
		return nil, fmt.Errorf("session.accept error %d: %s", accept.Error.Code, accept.Error.Message)
	}

	salt := append(append([]byte{}, nonceS...), nonceA...)
	info := []byte(fmt.Sprintf("pcc2k.session.v1|%s", cfg.agentID))
	rdr := hkdf.New(sha256.New, proofKey, salt, info)
	sessionKey := make([]byte, 32)
	if _, err := rdr.Read(sessionKey); err != nil {
		conn.Close()
		return nil, fmt.Errorf("hkdf: %w", err)
	}

	hbSec := accept.Result.HeartbeatSec
	if hbSec <= 0 {
		hbSec = 30
	}
	log.Printf("session established with %s (proto %s, accepted %v)",
		cfg.gatewayURL, accept.Result.ProtocolVersion, accept.Result.AcceptedCapabilities)

	return &session{
		cfg:          cfg,
		conn:         conn,
		proofKey:     proofKey,
		sessionKey:   sessionKey,
		heartbeatSec: hbSec,
	}, nil
}

func (s *session) sendInventoryReport() (string, error) {
	inv := collectInventory()
	params := map[string]interface{}{
		"device": DeviceFacts{
			ClientName: s.cfg.clientName,
			Hostname:   s.cfg.hostname,
			OS:         detectFamily(),
			OSVersion:  runtimeOSVersion(),
			Role:       s.cfg.role,
		},
		"inventory": inv,
	}
	return s.sendAuthed("inventory.report", params)
}

func (s *session) sendHeartbeat() (string, error) {
	params := map[string]interface{}{
		"device": map[string]interface{}{
			"clientName": s.cfg.clientName,
			"hostname":   s.cfg.hostname,
		},
	}
	return s.sendAuthed("agent.heartbeat", params)
}

// sendAuthed wraps session.request for the existing inventory/heartbeat
// callers. Returns the deviceId string from result.deviceId for backwards
// compatibility with sendInventoryReport's prior contract.
func (s *session) sendAuthed(method string, params interface{}) (string, error) {
	resp, err := s.request(method, params)
	if err != nil {
		return "", err
	}
	if resp.Result == nil {
		return "", nil
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return "", nil
	}
	if did, _ := result["deviceId"].(string); did != "" {
		return did, nil
	}
	return "", nil
}

// runtimeOSVersion is per-OS (inventory_linux.go / inventory_windows.go).

func hmacSha256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func envDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func fatal(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "pcc2k-agent: "+format+"\n", a...)
	os.Exit(2)
}
