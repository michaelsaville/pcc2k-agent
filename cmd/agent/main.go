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
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/hkdf"
)

const protocolVersion = "1.0"

func main() {
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

	for {
		err := runSession(cfg)
		if err != nil {
			log.Printf("session ended: %v — reconnecting in 5s", err)
		}
		time.Sleep(5 * time.Second)
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
	cfg        agentConfig
	conn       *websocket.Conn
	proofKey   []byte
	sessionKey []byte
	heartbeatSec int
}

func runOnce(cfg agentConfig) error {
	s, err := dialAndHandshake(cfg)
	if err != nil {
		return err
	}
	defer s.conn.Close()
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

func (s *session) sendAuthed(method string, params interface{}) (string, error) {
	id := fmt.Sprintf("go-%d", time.Now().UnixNano())
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(nonceBytes)

	// canonicalBytes wants the JSON representation of params, not the
	// Go struct. Round-trip through json.Marshal/Unmarshal so we get
	// the same shape the gateway sees on the wire.
	rawParams, err := json.Marshal(params)
	if err != nil {
		return "", err
	}
	var generic interface{}
	if err := json.Unmarshal(rawParams, &generic); err != nil {
		return "", err
	}
	cb, err := canonicalBytes(method, id, ts, nonce, generic)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write(cb)
	macB64 := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	frame := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  generic,
		"auth": map[string]interface{}{
			"ts":    ts,
			"nonce": nonce,
			"mac":   macB64,
		},
	}
	if err := s.conn.WriteJSON(frame); err != nil {
		return "", fmt.Errorf("write %s: %w", method, err)
	}

	if err := s.conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return "", err
	}
	defer s.conn.SetReadDeadline(time.Time{})
	var resp map[string]interface{}
	if err := s.conn.ReadJSON(&resp); err != nil {
		return "", fmt.Errorf("read %s reply: %w", method, err)
	}
	if errObj, ok := resp["error"].(map[string]interface{}); ok {
		return "", fmt.Errorf("server error: %v", errObj["message"])
	}
	if result, ok := resp["result"].(map[string]interface{}); ok {
		if did, _ := result["deviceId"].(string); did != "" {
			return did, nil
		}
	}
	return "", nil
}

func runtimeOSVersion() string {
	if v := tryRead("/etc/os-release", ""); v != "" {
		// e.g. PRETTY_NAME="Ubuntu 24.04.1 LTS"
		osRel := readOsRelease()
		if pn := osRel["PRETTY_NAME"]; pn != "" {
			return pn
		}
	}
	return runtimeFamily()
}

func runtimeFamily() string {
	return detectFamily()
}

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
