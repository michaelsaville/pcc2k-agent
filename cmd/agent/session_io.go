package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Bidirectional session I/O.
//
// Phase 1 ran the WS as outbound-only: every WriteJSON was followed by a
// blocking ReadJSON for that exact reply. That precluded server-initiated
// RPCs (scripts.exec, software.install, patches.deploy, scripts.cancel,
// etc) because pushed frames would never get read.
//
// This file owns the post-handshake conn from now on:
//
//   - readerLoop: single goroutine, reads every inbound frame, demuxes by
//     `id` (→ pendingResponses chan) or `method` (→ inbound dispatcher).
//   - writeMu: serializes WriteJSON. gorilla/websocket WriteMessage is not
//     goroutine-safe.
//   - request(method, params): writes a frame and awaits its `id` reply on
//     a per-id channel. Replaces the read-after-write pattern.
//   - notify(method, params): fire-and-forget, no id, no awaited reply.
//     Used for streaming output and for events the server can't reply to.
//   - dispatchInbound(frame): routes server-pushed RPCs to handlers
//     registered via registerInboundHandler.

const (
	// Hard cap on a single response wait. The protocol's auth.ts window is
	// ±300s; 30s is a generous bound for any single round trip.
	requestTimeout = 30 * time.Second

	// Inbound frame channel buffer. If the dispatcher gets behind by more
	// than this, the reader blocks — which is fine; the gateway will
	// backpressure the server.
	inboundBufferSize = 64
)

// inboundFrame is a parsed JSON-RPC frame from the server. We keep
// params as RawMessage so each handler unmarshals into its own type.
type inboundFrame struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *frameError     `json:"error,omitempty"`
	Auth    *frameAuth      `json:"auth,omitempty"`
}

type frameError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type frameAuth struct {
	TS    string `json:"ts"`
	Nonce string `json:"nonce"`
	MAC   string `json:"mac"`
}

// inboundHandler runs in the reader goroutine path (see dispatchInbound).
// Long-running work MUST be moved to its own goroutine — blocking here
// stalls every other server-initiated RPC and our own response demux.
type inboundHandler func(s *session, frame *inboundFrame)

var inboundHandlers = map[string]inboundHandler{}

func registerInboundHandler(method string, h inboundHandler) {
	inboundHandlers[method] = h
}

// startIO must be called exactly once after dialAndHandshake. Spawns
// the reader goroutine and prepares state for request/notify. Returns
// a channel that closes when the reader exits (conn drop, parse error,
// etc) so the supervisor can trigger reconnect.
func (s *session) startIO() <-chan struct{} {
	s.pendingResponses = make(map[string]chan *inboundFrame)
	done := make(chan struct{})
	go s.readerLoop(done)
	return done
}

func (s *session) readerLoop(done chan struct{}) {
	defer close(done)
	for {
		var frame inboundFrame
		if err := s.conn.ReadJSON(&frame); err != nil {
			log.Printf("session: reader exiting: %v", err)
			s.failAllPending(fmt.Errorf("connection closed: %w", err))
			return
		}
		// Response to one of our outbound requests.
		if frame.ID != "" && (frame.Result != nil || frame.Error != nil) {
			s.deliverResponse(&frame)
			continue
		}
		// Server-initiated request or notification.
		if frame.Method != "" {
			s.dispatchInbound(&frame)
			continue
		}
		log.Printf("session: ignoring frame with neither method nor result/error (id=%q)", frame.ID)
	}
}

func (s *session) deliverResponse(frame *inboundFrame) {
	s.pendingMu.Lock()
	ch, ok := s.pendingResponses[frame.ID]
	if ok {
		delete(s.pendingResponses, frame.ID)
	}
	s.pendingMu.Unlock()
	if !ok {
		log.Printf("session: response with no pending request (id=%q)", frame.ID)
		return
	}
	// Non-blocking — the channel is buffered to size 1.
	select {
	case ch <- frame:
	default:
		log.Printf("session: dropped response (channel full) (id=%q)", frame.ID)
	}
}

func (s *session) dispatchInbound(frame *inboundFrame) {
	h, ok := inboundHandlers[frame.Method]
	if !ok {
		log.Printf("session: no handler for inbound method %q (id=%q)", frame.Method, frame.ID)
		// Per §15, unknown method → -32601. Only meaningful when the
		// server expected a response (i.e. id != "").
		if frame.ID != "" {
			s.replyError(frame.ID, -32601, "method not found")
		}
		return
	}
	h(s, frame)
}

func (s *session) failAllPending(cause error) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	for id, ch := range s.pendingResponses {
		// Wake waiters with a synthetic error frame.
		select {
		case ch <- &inboundFrame{
			ID:    id,
			Error: &frameError{Code: -32099, Message: cause.Error()},
		}:
		default:
		}
		delete(s.pendingResponses, id)
	}
}

// writeFrame serializes one frame to the wire under writeMu. Used by
// both request() and notify().
func (s *session) writeFrame(frame map[string]interface{}) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	defer s.conn.SetWriteDeadline(time.Time{})
	return s.conn.WriteJSON(frame)
}

// authedFrame builds an HMAC-signed envelope for `method` with `params`,
// using `id` for request/response correlation (empty for notifications).
func (s *session) authedFrame(method, id string, params interface{}) (map[string]interface{}, error) {
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(nonceBytes)

	rawParams, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	var generic interface{}
	if err := json.Unmarshal(rawParams, &generic); err != nil {
		return nil, err
	}
	cb, err := canonicalBytes(method, id, ts, nonce, generic)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write(cb)
	macB64 := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	frame := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  generic,
		"auth": map[string]interface{}{
			"ts":    ts,
			"nonce": nonce,
			"mac":   macB64,
		},
	}
	if id != "" {
		frame["id"] = id
	}
	return frame, nil
}

// request sends a server-bound RPC and blocks until the reply (or a
// timeout / connection drop). Replaces sendAuthed for outbound calls.
func (s *session) request(method string, params interface{}) (*inboundFrame, error) {
	id := fmt.Sprintf("go-%d", time.Now().UnixNano())
	frame, err := s.authedFrame(method, id, params)
	if err != nil {
		return nil, err
	}

	ch := make(chan *inboundFrame, 1)
	s.pendingMu.Lock()
	s.pendingResponses[id] = ch
	s.pendingMu.Unlock()

	if err := s.writeFrame(frame); err != nil {
		s.pendingMu.Lock()
		delete(s.pendingResponses, id)
		s.pendingMu.Unlock()
		return nil, fmt.Errorf("write %s: %w", method, err)
	}

	select {
	case resp := <-ch:
		if resp.Error != nil {
			return resp, fmt.Errorf("server error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		return resp, nil
	case <-time.After(requestTimeout):
		s.pendingMu.Lock()
		delete(s.pendingResponses, id)
		s.pendingMu.Unlock()
		return nil, fmt.Errorf("%s: timeout after %s", method, requestTimeout)
	}
}

// notify sends a fire-and-forget frame (no id, no awaited reply). Used
// for streaming chunks (scripts.output) and for terminal events the
// server doesn't reply to (scripts.complete, alert.fire).
func (s *session) notify(method string, params interface{}) error {
	frame, err := s.authedFrame(method, "", params)
	if err != nil {
		return err
	}
	return s.writeFrame(frame)
}

// reply* write the response side of a server-initiated RPC. Only used
// when an inbound handler needs to return a result/error to the server.
func (s *session) replyResult(id string, result interface{}) error {
	frame := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}
	return s.writeFrame(frame)
}

func (s *session) replyError(id string, code int, message string) error {
	frame := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
	}
	return s.writeFrame(frame)
}

// keep these as imports for files in the package
var _ = websocket.TextMessage
var _ = sync.Mutex{}
