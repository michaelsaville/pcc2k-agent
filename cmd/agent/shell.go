package main

// Phase 1 / v1.0.1 WS-B — interactive shell session verbs.
//
// AGENT-PROTOCOL §10.1 (long-running RPCs):
//   shell.open    server → agent  request   replies queued
//   shell.input   server → agent  request   writes to stdin
//   shell.close   server → agent  request   terminates
//   shell.output  agent  → server notification   stdout/stderr chunks
//   shell.exited  agent  → server notification   terminal frame
//
// Mirrors the scripts.* pattern in scripts.go — the entry handler
// replies queued immediately so the server knows the agent accepted
// the dispatch; output + exit are delivered via later notifications.
//
// v1 uses plain stdio pipes (NOT a PTY). Most operator workflows
// — `dir`, `ls`, `ps`, `service status`, ad-hoc one-liners — work
// fine on line-buffered pipes. Full PTY (for vim/top/colored output
// + resize) is v1.0.2 polish (adds github.com/creack/pty dep + the
// Windows pseudoconsole branch).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os/exec"
	"sync"
	"time"
)

// ─── State ─────────────────────────────────────────────────────────

// shellSession is the agent-local handle for an open shell. The
// goroutine that owns the spawned process reads stdout/stderr +
// writes to stdin via channels.
type shellSession struct {
	sessionID    string
	cmd          *exec.Cmd
	stdin        io.WriteCloser
	cancel       context.CancelFunc
	startedAt    time.Time
	maxDuration  time.Duration
	bytesTx      int64 // operator → agent (input)
	bytesRx      int64 // agent → operator (output)
	mu           sync.Mutex
	closed       bool
	exitReasonCh chan string // closed when the goroutine emits shell.exited
}

var (
	shellSessionsMu sync.Mutex
	shellSessions   = map[string]*shellSession{}
)

const (
	shellDefaultMaxDuration = 60 * time.Minute
	shellHardMaxDuration    = 24 * time.Hour
	shellOutputFlushMs      = 200 * time.Millisecond
	shellOutputFrameMax     = 16 * 1024
)

// ─── Verb params ───────────────────────────────────────────────────

type shellOpenParams struct {
	SessionID      string `json:"sessionId"`
	MaxDurationMin int    `json:"maxDurationMin"` // 0 = default 60
}

type shellInputParams struct {
	SessionID string `json:"sessionId"`
	// Base64-encoded raw stdin bytes (the operator's keypresses).
	Bytes string `json:"bytes"`
}

type shellCloseParams struct {
	SessionID string `json:"sessionId"`
}

// ─── Router registration ───────────────────────────────────────────

func init() {
	registerInboundHandler("shell.open", handleShellOpen)
	registerInboundHandler("shell.input", handleShellInput)
	registerInboundHandler("shell.close", handleShellClose)
}

// ─── shell.open ────────────────────────────────────────────────────

func handleShellOpen(s *session, frame *inboundFrame) {
	var params shellOpenParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "shell.open: invalid params")
		return
	}
	if params.SessionID == "" {
		_ = s.replyError(frame.ID, -32602, "shell.open: sessionId required")
		return
	}

	maxDur := time.Duration(params.MaxDurationMin) * time.Minute
	if maxDur <= 0 {
		maxDur = shellDefaultMaxDuration
	}
	if maxDur > shellHardMaxDuration {
		maxDur = shellHardMaxDuration
	}

	// Refuse duplicate sessionId — server should never re-issue.
	shellSessionsMu.Lock()
	if _, exists := shellSessions[params.SessionID]; exists {
		shellSessionsMu.Unlock()
		_ = s.replyError(frame.ID, -32040, "shell.open: sessionId already active")
		return
	}
	shellSessionsMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), maxDur)
	cmd, stdin, stdout, stderr, err := spawnShell(ctx)
	if err != nil {
		cancel()
		_ = s.replyError(frame.ID, -32041, fmt.Sprintf("shell.open: spawn failed: %v", err))
		return
	}

	ss := &shellSession{
		sessionID:    params.SessionID,
		cmd:          cmd,
		stdin:        stdin,
		cancel:       cancel,
		startedAt:    time.Now(),
		maxDuration:  maxDur,
		exitReasonCh: make(chan string, 1),
	}
	shellSessionsMu.Lock()
	shellSessions[params.SessionID] = ss
	shellSessionsMu.Unlock()

	// Reply queued IMMEDIATELY so the server knows the agent accepted
	// dispatch. Output + exit arrive as later notifications.
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state":          "queued",
		"sessionId":      params.SessionID,
		"maxDurationMin": int(maxDur.Minutes()),
	})

	// Goroutines: stdout reader, stderr reader, waitloop.
	go ss.streamReader(s, "stdout", stdout)
	go ss.streamReader(s, "stderr", stderr)
	go ss.waitLoop(s)
}

// ─── shell.input ───────────────────────────────────────────────────

func handleShellInput(s *session, frame *inboundFrame) {
	var params shellInputParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "shell.input: invalid params")
		return
	}
	ss := lookupShellSession(params.SessionID)
	if ss == nil {
		_ = s.replyError(frame.ID, -32044, "shell.input: session not found")
		return
	}
	if params.Bytes == "" {
		_ = s.replyResult(frame.ID, map[string]interface{}{"ok": true, "bytesWritten": 0})
		return
	}
	raw, err := base64.StdEncoding.DecodeString(params.Bytes)
	if err != nil {
		_ = s.replyError(frame.ID, -32602, fmt.Sprintf("shell.input: bytes b64 decode: %v", err))
		return
	}
	ss.mu.Lock()
	if ss.closed {
		ss.mu.Unlock()
		_ = s.replyError(frame.ID, -32045, "shell.input: session already closed")
		return
	}
	n, werr := ss.stdin.Write(raw)
	if werr == nil {
		ss.bytesTx += int64(n)
	}
	ss.mu.Unlock()
	if werr != nil {
		_ = s.replyError(frame.ID, -32046, fmt.Sprintf("shell.input: write failed: %v", werr))
		return
	}
	_ = s.replyResult(frame.ID, map[string]interface{}{"ok": true, "bytesWritten": n})
}

// ─── shell.close ───────────────────────────────────────────────────

func handleShellClose(s *session, frame *inboundFrame) {
	var params shellCloseParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "shell.close: invalid params")
		return
	}
	ss := lookupShellSession(params.SessionID)
	if ss == nil {
		// Already-closed semantically equivalent to never-existed for the
		// server's cleanup flow.
		_ = s.replyResult(frame.ID, map[string]interface{}{
			"state":     "not-found",
			"sessionId": params.SessionID,
		})
		return
	}
	// Cancel the context — kills the process; waitLoop emits shell.exited.
	ss.cancel()
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state":     "closing",
		"sessionId": params.SessionID,
	})
}

// ─── Session helpers ───────────────────────────────────────────────

func lookupShellSession(id string) *shellSession {
	shellSessionsMu.Lock()
	defer shellSessionsMu.Unlock()
	return shellSessions[id]
}

func removeShellSession(id string) {
	shellSessionsMu.Lock()
	defer shellSessionsMu.Unlock()
	delete(shellSessions, id)
}

// streamReader reads from stdout or stderr until EOF and emits
// shell.output notifications. Chunks are line-flushed OR
// time-flushed (200ms) OR size-capped (16KB). Mirrors the
// scripts.output rhythm.
func (ss *shellSession) streamReader(s *session, stream string, r io.Reader) {
	buf := make([]byte, 4096)
	var pending []byte
	flushDeadline := time.NewTimer(shellOutputFlushMs)
	defer flushDeadline.Stop()

	flush := func() {
		if len(pending) == 0 {
			return
		}
		_ = s.notify("shell.output", map[string]interface{}{
			"sessionId": ss.sessionID,
			"stream":    stream,
			"bytes":     base64.StdEncoding.EncodeToString(pending),
			"ts":        time.Now().UTC().Format(time.RFC3339Nano),
		})
		ss.mu.Lock()
		ss.bytesRx += int64(len(pending))
		ss.mu.Unlock()
		pending = nil
	}

	for {
		// Try a non-blocking read first? gorilla doesn't expose deadline
		// on stdio pipes, so we do a blocking Read + rely on EOF from
		// process exit to terminate.
		n, err := r.Read(buf)
		if n > 0 {
			pending = append(pending, buf[:n]...)
			if len(pending) >= shellOutputFrameMax {
				flush()
				if !flushDeadline.Stop() {
					select {
					case <-flushDeadline.C:
					default:
					}
				}
				flushDeadline.Reset(shellOutputFlushMs)
			}
		}
		if err != nil {
			flush()
			return
		}
		// Drain timer + reset every iteration to opportunistically flush.
		select {
		case <-flushDeadline.C:
			flush()
			flushDeadline.Reset(shellOutputFlushMs)
		default:
		}
	}
}

// waitLoop blocks until the spawned process exits (natural / cancel /
// max-duration) and emits the terminal shell.exited frame.
func (ss *shellSession) waitLoop(s *session) {
	err := ss.cmd.Wait()
	ss.mu.Lock()
	ss.closed = true
	ss.mu.Unlock()
	removeShellSession(ss.sessionID)

	exitReason := "process-exit"
	exitCode := 0
	if err != nil {
		if exErr, ok := err.(*exec.ExitError); ok {
			exitCode = exErr.ExitCode()
		}
		// Context deadline / kill maps to max-duration or operator-close.
		// We can't always tell which from exec.ExitError alone — best
		// effort heuristic via duration elapsed.
		elapsed := time.Since(ss.startedAt)
		switch {
		case elapsed >= ss.maxDuration-time.Second:
			exitReason = "max-duration"
		case exitCode == -1:
			exitReason = "operator-close"
		default:
			exitReason = "process-exit"
		}
	}

	_ = s.notify("shell.exited", map[string]interface{}{
		"sessionId":  ss.sessionID,
		"exitReason": exitReason,
		"exitCode":   exitCode,
		"bytesTx":    ss.bytesTx,
		"bytesRx":    ss.bytesRx,
		"ts":         time.Now().UTC().Format(time.RFC3339Nano),
	})
	log.Printf("shell.exited: session=%s reason=%s code=%d tx=%d rx=%d",
		ss.sessionID, exitReason, exitCode, ss.bytesTx, ss.bytesRx)
}

// spawnShell is defined per-platform (shell_unix.go, shell_windows.go).
// Returns (cmd, stdin, stdout, stderr, error). Caller owns lifecycle.
