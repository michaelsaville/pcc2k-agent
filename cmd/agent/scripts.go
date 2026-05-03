package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// AGENT-PROTOCOL §21: scripts.* method bodies.
//
//   - scripts.exec     server → agent  request
//   - scripts.cancel   server → agent  request
//   - scripts.output   agent  → server notification (streamed chunks)
//   - scripts.complete agent  → server notification (terminal frame)
//
// This file owns:
//   - Inbound dispatch for scripts.exec / scripts.cancel
//   - In-memory tracking of running commandIds → cancel func
//   - Output streaming with frame-size + batching budgets per §21.2
//   - Completion frame emission per §21.3
//
// The actual process spawn is platform-specific:
//   - scripts_unix.go    (linux/darwin) — bash via os/exec
//   - scripts_windows.go (windows)      — powershell + JobObject

const (
	// §21.2 caps each output frame at 4 KiB. We flush at the byte cap
	// OR at the time budget, whichever comes first.
	outputFrameMaxBytes = 4 * 1024
	outputFlushInterval = 200 * time.Millisecond

	// Default output cap if the server doesn't specify outputBytesCap.
	defaultOutputBytesCap = 64 * 1024
)

type scriptExecParams struct {
	CommandID      string            `json:"commandId"`
	ScriptID       string            `json:"scriptId"`
	ScriptBody     string            `json:"scriptBody"`
	ScriptSig      string            `json:"scriptSig,omitempty"`
	SignerKid      string            `json:"signerKid,omitempty"`
	ScriptSha256   string            `json:"scriptSha256"`
	Interpreter    string            `json:"interpreter"`
	Args           []string          `json:"args,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	DryRun         bool              `json:"dryRun"`
	TimeoutSec     int               `json:"timeoutSec,omitempty"`
	OutputBytesCap int               `json:"outputBytesCap,omitempty"`
}

type scriptCancelParams struct {
	CommandID string `json:"commandId"`
	Reason    string `json:"reason,omitempty"`
}

// scriptRun tracks one in-flight script execution.
type scriptRun struct {
	commandID  string
	cancel     context.CancelFunc
	startedAt  time.Time
	totalBytes int

	// stdout/stderr stream state
	streamMu     sync.Mutex
	pendingBuf   map[string][]byte // keyed by "stdout"|"stderr"
	pendingSeq   map[string]int
	flushTimer   *time.Timer
	outputCap    int
	capExceeded  bool
}

var (
	scriptRunsMu sync.Mutex
	scriptRuns   = map[string]*scriptRun{}
)

func init() {
	registerInboundHandler("scripts.exec", handleScriptsExec)
	registerInboundHandler("scripts.cancel", handleScriptsCancel)
}

// handleScriptsExec is the entry-point for server → agent script
// dispatch. Per §10.1, long-running commands reply IMMEDIATELY with
// `{state: "queued", commandId}`; the actual output and exit are
// delivered via separate scripts.output + scripts.complete frames.
func handleScriptsExec(s *session, frame *inboundFrame) {
	var params scriptExecParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "scripts.exec: invalid params")
		return
	}
	if params.CommandID == "" {
		_ = s.replyError(frame.ID, -32602, "scripts.exec: commandId required")
		return
	}
	if params.OutputBytesCap == 0 {
		params.OutputBytesCap = defaultOutputBytesCap
	}

	// Body integrity (always required).
	if err := verifyScriptBody(params.ScriptBody, params.ScriptSha256); err != nil {
		_ = s.replyError(frame.ID, -32030, fmt.Sprintf("script.hash_mismatch: %v", err))
		return
	}
	// Signature (HIPAA tenants reject unsigned).
	signed, err := verifyScriptSig(params.ScriptSig, params.SignerKid, params.ScriptSha256)
	if err != nil {
		// Map to specific error code per §15.
		code := -32031 // script.unsigned
		msg := err.Error()
		if msg == "script.sig_invalid" {
			code = -32031 // tracked as unsigned-or-invalid; design doesn't differentiate yet
		}
		_ = s.replyError(frame.ID, code, msg)
		return
	}
	if !signed {
		log.Printf("scripts.exec: running unsigned script %q (commandId=%s)", params.ScriptID, params.CommandID)
	}

	// Reply queued IMMEDIATELY so the server knows the agent accepted
	// the dispatch. Output + complete arrive as later notifications.
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state":     "queued",
		"commandId": params.CommandID,
		"signed":    signed,
	})

	// Spawn the runner goroutine — we MUST NOT block the reader loop.
	go runScriptCommand(s, &params)
}

func handleScriptsCancel(s *session, frame *inboundFrame) {
	var params scriptCancelParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "scripts.cancel: invalid params")
		return
	}
	scriptRunsMu.Lock()
	run, ok := scriptRuns[params.CommandID]
	scriptRunsMu.Unlock()
	if !ok {
		// Not currently running — likely already finished.
		_ = s.replyResult(frame.ID, map[string]interface{}{
			"state":     "not-found",
			"commandId": params.CommandID,
		})
		return
	}
	run.cancel()
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state":     "cancelling",
		"commandId": params.CommandID,
	})
}

// runScriptCommand orchestrates the platform-specific spawn + output
// streaming + completion frame. Blocks until the process exits or the
// context is cancelled.
func runScriptCommand(s *session, params *scriptExecParams) {
	timeout := time.Duration(params.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	run := &scriptRun{
		commandID:  params.CommandID,
		cancel:     cancel,
		startedAt:  time.Now(),
		pendingBuf: map[string][]byte{"stdout": nil, "stderr": nil},
		pendingSeq: map[string]int{"stdout": 0, "stderr": 0},
		outputCap:  params.OutputBytesCap,
	}

	scriptRunsMu.Lock()
	scriptRuns[params.CommandID] = run
	scriptRunsMu.Unlock()
	defer func() {
		scriptRunsMu.Lock()
		delete(scriptRuns, params.CommandID)
		scriptRunsMu.Unlock()
	}()

	// Dry-run mode: don't actually exec — report what would happen.
	if params.DryRun {
		emitOutput(s, run, "stdout",
			fmt.Sprintf("[dry-run] would execute %s script %q (%d bytes, args=%v)",
				params.Interpreter, params.ScriptID, len(params.ScriptBody), params.Args))
		flushAll(s, run)
		emitComplete(s, run, 0, "dry-run")
		return
	}

	exitCode, exitMsg := execScript(ctx, run, params, func(stream, chunk string) {
		emitOutput(s, run, stream, chunk)
	})
	flushAll(s, run)
	emitComplete(s, run, exitCode, exitMsg)
}

// emitOutput appends to the per-stream pending buffer and either flushes
// at the byte cap OR sets a 200ms timer for the next opportunistic flush.
func emitOutput(s *session, run *scriptRun, stream, chunk string) {
	run.streamMu.Lock()
	defer run.streamMu.Unlock()

	if run.totalBytes >= run.outputCap {
		if !run.capExceeded {
			run.capExceeded = true
			log.Printf("scripts.output: cap %d bytes exceeded for %s — truncating", run.outputCap, run.commandID)
		}
		return
	}

	remaining := run.outputCap - run.totalBytes
	if len(chunk) > remaining {
		chunk = chunk[:remaining]
	}
	run.pendingBuf[stream] = append(run.pendingBuf[stream], []byte(chunk)...)
	run.totalBytes += len(chunk)

	// Flush immediately if a single stream exceeds the per-frame cap.
	if len(run.pendingBuf[stream]) >= outputFrameMaxBytes {
		flushStream(s, run, stream)
		return
	}
	// Otherwise schedule an opportunistic flush. Reuse the timer.
	if run.flushTimer == nil {
		run.flushTimer = time.AfterFunc(outputFlushInterval, func() {
			flushAll(s, run)
		})
	} else {
		run.flushTimer.Reset(outputFlushInterval)
	}
}

func flushAll(s *session, run *scriptRun) {
	run.streamMu.Lock()
	defer run.streamMu.Unlock()
	if run.flushTimer != nil {
		run.flushTimer.Stop()
		run.flushTimer = nil
	}
	for _, stream := range []string{"stdout", "stderr"} {
		if len(run.pendingBuf[stream]) > 0 {
			flushStream(s, run, stream)
		}
	}
}

// flushStream MUST be called under run.streamMu.
func flushStream(s *session, run *scriptRun, stream string) {
	buf := run.pendingBuf[stream]
	if len(buf) == 0 {
		return
	}
	// Frame at the §21.2 cap; remainder stays in the buffer for the next flush.
	frameLen := len(buf)
	if frameLen > outputFrameMaxBytes {
		frameLen = outputFrameMaxBytes
	}
	frameData := string(buf[:frameLen])
	run.pendingBuf[stream] = buf[frameLen:]
	seq := run.pendingSeq[stream]
	run.pendingSeq[stream] = seq + 1

	if err := s.notify("scripts.output", map[string]interface{}{
		"commandId": run.commandID,
		"stream":    stream,
		"seq":       seq,
		"data":      frameData,
	}); err != nil {
		log.Printf("scripts.output: send failed (commandId=%s, stream=%s): %v", run.commandID, stream, err)
	}
}

func emitComplete(s *session, run *scriptRun, exitCode int, exitMsg string) {
	durationMs := time.Since(run.startedAt).Milliseconds()
	params := map[string]interface{}{
		"commandId":   run.commandID,
		"exitCode":    exitCode,
		"durationMs":  durationMs,
		"outputBytes": run.totalBytes,
		// outputUrl + outputSha256 stay null until S3 lands. Per §21.3
		// these are optional whenever the buffered transcript is under cap.
	}
	if exitMsg != "" {
		params["exitMessage"] = exitMsg
	}
	if err := s.notify("scripts.complete", params); err != nil {
		log.Printf("scripts.complete: send failed (commandId=%s): %v", run.commandID, err)
	}
}
