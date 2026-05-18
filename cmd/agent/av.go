package main

// Phase v1.0.2 WS-B — fleet.av.* verbs (Defender only in v1.0).
//
// AGENT-PROTOCOL §8 + §24:
//   fleet.av.scan          server → agent  request  long-running, queued
//   fleet.av.update-defs   server → agent  request  long-running, queued
//   fleet.av.quarantine    server → agent  request  per-threat, queued
//   fleet.av.release       server → agent  request  per-threat, queued
//   fleet.av.cancel        server → agent  request  cancels active scan
//   av.action-complete     agent  → server notif    terminal
//
// CRITICAL (§24): av.cancel MUST invoke product-native Stop-MpScan,
// NOT process.Kill. Defender scans run inside MsMpEng.exe; killing
// the agent's child PowerShell does NOT stop the scan.
//
// Per-product capability advertisement (architect §5 option a):
// fleet.av is advertised ONLY when defenderPresent() returns true.
// CrowdStrike hosts simply don't get the AV tab. No 502-on-click risk.

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"
)

const (
	avDefaultScanTimeout = 4 * time.Hour
	avHardScanTimeout    = 24 * time.Hour
)

// avRun is the agent-local handle for a long-running AV operation.
// Cancel via cancelOp() invokes Stop-MpScan in defenderCancelScan.
type avRun struct {
	runID     string
	verb      string // "scan" | "update-defs" | "quarantine" | "release"
	startedAt time.Time
	cancelOp  context.CancelFunc
	mu        sync.Mutex
	finished  bool
}

var (
	avRunsMu sync.Mutex
	avRuns   = map[string]*avRun{}
)

// AV verb params.
type avScanParams struct {
	RunID    string `json:"runId"`
	Kind     string `json:"kind"` // "quick" | "full" | "custom"
	ScanPath string `json:"scanPath,omitempty"`
}

type avUpdateDefsParams struct {
	RunID string `json:"runId"`
}

type avQuarantineParams struct {
	RunID    string `json:"runId"`
	ThreatID string `json:"threatId"`
}

type avReleaseParams struct {
	RunID    string `json:"runId"`
	ThreatID string `json:"threatId"`
}

type avCancelParams struct {
	RunID string `json:"runId"`
}

func init() {
	registerInboundHandler("fleet.av.scan", handleAvScan)
	registerInboundHandler("fleet.av.update-defs", handleAvUpdateDefs)
	registerInboundHandler("fleet.av.quarantine", handleAvQuarantine)
	registerInboundHandler("fleet.av.release", handleAvRelease)
	registerInboundHandler("fleet.av.cancel", handleAvCancel)
}

// ─── Verb handlers ─────────────────────────────────────────────────

func handleAvScan(s *session, frame *inboundFrame) {
	var params avScanParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "fleet.av.scan: invalid params")
		return
	}
	if params.RunID == "" {
		_ = s.replyError(frame.ID, -32602, "fleet.av.scan: runId required")
		return
	}
	if params.Kind != "quick" && params.Kind != "full" && params.Kind != "custom" {
		_ = s.replyError(frame.ID, -32602,
			"fleet.av.scan: kind must be quick | full | custom")
		return
	}
	if params.Kind == "custom" && params.ScanPath == "" {
		_ = s.replyError(frame.ID, -32602,
			"fleet.av.scan: scanPath required when kind=custom")
		return
	}

	avRunsMu.Lock()
	if _, exists := avRuns[params.RunID]; exists {
		avRunsMu.Unlock()
		_ = s.replyError(frame.ID, -32060, "fleet.av.scan: runId already active")
		return
	}
	avRunsMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), avDefaultScanTimeout)
	run := &avRun{
		runID:     params.RunID,
		verb:      "scan",
		startedAt: time.Now(),
		cancelOp:  cancel,
	}
	avRunsMu.Lock()
	avRuns[params.RunID] = run
	avRunsMu.Unlock()

	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state": "queued",
		"runId": params.RunID,
		"kind":  params.Kind,
	})
	go runAvScan(s, ctx, run, params.Kind, params.ScanPath)
}

func handleAvUpdateDefs(s *session, frame *inboundFrame) {
	var params avUpdateDefsParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "fleet.av.update-defs: invalid params")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	run := &avRun{runID: params.RunID, verb: "update-defs", startedAt: time.Now(), cancelOp: cancel}
	avRunsMu.Lock()
	avRuns[params.RunID] = run
	avRunsMu.Unlock()
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state": "queued", "runId": params.RunID,
	})
	go runAvUpdateDefs(s, ctx, run)
}

func handleAvQuarantine(s *session, frame *inboundFrame) {
	var params avQuarantineParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "fleet.av.quarantine: invalid params")
		return
	}
	if params.ThreatID == "" {
		_ = s.replyError(frame.ID, -32602, "fleet.av.quarantine: threatId required")
		return
	}
	go runAvQuarantine(s, params.RunID, params.ThreatID)
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state": "queued", "runId": params.RunID,
	})
}

func handleAvRelease(s *session, frame *inboundFrame) {
	var params avReleaseParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "fleet.av.release: invalid params")
		return
	}
	if params.ThreatID == "" {
		_ = s.replyError(frame.ID, -32602, "fleet.av.release: threatId required")
		return
	}
	go runAvRelease(s, params.RunID, params.ThreatID)
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state": "queued", "runId": params.RunID,
	})
}

func handleAvCancel(s *session, frame *inboundFrame) {
	var params avCancelParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "fleet.av.cancel: invalid params")
		return
	}
	avRunsMu.Lock()
	run, ok := avRuns[params.RunID]
	avRunsMu.Unlock()
	if !ok {
		_ = s.replyResult(frame.ID, map[string]interface{}{
			"state": "not-found", "runId": params.RunID,
		})
		return
	}
	// CRITICAL: invoke product-native cancel BEFORE context.cancel.
	// AGENT-PROTOCOL §24 — killing the agent's child process does
	// NOT stop a Defender scan; we must call Stop-MpScan first.
	if err := defenderCancelScan(); err != nil {
		log.Printf("fleet.av.cancel: defenderCancelScan returned %v "+
			"(falling back to context.cancel)", err)
	}
	run.cancelOp()
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state": "cancelling", "runId": params.RunID,
	})
}

// ─── Runners (call per-platform impl + emit av.action-complete) ────

func runAvScan(s *session, ctx context.Context, run *avRun, kind, scanPath string) {
	defer cleanupAvRun(run.runID)
	state, output, err := defenderScan(ctx, kind, scanPath)
	emitAvComplete(s, run, state, output, err)
}

func runAvUpdateDefs(s *session, ctx context.Context, run *avRun) {
	defer cleanupAvRun(run.runID)
	state, output, err := defenderUpdateDefs(ctx)
	emitAvComplete(s, run, state, output, err)
}

func runAvQuarantine(s *session, runID, threatID string) {
	state, output, err := defenderQuarantine(threatID)
	emitAvComplete(s, &avRun{runID: runID, verb: "quarantine"}, state, output, err)
}

func runAvRelease(s *session, runID, threatID string) {
	state, output, err := defenderRelease(threatID)
	emitAvComplete(s, &avRun{runID: runID, verb: "release"}, state, output, err)
}

func cleanupAvRun(runID string) {
	avRunsMu.Lock()
	delete(avRuns, runID)
	avRunsMu.Unlock()
}

func emitAvComplete(s *session, run *avRun, state, output string, err error) {
	body := map[string]interface{}{
		"runId":  run.runID,
		"verb":   run.verb,
		"state":  state,
		"ts":     time.Now().UTC().Format(time.RFC3339Nano),
		"output": output,
	}
	if err != nil {
		body["errorMsg"] = err.Error()
	}
	if nerr := s.notify("av.action-complete", body); nerr != nil {
		log.Printf("av.action-complete: send failed (runId=%s): %v", run.runID, nerr)
	}
}

// Per-platform implementations:
//   av_defender_windows.go — real Defender via PowerShell + Stop-MpScan
//   av_unsupported.go (linux + darwin) — all verbs return unsupported-os;
//     defenderPresent() returns false so capability not advertised.
//
// Function signatures shared:
//   defenderPresent() bool
//   defenderScan(ctx, kind, scanPath) (state, output, error)
//   defenderUpdateDefs(ctx) (state, output, error)
//   defenderQuarantine(threatID) (state, output, error)
//   defenderRelease(threatID) (state, output, error)
//   defenderCancelScan() error
//
// state ∈ {"ok", "failed", "cancelled", "unsupported-os", "unsupported-product"}
