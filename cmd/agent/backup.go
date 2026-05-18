package main

// Phase 1 / v1.0.1 WS-D — mutable backup verbs.
//
// AGENT-PROTOCOL §10.1:
//   backup.trigger    server → agent  request  replies queued
//   backup.cancel     server → agent  request  cancels in-flight
//   backup.complete   agent  → server notification  terminal
//
// The "which binary to invoke" decision uses Phase 8's detectBackup()
// posture result. Per-product invocation matrix lives in
// backup_windows.go (wbadmin / veeam / macrium) and backup_unix.go
// (restic / borg / duplicati / macos-tm).
//
// FleetHub-side gate: Fl_Tenant.backupTriggerEnabled (Phase 9) +
// Fl_Device.backupProduct (Phase 8) — agent assumes FH has already
// authorized the dispatch.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	backupDefaultTimeout = 4 * time.Hour
	backupHardTimeout    = 24 * time.Hour
	backupLogDir         = "/var/lib/pcc2k-agent/backups"
)

// backupRun is the agent-local handle for an in-flight backup.
type backupRun struct {
	runID     string
	product   string
	cancel    context.CancelFunc
	startedAt time.Time
	logPath   string
	mu        sync.Mutex
	finished  bool
}

var (
	backupRunsMu sync.Mutex
	backupRuns   = map[string]*backupRun{}
)

type backupTriggerParams struct {
	RunID      string         `json:"runId"`
	Product    string         `json:"product"` // "wbadmin"|"veeam"|"macrium"|"restic"|"borg"|"duplicati"|"macos-tm"
	TimeoutMin int            `json:"timeoutMin"`
	Options    map[string]any `json:"options,omitempty"`
}

type backupCancelParams struct {
	RunID string `json:"runId"`
}

func init() {
	registerInboundHandler("backup.trigger", handleBackupTrigger)
	registerInboundHandler("backup.cancel", handleBackupCancel)
}

// ─── backup.trigger ────────────────────────────────────────────────

func handleBackupTrigger(s *session, frame *inboundFrame) {
	var params backupTriggerParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "backup.trigger: invalid params")
		return
	}
	if params.RunID == "" || params.Product == "" {
		_ = s.replyError(frame.ID, -32602, "backup.trigger: runId + product required")
		return
	}

	// Confirm the product the server asked us to run is what we actually
	// have. Agent's posture sweep is authoritative; FH may have stale data.
	detected := detectBackup()
	if detected.Product != params.Product {
		_ = s.replyError(frame.ID, -32050,
			fmt.Sprintf("backup.trigger: server requested %q but host has %q",
				params.Product, detected.Product))
		return
	}
	if detected.Product == "" || detected.Product == "none" {
		_ = s.replyError(frame.ID, -32051,
			"backup.trigger: no backup product detected on this host")
		return
	}

	// Refuse duplicate runId.
	backupRunsMu.Lock()
	if _, exists := backupRuns[params.RunID]; exists {
		backupRunsMu.Unlock()
		_ = s.replyError(frame.ID, -32052, "backup.trigger: runId already active")
		return
	}
	backupRunsMu.Unlock()

	timeout := time.Duration(params.TimeoutMin) * time.Minute
	if timeout <= 0 {
		timeout = backupDefaultTimeout
	}
	if timeout > backupHardTimeout {
		timeout = backupHardTimeout
	}

	// Per-run log file under /var/lib/pcc2k-agent/backups/.
	if err := os.MkdirAll(backupLogDir, 0755); err != nil {
		_ = s.replyError(frame.ID, -32053,
			fmt.Sprintf("backup.trigger: mkdir log dir: %v", err))
		return
	}
	logPath := filepath.Join(backupLogDir, params.RunID+".log")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	run := &backupRun{
		runID:     params.RunID,
		product:   params.Product,
		cancel:    cancel,
		startedAt: time.Now(),
		logPath:   logPath,
	}
	backupRunsMu.Lock()
	backupRuns[params.RunID] = run
	backupRunsMu.Unlock()

	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state":      "queued",
		"runId":      params.RunID,
		"product":    params.Product,
		"timeoutMin": int(timeout.Minutes()),
		"logPath":    logPath,
	})

	go runBackup(s, ctx, run, params.Options)
}

// ─── backup.cancel ─────────────────────────────────────────────────

func handleBackupCancel(s *session, frame *inboundFrame) {
	var params backupCancelParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "backup.cancel: invalid params")
		return
	}
	backupRunsMu.Lock()
	run, ok := backupRuns[params.RunID]
	backupRunsMu.Unlock()
	if !ok {
		_ = s.replyResult(frame.ID, map[string]interface{}{
			"state": "not-found",
			"runId": params.RunID,
		})
		return
	}
	run.cancel()
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state": "cancelling",
		"runId": params.RunID,
	})
}

// ─── runner ────────────────────────────────────────────────────────

// runBackup orchestrates a single backup run. dispatches to the
// per-platform invokeBackup which knows the per-product binary +
// flags. Streams output to the per-run log file; on exit emits
// backup.complete with the final state.
func runBackup(s *session, ctx context.Context, run *backupRun, opts map[string]any) {
	defer func() {
		backupRunsMu.Lock()
		delete(backupRuns, run.runID)
		backupRunsMu.Unlock()
	}()

	logFile, err := os.OpenFile(run.logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		emitBackupComplete(s, run, "failed", -1, fmt.Sprintf("open log file: %v", err))
		return
	}
	defer logFile.Close()

	exitCode, exitErr := invokeBackup(ctx, run.product, opts, logFile)

	run.mu.Lock()
	run.finished = true
	run.mu.Unlock()

	state := "ok"
	var errMsg string
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		state = "failed"
		errMsg = "exceeded timeout"
	case ctx.Err() == context.Canceled:
		state = "cancelled"
	case exitCode != 0 || exitErr != nil:
		state = "failed"
		if exitErr != nil {
			errMsg = exitErr.Error()
		} else {
			errMsg = fmt.Sprintf("exit code %d", exitCode)
		}
	}

	emitBackupComplete(s, run, state, exitCode, errMsg)
}

func emitBackupComplete(s *session, run *backupRun, state string, exitCode int, errMsg string) {
	body := map[string]interface{}{
		"runId":    run.runID,
		"product":  run.product,
		"state":    state,
		"exitCode": exitCode,
		"logPath":  run.logPath,
		"ts":       time.Now().UTC().Format(time.RFC3339Nano),
	}
	if errMsg != "" {
		body["errorMsg"] = errMsg
	}
	if err := s.notify("backup.complete", body); err != nil {
		log.Printf("backup.complete: send failed (runId=%s): %v", run.runID, err)
	}
}

// invokeBackup is defined per-platform (backup_unix.go,
// backup_windows.go). Streams stdout/stderr to logFile, returns
// the process exit code (or -1 if it didn't start) + any err.
