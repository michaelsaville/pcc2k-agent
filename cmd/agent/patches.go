package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// AGENT-PROTOCOL §23: patches.* method bodies (Phase 4).
//
//   - patches.scan          server → agent  request
//   - patches.detect        server → agent  request (batch ≤50)
//   - patches.deploy        server → agent  request
//   - patches.uninstall     server → agent  request (rollback path)
//   - patches.advisory.fire agent  → server notification (one-shot)
//   - patches.progress      agent  → server notification (streamed)
//   - patches.complete      agent  → server notification (terminal)
//
// Reuses the bidirectional plumbing from session_io.go and the streaming
// helpers from software.go (renamed to be generic). patches.complete
// adds preflightGateFailed, detectionConsensus, perMethodDetection,
// rollbackStrategyUsed per §23.6.
//
// Multi-signal detection on Windows (§12 / §23.2):
//   - wmi-qfe        Get-HotFix → KB list
//   - dism-packages  DISM /Online /Get-Packages
//   - wu-history     Windows Update API history
//   "all-yes"       all methods say installed
//   "all-no"        all methods say missing
//   "disagreement"  alert-worthy: dashboards lying
//
// Linux/macOS scan + detect collapse to a single method (apt/dnf/brew).

type patchScanParams struct {
	CommandID         string   `json:"commandId"`
	FullRescan        bool     `json:"fullRescan,omitempty"`
	DetectionMethods  []string `json:"detectionMethods,omitempty"`
}

type patchDetectParams struct {
	CommandID string `json:"commandId"`
	Checks    []struct {
		PatchID string          `json:"patchId"`
		Rule    json.RawMessage `json:"rule"`
	} `json:"checks"`
}

type patchRef struct {
	ID             string `json:"id"`
	Source         string `json:"source"`         // ms | thirdparty | custom
	SourceID       string `json:"sourceId"`       // KB5036893 / Adobe.Acrobat.DC / custom:<id>
	IsHotpatch     bool   `json:"isHotpatch,omitempty"`
	RequiresReboot bool   `json:"requiresReboot,omitempty"`
	ArtifactURL    string `json:"artifactUrl,omitempty"`
	ArtifactSha256 string `json:"artifactSha256,omitempty"`
	BodyEd25519Sig string `json:"bodyEd25519Sig,omitempty"`
}

type preflightGate struct {
	MinDiskSpaceGb           int    `json:"minDiskSpaceGb,omitempty"`
	MaxRamPercent            int    `json:"maxRamPercent,omitempty"`
	RequireBackupWithinHours int    `json:"requireBackupWithinHours,omitempty"`
	RequireNoPendingReboot   bool   `json:"requireNoPendingReboot,omitempty"`
	RequireServiceHealth     bool   `json:"requireServiceHealth,omitempty"`
	RespectMaintenanceMode   bool   `json:"respectMaintenanceMode,omitempty"`
	CustomPreflightScriptID  string `json:"customPreflightScriptId,omitempty"`
}

type patchDeployParams struct {
	CommandID      string         `json:"commandId"`
	DeploymentID   string         `json:"deploymentId,omitempty"`
	Patch          patchRef       `json:"patch"`
	PreflightGate  preflightGate  `json:"preflightGate"`
	RebootPolicy   string         `json:"rebootPolicy,omitempty"`
	DryRun         bool           `json:"dryRun"`
	TimeoutSec     int            `json:"timeoutSec,omitempty"`
	OutputBytesCap int            `json:"outputBytesCap,omitempty"`
}

type patchUninstallParams struct {
	CommandID  string   `json:"commandId"`
	PatchID    string   `json:"patchId"`
	KbID       string   `json:"kbId,omitempty"`
	Strategies []string `json:"strategies"`
	TimeoutSec int      `json:"timeoutSec,omitempty"`
}

// patchRun mirrors softwareRun. Output cap + flush timer used for both
// progress streams and the post-deploy multi-signal detection summary.
type patchRun struct {
	commandID  string
	cancel     context.CancelFunc
	startedAt  time.Time
	totalBytes int

	streamMu    sync.Mutex
	pendingBuf  map[string][]byte
	pendingSeq  map[string]int
	flushTimer  *time.Timer
	outputCap   int
	capExceeded bool
}

var (
	patchRunsMu sync.Mutex
	patchRuns   = map[string]*patchRun{}
)

func init() {
	registerInboundHandler("patches.scan", handlePatchesScan)
	registerInboundHandler("patches.detect", handlePatchesDetect)
	registerInboundHandler("patches.deploy", handlePatchesDeploy)
	registerInboundHandler("patches.uninstall", handlePatchesUninstall)
}

func handlePatchesScan(s *session, frame *inboundFrame) {
	var params patchScanParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "patches.scan: invalid params")
		return
	}
	// Reply with a counts summary inline; the full report lands as a
	// `patches.report` notification (large payloads avoided in reply).
	go func() {
		results, err := scanInstalledPatches(params.DetectionMethods, params.FullRescan)
		if err != nil {
			_ = s.notify("patches.report", map[string]interface{}{
				"commandId": params.CommandID,
				"error":     err.Error(),
			})
			return
		}
		_ = s.notify("patches.report", map[string]interface{}{
			"commandId":      params.CommandID,
			"installedCount": len(results),
			"patches":        results,
		})
	}()
	// Synchronous reply lets the server know we accepted the scan.
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state":     "scanning",
		"commandId": params.CommandID,
	})
}

func handlePatchesDetect(s *session, frame *inboundFrame) {
	var params patchDetectParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "patches.detect: invalid params")
		return
	}
	results := make([]map[string]interface{}, 0, len(params.Checks))
	for _, check := range params.Checks {
		methods, consensus := runPatchDetection(check.Rule)
		results = append(results, map[string]interface{}{
			"patchId":   check.PatchID,
			"methods":   methods,
			"consensus": consensus,
		})
	}
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"commandId": params.CommandID,
		"results":   results,
	})
}

func handlePatchesDeploy(s *session, frame *inboundFrame) {
	var params patchDeployParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "patches.deploy: invalid params")
		return
	}
	if params.CommandID == "" {
		_ = s.replyError(frame.ID, -32602, "commandId required")
		return
	}
	if params.OutputBytesCap == 0 {
		params.OutputBytesCap = defaultOutputBytesCap
	}
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state":     "queued",
		"commandId": params.CommandID,
	})
	go runPatchDeploy(s, &params)
}

func handlePatchesUninstall(s *session, frame *inboundFrame) {
	var params patchUninstallParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "patches.uninstall: invalid params")
		return
	}
	if params.CommandID == "" {
		_ = s.replyError(frame.ID, -32602, "commandId required")
		return
	}
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state":     "queued",
		"commandId": params.CommandID,
	})
	go runPatchUninstall(s, &params)
}

func runPatchDeploy(s *session, params *patchDeployParams) {
	timeout := time.Duration(params.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	run := newPatchRun(params.CommandID, cancel, params.OutputBytesCap)
	defer endPatchRun(params.CommandID)

	progress := func(phase, message string, percent int) {
		emitPatchProgress(s, run, phase, message, percent, "", "")
	}
	emitOut := func(stream, chunk string) {
		emitPatchProgress(s, run, "installing", "", -1, stream, chunk)
	}

	// 1. Pre-flight gate.
	progress("verifying", "running pre-flight gate", 5)
	if gateName, ok := runPreflightGate(&params.PreflightGate); !ok {
		flushPatchAll(s, run)
		emitPatchComplete(s, run, "preflight-failed", -1, "", false,
			fmt.Sprintf("preflight gate failed: %s", gateName),
			gateName, "all-no", nil, "")
		return
	}

	// 2. Dry-run short-circuit.
	if params.DryRun {
		emitOut("stdout", fmt.Sprintf(
			"[dry-run] would deploy %s/%s%s\n",
			params.Patch.Source, params.Patch.SourceID,
			func() string {
				if params.Patch.IsHotpatch {
					return " (hotpatch — no reboot)"
				}
				return ""
			}(),
		))
		flushPatchAll(s, run)
		emitPatchComplete(s, run, "no-op", 0, "", false, "dry-run", "", "all-no", nil, "")
		return
	}

	// 3. Pre-deploy detection: skip if already installed.
	progress("verifying", "running pre-deploy detection", 10)
	preMethods, preConsensus := runPatchDetectionForPatch(&params.Patch)
	if preConsensus == "all-yes" {
		flushPatchAll(s, run)
		emitPatchComplete(s, run, "no-op", 0, "", false, "already installed", "", preConsensus, preMethods, "")
		return
	}

	// 4. Run the install.
	progress("downloading", "starting deploy", 15)
	exitCode, exitMsg := execPatchDeploy(ctx, run, params, emitOut, progress)
	flushPatchAll(s, run)

	// 5. Post-deploy multi-signal detection (§12 trust loop).
	progress("verifying", "running post-deploy detection", 90)
	postMethods, postConsensus := runPatchDetectionForPatch(&params.Patch)
	rebootPending := checkRebootPendingPlatform()
	result := mapPatchResult(exitCode, exitMsg, postConsensus, rebootPending, params.Patch.IsHotpatch)
	emitPatchComplete(s, run, result, exitCode, "", rebootPending, exitMsg, "", postConsensus, postMethods, "")
}

func runPatchUninstall(s *session, params *patchUninstallParams) {
	timeout := time.Duration(params.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	run := newPatchRun(params.CommandID, cancel, defaultOutputBytesCap)
	defer endPatchRun(params.CommandID)

	progress := func(phase, message string, percent int) {
		emitPatchProgress(s, run, phase, message, percent, "", "")
	}
	emitOut := func(stream, chunk string) {
		emitPatchProgress(s, run, "installing", "", -1, stream, chunk)
	}

	progress("downloading", "starting rollback", 10)
	strategy, exitCode, exitMsg := execPatchUninstall(ctx, run, params, emitOut, progress)
	flushPatchAll(s, run)

	var result string
	switch {
	case strategy != "" && exitCode == 0:
		result = "rolled-back"
	case strategy != "" && exitCode != 0:
		result = "rollback-partial"
	default:
		result = "rollback-failed"
	}
	emitPatchComplete(s, run, result, exitCode, "", false, exitMsg, "", "all-no", nil, strategy)
}

func mapPatchResult(exitCode int, exitMsg, postConsensus string, rebootPending, isHotpatch bool) string {
	if exitCode != 0 {
		return "failed"
	}
	if postConsensus == "disagreement" {
		return "detection-disagreement"
	}
	if rebootPending && !isHotpatch {
		// Server-side rebootPolicy on the deployment decides whether to
		// reboot now or defer. Agent surfaces the state honestly.
		return "reboot-required"
	}
	return "installed"
}

func newPatchRun(commandID string, cancel context.CancelFunc, outputCap int) *patchRun {
	if outputCap == 0 {
		outputCap = defaultOutputBytesCap
	}
	run := &patchRun{
		commandID:  commandID,
		cancel:     cancel,
		startedAt:  time.Now(),
		pendingBuf: map[string][]byte{"stdout": nil, "stderr": nil},
		pendingSeq: map[string]int{"stdout": 0, "stderr": 0},
		outputCap:  outputCap,
	}
	patchRunsMu.Lock()
	patchRuns[commandID] = run
	patchRunsMu.Unlock()
	return run
}

func endPatchRun(commandID string) {
	patchRunsMu.Lock()
	delete(patchRuns, commandID)
	patchRunsMu.Unlock()
}

// emitPatchProgress / flushPatchAll / flushPatchStream: same mechanics as
// the software equivalents, but ship `patches.progress` instead and
// preserve the §23.6 result-shape expectations on completion.

func emitPatchProgress(s *session, run *patchRun, phase, message string, percent int, stream, chunk string) {
	run.streamMu.Lock()
	defer run.streamMu.Unlock()

	if chunk == "" {
		params := map[string]interface{}{
			"commandId": run.commandID,
			"phase":     phase,
		}
		if percent >= 0 {
			params["percent"] = percent
		}
		if message != "" {
			params["message"] = message
		}
		_ = s.notify("patches.progress", params)
		return
	}

	if run.totalBytes >= run.outputCap {
		if !run.capExceeded {
			run.capExceeded = true
			log.Printf("patches.progress: cap %d bytes exceeded for %s — truncating", run.outputCap, run.commandID)
		}
		return
	}
	remaining := run.outputCap - run.totalBytes
	if len(chunk) > remaining {
		chunk = chunk[:remaining]
	}
	run.pendingBuf[stream] = append(run.pendingBuf[stream], []byte(chunk)...)
	run.totalBytes += len(chunk)

	if len(run.pendingBuf[stream]) >= outputFrameMaxBytes {
		flushPatchStream(s, run, phase, stream)
		return
	}
	if run.flushTimer == nil {
		run.flushTimer = time.AfterFunc(outputFlushInterval, func() {
			flushPatchAll(s, run)
		})
	} else {
		run.flushTimer.Reset(outputFlushInterval)
	}
}

func flushPatchAll(s *session, run *patchRun) {
	run.streamMu.Lock()
	defer run.streamMu.Unlock()
	if run.flushTimer != nil {
		run.flushTimer.Stop()
		run.flushTimer = nil
	}
	for _, stream := range []string{"stdout", "stderr"} {
		if len(run.pendingBuf[stream]) > 0 {
			flushPatchStream(s, run, "installing", stream)
		}
	}
}

func flushPatchStream(s *session, run *patchRun, phase, stream string) {
	buf := run.pendingBuf[stream]
	if len(buf) == 0 {
		return
	}
	frameLen := len(buf)
	if frameLen > outputFrameMaxBytes {
		frameLen = outputFrameMaxBytes
	}
	frameData := string(buf[:frameLen])
	run.pendingBuf[stream] = buf[frameLen:]
	seq := run.pendingSeq[stream]
	run.pendingSeq[stream] = seq + 1

	_ = s.notify("patches.progress", map[string]interface{}{
		"commandId": run.commandID,
		"phase":     phase,
		"stream":    stream,
		"seq":       seq,
		"data":      frameData,
	})
}

func emitPatchComplete(
	s *session,
	run *patchRun,
	result string,
	exitCode int,
	detectedVersion string,
	rebootPending bool,
	stderrTail string,
	preflightGateFailed string,
	detectionConsensus string,
	perMethodDetection map[string]bool,
	rollbackStrategyUsed string,
) {
	durationMs := time.Since(run.startedAt).Milliseconds()
	params := map[string]interface{}{
		"commandId":     run.commandID,
		"result":        result,
		"exitCode":      exitCode,
		"durationMs":    durationMs,
		"rebootPending": rebootPending,
	}
	if detectedVersion != "" {
		params["detectedVersion"] = detectedVersion
	}
	if stderrTail != "" {
		if len(stderrTail) > outputFrameMaxBytes {
			stderrTail = stderrTail[len(stderrTail)-outputFrameMaxBytes:]
		}
		params["stderrTail"] = stderrTail
	}
	if preflightGateFailed != "" {
		params["preflightGateFailed"] = preflightGateFailed
	}
	if detectionConsensus != "" {
		params["detectionConsensus"] = detectionConsensus
	}
	if perMethodDetection != nil {
		params["perMethodDetection"] = perMethodDetection
	}
	if rollbackStrategyUsed != "" {
		params["rollbackStrategyUsed"] = rollbackStrategyUsed
	}
	_ = s.notify("patches.complete", params)
}
