package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// AGENT-PROTOCOL §22: software.* method bodies (Phase 3).
//
//   - software.install   server → agent  request
//   - software.uninstall server → agent  request
//   - software.detect    server → agent  request (lightweight, batch ≤50)
//   - software.progress  agent  → server notification (phase + stream)
//   - software.complete  agent  → server notification (terminal)
//
// Reuses the bidirectional plumbing in session_io.go: registers inbound
// handlers, kicks platform-specific code in a goroutine, streams progress
// chunks, emits the final frame. No new transport machinery — same write
// mutex, same response correlation, same ≤4 KiB chunked output cap.

type pkgRef struct {
	ID                string `json:"id"`
	Source            string `json:"source"`            // winget | choco | brew | apt | dnf | custom
	SourceID          string `json:"sourceId"`
	Version           string `json:"version,omitempty"`
	Scope             string `json:"scope,omitempty"`   // machine | user
	SilentInstallArgs string `json:"silentInstallArgs,omitempty"`
	ArtifactURL       string `json:"artifactUrl,omitempty"`    // custom only
	ArtifactSha256    string `json:"artifactSha256,omitempty"` // custom only
	BodyEd25519Sig    string `json:"bodyEd25519Sig,omitempty"`
}

// detectionRule is a minimally-typed JSON object — the agent decodes
// it into kind-specific shapes inside the handler. Kinds per
// PHASE-3-DESIGN §3.2: msi-product-code, registry-uninstall-key,
// file-version, winget-list, brew-list, custom-script. PCC2K extensions:
// dpkg-list, rpm-list, which.
type detectionRule = json.RawMessage

type softwareInstallParams struct {
	CommandID      string         `json:"commandId"`
	DeploymentID   string         `json:"deploymentId,omitempty"`
	Action         string         `json:"action,omitempty"` // "install" | "uninstall"
	Package        pkgRef         `json:"package"`
	DetectionRule  detectionRule  `json:"detectionRule,omitempty"`
	RebootPolicy   string         `json:"rebootPolicy,omitempty"`
	DryRun         bool           `json:"dryRun"`
	TimeoutSec     int            `json:"timeoutSec,omitempty"`
	OutputBytesCap int            `json:"outputBytesCap,omitempty"`
}

type softwareDetectParams struct {
	CommandID string `json:"commandId"`
	Checks    []struct {
		PackageID string        `json:"packageId"`
		Rule      detectionRule `json:"rule"`
	} `json:"checks"`
}

// softwareRun mirrors scriptRun: per-command state for streaming +
// cancellation. Only used for install/uninstall (detect is synchronous).
type softwareRun struct {
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
	softwareRunsMu sync.Mutex
	softwareRuns   = map[string]*softwareRun{}
)

func init() {
	registerInboundHandler("software.install", handleSoftwareInstall)
	registerInboundHandler("software.uninstall", handleSoftwareUninstall)
	registerInboundHandler("software.detect", handleSoftwareDetect)
}

func handleSoftwareInstall(s *session, frame *inboundFrame) {
	dispatchSoftwareCommand(s, frame, "install")
}

func handleSoftwareUninstall(s *session, frame *inboundFrame) {
	dispatchSoftwareCommand(s, frame, "uninstall")
}

func dispatchSoftwareCommand(s *session, frame *inboundFrame, defaultAction string) {
	var params softwareInstallParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, fmt.Sprintf("software.%s: invalid params", defaultAction))
		return
	}
	if params.CommandID == "" {
		_ = s.replyError(frame.ID, -32602, "commandId required")
		return
	}
	if params.Action == "" {
		params.Action = defaultAction
	}
	if params.OutputBytesCap == 0 {
		params.OutputBytesCap = defaultOutputBytesCap
	}

	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state":     "queued",
		"commandId": params.CommandID,
	})
	go runSoftwareCommand(s, &params)
}

func handleSoftwareDetect(s *session, frame *inboundFrame) {
	var params softwareDetectParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "software.detect: invalid params")
		return
	}
	results := make([]map[string]interface{}, 0, len(params.Checks))
	for _, check := range params.Checks {
		present, version, derr := runDetectionRule(check.Rule)
		entry := map[string]interface{}{
			"packageId": check.PackageID,
			"present":   present,
		}
		if version != "" {
			entry["detectedVersion"] = version
		}
		if derr != nil {
			entry["error"] = derr.Error()
		}
		results = append(results, entry)
	}
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"commandId": params.CommandID,
		"results":   results,
	})
}

func runSoftwareCommand(s *session, params *softwareInstallParams) {
	timeout := time.Duration(params.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	run := &softwareRun{
		commandID:  params.CommandID,
		cancel:     cancel,
		startedAt:  time.Now(),
		pendingBuf: map[string][]byte{"stdout": nil, "stderr": nil},
		pendingSeq: map[string]int{"stdout": 0, "stderr": 0},
		outputCap:  params.OutputBytesCap,
	}
	softwareRunsMu.Lock()
	softwareRuns[params.CommandID] = run
	softwareRunsMu.Unlock()
	defer func() {
		softwareRunsMu.Lock()
		delete(softwareRuns, params.CommandID)
		softwareRunsMu.Unlock()
	}()

	progress := func(phase, message string, percent int) {
		emitSoftwareProgress(s, run, phase, message, percent, "", "")
	}
	emitOut := func(stream, chunk string) {
		emitSoftwareProgress(s, run, "installing", "", -1, stream, chunk)
	}

	// Pre-detection: if already at requested version, short-circuit no-op.
	if params.Action == "install" && len(params.DetectionRule) > 0 {
		progress("verifying", "running pre-install detection", 5)
		present, version, _ := runDetectionRule(params.DetectionRule)
		if present && (params.Package.Version == "" || version == params.Package.Version) {
			flushSoftwareAll(s, run)
			emitSoftwareComplete(s, run, "no-op", 0, version, false, "already at requested version")
			return
		}
	}

	// Dry-run mode: no-op + report what would happen.
	if params.DryRun {
		emitOut("stdout", fmt.Sprintf(
			"[dry-run] would %s %s/%s%s\n",
			params.Action, params.Package.Source, params.Package.SourceID,
			func() string {
				if params.Package.Version != "" {
					return "@" + params.Package.Version
				}
				return ""
			}(),
		))
		flushSoftwareAll(s, run)
		emitSoftwareComplete(s, run, "no-op", 0, params.Package.Version, false, "dry-run")
		return
	}

	progress("downloading", "starting "+params.Action, 10)
	exitCode, exitMsg, rebootPending := execSoftware(ctx, run, params, emitOut, progress)
	flushSoftwareAll(s, run)

	// Post-detection: confirm version.
	postVersion := ""
	if exitCode == 0 && len(params.DetectionRule) > 0 {
		progress("verifying", "running post-install detection", 95)
		_, postVersion, _ = runDetectionRule(params.DetectionRule)
	}

	result := mapSoftwareResult(params.Action, exitCode, exitMsg, rebootPending)
	emitSoftwareComplete(s, run, result, exitCode, postVersion, rebootPending, exitMsg)
}

func mapSoftwareResult(action string, exitCode int, exitMsg string, rebootPending bool) string {
	if exitCode != 0 {
		return "failed"
	}
	if rebootPending {
		return "reboot-required"
	}
	if action == "uninstall" {
		return "installed" // historic naming; protocol uses same enum
	}
	return "installed"
}

func emitSoftwareProgress(s *session, run *softwareRun, phase, message string, percent int, stream, chunk string) {
	run.streamMu.Lock()
	defer run.streamMu.Unlock()

	// Stream chunks accumulate into pendingBuf and flush per-frame cap;
	// metadata-only frames (phase + percent + message) ship immediately.
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
		_ = s.notify("software.progress", params)
		return
	}

	if run.totalBytes >= run.outputCap {
		if !run.capExceeded {
			run.capExceeded = true
			log.Printf("software.progress: cap %d bytes exceeded for %s — truncating", run.outputCap, run.commandID)
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
		flushSoftwareStream(s, run, phase, stream)
		return
	}
	if run.flushTimer == nil {
		run.flushTimer = time.AfterFunc(outputFlushInterval, func() {
			flushSoftwareAll(s, run)
		})
	} else {
		run.flushTimer.Reset(outputFlushInterval)
	}
}

func flushSoftwareAll(s *session, run *softwareRun) {
	run.streamMu.Lock()
	defer run.streamMu.Unlock()
	if run.flushTimer != nil {
		run.flushTimer.Stop()
		run.flushTimer = nil
	}
	for _, stream := range []string{"stdout", "stderr"} {
		if len(run.pendingBuf[stream]) > 0 {
			flushSoftwareStream(s, run, "installing", stream)
		}
	}
}

func flushSoftwareStream(s *session, run *softwareRun, phase, stream string) {
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

	_ = s.notify("software.progress", map[string]interface{}{
		"commandId": run.commandID,
		"phase":     phase,
		"stream":    stream,
		"seq":       seq,
		"data":      frameData,
	})
}

func emitSoftwareComplete(s *session, run *softwareRun, result string, exitCode int, detectedVersion string, rebootPending bool, stderrTail string) {
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
		// §22.5 mandates inline tail (≤4 KiB) so the deploy monitor renders
		// without drilling. Truncate from the END (recent stderr is what
		// matters for failure diagnosis).
		if len(stderrTail) > outputFrameMaxBytes {
			stderrTail = stderrTail[len(stderrTail)-outputFrameMaxBytes:]
		}
		params["stderrTail"] = stderrTail
	}
	_ = s.notify("software.complete", params)
}
