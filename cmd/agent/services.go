package main

// Phase v1.0.2 WS-A — fleet.services.* verbs.
//
// AGENT-PROTOCOL §8:
//   fleet.services.list     server → agent  request   list installed services
//   fleet.services.start    server → agent  request   start <name>
//   fleet.services.stop     server → agent  request   stop <name>
//   fleet.services.restart  server → agent  request   restart <name>
//
// Per architect §4: cross-platform LIST (linux + windows + macOS).
// CONTROL only linux + windows; macOS hosts get fleet.processes
// capability but NOT fleet.services capability — list happens via
// fleet.processes.list on Darwin. (See capabilities.go for the
// per-platform append.)
//
// 4-eyes gate: applied FH-side via Phase 11 shouldRequireApproval().
// Agent does not re-check.

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	servicesListMaxBytes = 200 * 1024 // headroom under 256KB frame cap
)

// Service is the canonical cross-platform row.
type Service struct {
	Name        string `json:"name"`        // canonical service name
	DisplayName string `json:"displayName"` // operator-visible
	State       string `json:"state"`       // running | stopped | failed | unknown
	StartupType string `json:"startupType"` // auto | manual | disabled | unknown
}

type servicesListParams struct{}

type serviceControlParams struct {
	Name string `json:"name"`
}

var servicesListCacheMu sync.Mutex

func init() {
	registerInboundHandler("fleet.services.list", handleServicesList)
	registerInboundHandler("fleet.services.start", handleServicesStart)
	registerInboundHandler("fleet.services.stop", handleServicesStop)
	registerInboundHandler("fleet.services.restart", handleServicesRestart)
}

func handleServicesList(s *session, frame *inboundFrame) {
	servicesListCacheMu.Lock()
	defer servicesListCacheMu.Unlock()
	svcs, err := listServices()
	if err != nil {
		_ = s.replyError(frame.ID, -32603,
			fmt.Sprintf("fleet.services.list: collect failed: %v", err))
		return
	}
	result := map[string]interface{}{
		"services": svcs,
	}
	if rerr := s.replyResult(frame.ID, result); rerr != nil {
		if IsFrameTooLarge(rerr) {
			_ = s.replyError(frame.ID, errCodeResponseTooLarge,
				fmt.Sprintf("response too large (%d services)", len(svcs)))
		}
	}
}

func handleServicesStart(s *session, frame *inboundFrame) {
	handleServiceControl(s, frame, "start")
}

func handleServicesStop(s *session, frame *inboundFrame) {
	handleServiceControl(s, frame, "stop")
}

func handleServicesRestart(s *session, frame *inboundFrame) {
	handleServiceControl(s, frame, "restart")
}

func handleServiceControl(s *session, frame *inboundFrame, verb string) {
	var params serviceControlParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602,
			fmt.Sprintf("fleet.services.%s: invalid params", verb))
		return
	}
	name := strings.TrimSpace(params.Name)
	if name == "" {
		_ = s.replyError(frame.ID, -32602,
			fmt.Sprintf("fleet.services.%s: name required", verb))
		return
	}
	// Refuse names that look like shell injection (paranoia — the
	// per-platform impl already passes name as a separate exec arg,
	// but the operator should never see a "service started" response
	// for "; rm -rf /").
	if strings.ContainsAny(name, ";&|`$<>\n\r") {
		_ = s.replyError(frame.ID, -32602,
			fmt.Sprintf("fleet.services.%s: name contains shell metachars", verb))
		return
	}
	start := time.Now()
	out, err := controlService(name, verb)
	elapsed := time.Since(start)
	if err != nil {
		_ = s.replyResult(frame.ID, map[string]interface{}{
			"state":    "failed",
			"name":     name,
			"verb":     verb,
			"output":   out,
			"errorMsg": err.Error(),
			"elapsedMs": elapsed.Milliseconds(),
		})
		return
	}
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state":    "ok",
		"name":     name,
		"verb":     verb,
		"output":   out,
		"elapsedMs": elapsed.Milliseconds(),
	})
}

// listServices + controlService are implemented per-platform.
//   services_linux.go   — systemctl list-units / systemctl start|stop|restart
//   services_windows.go — Get-Service / sc.exe start|stop|Restart-Service
//   services_darwin.go  — launchctl list (control verbs return
//                         unsupported-os; fleet.services capability
//                         not advertised on macOS).
