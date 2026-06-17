package main

// WS-C — power control verbs (reboot / shutdown / logoff).
//
// Dispatched server→agent via the gateway like every other inbound
// command. The handler validates platform support, ACKs immediately
// with {state:"queued"}, then performs the action after a short grace
// so the reply frame flushes over the wire before the box goes down.
//
// FleetHub gates these behind a 4-eyes approval + TECH role on the
// server side; the agent just executes. Per-OS implementation lives in
// power_unix.go / power_windows.go.

import (
	"encoding/json"
	"time"
)

type powerParams struct {
	CommandID string `json:"commandId"`
	DelaySec  int    `json:"delaySec"`
	Message   string `json:"message"`
	Force     bool   `json:"force"`
}

func init() {
	registerInboundHandler("power.reboot", handlePowerReboot)
	registerInboundHandler("power.shutdown", handlePowerShutdown)
	registerInboundHandler("power.logoff", handlePowerLogoff)
}

func handlePowerReboot(s *session, frame *inboundFrame)   { handlePower(s, frame, "reboot") }
func handlePowerShutdown(s *session, frame *inboundFrame) { handlePower(s, frame, "shutdown") }
func handlePowerLogoff(s *session, frame *inboundFrame)   { handlePower(s, frame, "logoff") }

func handlePower(s *session, frame *inboundFrame, action string) {
	var p powerParams
	if len(frame.Params) > 0 {
		if err := json.Unmarshal(frame.Params, &p); err != nil {
			_ = s.replyError(frame.ID, -32602, action+": invalid params")
			return
		}
	}
	delay := p.DelaySec
	if delay < 0 {
		delay = 0
	}
	if delay > 3600 {
		delay = 3600 // cap at 1h so a typo can't park the box for days
	}

	// Validate platform support up front so the operator gets a real
	// error instead of a silent no-op (e.g. logoff on Linux).
	if err := powerActionSupported(action); err != nil {
		_ = s.replyError(frame.ID, -32060, err.Error())
		return
	}

	// ACK first; the actual power action runs after a short grace so the
	// reply flushes before the network/host drops.
	_ = s.replyResult(frame.ID, map[string]interface{}{
		"state":    "queued",
		"action":   action,
		"delaySec": delay,
	})

	go func() {
		time.Sleep(1500 * time.Millisecond)
		_ = doPowerAction(action, delay, p.Message, p.Force)
	}()
}
