package main

// Phase 8 Workstream B step 2 — posture detectors.
//
// Backup product + AV/EDR + BitLocker / FileVault + warranty
// reporting. Per-OS detectors live in posture_{linux,windows,darwin}.go
// behind build tags; this file owns the platform-neutral shapes +
// the HTTP poster to FleetHub.
//
// Wire format and ingest endpoints are defined on the FleetHub side
// (Phase 8 WS-B step 3 in fleethub/app/app/api/agent/posture/*).
// The agent posts directly via HTTPS with Bearer
// FLEETHUB_AGENT_SECRET — separate from the WSS session protocol
// because posture is heartbeat-frequency, fire-and-forget data
// with no need for command/response semantics.
//
// Activation: set --fleethub-url + --fleethub-agent-secret (or the
// matching env vars). If either is unset, posture is silently skipped
// and the agent continues with the existing inventory.report loop.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// BackupReport is the body for POST /api/agent/posture/backup.
// Fields match Fl_Device columns; nil/empty fields map to NULL.
type BackupReport struct {
	ClientName    string  `json:"clientName"`
	Hostname      string  `json:"hostname"`
	Product       string  `json:"product"` // "veeam"|"datto"|"restic"|"windows-backup"|"macos-tm"|"none"
	LastSuccessAt *string `json:"lastSuccessAt,omitempty"`
	LastErrorAt   *string `json:"lastErrorAt,omitempty"`
	LastErrorMsg  *string `json:"lastErrorMsg,omitempty"`
}

// AvReport is the body for POST /api/agent/posture/av.
type AvReport struct {
	ClientName        string  `json:"clientName"`
	Hostname          string  `json:"hostname"`
	Engine            string  `json:"engine"` // "defender"|"crowdstrike"|"sophos"|"sentinelone"|"bitdefender"|"none"
	Enabled           *bool   `json:"enabled,omitempty"`
	SignaturesAt      *string `json:"signaturesAt,omitempty"`
	BitlockerOn       *bool   `json:"bitlockerOn,omitempty"`
	WarrantyExpiresAt *string `json:"warrantyExpiresAt,omitempty"`
}

// postureClient wraps the HTTP transport. Constructed once at
// startup; the run-loop calls Send* on every tick.
type postureClient struct {
	baseURL string
	secret  string
	http    *http.Client
}

func newPostureClient(baseURL, secret string) *postureClient {
	return &postureClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		secret:  secret,
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// ready reports whether the client has enough config to actually send.
// Lets the main loop skip the cycle without erroring when an operator
// hasn't filled in --fleethub-url yet.
func (p *postureClient) ready() bool {
	return p != nil && p.baseURL != "" && p.secret != ""
}

func (p *postureClient) sendBackup(ctx context.Context, r BackupReport) error {
	return p.post(ctx, "/api/agent/posture/backup", r)
}

func (p *postureClient) sendAv(ctx context.Context, r AvReport) error {
	return p.post(ctx, "/api/agent/posture/av", r)
}

// Phase v1.0.2 WS-C — remote-access posture (RustDesk peer-id).
// Posted every posture cycle so Fl_Device.rustdeskId stays current
// without operator hand-entry.
func (p *postureClient) sendRemote(ctx context.Context, r RemoteReport) error {
	return p.post(ctx, "/api/agent/posture/remote", r)
}

// RemoteReport is the body for POST /api/agent/posture/remote.
// FleetHub stores rustdeskId on Fl_Device for the Phase 7 Remote tab.
type RemoteReport struct {
	ClientName string  `json:"clientName"`
	Hostname   string  `json:"hostname"`
	RustdeskID *string `json:"rustdeskId,omitempty"` // null = no RustDesk installed / could not read
}

func (p *postureClient) post(ctx context.Context, path string, body interface{}) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.secret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Limit error body read so a misconfigured proxy returning a
		// huge HTML page doesn't blow up the log.
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	return nil
}

// rfc3339Ptr formats t in RFC3339 (matches FleetHub's parseIso) or
// returns nil for the zero value.
func rfc3339Ptr(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// nilPtrString returns nil for empty input, else a pointer to s.
// Used for optional error-message fields.
func nilPtrString(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}

// boolPtr is the small helper Go avoids by convention but every
// posture branch needs.
func boolPtr(b bool) *bool { return &b }
