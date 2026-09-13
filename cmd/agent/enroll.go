package main

// Phase 1 / v1.0.1 WS-E — bootstrap enrollment.
//
// Called from main.go runConsole() when --bootstrap-token is set.
// Single-shot:
//   1. POST {token, hostname, os, osVersion} to FH
//      /api/agent-ingest/enroll
//   2. Receive {agentId, agentSecret, fleethubBaseUrl}
//   3. Print to stdout — operator's scripts/bootstrap.{sh,ps1}
//      parses these and writes them to a restricted secret file
//      that the systemd / Windows service uses via EnvironmentFile.
//   4. Exit 0 on success, non-zero on failure.
//
// The agent does NOT itself install the systemd unit / Windows
// service; that's the bootstrap script's job (it knows the host OS
// + has root/admin). Agent stays platform-agnostic for the
// enrollment step.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

type bootstrapRequest struct {
	Token     string `json:"token"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	OSVersion string `json:"osVersion"`
}

type bootstrapResponse struct {
	AgentID         string `json:"agentId"`
	AgentSecret     string `json:"agentSecret"`
	FleetHubBaseURL string `json:"fleethubBaseUrl"`
	GatewayURL      string `json:"gatewayUrl"`
	TenantName      string `json:"tenantName"`
	Error           string `json:"error,omitempty"`
}

// enrollRequest is the HTTP half of enrollment, shared by the legacy
// --bootstrap-token path and the 2026-09 `setup` path (per-tenant key).
// The server accepts either credential on the same endpoint.
func enrollRequest(fleethubURL, token string) (*bootstrapResponse, error) {
	if strings.TrimSpace(fleethubURL) == "" {
		return nil, fmt.Errorf("fleethubURL required")
	}
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("token required")
	}

	hn, _ := os.Hostname()
	body := bootstrapRequest{
		Token:     token,
		Hostname:  hn,
		OS:        runtime.GOOS,
		OSVersion: runtimeOSVersion(),
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	url := strings.TrimRight(fleethubURL, "/") + "/api/agent-ingest/enroll"
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pcc2k-agent/v1.0.1-bootstrap")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 201 {
		// Try to parse the standard error envelope.
		var errEnv struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(rawBody, &errEnv)
		if errEnv.Error != "" {
			return nil, fmt.Errorf("enroll HTTP %d: %s", resp.StatusCode, errEnv.Error)
		}
		return nil, fmt.Errorf("enroll HTTP %d: %s", resp.StatusCode, string(rawBody))
	}

	var result bootstrapResponse
	if err := json.Unmarshal(rawBody, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w (body=%s)", err, string(rawBody))
	}
	if result.AgentID == "" || result.AgentSecret == "" {
		return nil, fmt.Errorf("server returned empty agentId or agentSecret")
	}

	return &result, nil
}

func bootstrapEnroll(fleethubURL, token string) error {
	result, err := enrollRequest(fleethubURL, token)
	if err != nil {
		return err
	}
	// Print to stdout in env-file format. scripts/bootstrap.sh parses
	// this via sed; the Windows scripts/bootstrap.ps1 parses JSON
	// directly from the HTTP call instead and bypasses this format,
	// but we still print here so operators can see what enrolled.
	fmt.Fprintln(os.Stdout, "# pcc2k-agent enrolled successfully")
	fmt.Fprintf(os.Stdout, "# tenant=%s\n", result.TenantName)
	fmt.Fprintf(os.Stdout, "PCC2K_AGENT_ID=%s\n", result.AgentID)
	fmt.Fprintf(os.Stdout, "PCC2K_FLEETHUB_AGENT_SECRET=%s\n", result.AgentSecret)
	fmt.Fprintf(os.Stdout, "PCC2K_FLEETHUB_URL=%s\n", result.FleetHubBaseURL)

	return nil
}
