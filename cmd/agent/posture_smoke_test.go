//go:build smoke

package main

// Smoke test for the posture path. Runs the per-OS detectors against
// the host the test runs on, then posts to a real FleetHub via the
// same HTTP poster the agent uses.
//
// Not part of the default test run — gated on `-tags smoke`. Run with:
//
//   PCC2K_FLEETHUB_URL=https://fleethub.pcc2k.com \
//   PCC2K_FLEETHUB_AGENT_SECRET=... \
//   PCC2K_CLIENT_NAME='PCC2K (Internal)' \
//   PCC2K_HOSTNAME=dochub-server \
//   go test -tags smoke ./cmd/agent -run TestPostureSmoke

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func TestPostureSmoke(t *testing.T) {
	url := os.Getenv("PCC2K_FLEETHUB_URL")
	secret := os.Getenv("PCC2K_FLEETHUB_AGENT_SECRET")
	if url == "" || secret == "" {
		t.Skip("posture smoke requires PCC2K_FLEETHUB_URL + PCC2K_FLEETHUB_AGENT_SECRET")
	}
	cfg := agentConfig{
		clientName: envOrDefault("PCC2K_CLIENT_NAME", "PCC2K (Internal)"),
		hostname:   envOrDefault("PCC2K_HOSTNAME", "smoke-host"),
	}
	p := newPostureClient(url, secret)
	if !p.ready() {
		t.Fatal("postureClient not ready")
	}

	ctx := context.Background()

	bk := detectBackup()
	bk.ClientName = cfg.clientName
	bk.Hostname = cfg.hostname
	t.Logf("backup detector: product=%s lastSuccess=%v err=%v",
		bk.Product, derefStr(bk.LastSuccessAt), derefStr(bk.LastErrorMsg))
	if err := p.sendBackup(ctx, bk); err != nil {
		t.Fatalf("sendBackup: %v", err)
	}

	av := detectAv()
	av.ClientName = cfg.clientName
	av.Hostname = cfg.hostname
	t.Logf("av detector: engine=%s enabled=%v sigs=%v bitlocker=%v",
		av.Engine, derefBool(av.Enabled), derefStr(av.SignaturesAt), derefBool(av.BitlockerOn))
	if err := p.sendAv(ctx, av); err != nil {
		t.Fatalf("sendAv: %v", err)
	}
}

func envOrDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
func derefBool(p *bool) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%v", *p)
}
