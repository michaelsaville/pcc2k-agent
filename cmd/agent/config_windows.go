//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// configDir is the per-machine settings directory for the agent service.
// %ProgramData%\PCC2K is the canonical location for cross-user system
// data on Windows. The directory is created with default ACLs at install
// time — write access is restricted to Administrators + LocalSystem,
// which means the encrypted token blob (agent.dat) and config (config.json)
// can only be modified by elevated processes. Read access is broader,
// which is fine for the non-secret config.json and is the design point
// for the DPAPI blob (see dpapi_windows.go for the security argument).
func configDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "PCC2K")
}

const (
	configFileName = "config.json"
	tokenFileName  = "agent.dat" // DPAPI-encrypted enrollment token
)

// persistedConfig is the on-disk shape of the agent's non-secret
// configuration. The token is NOT in this struct — it lives in a
// separate DPAPI-encrypted blob.
type persistedConfig struct {
	GatewayURL string `json:"gatewayUrl"`
	AgentID    string `json:"agentId"`
	ClientName string `json:"clientName"`
	Hostname   string `json:"hostname"`
	Role       string `json:"role"`
	Insecure   bool   `json:"insecure"`
}

func saveConfig(cfg agentConfig, insecure bool) error {
	if err := os.MkdirAll(configDir(), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", configDir(), err)
	}
	pc := persistedConfig{
		GatewayURL: cfg.gatewayURL,
		AgentID:    cfg.agentID,
		ClientName: cfg.clientName,
		Hostname:   cfg.hostname,
		Role:       cfg.role,
		Insecure:   insecure,
	}
	body, err := json.MarshalIndent(pc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	configPath := filepath.Join(configDir(), configFileName)
	if err := os.WriteFile(configPath, body, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", configPath, err)
	}

	enc, err := dpapiProtect([]byte(cfg.token))
	if err != nil {
		return fmt.Errorf("dpapi protect: %w", err)
	}
	tokenPath := filepath.Join(configDir(), tokenFileName)
	if err := os.WriteFile(tokenPath, enc, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tokenPath, err)
	}
	return nil
}

func loadConfig() (agentConfig, bool, error) {
	configPath := filepath.Join(configDir(), configFileName)
	body, err := os.ReadFile(configPath)
	if err != nil {
		return agentConfig{}, false, fmt.Errorf("read %s: %w", configPath, err)
	}
	var pc persistedConfig
	if err := json.Unmarshal(body, &pc); err != nil {
		return agentConfig{}, false, fmt.Errorf("parse %s: %w", configPath, err)
	}

	tokenPath := filepath.Join(configDir(), tokenFileName)
	enc, err := os.ReadFile(tokenPath)
	if err != nil {
		return agentConfig{}, false, fmt.Errorf("read %s: %w", tokenPath, err)
	}
	plain, err := dpapiUnprotect(enc)
	if err != nil {
		return agentConfig{}, false, fmt.Errorf("dpapi unprotect: %w", err)
	}

	cfg := agentConfig{
		gatewayURL: pc.GatewayURL,
		token:      string(plain),
		agentID:    pc.AgentID,
		clientName: pc.ClientName,
		hostname:   pc.Hostname,
		role:       pc.Role,
	}
	return cfg, pc.Insecure, nil
}
