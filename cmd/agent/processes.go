package main

// Phase v1.0.2 WS-A — fleet.processes.* verbs.
//
// AGENT-PROTOCOL §8 + §21:
//   fleet.processes.list   server → agent  request   cursor-paginated
//
// Canonical normalized schema (architect §7 — normalize-in-agent):
//   {pid: int, name: string, user: string, cpuPct: float|null,
//    rssMb: int, startedAt: ISO8601-UTC}
//
// `cpuPct` is single-core 0-100; null on first call (sample warming
// up). Per-platform impl owns the unit conversion.
//
// Cursor format: opaque base64(snapshotId + ":" + offset). 5min TTL.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	processesListDefaultLimit = 500
	processesListMaxLimit     = 500
	processesSnapshotTTL      = 5 * time.Minute
)

// Process is the canonical cross-platform row. Per-platform
// collectors fill this and the rest of the pipeline doesn't care
// which OS produced it.
type Process struct {
	PID       int     `json:"pid"`
	Name      string  `json:"name"`
	User      string  `json:"user"`
	CPUPct    *float64 `json:"cpuPct,omitempty"` // null on first sample
	RSSMb     int     `json:"rssMb"`
	StartedAt string  `json:"startedAt"`
}

// snapshot is the agent-local handle for a paginated processes list.
// One per cursor-call-chain. GC'd after TTL.
type snapshot struct {
	id        string
	createdAt time.Time
	rows      []Process
}

var (
	snapshotsMu sync.Mutex
	snapshots   = map[string]*snapshot{}
)

type processesListParams struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

func init() {
	registerInboundHandler("fleet.processes.list", handleProcessesList)
	// One-shot GC goroutine — sweep expired snapshots every minute.
	go snapshotGcLoop()
}

func handleProcessesList(s *session, frame *inboundFrame) {
	var params processesListParams
	if err := json.Unmarshal(frame.Params, &params); err != nil {
		_ = s.replyError(frame.ID, -32602, "fleet.processes.list: invalid params")
		return
	}
	limit := params.Limit
	if limit <= 0 || limit > processesListMaxLimit {
		limit = processesListDefaultLimit
	}

	snap, offset, err := resolveSnapshot(params.Cursor)
	if err != nil {
		// Cursor expired — surface via §22 error code.
		_ = s.replyError(frame.ID, errCodeCursorExpired,
			fmt.Sprintf("cursor expired: %v", err))
		return
	}
	// Fresh snapshot needed.
	if snap == nil {
		rows, cerr := collectProcesses()
		if cerr != nil {
			_ = s.replyError(frame.ID, -32603,
				fmt.Sprintf("fleet.processes.list: collect failed: %v", cerr))
			return
		}
		snap = &snapshot{
			id:        randSnapshotID(),
			createdAt: time.Now(),
			rows:      rows,
		}
		snapshotsMu.Lock()
		snapshots[snap.id] = snap
		snapshotsMu.Unlock()
	}

	end := offset + limit
	if end > len(snap.rows) {
		end = len(snap.rows)
	}
	page := snap.rows[offset:end]

	result := map[string]interface{}{
		"processes": page,
		"truncated": len(snap.rows) > processesListMaxLimit && offset == 0,
	}
	if end < len(snap.rows) {
		result["nextCursor"] = encodeCursor(snap.id, end)
	}
	if err := s.replyResult(frame.ID, result); err != nil {
		// If the response exceeds 256KB, retry with a smaller page.
		if IsFrameTooLarge(err) {
			_ = s.replyError(frame.ID, errCodeResponseTooLarge,
				"response too large — retry with smaller limit")
		}
	}
}

// ─── Cursor + snapshot management ──────────────────────────────────

func randSnapshotID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func encodeCursor(snapshotID string, offset int) string {
	raw := snapshotID + ":" + strconv.Itoa(offset)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// resolveSnapshot returns (snap, offset, err). When cursor is empty,
// snap is nil and offset is 0 (caller must collect a fresh snapshot).
// When cursor is set but expired/invalid, returns an error so the
// caller emits cursor-expired.
func resolveSnapshot(cursor string) (*snapshot, int, error) {
	if cursor == "" {
		return nil, 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return nil, 0, fmt.Errorf("malformed cursor: %v", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("malformed cursor")
	}
	offset, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, 0, fmt.Errorf("malformed cursor offset")
	}
	snapshotsMu.Lock()
	snap, ok := snapshots[parts[0]]
	snapshotsMu.Unlock()
	if !ok {
		return nil, 0, fmt.Errorf("snapshot not found (expired or never existed)")
	}
	return snap, offset, nil
}

func snapshotGcLoop() {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-processesSnapshotTTL)
		snapshotsMu.Lock()
		for id, snap := range snapshots {
			if snap.createdAt.Before(cutoff) {
				delete(snapshots, id)
			}
		}
		snapshotsMu.Unlock()
	}
}

// collectProcesses is implemented per-platform.
//   processes_linux.go   — parses /proc
//   processes_windows.go — parses tasklist /v /fo csv
//   processes_darwin.go  — parses ps aux
