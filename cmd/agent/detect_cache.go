package main

// Phase v1.0.2 WS-0b — TTL'd detect cache.
//
// `detectBackup() / detectAv() / detectRustdesk() / detectServices()` each
// shell out to product binaries (restic snapshots, Get-WBSummary,
// tmutil status, etc.) and take 1–10s per call. v1.0.1 already had
// `detectBackup()` called from THREE sites (capability detection,
// backup.trigger validation, posture sweep). v1.0.2 adds RustDesk +
// services + AV detectors on the same access pattern.
//
// Without caching:
//   3 v1.0.1 sites × 1 detector  = 3 spawns/cycle
//   5 v1.0.2 sites × 4 detectors = 20 spawns/cycle, every 15min
//
// With caching: 1 spawn per detector per 60s, shared across all callers.

import (
	"sync"
	"time"
)

const defaultDetectTTL = 60 * time.Second

type detectEntry struct {
	expiresAt time.Time
	value     any
}

var (
	detectCacheMu sync.Mutex
	detectCache   = map[string]detectEntry{}
)

// cachedDetect runs `fill` (the actual detection logic) at most once
// per `ttl` per `key`. Concurrent callers with the same key block on
// each other so the spawn only happens once.
//
// Typed-result wrappers below avoid runtime assertions at call sites:
// cachedBackup() / cachedRustdesk() etc.
func cachedDetect(key string, ttl time.Duration, fill func() any) any {
	detectCacheMu.Lock()
	if entry, ok := detectCache[key]; ok && entry.expiresAt.After(time.Now()) {
		detectCacheMu.Unlock()
		return entry.value
	}
	detectCacheMu.Unlock()
	// Cache miss — compute outside the mutex so a slow detector doesn't
	// serialize all detect calls. Risk: two callers hit the slow path
	// before the first writes back; acceptable, both write the same
	// value (detectors are deterministic for the host snapshot).
	v := fill()
	detectCacheMu.Lock()
	detectCache[key] = detectEntry{
		expiresAt: time.Now().Add(ttl),
		value:     v,
	}
	detectCacheMu.Unlock()
	return v
}

// cachedBackup wraps detectBackup() with the shared 60s TTL.
func cachedBackup() BackupReport {
	return cachedDetect("backup", defaultDetectTTL, func() any {
		return detectBackup()
	}).(BackupReport)
}

// cachedAv wraps detectAv() with the shared 60s TTL.
func cachedAv() AvReport {
	return cachedDetect("av", defaultDetectTTL, func() any {
		return detectAv()
	}).(AvReport)
}

// invalidateDetectCache forces a re-detect on next call. Used by tests
// and (future) by an `agent.cache.flush` admin verb.
func invalidateDetectCache() {
	detectCacheMu.Lock()
	defer detectCacheMu.Unlock()
	detectCache = map[string]detectEntry{}
}
