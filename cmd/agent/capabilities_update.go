package main

// Phase v1.0.2 WS-0b — capabilities.update notification.
//
// agent.hello carries the capability list at session start. But the
// detector runs ONCE at startup — if the operator installs CrowdStrike
// or restores a backup product DURING an active session, the agent's
// advertised capabilities go stale and FH's Phase-13 button gating
// stays wrong until the agent restarts.
//
// Fix: run the detector on the same cadence as the posture sweep
// (15min default) and fire `capabilities.update` when the sorted+
// deduped list differs from the last-advertised value.
//
// AGENT-PROTOCOL.md §23 documents the wire shape + the sort
// invariant.
//
// v1.0.1-hotfix pre-empt (architect §10):  the slice MUST be sorted
// deterministically before equality. Sort drift between detector
// calls would fire the notification every cycle = log-spam infinite
// loop. The unit test in capabilities_test.go asserts 100 runs return
// identical sorted output.

import (
	"log"
	"sort"
	"sync"
)

var (
	lastAdvertisedMu sync.Mutex
	lastAdvertised   []string // sorted+deduped snapshot
)

// recordInitialCapabilities caches what agent.hello advertised so the
// first cadence tick doesn't fire a spurious capabilities.update.
// Called from main.go right after the hello frame is sent.
func recordInitialCapabilities(caps []string) {
	canonical := canonicalizeCapabilities(caps)
	lastAdvertisedMu.Lock()
	lastAdvertised = canonical
	lastAdvertisedMu.Unlock()
}

// fireCapabilitiesUpdateIfChanged re-runs detectCapabilities(), sorts
// + dedupes, compares to the cached last-advertised list, and fires
// capabilities.update notify if different. No-op if unchanged.
func fireCapabilitiesUpdateIfChanged(s *session) {
	current := canonicalizeCapabilities(detectCapabilities())
	lastAdvertisedMu.Lock()
	prev := lastAdvertised
	lastAdvertisedMu.Unlock()
	if stringSliceEqual(current, prev) {
		return
	}
	// Push update, then cache.
	if err := s.notify("capabilities.update", map[string]interface{}{
		"capabilities": current,
	}); err != nil {
		log.Printf("capabilities.update: notify failed: %v", err)
		return
	}
	lastAdvertisedMu.Lock()
	lastAdvertised = current
	lastAdvertisedMu.Unlock()
	log.Printf("capabilities.update: advertised %d capabilities", len(current))
}

// canonicalizeCapabilities sorts + dedupes a capability slice into the
// deterministic form used for equality comparison. Exported lowercase
// for testability.
func canonicalizeCapabilities(caps []string) []string {
	if len(caps) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(caps))
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
