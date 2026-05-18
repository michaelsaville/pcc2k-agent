package main

// Phase v1.0.2 WS-0b — capability sort-idempotency unit test.
// Architect §10 v1.0.1-hotfix pre-empt: slice sort drift would fire
// capabilities.update every cycle = infinite log spam. Lock the
// invariant.

import "testing"

func TestCanonicalizeCapabilitiesIsIdempotent(t *testing.T) {
	input := []string{
		"fleet.shell", "agent", "fleet.av", "inventory",
		"fleet.processes", "fleet.file", "alerts", "fleet.services",
		"fleet.backup",
	}
	first := canonicalizeCapabilities(input)
	for i := 0; i < 100; i++ {
		again := canonicalizeCapabilities(input)
		if !stringSliceEqual(first, again) {
			t.Fatalf("iteration %d: not idempotent (first=%v, again=%v)", i, first, again)
		}
	}
}

func TestCanonicalizeCapabilitiesDedupes(t *testing.T) {
	input := []string{
		"agent", "inventory", "agent", "alerts", "inventory",
		"fleet.shell", "fleet.shell",
	}
	out := canonicalizeCapabilities(input)
	want := []string{"agent", "alerts", "fleet.shell", "inventory"}
	if !stringSliceEqual(out, want) {
		t.Fatalf("dedupe failed: want %v got %v", want, out)
	}
}

func TestCanonicalizeCapabilitiesSorts(t *testing.T) {
	input := []string{"z", "a", "m", "fleet.shell", "agent"}
	out := canonicalizeCapabilities(input)
	want := []string{"a", "agent", "fleet.shell", "m", "z"}
	if !stringSliceEqual(out, want) {
		t.Fatalf("sort failed: want %v got %v", want, out)
	}
}

func TestCanonicalizeCapabilitiesEmpty(t *testing.T) {
	if got := canonicalizeCapabilities(nil); got != nil {
		t.Fatalf("empty in expects nil, got %v", got)
	}
	if got := canonicalizeCapabilities([]string{}); got != nil {
		t.Fatalf("empty slice expects nil, got %v", got)
	}
}

func TestStringSliceEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
		want bool
	}{
		{"both nil", nil, nil, true},
		{"both empty", []string{}, []string{}, true},
		{"identical", []string{"a", "b"}, []string{"a", "b"}, true},
		{"different len", []string{"a"}, []string{"a", "b"}, false},
		{"different elem", []string{"a", "b"}, []string{"a", "c"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := stringSliceEqual(tc.a, tc.b); got != tc.want {
				t.Errorf("stringSliceEqual(%v, %v) = %v; want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
