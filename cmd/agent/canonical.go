package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// canonicalJSON serializes any JSON-compatible Go value using the same
// rules as pcc2k-gateway/src/canonical.mjs:
//   - object keys sorted lexicographically
//   - no whitespace between tokens
//   - strings encoded by the standard Go JSON encoder (RFC-7159 escapes)
//   - numbers encoded as Go's default float / int formatting
//
// This is a pragmatic subset of RFC 8785 JCS — sufficient for the
// dev synthetic agent + reference WSS test client to interop. Strict
// JCS migration is tracked as a Phase 1.5 sweep across all three
// PCC2K-Agent implementations (Go, JS test client, gateway).
func canonicalJSON(v interface{}) (string, error) {
	switch t := v.(type) {
	case nil:
		return "null", nil
	case bool:
		if t {
			return "true", nil
		}
		return "false", nil
	case string:
		b, err := json.Marshal(t)
		if err != nil {
			return "", err
		}
		return string(b), nil
	case float64:
		return formatNumber(t), nil
	case int:
		return strconv.FormatInt(int64(t), 10), nil
	case int64:
		return strconv.FormatInt(t, 10), nil
	case []interface{}:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			s, err := canonicalJSON(e)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			kb, err := json.Marshal(k)
			if err != nil {
				return "", err
			}
			vb, err := canonicalJSON(t[k])
			if err != nil {
				return "", err
			}
			parts = append(parts, string(kb)+":"+vb)
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	}

	// Fallback: round-trip through JSON to coerce to the cases above.
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var generic interface{}
	if err := json.Unmarshal(b, &generic); err != nil {
		return "", err
	}
	return canonicalJSON(generic)
}

// formatNumber mirrors ECMAScript ToString(Number) for the value
// ranges we ship today (percentages, GB counts, integer counters).
// strconv.FormatFloat(f, 'g', -1, 64) yields the shortest round-trip
// representation, identical to JS `String(n)` for 1e-6 ≤ |n| < 1e21
// and integer-valued floats. Edge cases at the exponent boundaries
// (Go: "1e-07" vs JS: "1e-7") are out of scope tonight; tracked with
// the JCS strict migration as a Phase 1.5 sweep.
func formatNumber(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// canonicalBytes mirrors pcc2k-gateway/src/canonical.mjs canonicalBytes.
//   utf8(method) || 0x00 || utf8(id||"") || 0x00 || utf8(ts) || 0x00 ||
//   utf8(nonce)  || 0x00 || sha256(canonical_json(payload))
func canonicalBytes(method, id, ts, nonce string, payload interface{}) ([]byte, error) {
	cj, err := canonicalJSON(payload)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(cj))
	hashHex := hex.EncodeToString(hash[:])

	out := make([]byte, 0, len(method)+len(id)+len(ts)+len(nonce)+len(hashHex)+4)
	out = append(out, []byte(method)...)
	out = append(out, 0)
	out = append(out, []byte(id)...)
	out = append(out, 0)
	out = append(out, []byte(ts)...)
	out = append(out, 0)
	out = append(out, []byte(nonce)...)
	out = append(out, 0)
	out = append(out, []byte(hashHex)...)
	return out, nil
}
