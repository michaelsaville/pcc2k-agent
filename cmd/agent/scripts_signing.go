package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// AGENT-PROTOCOL §13: every scripts.exec carries scriptBody, scriptSha256
// (hex SHA-256 of body), and optionally scriptSig (base64 ed25519 over the
// hash bytes) + signerKid. HIPAA tenants reject unsigned scripts entirely;
// non-HIPAA tenants allow them but the operator UI flags them.
//
// The signer pubkey set is delivered by `agent.config.fetch` (Phase 1.5b);
// for now we expose a per-process map populated from env / flags. Once
// agent.config.fetch ships, this map is refreshed from the response.

var (
	pinnedSignerKeys = map[string]ed25519.PublicKey{}
	hipaaTenantMode  = false
)

// loadSignerKey adds a kid → pubkey entry. Pubkey is base64-encoded
// 32 bytes (ed25519 standard). Called from main during startup once
// the env (or future agent.config.fetch result) is parsed.
func loadSignerKey(kid, pubKeyB64 string) error {
	raw, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return fmt.Errorf("kid %s: invalid base64 pubkey: %w", kid, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("kid %s: pubkey is %d bytes, want %d", kid, len(raw), ed25519.PublicKeySize)
	}
	pinnedSignerKeys[kid] = ed25519.PublicKey(raw)
	return nil
}

// verifyScriptBody recomputes SHA-256(scriptBody) and compares against
// the hex-encoded scriptSha256 from the wire. Mismatch = the body was
// tampered between signer and us.
func verifyScriptBody(scriptBody, scriptSha256 string) error {
	if scriptSha256 == "" {
		return errors.New("scriptSha256 missing")
	}
	want, err := hex.DecodeString(scriptSha256)
	if err != nil {
		return fmt.Errorf("scriptSha256 not hex: %w", err)
	}
	got := sha256.Sum256([]byte(scriptBody))
	if subtleEqual(got[:], want) {
		return nil
	}
	return errors.New("script body sha256 mismatch")
}

// verifyScriptSig validates an ed25519 signature over the body's hash.
// scriptSig is base64. signerKid must resolve to a pinned pubkey.
//
// Empty sig + non-HIPAA tenant = OK (returns nil, signed=false). Empty sig
// + HIPAA tenant = reject. The caller logs `signed=false` when applicable.
func verifyScriptSig(scriptSig, signerKid, scriptSha256 string) (signed bool, err error) {
	if scriptSig == "" {
		if hipaaTenantMode {
			return false, errors.New("script.unsigned (HIPAA mode requires signed scripts)")
		}
		return false, nil
	}
	if signerKid == "" {
		return false, errors.New("script.signer_unknown (signature present, no kid)")
	}
	pubkey, ok := pinnedSignerKeys[signerKid]
	if !ok {
		return false, fmt.Errorf("script.signer_unknown (kid %q not pinned)", signerKid)
	}
	sig, err := base64.StdEncoding.DecodeString(scriptSig)
	if err != nil {
		return false, fmt.Errorf("scriptSig not base64: %w", err)
	}
	hash, err := hex.DecodeString(scriptSha256)
	if err != nil {
		return false, fmt.Errorf("scriptSha256 not hex: %w", err)
	}
	if !ed25519.Verify(pubkey, hash, sig) {
		return false, errors.New("script.sig_invalid")
	}
	return true, nil
}

// subtleEqual is a constant-time byte compare. Strictly speaking SHA-256
// equality is not a secret comparison, but using subtle.ConstantTimeCompare
// is the right habit and the cost is negligible.
func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
