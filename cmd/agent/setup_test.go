package main

import "testing"

func TestKeyFromFilename(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef01234567"
	cases := map[string]string{
		`C:\Users\tech\Downloads\pcc2k-agent-` + key + `.exe`:                key,
		`C:\Users\tech\Downloads\pcc2k-agent-` + key + ` (1).exe`:            key,
		`/tmp/pcc2k-agent-` + key:                                            key,
		`PCC2K-AGENT-` + "0123456789ABCDEF0123456789ABCDEF01234567" + `.EXE`: key,
		`C:\Program Files\pcc2k-agent\pcc2k-agent.exe`:                       "",
		`pcc2k-agent-0123.exe`:                                               "",
		`pcc2k-agent-` + key + "zz.exe":                                      key, // trailing junk after 40 hex is fine
	}
	for in, want := range cases {
		if got := keyFromFilename(in); got != want {
			t.Errorf("keyFromFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSetupArgs(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef01234567"
	o, err := parseSetupArgs([]string{"--key", key, "--url", "https://fh.example.com/", "--no-pause"})
	if err != nil {
		t.Fatal(err)
	}
	if o.key != key || o.url != "https://fh.example.com" || !o.noPause || o.role != "workstation" {
		t.Errorf("unexpected options: %+v", o)
	}
	if _, err := parseSetupArgs([]string{"--url", "https://x"}); err == nil {
		t.Error("expected error when no key and plain filename")
	}
}
