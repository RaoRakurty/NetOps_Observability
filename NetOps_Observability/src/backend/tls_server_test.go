package main

import "testing"

// TestBuildTLSServerDormant: with no TLS env, the API stays plaintext (nginx is
// the ingress terminator) — buildTLSServer returns (nil, nil), no error.
func TestBuildTLSServerDormant(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	ts, err := buildTLSServer()
	if err != nil || ts != nil {
		t.Fatalf("dormant mode: want (nil,nil), got (%v,%v)", ts, err)
	}
}

// TestBuildTLSServerFailClosed: a half-configured TLS (cert without key) must be
// a fatal error, never a silent downgrade to plaintext.
func TestBuildTLSServerFailClosed(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "/tmp/does-not-matter.crt")
	t.Setenv("TLS_KEY_FILE", "")
	if _, err := buildTLSServer(); err == nil {
		t.Fatal("cert without key must error (fail closed), not fall back to plaintext")
	}
}

func TestSplitCSV(t *testing.T) {
	got := splitCSV(" a , ,b,c ")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("splitCSV trimming/empty handling wrong: %#v", got)
	}
	if splitCSV("") != nil {
		t.Fatal("empty string should yield nil")
	}
}
