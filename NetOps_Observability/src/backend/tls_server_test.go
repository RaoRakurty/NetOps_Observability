// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"testing"

	"netops/backend/tlsconfig"
)

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

// TestParseFederationBundles: well-formed pairs parse; a missing '=' or empty
// side is fail-closed; empty input disables federation.
func TestParseFederationBundles(t *testing.T) {
	got, err := parseFederationBundles("west=/a.pem, east=/b.pem ")
	if err != nil || len(got) != 2 || got[0] != (tlsconfig.FederationEntry{Domain: "west", Path: "/a.pem"}) {
		t.Fatalf("good parse failed: %#v err=%v", got, err)
	}
	if g, err := parseFederationBundles(""); g != nil || err != nil {
		t.Fatalf("empty should disable federation: %#v err=%v", g, err)
	}
	for _, bad := range []string{"noequals", "=/p.pem", "dom="} {
		if _, err := parseFederationBundles(bad); err == nil {
			t.Errorf("parseFederationBundles(%q) must fail closed", bad)
		}
	}
}

// TestEnsureLocalDomain: enabling federation must always register the local
// trust domain (so same-domain mTLS keeps working), unless the operator already
// mapped it (then their entry wins, no duplicate).
func TestEnsureLocalDomain(t *testing.T) {
	t.Setenv("TLS_TRUST_DOMAIN", "netops")
	out := ensureLocalDomain([]tlsconfig.FederationEntry{{Domain: "west", Path: "/w.pem"}}, "/local-ca.pem")
	if len(out) != 2 || out[0] != (tlsconfig.FederationEntry{Domain: "netops", Path: "/local-ca.pem"}) {
		t.Fatalf("local domain must be prepended: %#v", out)
	}
	// Operator already listed the local domain → no duplicate, their path wins.
	in := []tlsconfig.FederationEntry{{Domain: "netops", Path: "/custom.pem"}, {Domain: "west", Path: "/w.pem"}}
	if out := ensureLocalDomain(in, "/local-ca.pem"); len(out) != 2 || out[0].Path != "/custom.pem" {
		t.Fatalf("explicit local domain must not be duplicated: %#v", out)
	}
}

// FuzzParseFederationBundles: the env parser must never panic on arbitrary input,
// and any successful parse must yield entries with non-empty domain and path.
func FuzzParseFederationBundles(f *testing.F) {
	for _, s := range []string{"", "a=/b.pem", "a=/b.pem,c=/d.pem", "noequals", "=/p", "d=", ",,,"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, err := parseFederationBundles(s)
		if err != nil {
			return
		}
		for _, e := range out {
			if e.Domain == "" || e.Path == "" {
				t.Fatalf("parseFederationBundles(%q) produced empty field: %#v", s, e)
			}
		}
	})
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

// TestHandshakeErrLogDoesNotSwallowPanics pins §10: http.Server.ErrorLog is the
// ONLY place net/http reports a recovered handler panic, and this writer is what
// is wired to it under TLS. It used to drop every line that was not a TLS
// handshake error, which is how a nil-map panic in POST /api/ai/feedback stayed
// invisible while nginx returned a bare 502. Both classes must be reported.
func TestHandshakeErrLogDoesNotSwallowPanics(t *testing.T) {
	m := &tlsMetrics{}
	w := handshakeErrLog{m: m}

	hs := []byte("http: TLS handshake error from 10.0.0.1:5000: remote error: tls: bad certificate\n")
	if n, err := w.Write(hs); err != nil || n != len(hs) {
		t.Fatalf("Write(handshake) = %d, %v", n, err)
	}
	if got := m.handshakeErrors.Load(); got != 1 {
		t.Fatalf("handshakeErrors = %d, want 1", got)
	}

	pan := []byte("http: panic serving 10.0.0.1:5001: assignment to entry in nil map\ngoroutine 42 [running]:\n")
	if n, err := w.Write(pan); err != nil || n != len(pan) {
		t.Fatalf("Write(panic) = %d, %v", n, err)
	}
	// A panic is NOT a handshake failure and must not be counted as one…
	if got := m.handshakeErrors.Load(); got != 1 {
		t.Fatalf("panic line counted as a handshake error: %d", got)
	}
	// …and a blank write must not manufacture a log line.
	if n, err := w.Write([]byte("   \n")); err != nil || n != 4 {
		t.Fatalf("Write(blank) = %d, %v", n, err)
	}
}
