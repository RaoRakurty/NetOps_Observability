// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The sidecar base is DERIVED from CORRELATION_URL rather than guessed: on the
// hardened deployment that URL is https and the sidecar presents the same
// service certificate, so keeping the scheme is what lets the internal-mTLS
// client verify by name. Guessing http would silently downgrade.
func TestSidecarBaseDerivesSchemeAndHostFromCorrelationURL(t *testing.T) {
	cases := []struct {
		explicit, corr, want string
		wantErr              bool
	}{
		{explicit: "", corr: "https://correlation:8443", want: "https://correlation:8094"},
		{explicit: "", corr: "http://correlation:8000", want: "http://correlation:8094"},
		{explicit: "", corr: "https://correlation:8443/", want: "https://correlation:8094"},
		{explicit: "https://elsewhere:9999/", corr: "https://correlation:8443", want: "https://elsewhere:9999"},
		// NOT CONFIGURED: "" with NO error — an honest, expected state.
		{explicit: "", corr: "", want: ""},
		// MISCONFIGURED: "" WITH an error — an operator mistake that must be
		// named, never folded into "the feature is off" (§10).
		{explicit: "", corr: "::not a url::", want: "", wantErr: true},
		{explicit: "", corr: "https:///nohost", want: "", wantErr: true},
	}
	for _, c := range cases {
		got, err := SidecarBase(c.explicit, c.corr, DefaultSidecarPort)
		if got != c.want {
			t.Errorf("SidecarBase(%q,%q) = %q, want %q", c.explicit, c.corr, got, c.want)
		}
		if (err != nil) != c.wantErr {
			t.Errorf("SidecarBase(%q,%q) err = %v, wantErr %v — a MISCONFIGURED upstream must not look like an unconfigured one",
				c.explicit, c.corr, err, c.wantErr)
		}
	}
	if got, err := SidecarBase("", "https://correlation:8443", 70000); err != nil || got != "https://correlation:8094" {
		t.Errorf("an out-of-range port was not defaulted: %q (%v)", got, err)
	}
}

// Default-closed: with no token the peek REFUSES with a reason the stage turns
// into "not observable", rather than dialling an unauthenticated endpoint.
func TestKafkaPeekIsDefaultClosed(t *testing.T) {
	peek := NewKafkaPeek(&http.Client{}, "https://correlation:8094", "")
	if _, err := peek(context.Background(), PeekRequest{Topic: "netops.syslog", Marker: testMarker}); err == nil {
		t.Fatal("the peek dialled with no shared secret configured")
	}
	peek = NewKafkaPeek(&http.Client{}, "", "tok")
	if _, err := peek(context.Background(), PeekRequest{Topic: "netops.syslog", Marker: testMarker}); err == nil {
		t.Fatal("the peek dialled with no base URL configured")
	}
}

func TestKafkaPeekValidatesBeforeItDials(t *testing.T) {
	var dialled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dialled = true
		_, _ = w.Write([]byte(`{"records":[]}`))
	}))
	defer srv.Close()
	peek := NewKafkaPeek(srv.Client(), srv.URL, "tok")
	if _, err := peek(context.Background(), PeekRequest{Topic: "netops.syslog; drop", Marker: testMarker}); err == nil {
		t.Error("an illegal topic reached the sidecar")
	}
	if _, err := peek(context.Background(), PeekRequest{Topic: "netops.syslog", Marker: "bad"}); err == nil {
		t.Error("a malformed marker reached the sidecar")
	}
	if dialled {
		t.Error("the peek dialled before validating its arguments")
	}
}

func TestKafkaPeekSendsTheBearerAndDecodesTheAnswer(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"records":[{"topic":"netops.syslog","partition":1,"offset":9,"timestamp_ms":5,"excerpt":"x"}],"scanned":3,"elapsed_s":0.1}`))
	}))
	defer srv.Close()
	res, err := NewKafkaPeek(srv.Client(), srv.URL, "s3cret")(context.Background(),
		PeekRequest{Topic: "netops.syslog", Marker: testMarker, MaxSeconds: 10, MaxRecords: 5})
	if err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer s3cret" {
		t.Errorf("Authorization header = %q", auth)
	}
	if len(res.Records) != 1 || res.Records[0].Offset != 9 || res.Scanned != 3 {
		t.Errorf("peek result not decoded: %+v", res)
	}
}

func TestSidecarErrorsAreBoundedAndRedacted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom: snmp-server community peekLeak RO " + strings.Repeat("x", 4000)))
	}))
	defer srv.Close()
	_, err := NewKafkaPeek(srv.Client(), srv.URL, "tok")(context.Background(),
		PeekRequest{Topic: "netops.syslog", Marker: testMarker})
	if err == nil {
		t.Fatal("a 500 from the sidecar was not an error")
	}
	if strings.Contains(err.Error(), "peekLeak") {
		t.Error("the peer's error body reached the caller unredacted")
	}
	if len(err.Error()) > 1000 {
		t.Errorf("the peer's error body was not bounded: %d chars", len(err.Error()))
	}
}

func TestCorrLogLevelIsHonestWhenUnconfigured(t *testing.T) {
	change, err := NewCorrLogLevel(&http.Client{}, "", "")(context.Background(), LevelDebug, time.Minute)
	if err != nil {
		t.Fatalf("an unconfigured sidecar must be an honest answer, not an error: %v", err)
	}
	if change.Applied || change.Reason == "" {
		t.Errorf("an unconfigured sidecar reported %+v", change)
	}
}

// Hitting the read cap is a FAILURE, not a truncation: a clipped JSON body
// decodes to a plausible-looking partial answer, which is worse than an error.
func TestReadLimitedTreatsTheCapAsAFailure(t *testing.T) {
	if _, err := readLimited(strings.NewReader(strings.Repeat("x", 200)), 100); err == nil {
		t.Error("an over-cap body was returned truncated instead of refused")
	}
	got, err := readLimited(strings.NewReader("short"), 100)
	if err != nil || string(got) != "short" {
		t.Errorf("an under-cap body was mishandled: %q %v", got, err)
	}
}

// The metrics upstream is configured with credentials IN THE URL on the
// hardened deployment, and an error message is a log line (§8).
func TestErrorsNeverEchoURLCredentials(t *testing.T) {
	got := redactURL("https://svc-api:hunter2@vmauth:8427/api/v1/export?match[]=x")
	if strings.Contains(got, "hunter2") {
		t.Errorf("a URL password survived redaction: %q", got)
	}
	if !strings.Contains(got, "vmauth:8427") {
		t.Errorf("redaction destroyed the useful part of the URL: %q", got)
	}
}

func TestVictoriaExportRefusesAnEmptySelector(t *testing.T) {
	if _, err := NewVictoriaExport(&http.Client{}, "http://vm:8428")(context.Background(), "  ", time.Now(), time.Now()); err == nil {
		t.Error("an export with no series selector was allowed — it would dump the whole store")
	}
	if _, err := NewVictoriaExport(&http.Client{}, "")(context.Background(), "up", time.Now(), time.Now()); err == nil {
		t.Error("an export with no base URL was allowed")
	}
}

func TestUDPInjectorRefusesAnUnconfiguredTarget(t *testing.T) {
	if err := NewUDPInjector("", time.Second)(context.Background(), []byte("x")); err == nil {
		t.Error("the injector guessed a target rather than refusing")
	}
}
