// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

import (
	"context"
	"encoding/json"
	"fmt"
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

// ── 3.9-01: the flow probe's bus needle must reach the sidecar ──────────────
//
// A NetFlow v5 record has no free-text field, so it cannot carry the marker.
// KafkaStage knows that and sets ProbeSrc — the probe's RFC 5737 source
// address — as the alternative needle, and it PRINTS it in the query it shows
// the operator. The peek body did not send it, so the sidecar only ever looked
// for the text marker and every flow trace's bus hop reported a false
// not_seen while ClickHouse reported seen.
//
// sidecarStandIn is the Python sidecar's contract in Go: it matches a record
// on EITHER needle and refuses a probe_src outside the closed grammar.
func sidecarStandIn(t *testing.T, recordPayload string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Topic    string `json:"topic"`
			Marker   string `json:"marker"`
			ProbeSrc string `json:"probe_src"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"detail":"body is not JSON"}`, http.StatusBadRequest)
			return
		}
		if body.ProbeSrc != "" && !ValidProbeSrc(body.ProbeSrc) {
			http.Error(w, `{"detail":"probe_src outside the closed grammar"}`, http.StatusBadRequest)
			return
		}
		needles := []string{"cx_debug=" + body.Marker}
		if body.ProbeSrc != "" {
			needles = append(needles, body.ProbeSrc)
		}
		for _, n := range needles {
			if strings.Contains(recordPayload, n) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"records":[{"topic":%q,"partition":0,"offset":7,"timestamp_ms":1700,"excerpt":%q}],"scanned":4,"elapsed_s":0.2}`,
					body.Topic, recordPayload)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"records":[],"scanned":4,"elapsed_s":0.2}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFlowBusHopIsSeenBecauseTheProbeSrcNeedleIsSent(t *testing.T) {
	fp := NewFlowFingerprint(testMarker)
	// What goflow2 actually puts on netops.flows.raw: numbers and addresses,
	// no marker text anywhere.
	record := fmt.Sprintf(`{"src_addr":"%s","dst_addr":"%s","src_port":%d,"dst_port":%d,"proto":17,"bytes":1,"packets":1}`,
		fp.SrcAddr, fp.DstAddr, fp.SrcPort, fp.DstPort)
	srv := sidecarStandIn(t, record)

	api := New(Deps{KafkaPeek: NewKafkaPeek(srv.Client(), srv.URL, "tok")})
	e := api.KafkaStage(context.Background(), KindFlow, testMarker)
	if e.Verdict != VerdictSeen {
		t.Fatalf("the flow bus hop reported %s (%s) — the record IS on the bus", e.Verdict, e.Reason)
	}
	if e.EvidenceRef != "netops.flows.raw[0]@7" {
		t.Errorf("evidence ref = %q", e.EvidenceRef)
	}
	if !strings.Contains(e.Query, "probe_src="+fp.SrcAddr) {
		t.Errorf("the query shown to the operator does not name the needle actually sent: %q", e.Query)
	}
}

// A syslog record carries the marker verbatim, so the text needle still works
// and no probe_src is sent for it.
func TestSyslogBusHopSendsNoProbeSrc(t *testing.T) {
	var sent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ProbeSrc string `json:"probe_src"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		sent = body.ProbeSrc
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"records":[],"scanned":1,"elapsed_s":0.1}`))
	}))
	defer srv.Close()
	api := New(Deps{KafkaPeek: NewKafkaPeek(srv.Client(), srv.URL, "tok")})
	if e := api.KafkaStage(context.Background(), KindSyslog, testMarker); e.Verdict != VerdictNotSeen {
		t.Fatalf("verdict = %s", e.Verdict)
	}
	if sent != "" {
		t.Errorf("a syslog peek sent probe_src=%q; the text marker is its only needle", sent)
	}
}

// Zero trust in BOTH directions (§3): a probe_src outside the closed grammar
// never reaches the wire, so the sidecar cannot be steered into scanning the
// bus for arbitrary content by way of this API.
func TestKafkaPeekRefusesAProbeSrcOutsideTheClosedGrammar(t *testing.T) {
	var dialled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dialled = true
		_, _ = w.Write([]byte(`{"records":[]}`))
	}))
	defer srv.Close()
	peek := NewKafkaPeek(srv.Client(), srv.URL, "tok")
	for _, bad := range []string{"192.0.2.0", "192.0.2.255", "192.0.2.1 OR 1", "10.0.0.1", "192.0.2.", "192.0.2.01", "198.51.100.4"} {
		if _, err := peek(context.Background(), PeekRequest{
			Topic: "netops.flows.raw", Marker: testMarker, ProbeSrc: bad,
		}); err == nil {
			t.Errorf("probe_src %q was accepted", bad)
		}
	}
	if dialled {
		t.Error("a malformed probe_src reached the sidecar")
	}
}

// Every address the fingerprint can mint must pass the grammar both sides
// validate, or a legitimate trace would be refused.
func TestEveryFlowProbeSrcSatisfiesTheClosedGrammar(t *testing.T) {
	for i := 0; i < 2000; i++ {
		src := NewFlowFingerprint(NewMarker(time.Unix(int64(1757000000+i), 0))).SrcAddr
		if !ValidProbeSrc(src) {
			t.Fatalf("the fingerprint minted %q, which the grammar refuses", src)
		}
	}
	if ValidProbeSrc("") {
		t.Error("the empty string is the ABSENCE of a needle, not a needle")
	}
}
