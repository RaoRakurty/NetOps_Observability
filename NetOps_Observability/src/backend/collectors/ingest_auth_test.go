package collectors

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ingest_auth_test.go — F-08.
//
// Two things are tested, and the second matters more than the first:
//   1. the credential is actually sent;
//   2. every ingest forwarder in this package OBSERVES a rejection.
//
// (2) is the guard for the class. Introducing authentication introduces a new
// way for three telemetry lanes to go completely silent — a wrong token means
// 401 on every POST — and before this change two of the three forwarders
// discarded the response status entirely. A credential added without a way to
// see it failing would have replaced one invisible failure with another.

func TestSetIngestAuthSendsBasicCredential(t *testing.T) {
	t.Setenv("INGEST_USER", "netops-ingest")
	t.Setenv("INGEST_TOKEN", "s3cret")
	resetIngestCredentialForTest()

	req, err := http.NewRequest(http.MethodPost, "http://example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	SetIngestAuth(req, LaneMetrics)

	user, pass, ok := req.BasicAuth()
	if !ok {
		t.Fatal("no Authorization header set — every ingest POST would be rejected")
	}
	if user != "netops-ingest" || pass != "s3cret" {
		t.Errorf("wrong credential: %q/%q", user, pass)
	}
}

func TestSetIngestAuthOmitsHeaderWhenUnset(t *testing.T) {
	// The documented upgrade window: Vector is the fail-closed half (it refuses
	// to start without INGEST_TOKEN), so an unauthenticated client can never
	// reach an unauthenticated collector by accident. Sending an EMPTY password
	// instead would be worse — it fails identically but reads as configured.
	t.Setenv("INGEST_TOKEN", "")
	resetIngestCredentialForTest()

	req, _ := http.NewRequest(http.MethodPost, "http://example/", nil)
	SetIngestAuth(req, LaneMetrics)
	if _, _, ok := req.BasicAuth(); ok {
		t.Error("an empty INGEST_TOKEN must send no header at all")
	}
	if IngestAuthConfigured() {
		t.Error("IngestAuthConfigured must report false with no token")
	}
}

// TestMetricForwarderReportsRejection: a 401 must be counted, not swallowed.
func TestMetricForwarderReportsRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("METRIC_EVENT_SINK_URL", srv.URL)
	t.Setenv("INGEST_TOKEN", "")
	resetIngestCredentialForTest()

	before := IngestRejections("metrics")
	sent := forwardMetricEvents(t.Context(), []MetricEvent{{Metric: "x", Device: "d"}})
	if sent != 0 {
		t.Errorf("a rejected batch must not be reported as sent, got %d", sent)
	}
	if got := IngestRejections("metrics"); got <= before {
		t.Errorf("rejection not counted: %d -> %d", before, got)
	}

	// With the credential present the same server accepts the batch, proving
	// the forwarder is sending it rather than merely counting failures.
	t.Setenv("INGEST_TOKEN", "s3cret")
	resetIngestCredentialForTest()
	if sent := forwardMetricEvents(t.Context(), []MetricEvent{{Metric: "x", Device: "d"}}); sent != 1 {
		t.Errorf("authenticated batch should be accepted, got sent=%d", sent)
	}
}

// TestEveryIngestForwarderChecksStatus is the CLASS guard: it scans this
// package's sources rather than exercising one call site, so a new ingest
// forwarder that ignores the response fails the build. That is the shape of
// defect the audit found four times over — the fix applied to one call site
// and not its siblings.
func TestEveryIngestForwarderChecksStatus(t *testing.T) {
	for _, file := range []string{"metric_events.go", "probe_events.go", "snmptrap.go"} {
		raw, err := os.ReadFile(file) // #nosec G304 -- fixed in-package source file
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		src := string(raw)
		if !strings.Contains(src, "SetIngestAuth(req, Lane") {
			t.Errorf("%s does not authenticate to the ingest tier (F-08)", file)
		}
		if !strings.Contains(src, "logIngestRejection(") {
			t.Errorf("%s does not observe a rejected ingest POST — the lane would die silently", file)
		}
	}
}

// ── SEC-013.1: per-lane credentials ─────────────────────────────────────────

func TestLaneTokensAreScopedWithSharedFallback(t *testing.T) {
	// Per-lane tokens when provisioned; the shared token remains the
	// fallback so a pre-SEC-013 deployment is bit-for-bit unchanged.
	t.Setenv("INGEST_TOKEN", "shared-legacy")
	t.Setenv("INGEST_TOKEN_BUS", "bus-only")
	t.Setenv("INGEST_TOKEN_METRICS", "metrics-only")
	resetIngestCredentialForTest()

	check := func(lane, want string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, "http://example/", nil)
		SetIngestAuth(req, lane)
		_, pass, ok := req.BasicAuth()
		if !ok || pass != want {
			t.Errorf("lane %s: got %q ok=%v, want %q", lane, pass, ok, want)
		}
	}
	check(LaneBus, "bus-only")
	check(LaneMetrics, "metrics-only")
	// Unprovisioned lanes ride the shared fallback (the accept-set window).
	check(LaneTraps, "shared-legacy")
	check(LaneProbes, "shared-legacy")
}

func TestUnknownLaneSendsNothing(t *testing.T) {
	// Fail closed: a typo'd lane name must not silently borrow another
	// lane's credential — the request goes out unauthenticated and the
	// server's 401 (plus the rejection counter) makes the bug loud.
	t.Setenv("INGEST_TOKEN", "shared")
	resetIngestCredentialForTest()
	req, _ := http.NewRequest(http.MethodPost, "http://example/", nil)
	SetIngestAuth(req, "no-such-lane")
	if _, _, ok := req.BasicAuth(); ok {
		t.Fatal("unknown lane must not send any credential")
	}
}
