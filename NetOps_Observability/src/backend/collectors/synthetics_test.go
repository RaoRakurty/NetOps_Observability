package collectors

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSynTargetsParsing(t *testing.T) {
	t.Setenv("SYNTHETIC_HTTP_TARGETS", "example.com, https://a.example/x ,")
	t.Setenv("SYNTHETIC_ICMP_TARGETS", "10.0.0.1")
	t.Setenv("SYNTHETIC_TCP_TARGETS", "db.example:5432")
	got := synTargets()
	want := []synTarget{
		{check: "http", dst: "https://example.com"}, // scheme defaulted
		{check: "http", dst: "https://a.example/x"},
		{check: "icmp", dst: "10.0.0.1"},
		{check: "tcp", dst: "db.example:5432"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d targets, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("target[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSynTargetsEmpty(t *testing.T) {
	t.Setenv("SYNTHETIC_HTTP_TARGETS", "")
	t.Setenv("SYNTHETIC_ICMP_TARGETS", "")
	t.Setenv("SYNTHETIC_TCP_TARGETS", "")
	if got := synTargets(); len(got) != 0 {
		t.Fatalf("expected no targets, got %+v", got)
	}
}

func TestCheckHTTPPlain(t *testing.T) {
	srv := httptest.NewServer(httpOK())
	defer srv.Close()
	s := &synthetics{timeout: 5 * time.Second}
	res := s.checkHTTP(context.Background(), synTarget{check: "http", dst: srv.URL})
	if !res.up {
		t.Fatalf("expected up, got %+v", res)
	}
	assertLine(t, res.lines, "synthetic_http_status_code", "200")
	assertHasMetric(t, res.lines, "synthetic_http_connect_ms")
	assertHasMetric(t, res.lines, "synthetic_http_ttfb_ms")
	assertHasMetric(t, res.lines, "synthetic_http_total_ms")
	// Plain HTTP: no TLS phase, no cert metric.
	for _, l := range res.lines {
		if strings.HasPrefix(l, "synthetic_http_cert_expiry_days") {
			t.Errorf("unexpected cert metric for plain http: %s", l)
		}
	}
}

func TestCheckHTTPTLS(t *testing.T) {
	srv := httptest.NewTLSServer(httpOK())
	defer srv.Close()
	// Trust the test server's CA via its preconfigured client transport —
	// production keeps full verification (we never skip verify).
	s := &synthetics{timeout: 5 * time.Second, transport: srv.Client().Transport}
	res := s.checkHTTP(context.Background(), synTarget{check: "http", dst: srv.URL})
	if !res.up {
		t.Fatalf("expected up, got %+v", res)
	}
	assertHasMetric(t, res.lines, "synthetic_http_tls_ms")
	assertHasMetric(t, res.lines, "synthetic_http_cert_expiry_days")
}

func TestCheckHTTPDown(t *testing.T) {
	s := &synthetics{timeout: 500 * time.Millisecond}
	// Reserved-but-closed port on loopback: connection refused fast.
	res := s.checkHTTP(context.Background(), synTarget{check: "http", dst: "http://127.0.0.1:1"})
	if res.up {
		t.Fatal("expected down for refused connection")
	}
	if len(res.lines) != 0 {
		t.Fatalf("expected no phase metrics on failure, got %v", res.lines)
	}
	if res.failClass != "connect_refused" {
		t.Errorf("failClass = %q, want connect_refused", res.failClass)
	}
}

func TestCheckHTTPBadStatus(t *testing.T) {
	srv := httptest.NewServer(httpStatus(503))
	defer srv.Close()
	s := &synthetics{timeout: 5 * time.Second}
	res := s.checkHTTP(context.Background(), synTarget{check: "http", dst: srv.URL})
	if res.up {
		t.Fatal("5xx must count as down")
	}
	assertLine(t, res.lines, "synthetic_http_status_code", "503")
	// Status-based failure: the semantic lane classifies by status_code, so
	// the event must carry it and must NOT invent a transport fail_class.
	if res.statusCode != 503 {
		t.Errorf("statusCode = %d, want 503", res.statusCode)
	}
	if res.failClass != "" {
		t.Errorf("failClass = %q, want empty for status-based failure", res.failClass)
	}
}

func TestCheckHTTPDNSFail(t *testing.T) {
	s := &synthetics{timeout: 5 * time.Second}
	// RFC 6761 reserves .invalid — resolution must fail everywhere.
	res := s.checkHTTP(context.Background(), synTarget{check: "http", dst: "https://synthetics-probe.invalid"})
	if res.up {
		t.Fatal("expected down for unresolvable host")
	}
	if res.failClass != "dns" {
		t.Errorf("failClass = %q, want dns", res.failClass)
	}
}

func TestCheckHTTPTLSUntrusted(t *testing.T) {
	srv := httptest.NewTLSServer(httpOK())
	defer srv.Close()
	// No transport override: the self-signed test CA is NOT trusted, so the
	// handshake must fail verification — and classify as tls, not unknown.
	s := &synthetics{timeout: 5 * time.Second}
	res := s.checkHTTP(context.Background(), synTarget{check: "http", dst: srv.URL})
	if res.up {
		t.Fatal("expected down for untrusted certificate")
	}
	if res.failClass != "tls" {
		t.Errorf("failClass = %q, want tls", res.failClass)
	}
}

func TestCheckHTTPResponseTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()
	s := &synthetics{timeout: 300 * time.Millisecond}
	res := s.checkHTTP(context.Background(), synTarget{check: "http", dst: srv.URL})
	if res.up {
		t.Fatal("expected down for stalled response")
	}
	// Connected fine, then the response never arrived: timeout, not connect_timeout.
	if res.failClass != "timeout" {
		t.Errorf("failClass = %q, want timeout", res.failClass)
	}
}

func TestCheckTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	s := &synthetics{timeout: 5 * time.Second}
	res := s.checkTCP(context.Background(), synTarget{check: "tcp", dst: ln.Addr().String()})
	if !res.up {
		t.Fatalf("expected up, got %+v", res)
	}
	assertHasMetric(t, res.lines, "synthetic_tcp_connect_ms")

	res = s.checkTCP(context.Background(), synTarget{check: "tcp", dst: "127.0.0.1:1"})
	if res.up {
		t.Fatal("expected down for refused connect")
	}
	if res.failClass != "connect_refused" {
		t.Errorf("failClass = %q, want connect_refused", res.failClass)
	}
}

func TestCheckHTTPEnrichment(t *testing.T) {
	srv := httptest.NewTLSServer(httpOK())
	defer srv.Close()
	s := &synthetics{timeout: 5 * time.Second, transport: srv.Client().Transport}
	res := s.checkHTTP(context.Background(), synTarget{check: "http", dst: srv.URL + "/health"})
	if !res.up {
		t.Fatalf("expected up, got %+v", res)
	}
	if res.statusCode != 200 {
		t.Errorf("statusCode = %d, want 200", res.statusCode)
	}
	if res.method != http.MethodGet || res.path != "/health" {
		t.Errorf("method/path = %q %q, want GET /health", res.method, res.path)
	}
	if res.totalMs <= 0 || res.connectMs <= 0 || res.ttfbMs <= 0 {
		t.Errorf("phase timings not captured: %+v", res)
	}
	if res.certDays == nil || *res.certDays <= 0 {
		t.Errorf("certDays not captured for TLS check: %+v", res.certDays)
	}
}

// TestProbeEventGoldenContract (#99 R5) — the CROSS-LANGUAGE contract: this
// side must MARSHAL the canonical event to exactly the JSON checked into
// src/contracts/probe_event_wire.json, which the Python CI normalizes from
// the same file. Field renames/type changes break exactly one CI against the
// shared artifact instead of each side pinning its own idea of the wire.
func TestProbeEventGoldenContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "probe_event_wire.json"))
	if err != nil {
		t.Fatalf("shared contract file: %v", err)
	}
	var contract struct {
		Event map[string]any `json:"event"`
	}
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	days := 143.5
	got, err := json.Marshal(ProbeEvent{
		Kind: "http", Prober: "syn-frisco", Target: "https://teams.microsoft.com",
		OK: false, RTTms: 842.1, LossPct: 100, TS: "2026-07-09T09:00:00.000000Z",
		SiteID: "frisco", FailClass: "tls", StatusCode: 503,
		Method: "GET", Path: "/",
		DNSMs: 11.2, TCPConnectMs: 34.8, TLSMs: 51.3, TTFBMs: 700.4, TotalMs: 842.1,
		CertDaysToExpiry: &days,
		CertSubject:      "teams.microsoft.com",
		CertIssuer:       "Microsoft Azure TLS Issuing CA 05",
	})
	if err != nil {
		t.Fatal(err)
	}
	var gotMap map[string]any
	if err := json.Unmarshal(got, &gotMap); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotMap, contract.Event) {
		t.Errorf("marshaled ProbeEvent diverges from src/contracts/probe_event_wire.json:\n got: %s\nwant: %v", got, contract.Event)
	}
}

// TestProbeEventWireContract pins the JSON field names the correlation side
// (synthetic_normalize.py) consumes, and that enrichment is omitted when
// absent — STAMP/ICMP events must stay byte-compatible with the old shape.
func TestProbeEventWireContract(t *testing.T) {
	days := 12.5
	full, err := json.Marshal(ProbeEvent{
		Kind: "http", Prober: "syn-1", Target: "https://a.example", OK: false,
		RTTms: 42, LossPct: 100, TS: "2026-07-09T09:00:00Z",
		SiteID: "frisco", FailClass: "tls", StatusCode: 503,
		Method: "GET", Path: "/", DNSMs: 1, TCPConnectMs: 2, TLSMs: 3,
		TTFBMs: 4, TotalMs: 5, CertDaysToExpiry: &days,
		CertSubject: "a.example", CertIssuer: "Test CA",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		`"site_id":"frisco"`, `"fail_class":"tls"`, `"status_code":503`,
		`"method":"GET"`, `"path":"/"`, `"dns_ms":1`, `"tcp_connect_ms":2`,
		`"tls_ms":3`, `"ttfb_ms":4`, `"total_ms":5`,
		`"cert_days_to_expiry":12.5`, `"cert_subject":"a.example"`, `"cert_issuer":"Test CA"`,
	} {
		if !strings.Contains(string(full), key) {
			t.Errorf("wire event missing %s: %s", key, full)
		}
	}
	bare, err := json.Marshal(ProbeEvent{
		Kind: "stamp", Prober: "p1", Target: "10.0.0.1", OK: true,
		RTTms: 1.2, LossPct: 0, TS: "2026-07-09T09:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"site_id", "fail_class", "status_code", "cert_days_to_expiry", "method"} {
		if strings.Contains(string(bare), key) {
			t.Errorf("bare event must omit %s: %s", key, bare)
		}
	}
}

// ICMP needs a datagram-ICMP-capable or raw socket; skip where the sandbox
// forbids both (CI containers). The prober sidecar carries CAP_NET_RAW.
func TestCheckICMPLoopback(t *testing.T) {
	if c, _, err := openICMP(); err != nil {
		t.Skipf("no ICMP socket available: %v", err)
	} else {
		c.Close()
	}
	s := &synthetics{timeout: 5 * time.Second}
	res := s.checkICMP(context.Background(), synTarget{check: "icmp", dst: "127.0.0.1"})
	if !res.up {
		t.Fatalf("loopback echo failed: %+v", res)
	}
	assertHasMetric(t, res.lines, "synthetic_icmp_rtt_ms")
	assertHasMetric(t, res.lines, "synthetic_icmp_loss_pct")
}

func TestMsPhaseMath(t *testing.T) {
	var zero time.Time
	a := time.Now()
	b := a.Add(15 * time.Millisecond)
	if got := ms(a, b); got < 14.9 || got > 15.1 {
		t.Errorf("ms(a,b) = %v, want ~15", got)
	}
	if ms(zero, b) != 0 || ms(a, zero) != 0 {
		t.Error("unset phase marks must yield 0")
	}
	if ms(b, a) != 0 {
		t.Error("inverted marks must yield 0, not negative")
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func httpOK() http.Handler { return httpStatus(200) }
func httpStatus(code int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte("ok"))
	})
}

func assertHasMetric(t *testing.T, lines []string, name string) {
	t.Helper()
	for _, l := range lines {
		if strings.HasPrefix(l, name+"{") {
			return
		}
	}
	t.Errorf("missing metric %s in %v", name, lines)
}

func assertLine(t *testing.T, lines []string, name, val string) {
	t.Helper()
	for _, l := range lines {
		if strings.HasPrefix(l, name+"{") && strings.HasSuffix(strings.TrimSpace(l), " "+val) {
			return
		}
	}
	t.Errorf("missing %s ... %s in %v", name, val, lines)
}
