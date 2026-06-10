package collectors

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
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
