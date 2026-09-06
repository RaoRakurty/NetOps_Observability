// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"netops/backend/safego"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// synthetics.go — service-level synthetic checks (build-order #12, second half).
// STAMP (RFC 8762) + traceroute measure the *path*; synthetics measure the
// *service* an operator actually depends on, the way the major monitoring
// vendors model "synthetic monitoring":
//
//   - HTTP(S): full request with per-phase timings via net/http/httptrace —
//     DNS resolution, TCP connect (RFC 9293), TLS handshake (RFC 8446), time
//     to first byte, total — plus status code and certificate days-to-expiry.
//     The phase split mirrors curl's timing variables / W3C Resource Timing
//     semantics so the numbers are comparable with what operators know.
//   - ICMP: RFC 792 echo (the classic reachability + RTT signal). Tries an
//     unprivileged datagram ICMP socket first (Linux ping_group_range), falls
//     back to raw (CAP_NET_RAW — present in the prober sidecar, ADR 0001).
//   - TCP: bare connect-time to host:port — covers anything with a listener
//     (SSH, DB, syslog…) with zero privileges.
//
// Zero trust / reliability (§3, §9): every check is bounded — per-check
// timeout, capped response read, bounded concurrency, no retries inside a
// tick (the next tick is the retry; no storm). TLS verification is NEVER
// disabled; a bad certificate is a failed check (that is the signal).
// Results go to VictoriaMetrics as synthetic_* gauges via emitMetrics.

const (
	synDefaultInterval = 60 * time.Second
	synDefaultTimeout  = 10 * time.Second
	synMaxBodyBytes    = 1 << 20 // read at most 1 MiB of the response body
	synIcmpPackets     = 5
	synConcurrency     = 4
)

// synTarget is one configured check.
type synTarget struct {
	check string // "http" | "icmp" | "tcp"
	dst   string // URL (http) or host / host:port
}

// synResult is one check's measurement, flattened to exposition lines.
// rttMs/lossPct mirror the headline numbers structurally so the probe-event
// bus lane (#67 build ⑦) doesn't have to parse exposition text.
type synResult struct {
	target  synTarget
	up      bool
	rttMs   float64
	lossPct float64
	lines   []string

	// Application-experience enrichment forwarded on the ProbeEvent (the
	// semantic lane, synthetic_normalize.py). Zero values are omitted on the
	// wire; certDays is a pointer because 0/negative days are meaningful.
	failClass   string // dns|tls|connect_refused|connect_timeout|timeout|reset|unknown ("" = none)
	statusCode  int
	method      string
	path        string
	dnsMs       float64
	connectMs   float64
	tlsMs       float64
	ttfbMs      float64
	totalMs     float64
	certDays    *float64
	certSubject string
	certIssuer  string
}

type synthetics struct {
	interval time.Duration
	timeout  time.Duration
	// transport overrides the HTTP transport in tests (httptest TLS roots).
	// nil in production — the default transport verifies normally.
	transport http.RoundTripper
	mu        sync.RWMutex
	status    Status
}

// NewSynthetics builds the synthetic-check runner. Targets come from
// SYNTHETIC_HTTP_TARGETS (comma-separated URLs), SYNTHETIC_ICMP_TARGETS
// (hosts) and SYNTHETIC_TCP_TARGETS (host:port); each set is probed every
// SYNTHETIC_INTERVAL (default 60s) with a SYNTHETIC_TIMEOUT per check.
func NewSynthetics() Collector {
	return &synthetics{
		interval: envDuration("SYNTHETIC_INTERVAL", synDefaultInterval),
		timeout:  envDuration("SYNTHETIC_TIMEOUT", synDefaultTimeout),
		status:   Status{Name: "synthetics", Healthy: true, Kind: "metrics"},
	}
}

func (s *synthetics) Name() string { return "synthetics" }
func (s *synthetics) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *synthetics) Run(ctx context.Context) error {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	s.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			s.tick(ctx)
		}
	}
}

// synTargets parses the three target env lists into one check list.
func synTargets() []synTarget {
	var out []synTarget
	add := func(env, check string, norm func(string) string) {
		for _, p := range strings.Split(os.Getenv(env), ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if norm != nil {
				p = norm(p)
			}
			out = append(out, synTarget{check: check, dst: p})
		}
	}
	add("SYNTHETIC_HTTP_TARGETS", "http", func(u string) string {
		if !strings.Contains(u, "://") {
			return "https://" + u
		}
		return u
	})
	add("SYNTHETIC_ICMP_TARGETS", "icmp", nil)
	add("SYNTHETIC_TCP_TARGETS", "tcp", nil)
	return out
}

// tick runs every configured check once, with bounded concurrency, and emits
// the batch to VictoriaMetrics.
func (s *synthetics) tick(ctx context.Context) {
	targets := synTargets()
	results := make([]synResult, len(targets))
	sem := make(chan struct{}, synConcurrency)
	var wg sync.WaitGroup
	for i, tgt := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, tgt synTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			// safego (H3): a bare worker goroutine talking to arbitrary remote
			// endpoints — a panic in one check must cost that check's cycle (it
			// reports as down), never the process. safego logs name+stack.
			if !safego.Run(safego.Stderr, "synthetic-check", func() {
				cctx, cancel := context.WithTimeout(ctx, s.timeout)
				defer cancel()
				switch tgt.check {
				case "http":
					results[i] = s.checkHTTP(cctx, tgt)
				case "icmp":
					results[i] = s.checkICMP(cctx, tgt)
				case "tcp":
					results[i] = s.checkTCP(cctx, tgt)
				}
			}) {
				results[i] = synResult{target: tgt, failClass: "unknown"}
			}
		}(i, tgt)
	}
	wg.Wait()

	now := time.Now().UnixMilli()
	prober := proberID()
	site := proberSite()
	decl := loadProberDeclaration()
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	up := 0
	checked := 0 // checks actually executed this cycle
	var lines []string
	var events []ProbeEvent
	for _, r := range results {
		if r.target.dst == "" {
			continue
		}
		checked++
		if r.up {
			up++
		}
		loss := r.lossPct
		if !r.up && loss == 0 {
			loss = 100 // check failed outright: the path observation is full loss
		}
		events = append(events, ProbeEvent{
			Kind: r.target.check, Prober: prober, Target: r.target.dst,
			OK: r.up, RTTms: r.rttMs, LossPct: loss, TS: ts,
			SiteID: site, FailClass: r.failClass, StatusCode: r.statusCode,
			Method: r.method, Path: r.path,
			DNSMs: r.dnsMs, TCPConnectMs: r.connectMs, TLSMs: r.tlsMs,
			TTFBMs: r.ttfbMs, TotalMs: r.totalMs,
			CertDaysToExpiry: r.certDays, CertSubject: r.certSubject, CertIssuer: r.certIssuer,
			// One check execution = one lineage id: every signal the correlation
			// side derives from this event must share it (§2 — never two
			// independent observers from one execution).
			ExecutionID: newExecutionID(),
			// The recurring test's stable identity — with the vantage host it
			// forms the fate fingerprint (§3): two probes sharing (seam, target,
			// schedule) or an agent host must never corroborate each other.
			ScheduleID:  r.target.check + "|" + r.target.dst,
			ProbeIntent: decl.Intent, VantageType: decl.Vantage,
			Environment: decl.Environment, SignalPurpose: decl.Purpose,
		})
		lines = append(lines, fmt.Sprintf(`synthetic_up{dst=%q,check=%q} %d %d`, r.target.dst, r.target.check, b2i(r.up), now))
		for _, l := range r.lines {
			lines = append(lines, l+fmt.Sprintf(" %d", now))
		}
	}
	if len(lines) > 0 {
		emitMetrics(ctx, strings.Join(lines, "\n"))
	}
	forwardProbeEvents(ctx, events)
	s.mu.Lock()
	s.status.LastTick = time.Now().UTC()
	s.status.Targets = len(targets)
	s.status.Reachable = up
	// Honest verdict instead of a hard-coded true: most checks failing means the
	// synthetic view of the estate is not trustworthy this cycle.
	s.status.Healthy = cycleHealthy(checked, up)
	s.status.LastError = cycleError(checked, up, "")
	s.mu.Unlock()
}

// ── HTTP(S) ───────────────────────────────────────────────────────────────────

// httpPhases holds the httptrace-derived phase boundaries for one request,
// plus each phase's error so a failure classifies to the phase that broke
// (the client wraps everything in one *url.Error; the trace sees the truth).
type httpPhases struct {
	dnsStart, dnsDone   time.Time
	connStart, connDone time.Time
	tlsStart, tlsDone   time.Time
	wroteReq, firstByte time.Time
	dnsErr, connErr     error
	tlsErr              error
}

// ms returns the millisecond delta between two phase marks, 0 when either is
// unset (phase didn't occur — e.g. no DNS for an IP literal, no TLS for http).
func ms(from, to time.Time) float64 {
	if from.IsZero() || to.IsZero() || to.Before(from) {
		return 0
	}
	return float64(to.Sub(from)) / float64(time.Millisecond)
}

// checkHTTP performs one GET with per-phase instrumentation. Redirects are
// followed (default client policy, capped at 10); phases describe the FINAL
// connection — for a redirect chain the total is still wall-clock end-to-end.
func (s *synthetics) checkHTTP(ctx context.Context, tgt synTarget) synResult {
	res := synResult{target: tgt}
	var ph httpPhases
	trace := &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { ph.dnsStart = time.Now() },
		DNSDone:              func(i httptrace.DNSDoneInfo) { ph.dnsDone, ph.dnsErr = time.Now(), i.Err },
		ConnectStart:         func(string, string) { ph.connStart = time.Now() },
		ConnectDone:          func(_, _ string, err error) { ph.connDone, ph.connErr = time.Now(), err },
		TLSHandshakeStart:    func() { ph.tlsStart = time.Now() },
		TLSHandshakeDone:     func(_ tls.ConnectionState, err error) { ph.tlsDone, ph.tlsErr = time.Now(), err },
		WroteRequest:         func(httptrace.WroteRequestInfo) { ph.wroteReq = time.Now() },
		GotFirstResponseByte: func() { ph.firstByte = time.Now() },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, tgt.dst, nil)
	if err != nil {
		return res
	}
	res.method = http.MethodGet
	if u, uerr := url.Parse(tgt.dst); uerr == nil {
		res.path = u.Path
	}
	req.Header.Set("User-Agent", "netops-synthetics/1")
	client := &http.Client{Timeout: s.timeout}
	if s.transport != nil {
		client.Transport = s.transport
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		res.failClass = classifyHTTPErr(err, ph)
		return res
	}
	defer resp.Body.Close()
	// Drain (bounded) so total includes the body and the connection is reusable.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, synMaxBodyBytes)) // best-effort: drain for connection reuse
	total := float64(time.Since(start)) / float64(time.Millisecond)

	res.up = resp.StatusCode >= 200 && resp.StatusCode < 400
	res.rttMs = total
	res.statusCode = resp.StatusCode
	res.dnsMs = ms(ph.dnsStart, ph.dnsDone)
	res.connectMs = ms(ph.connStart, ph.connDone)
	res.tlsMs = ms(ph.tlsStart, ph.tlsDone)
	res.ttfbMs = ms(ph.wroteReq, ph.firstByte)
	res.totalMs = total
	q := func(name string, v float64) string {
		return fmt.Sprintf(`%s{dst=%q,check="http"} %.3f`, name, tgt.dst, v)
	}
	res.lines = append(res.lines,
		fmt.Sprintf(`synthetic_http_status_code{dst=%q,check="http"} %d`, tgt.dst, resp.StatusCode),
		q("synthetic_http_dns_ms", ms(ph.dnsStart, ph.dnsDone)),
		q("synthetic_http_connect_ms", ms(ph.connStart, ph.connDone)),
		q("synthetic_http_tls_ms", ms(ph.tlsStart, ph.tlsDone)),
		q("synthetic_http_ttfb_ms", ms(ph.wroteReq, ph.firstByte)),
		q("synthetic_http_total_ms", total),
	)
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := resp.TLS.PeerCertificates[0]
		days := time.Until(leaf.NotAfter).Hours() / 24
		res.lines = append(res.lines, q("synthetic_http_cert_expiry_days", days))
		res.certDays = &days
		res.certSubject = leaf.Subject.CommonName
		res.certIssuer = leaf.Issuer.CommonName
	}
	return res
}

// classifyHTTPErr maps a failed HTTP check to its fail_class — the phase that
// actually broke, preferring the per-phase trace errors over parsing the
// client's wrapped error. Values are the ProbeEvent.FailClass wire vocabulary
// consumed by synthetic_normalize.py.
func classifyHTTPErr(err error, ph httpPhases) string {
	switch {
	case ph.dnsErr != nil:
		return "dns"
	case ph.tlsErr != nil:
		return "tls"
	case ph.connErr != nil:
		if errors.Is(ph.connErr, syscall.ECONNREFUSED) {
			return "connect_refused"
		}
		return "connect_timeout"
	}
	// No phase reported an error — classify from the wrapped client error.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "tls"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connect_refused"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "reset"
	}
	var nerr net.Error
	if (errors.As(err, &nerr) && nerr.Timeout()) || errors.Is(err, context.DeadlineExceeded) {
		if ph.connDone.IsZero() {
			return "connect_timeout" // never got a connection
		}
		return "timeout" // connected, then the response never arrived
	}
	// TLS started but never completed (some handshake aborts surface only here).
	if !ph.tlsStart.IsZero() && ph.tlsDone.IsZero() {
		return "tls"
	}
	return "unknown"
}

// ── TCP connect ───────────────────────────────────────────────────────────────

func (s *synthetics) checkTCP(ctx context.Context, tgt synTarget) synResult {
	res := synResult{target: tgt}
	d := net.Dialer{}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", withPort(tgt.dst, 443))
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			res.failClass = "connect_refused"
		} else {
			res.failClass = "connect_timeout"
		}
		return res
	}
	connectMs := float64(time.Since(start)) / float64(time.Millisecond)
	_ = conn.Close() // best-effort: probe socket; nothing actionable on close failure
	res.up = true
	res.rttMs = connectMs
	res.connectMs = connectMs
	res.lines = append(res.lines,
		fmt.Sprintf(`synthetic_tcp_connect_ms{dst=%q,check="tcp"} %.3f`, tgt.dst, connectMs))
	return res
}

// ── ICMP echo (RFC 792) ───────────────────────────────────────────────────────

// openICMP opens an ICMP socket: unprivileged datagram first (works when
// net.ipv4.ping_group_range admits us, no capabilities), then raw
// (CAP_NET_RAW — the prober sidecar has it).
func openICMP() (*icmp.PacketConn, bool, error) {
	if c, err := icmp.ListenPacket("udp4", ""); err == nil {
		return c, true, nil
	}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	return c, false, err
}

func (s *synthetics) checkICMP(ctx context.Context, tgt synTarget) synResult {
	res := synResult{target: tgt}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", tgt.dst)
	if err != nil || len(ips) == 0 {
		return res
	}
	conn, datagram, err := openICMP()
	if err != nil {
		return res
	}
	defer conn.Close()

	var dst net.Addr = &net.IPAddr{IP: ips[0]}
	if datagram {
		dst = &net.UDPAddr{IP: ips[0]}
	}
	id := os.Getpid() & 0xffff
	sent, recv := 0, 0
	var rtts []float64
	buf := make([]byte, 1500)
	for i := 0; i < synIcmpPackets; i++ {
		if ctx.Err() != nil {
			break
		}
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{ID: id, Seq: i, Data: []byte("netops-synthetics")},
		}
		wb, err := msg.Marshal(nil)
		if err != nil {
			break
		}
		start := time.Now()
		if _, err := conn.WriteTo(wb, dst); err != nil {
			continue
		}
		sent++
		// One read window per packet; a reply for an earlier seq still counts
		// (datagram sockets demux per-socket, raw sockets see all ICMP).
		_ = conn.SetReadDeadline(time.Now().Add(time.Second)) // best-effort: a failed deadline set surfaces as a read/write error
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				break // timeout — packet lost
			}
			m, err := icmp.ParseMessage(1, buf[:n])
			if err != nil {
				continue
			}
			echo, ok := m.Body.(*icmp.Echo)
			if m.Type != ipv4.ICMPTypeEchoReply || !ok {
				continue
			}
			// Datagram sockets rewrite the ID — match on payload+seq there.
			if !datagram && echo.ID != id {
				continue
			}
			recv++
			rtts = append(rtts, float64(time.Since(start))/float64(time.Millisecond))
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if sent == 0 {
		return res
	}
	res.up = recv > 0
	loss := float64(sent-recv) / float64(sent) * 100
	mean := 0.0
	for _, r := range rtts {
		mean += r
	}
	if len(rtts) > 0 {
		mean /= float64(len(rtts))
	}
	res.rttMs = mean
	res.lossPct = loss
	res.lines = append(res.lines,
		fmt.Sprintf(`synthetic_icmp_rtt_ms{dst=%q,check="icmp"} %.3f`, tgt.dst, mean),
		fmt.Sprintf(`synthetic_icmp_loss_pct{dst=%q,check="icmp"} %.2f`, tgt.dst, loss),
	)
	return res
}
