package tlsprobe

// tls_peer_probe.go — SEC-019.1: served-certificate expiry observability.
//
// THE GAP THIS CLOSES (incident 2026-08-05 ~20:45): the CA's reissue loop
// keeps the on-disk SVIDs fresh, and the disk material is what everything
// audited. But services that load certificates once at start (the store
// tls-entrypoint wrappers, Kafka's PEM keystore, uvicorn, nginx) keep
// SERVING the copy they loaded — ClickHouse and postgres both served
// expired certificates for hours, the disk looked perfectly healthy, and
// the first signal was every client failing at once. The cert that matters
// is the one on the WIRE, so this prober dials each mesh endpoint on an
// interval, records the served leaf's NotAfter, and exports it as a gauge
// rules.yaml alerts on long before clients start failing.
//
// Probe semantics, deliberately minimal:
//   - InsecureSkipVerify + a capture callback: the probe reads the peer
//     certificate and hangs up. It never sends application data, so chain
//     verification is not load-bearing here — expiry of whatever is served
//     is exactly the datum, even (especially) when the chain is broken.
//   - A server that requires a client certificate (correlation, MTLS:9094)
//     still presents its own certificate before rejecting ours — the
//     capture callback fires before the handshake fails, so a failed
//     handshake with a captured cert still yields the gauge.
//   - postgres does not speak TLS-on-accept: the 8-byte SSLRequest
//     preamble (length=8, code=80877103) and a single 'S' byte come first.
//
// Dormant on the plaintext baseline: started only when the internal mesh
// is configured (mirrors initBackendTransport's activation condition).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// peerEndpoint is one served-certificate observation point.
type peerEndpoint struct {
	Name string // metric label, stable: "postgres:5432"
	Addr string // host:port dialed on the compose network
	// Preamble upgrades the TCP connection before TLS. "" = TLS-on-accept;
	// "postgres" = SSLRequest handshake first.
	Preamble string
}

// defaultPeerEndpoints is the mesh's served-TLS surface as built. A hop added
// by a future epic must be added here — the transport inventory review is the
// reminder. Overridable wholesale via TLS_PROBE_ENDPOINTS
// ("name=host:port[/postgres],...") for labs and external-broker deployments.
var defaultPeerEndpoints = []peerEndpoint{
	{Name: "postgres:5432", Addr: "postgres:5432", Preamble: "postgres"},
	{Name: "clickhouse:8443", Addr: "clickhouse:8443"},
	{Name: "clickhouse:9440", Addr: "clickhouse:9440"},
	{Name: "opensearch:9200", Addr: "opensearch:9200"},
	{Name: "kafka:9094", Addr: "kafka:9094"},
	{Name: "kafka:9095", Addr: "kafka:9095"},
	{Name: "correlation:8443", Addr: "correlation:8443"},
	{Name: "vmauth:8427", Addr: "vmauth:8427"},
}

type peerProbeResult struct {
	// ok = the endpoint presented a certificate this cycle (independent of
	// whether the full handshake succeeded — see the file comment).
	ok        bool
	notAfter  time.Time
	checkedAt time.Time
}

// Prober watches the mesh's served certificates.
type Prober struct {
	endpoints []peerEndpoint
	interval  time.Duration
	timeout   time.Duration

	warnf func(msg string, fields map[string]any)

	mu      sync.RWMutex
	results map[string]peerProbeResult
}

// parsePeerEndpoints parses TLS_PROBE_ENDPOINTS. Empty input = defaults.
// A malformed entry is an error, not a skip: a typo that silently drops an
// endpoint from watching is this feature's own failure mode.
func parsePeerEndpoints(spec string) ([]peerEndpoint, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return defaultPeerEndpoints, nil
	}
	var out []peerEndpoint
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, addr, found := strings.Cut(item, "=")
		if !found || name == "" || addr == "" {
			return nil, fmt.Errorf("TLS_PROBE_ENDPOINTS entry %q: want name=host:port[/postgres]", item)
		}
		ep := peerEndpoint{Name: name}
		if base, pre, has := strings.Cut(addr, "/"); has {
			if pre != "postgres" {
				return nil, fmt.Errorf("TLS_PROBE_ENDPOINTS entry %q: unknown preamble %q", item, pre)
			}
			ep.Addr, ep.Preamble = base, pre
		} else {
			ep.Addr = addr
		}
		if _, _, err := net.SplitHostPort(ep.Addr); err != nil {
			return nil, fmt.Errorf("TLS_PROBE_ENDPOINTS entry %q: %w", item, err)
		}
		out = append(out, ep)
	}
	return out, nil
}

// New builds a Prober from the TLS_PROBE_ENDPOINTS-style spec (empty =
// the built-in mesh surface). warnf receives probe-failure log events.
func New(spec string, warnf func(msg string, fields map[string]any)) (*Prober, error) {
	eps, err := parsePeerEndpoints(spec)
	if err != nil {
		return nil, err
	}
	return &Prober{
		warnf:     warnf,
		endpoints: eps,
		interval:  5 * time.Minute,
		timeout:   6 * time.Second,
		results:   make(map[string]peerProbeResult),
	}, nil
}

// run probes every endpoint on the interval until ctx is done. The first
// sweep runs immediately: an operator restarting the api after an incident
// must not wait five minutes to see the posture.
func (p *Prober) Run(ctx context.Context) {
	p.sweep(ctx)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.sweep(ctx)
		}
	}
}

func (p *Prober) sweep(ctx context.Context) {
	for _, ep := range p.endpoints {
		res := p.probe(ctx, ep)
		p.mu.Lock()
		p.results[ep.Name] = res
		p.mu.Unlock()
		if !res.ok {
			if p.warnf != nil {
				p.warnf("peer certificate probe failed", map[string]any{"endpoint": ep.Name})
			}
		}
	}
}

// probe dials one endpoint and captures the served leaf's NotAfter.
func (p *Prober) probe(ctx context.Context, ep peerEndpoint) peerProbeResult {
	now := time.Now()
	dctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	var d net.Dialer
	raw, err := d.DialContext(dctx, "tcp", ep.Addr)
	if err != nil {
		return peerProbeResult{checkedAt: now}
	}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(p.timeout))

	if ep.Preamble == "postgres" {
		if !postgresSSLPreamble(raw) {
			return peerProbeResult{checkedAt: now}
		}
	}

	var captured *x509.Certificate
	cfg := &tls.Config{
		// #nosec G402 -- observability probe: it reads the served certificate
		// and hangs up without exchanging data. Expiry of WHATEVER is served
		// is the datum — including certs that would fail verification.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) > 0 {
				if c, err := x509.ParseCertificate(rawCerts[0]); err == nil {
					captured = c
				}
			}
			return nil
		},
	}
	tc := tls.Client(raw, cfg)
	// A handshake error (e.g. the server requires a client certificate) is
	// fine as long as the capture callback saw the leaf first.
	_ = tc.HandshakeContext(dctx)
	if captured == nil {
		return peerProbeResult{checkedAt: now}
	}
	return peerProbeResult{ok: true, notAfter: captured.NotAfter, checkedAt: now}
}

// postgresSSLPreamble performs the SSLRequest exchange and reports whether
// the server agreed to TLS ('S'). Wire format: int32 length (8), int32 code
// (80877103), one byte reply.
func postgresSSLPreamble(conn net.Conn) bool {
	var req [8]byte
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], 80877103)
	if _, err := conn.Write(req[:]); err != nil {
		return false
	}
	var reply [1]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return false
	}
	return reply[0] == 'S'
}

// Result is one endpoint's observation, exported for the SEC-021.1 posture
// view. Zero CheckedAt means the endpoint has not been probed yet this boot.
type Result struct {
	OK        bool
	NotAfter  time.Time
	CheckedAt time.Time
}

// Results returns a snapshot of the latest observation per endpoint, keyed by
// the stable endpoint name ("postgres:5432").
func (p *Prober) Results() map[string]Result {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]Result, len(p.results))
	for n, r := range p.results {
		out[n] = Result{OK: r.ok, NotAfter: r.notAfter, CheckedAt: r.checkedAt}
	}
	return out
}

// WriteMetrics emits the per-endpoint gauges at scrape time.
func (p *Prober) WriteMetrics(w io.Writer) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.results) == 0 {
		return
	}
	names := make([]string, 0, len(p.results))
	for n := range p.results {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintf(w, "# HELP netops_tls_peer_cert_expiry_seconds Seconds until the certificate SERVED by a mesh endpoint expires (the wire cert, not the disk cert).\n")
	fmt.Fprintf(w, "# TYPE netops_tls_peer_cert_expiry_seconds gauge\n")
	for _, n := range names {
		if r := p.results[n]; r.ok {
			fmt.Fprintf(w, "netops_tls_peer_cert_expiry_seconds{endpoint=%q} %.0f\n", n, time.Until(r.notAfter).Seconds())
		}
	}
	fmt.Fprintf(w, "# HELP netops_tls_peer_probe_ok Whether the last served-certificate probe of the endpoint captured a certificate (0 = endpoint unreachable or no TLS).\n")
	fmt.Fprintf(w, "# TYPE netops_tls_peer_probe_ok gauge\n")
	for _, n := range names {
		v := 0
		if p.results[n].ok {
			v = 1
		}
		fmt.Fprintf(w, "netops_tls_peer_probe_ok{endpoint=%q} %d\n", n, v)
	}
}
