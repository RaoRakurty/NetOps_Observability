package collectors

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// poller is the shared engine behind every protocol collector. It reads the
// live device inventory each interval, probes each target with a protocol-
// specific check, records real status (reachable count, latency, last error),
// and emits collector telemetry to VictoriaMetrics. The per-protocol files
// (snmp/gnmi/netconf) just supply a name, interval, default port, and probe.
//
// Kept strictly stdlib: SNMP does a genuine v2c GET over UDP; gNMI/NETCONF do
// a TCP reachability probe of their port (full gNMI gRPC subscription and
// NETCONF SSH RPCs need client libraries that are out of the zero-dependency
// scope — the connection probe is the faithful stdlib-only layer).

// Target is one device the collectors poll.
type Target struct {
	ID        string
	Address   string // host or host:port
	Protocol  string // preferred protocol: snmp|gnmi|netconf ("" => snmp)
	Community string // resolved SNMP v2c community ("" => SNMP_COMMUNITY/"public")

	// TenantID is the owning tenant from the device inventory ("" = global).
	// Collectors that persist rows MUST stamp it so at-rest isolation holds at
	// the storage layer (§3a.4). Added for audit F-56: the tunnel writer had no
	// tenant at all, so every discovered tunnel landed untagged and was shared
	// into every tenant's view by the row policy's untagged clause.
	TenantID string

	// SNMPv3 USM (set when the device's credential profile is v3; takes
	// precedence over Community). See snmpCreds.
	SNMPVersion int // 0/2 => v2c, 3 => v3
	V3User      string
	V3Level     string // noAuthNoPriv | authNoPriv | authPriv
	V3AuthProto string
	V3AuthKey   string
	V3PrivProto string
	V3PrivKey   string
	V3Context   string

	// GNMICapable marks a device that ALSO has gNMI telemetry (a gnmic subscription).
	// The SNMP metrics collector uses it to WITHHOLD gNMI-owned metric families on
	// these devices (single-contract: gNMI owns BGP/IS-IS where present; SNMP stays
	// the universal floor for devices WITHOUT gNMI). Set from the device label
	// `gnmi: "true"`.
	GNMICapable bool
}

// hasTransport reports whether the device has the named non-SNMP transport, so the
// SNMP collector can yield ownership of a family that transport owns. Today only
// gNMI overrides SNMP; add cases here when another transport (e.g. NETCONF) gains
// ownership of a family.
func (t Target) hasTransport(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "gnmi":
		return t.GNMICapable
	default:
		return false
	}
}

// creds builds the engine credentials for this target (v3 if configured, else
// v2c with the resolved community / global default).
func (t Target) creds() snmpCreds {
	if t.SNMPVersion == 3 {
		return snmpCreds{
			Version: 3, User: t.V3User, Level: t.V3Level,
			AuthProto: t.V3AuthProto, AuthKey: t.V3AuthKey,
			PrivProto: t.V3PrivProto, PrivKey: t.V3PrivKey, Context: t.V3Context,
		}
	}
	community := t.Community
	if community == "" {
		community = os.Getenv("SNMP_COMMUNITY")
	}
	if community == "" {
		community = "public"
	}
	return v2c(community)
}

// TargetFunc returns the current set of devices to poll.
type TargetFunc func() []Target

// byProtocol wraps a TargetFunc so a collector only sees the devices whose
// preferred protocol is its own. This keeps reachable counts meaningful per
// protocol — the SNMP collector isn't counted "unreachable" against a gNMI
// box and vice versa. A device with no preferred protocol is treated as SNMP.
func byProtocol(all TargetFunc, proto string) TargetFunc {
	if all == nil {
		return nil
	}
	return func() []Target {
		var out []Target
		for _, t := range all() {
			p := strings.ToLower(t.Protocol)
			if p == "" {
				p = "snmp"
			}
			if p == proto {
				out = append(out, t)
			}
		}
		return out
	}
}

// byProtocolVersion narrows byProtocol further to a single SNMP version class:
// v3 == true keeps only USM v3 targets (SNMPVersion 3); v3 == false keeps the
// community-string versions (SNMPVersion 0/1/2). This lets the v2c and v3 SNMP
// collectors report independent target/reachable counts in the Collectors view.
func byProtocolVersion(all TargetFunc, proto string, v3 bool) TargetFunc {
	base := byProtocol(all, proto)
	if base == nil {
		return nil
	}
	return func() []Target {
		var out []Target
		for _, t := range base() {
			isV3 := t.SNMPVersion == 3
			if isV3 == v3 {
				out = append(out, t)
			}
		}
		return out
	}
}

// probeFunc checks one target; nil error means reachable/healthy. The dialable
// addr (host:port) is precomputed; the full Target carries per-device details
// like the SNMP community.
type probeFunc func(ctx context.Context, addr string, t Target) error

type poller struct {
	name     string
	interval time.Duration
	port     int
	probe    probeFunc
	targets  TargetFunc

	mu     sync.RWMutex
	status Status
}

func newPoller(name string, interval time.Duration, port int, probe probeFunc, targets TargetFunc) *poller {
	return &poller{
		name:     name,
		interval: interval,
		port:     port,
		probe:    probe,
		targets:  targets,
		status:   Status{Name: name, Healthy: true, Kind: "protocol"},
	}
}

func (p *poller) Name() string { return p.name }

func (p *poller) Status() Status {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.status
}

func (p *poller) Run(ctx context.Context) error {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	p.pollOnce(ctx) // poll immediately so status is live within seconds of boot
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			p.pollOnce(ctx)
		}
	}
}

func (p *poller) pollOnce(ctx context.Context) {
	var targets []Target
	if p.targets != nil {
		targets = p.targets()
	}
	start := time.Now()
	now := start.UnixMilli()
	reachable := 0
	var lastErr string
	lines := make([]string, 0, len(targets)+4)

	for _, tg := range targets {
		addr := withPort(tg.Address, p.port)
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := p.probe(cctx, addr, tg)
		cancel()
		up := 0
		if err == nil {
			reachable++
			up = 1
		} else {
			lastErr = err.Error()
		}
		lines = append(lines, fmt.Sprintf(
			`collector_target_up{collector=%q,device=%q} %d %d`, p.name, tg.ID, up, now))
	}

	dur := time.Since(start)
	healthy := cycleHealthy(len(targets), reachable)
	lines = append(lines,
		collectorUpLine(p.name, healthy, now),
		fmt.Sprintf(`collector_targets{collector=%q} %d %d`, p.name, len(targets), now),
		fmt.Sprintf(`collector_targets_reachable{collector=%q} %d %d`, p.name, reachable, now),
		fmt.Sprintf(`collector_poll_duration_ms{collector=%q} %d %d`, p.name, dur.Milliseconds(), now),
	)
	emitMetrics(ctx, strings.Join(lines, "\n"))

	p.mu.Lock()
	p.status.LastTick = start.UTC()
	p.status.Targets = len(targets)
	p.status.Reachable = reachable
	p.status.LastPollMillis = dur.Milliseconds()
	p.status.Healthy = healthy
	p.status.LastError = cycleError(len(targets), reachable, lastErr)
	p.mu.Unlock()
}

// ── collector self-observability (§10: no silent failures) ───────────────────

// degradedReachFraction is the share of a collector's targets that must answer
// for the cycle to count as healthy.
//
// The rule (a judgement call, so it is documented): a cycle is UNHEALTHY when
// fewer than half of the targets answered, and LastError is populated whenever
// ANY target failed. The audit found the opposite: Healthy was re-set to a
// literal true every tick and LastError was cleared unless EVERY target failed,
// so a 9-of-10 blackout reported "healthy" with a blank error. Half is the line
// because below it the collector no longer produces a representative view of
// the fleet and the operator must be told; above it the loss is per-device and
// already visible as collector_target_up / collector_targets_reachable. A
// collector with NO targets stays healthy-and-idle — nothing to reach is not a
// failure to reach.
const degradedReachFraction = 0.5

// cycleHealthy is the health verdict for one poll cycle: answered is the number
// of targets whose probe SUCCEEDED (not the number that had something to say —
// a device with no LLDP neighbours answered fine).
func cycleHealthy(targets, answered int) bool {
	if targets <= 0 {
		return true
	}
	return float64(answered) >= degradedReachFraction*float64(targets)
}

// cycleError is the LastError one cycle should report. It is non-empty whenever
// any target failed — including the partial blackout that used to be silent —
// and carries the last underlying error when there is one.
func cycleError(targets, answered int, lastErr string) string {
	if targets <= 0 || answered >= targets {
		return ""
	}
	if strings.TrimSpace(lastErr) != "" {
		return fmt.Sprintf("%d/%d targets did not answer (last error: %s)", targets-answered, targets, lastErr)
	}
	return fmt.Sprintf("%d/%d targets did not answer", targets-answered, targets)
}

// collectorUpLine renders the collector_up sample honestly. This metric is the
// platform's own liveness signal and the shipped CollectorDown alert keys off
// `collector_up == 0`; every collector emitted the literal constant 1, so that
// alert could never fire no matter how blind the collector was.
func collectorUpLine(name string, up bool, nowMs int64) string {
	return fmt.Sprintf(`collector_up{collector=%q} %d %d`, name, b2i(up), nowMs)
}

// withPort returns addr unchanged if it already has a port, else appends def.
func withPort(addr string, def int) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, strconv.Itoa(def))
}

// sshBannerProbe dials the NETCONF-over-SSH port and reads the server's SSH
// identification string. Per RFC 4253 §4.2 an SSH server sends "SSH-2.0-<impl>"
// (or "SSH-1.99-…") in cleartext immediately on connect, before any key exchange
// or authentication — so we can confirm a real NETCONF/SSH transport is
// answering without credentials. This is a materially stronger signal than a
// bare TCP connect (which a firewall or half-open port would also satisfy) and
// is exactly how credential-less monitors (Nagios/Zabbix) verify NETCONF/830.
//
// A genuine *active NETCONF session count* would need the authenticated
// RFC 6022 ietf-netconf-monitoring /netconf-state/sessions <get> — that requires
// a full SSH client (golang.org/x/crypto/ssh), which is outside the backend's
// stdlib-only budget; the banner probe is the faithful stdlib-only layer.
func sshBannerProbe(ctx context.Context, addr string, _ Target) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetReadDeadline(dl) // best-effort: a failed deadline set surfaces as a read/write error
	} else {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second)) // best-effort: a failed deadline set surfaces as a read/write error
	}

	// The identification string is CRLF-terminated and capped at 255 bytes
	// (RFC 4253). Read a bounded chunk and look for the "SSH-" prefix; servers
	// may emit banner/comment lines first, so scan the lines we got.
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if n == 0 && err != nil {
		return err
	}
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "SSH-") {
			return nil // a real SSH/NETCONF transport answered
		}
	}
	return fmt.Errorf("no SSH identification banner from %s", addr)
}

// snmpProbe does a real SNMP GET of sysUpTime to prove reachability, using the
// device's resolved credentials — v2c community or full v3 USM. creds() supplies
// the v2c community fallback (SNMP_COMMUNITY / "public").
func snmpProbe(ctx context.Context, addr string, t Target) error {
	_, err := snmpGet(ctx, addr, t.creds(), sysUpTimeOID)
	return err
}

// ProbeSNMP is the exported credentialed reachability check — the exact probe
// the SNMP collectors use (sysUpTime GET, v2c or v3 per the target's fields).
// The credential sentinel uses it to verify which stored profile a device
// actually answers. Bounded by ctx.
func ProbeSNMP(ctx context.Context, t Target) error {
	return snmpProbe(ctx, withPort(t.Address, 161), t)
}

// Metric-push accounting. emitMetrics used to swallow EVERYTHING — an unset
// endpoint, a request-build error, a dead transport — and never looked at the
// status code, so VictoriaMetrics could reject every sample from all 14 call
// sites indefinitely with no counter, no log and no health effect. These are
// the collectors' own "am I being heard?" signal.
var (
	metricsPushOK      atomic.Uint64
	metricsPushFailed  atomic.Uint64
	metricsPushDropped atomic.Uint64 // no metrics endpoint configured at all

	metricsPushMu      sync.Mutex
	metricsPushLastErr string
	metricsPushLogged  time.Time
	metricsPushNoURL   sync.Once
)

// pushErrLogEvery bounds push-failure logging: every collector tick calls
// emitMetrics, so an unfiltered log of a down VictoriaMetrics would emit
// hundreds of identical lines a minute. The counters carry the rate, the log
// carries the cause.
const pushErrLogEvery = time.Minute

// MetricsPushStats reports the outcome of the collectors' own metric pushes:
// successful pushes, failed ones (transport, request-build, or a non-2xx/3xx
// reply), pushes dropped for want of a configured endpoint, and the most recent
// failure text. Exported so the API can publish it on /metrics.
func MetricsPushStats() (ok, failed, dropped uint64, lastErr string) {
	metricsPushMu.Lock()
	lastErr = metricsPushLastErr
	metricsPushMu.Unlock()
	return metricsPushOK.Load(), metricsPushFailed.Load(), metricsPushDropped.Load(), lastErr
}

func notePushFailure(reason string) {
	metricsPushFailed.Add(1)
	metricsPushMu.Lock()
	metricsPushLastErr = reason
	shouldLog := time.Since(metricsPushLogged) >= pushErrLogEvery
	if shouldLog {
		metricsPushLogged = time.Now()
	}
	metricsPushMu.Unlock()
	if shouldLog {
		log.Printf("collectors: metric push FAILED: %s — collector telemetry (including collector_up, which the CollectorDown alert reads) is not reaching the metric store", reason)
	}
}

// emitMetrics POSTs Prometheus-exposition samples to VictoriaMetrics so the
// collectors' telemetry shows up in the Metrics Explorer. Best-effort for the
// caller — it never returns an error — but never SILENT: every outcome is
// counted (MetricsPushStats) and failures are logged, rate-limited.
func emitMetrics(ctx context.Context, body string) {
	if strings.TrimSpace(body) == "" {
		return // nothing to say this cycle; not a failure
	}
	base := os.Getenv("VICTORIA_URL")
	if base == "" {
		base = os.Getenv("METRICS_URL")
	}
	if base == "" {
		metricsPushDropped.Add(1)
		// Configuration, not a transient fault: say it once, loudly.
		metricsPushNoURL.Do(func() {
			log.Print("collectors: neither VICTORIA_URL nor METRICS_URL is set — every collector sample, including collector_up, is being discarded")
		})
		return
	}
	url := strings.TrimRight(base, "/") + "/api/v1/import/prometheus"
	// #nosec G704 -- url is the operator-configured VICTORIA_URL/METRICS_URL metrics backend, not user input
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		notePushFailure("build request: " + err.Error())
		return
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := meshHTTPClient(5 * time.Second).Do(req)
	if err != nil {
		notePushFailure(err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// A rejected import (bad line format, over quota, auth) answers 4xx/5xx
		// and drops every sample in the batch — previously indistinguishable
		// from success. Quote a bounded slice of the reply so the cause is in
		// the log, not just the code.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512)) // best-effort: diagnostic snippet; a read error just leaves it empty
		notePushFailure(fmt.Sprintf("%s: HTTP %d %s", url, resp.StatusCode, strings.TrimSpace(string(snippet))))
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)) // best-effort: drain for connection reuse
	metricsPushOK.Add(1)
}

// ---- minimal BER encoding for the SNMP v2c GET ----------------------------

var sysUpTimeOID = []int{1, 3, 6, 1, 2, 1, 1, 3, 0} // DISMAN sysUpTimeInstance

func buildSNMPGet(community string, oid []int, reqID int) []byte {
	return buildSNMPRequest(0xA0, community, oid, reqID) // GetRequest PDU
}

// buildSNMPGetNext builds an SNMP v2c GetNextRequest — the primitive a table
// walk repeats, advancing to the lexically-next OID each call (see snmpWalkColumn).
func buildSNMPGetNext(community string, oid []int, reqID int) []byte {
	return buildSNMPRequest(0xA1, community, oid, reqID) // GetNextRequest PDU
}

// buildSNMPRequest encodes a v2c request with the given PDU tag (0xA0 Get,
// 0xA1 GetNext). The varbind value is NULL, as Get/GetNext require.
func buildSNMPRequest(pduTag byte, community string, oid []int, reqID int) []byte {
	varbind := berTLV(0x30, append(berOID(oid), berTLV(0x05, nil)...)) // { OID, NULL }
	varbinds := berTLV(0x30, varbind)
	pduBody := berInt(reqID)
	pduBody = append(pduBody, berInt(0)...) // error-status
	pduBody = append(pduBody, berInt(0)...) // error-index
	pduBody = append(pduBody, varbinds...)
	pdu := berTLV(pduTag, pduBody)

	msg := berInt(1) // version: 1 == SNMPv2c
	msg = append(msg, berTLV(0x04, []byte(community))...)
	msg = append(msg, pdu...)
	return berTLV(0x30, msg)
}

func berTLV(tag byte, content []byte) []byte {
	out := append([]byte{tag}, berLen(len(content))...)
	return append(out, content...)
}

func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(b))}, b...)
}

func berInt(v int) []byte {
	if v == 0 {
		return berTLV(0x02, []byte{0x00})
	}
	var b []byte
	for n := v; n > 0; n >>= 8 {
		b = append([]byte{byte(n & 0xff)}, b...)
	}
	if b[0]&0x80 != 0 { // keep it positive
		b = append([]byte{0x00}, b...)
	}
	return berTLV(0x02, b)
}

func berOID(parts []int) []byte {
	if len(parts) < 2 {
		return berTLV(0x06, nil)
	}
	content := []byte{byte(parts[0]*40 + parts[1])}
	for _, p := range parts[2:] {
		content = append(content, base128(p)...)
	}
	return berTLV(0x06, content)
}

func base128(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0x7f)}, b...)
		n >>= 7
	}
	for i := 0; i < len(b)-1; i++ {
		b[i] |= 0x80
	}
	return b
}
