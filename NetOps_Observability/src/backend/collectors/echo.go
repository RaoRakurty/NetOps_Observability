package collectors

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// wan-echo — the SD-WAN/BFD-style circuit SLA probe (#2 of the WAN path-metrics
// program).
//
// SD-WAN edges run BFD between TLOC pairs (local transport ⇄ remote transport)
// and derive latency / jitter / loss from that one continuous echo stream. We do
// the same, agentless: a short ICMP-echo burst per circuit (TCP-SYN fallback when
// ICMP is filtered), SOURCE-BOUND to the local WAN interface so a multi-uplink
// edge measures each circuit independently. All three SLA numbers come from the
// single RTT sample series — no STAMP reflector required, which is exactly why
// this is the enterprise default (STAMP is reserved for the SP world).
//
// Targets are the WAN circuits the API's projector publishes to Redis
// (FetchWANCircuits); WAN_ECHO_TARGETS is a standalone fallback for the prober
// sidecar. Per-circuit gauges are emitted to VictoriaMetrics as circuit_* and a
// ProbeEvent (Kind icmp|tcp) onto the bus, both tagged with the circuit labels.

type wanEcho struct {
	interval time.Duration
	packets  int
	timeout  time.Duration
	tcpPort  int
	mu       sync.RWMutex
	status   Status
}

// NewWANEcho builds the echo collector. Cadence WAN_ECHO_INTERVAL (default 30s),
// burst WAN_ECHO_PACKETS (default 10) — enough samples to derive jitter.
func NewWANEcho() Collector {
	return &wanEcho{
		interval: envDuration("WAN_ECHO_INTERVAL", 30*time.Second),
		packets:  envInt("WAN_ECHO_PACKETS", 10),
		timeout:  envDuration("WAN_ECHO_TIMEOUT", time.Second),
		tcpPort:  envInt("WAN_ECHO_TCP_PORT", 443),
		status:   Status{Name: "wan-echo", Healthy: true, Kind: "metrics"},
	}
}

func (s *wanEcho) Name() string { return "wan-echo" }

func (s *wanEcho) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *wanEcho) Run(ctx context.Context) error {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	s.probeAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			s.probeAll(ctx)
		}
	}
}

// echoTargets prefers the API-published circuit list (Redis), falling back to
// WAN_ECHO_TARGETS (comma list of `remoteAddr` or `localAddr=remoteAddr`).
func echoTargets(ctx context.Context) []EchoTarget {
	if t, err := FetchWANCircuits(ctx); err == nil && len(t) > 0 {
		return t
	}
	raw := strings.TrimSpace(os.Getenv("WAN_ECHO_TARGETS"))
	if raw == "" {
		return nil
	}
	var out []EchoTarget
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		local, remote := "", p
		if i := strings.Index(p, "="); i >= 0 {
			local, remote = strings.TrimSpace(p[:i]), strings.TrimSpace(p[i+1:])
		}
		out = append(out, EchoTarget{
			CircuitID: "env-" + remote, LocalAddr: local, RemoteAddr: remote,
			LocalDevice: "prober", RemoteDevice: remote,
		})
	}
	return out
}

// echoResult is one circuit's measurement summary.
type echoResult struct {
	sent, recv  int
	latencyMs   float64
	jitterMs    float64
	lossPct     float64
	qoe         float64
	method      string // icmp | tcp
	sourceBound bool   // whether we egressed the requested local interface
	// failReason names why the circuit could not be probed at all (resolution
	// failure, no socket). Empty when packets actually went out — a probe that
	// was never attempted must not be reported as a quiet, healthy circuit.
	failReason string
}

func (s *wanEcho) probeAll(ctx context.Context) {
	targets := echoTargets(ctx)
	now := time.Now().UnixMilli()
	prober := proberID()
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	// Probe circuits CONCURRENTLY with a bounded worker pool — a real WAN has
	// hundreds of circuits, and an unreachable one costs packets×timeout; serial
	// probing would stall a whole cycle. Cap keeps socket/CPU use bounded. Each
	// goroutine writes only its own results[i] slot, so no lock is needed.
	type outcome struct {
		lines      []string
		event      ProbeEvent
		reach      bool
		valid      bool
		failReason string // why this circuit could not be probed at all
	}
	sem := make(chan struct{}, echoConcurrency)
	results := make([]outcome, len(targets))
	var wg sync.WaitGroup
	for i, tgt := range targets {
		if tgt.RemoteAddr == "" {
			continue
		}
		wg.Add(1)
		go func(i int, tgt EchoTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := s.measure(ctx, tgt)
			lbl := fmt.Sprintf(
				`circuit=%q,dst=%q,local_device=%q,local_if=%q,remote_device=%q,remote_if=%q,tenant=%q,method=%q,source_bound=%q`,
				tgt.CircuitID, tgt.RemoteAddr, tgt.LocalDevice, tgt.LocalIf, tgt.RemoteDevice, tgt.RemoteIf, tgt.Tenant,
				res.method, boolLabel(res.sourceBound))
			out := outcome{valid: true, reach: res.recv > 0, failReason: res.failReason}
			if res.recv > 0 {
				out.lines = append(out.lines,
					fmt.Sprintf(`circuit_latency_ms{%s} %.3f %d`, lbl, res.latencyMs, now),
					fmt.Sprintf(`circuit_jitter_ms{%s} %.3f %d`, lbl, res.jitterMs, now),
					fmt.Sprintf(`circuit_qoe{%s} %.2f %d`, lbl, res.qoe, now),
				)
			}
			// Loss/sent/recv are meaningful even on total loss (the outage signal).
			out.lines = append(out.lines,
				fmt.Sprintf(`circuit_loss_pct{%s} %.2f %d`, lbl, res.lossPct, now),
				fmt.Sprintf(`circuit_sent{%s} %d %d`, lbl, res.sent, now),
				fmt.Sprintf(`circuit_recv{%s} %d %d`, lbl, res.recv, now),
			)
			out.event = ProbeEvent{
				Kind: res.method, Prober: prober, Target: tgt.RemoteAddr,
				OK: res.recv > 0, RTTms: res.latencyMs, JitterMs: res.jitterMs,
				LossPct: res.lossPct, TS: ts,
			}
			results[i] = out
		}(i, tgt)
	}
	wg.Wait()

	reachable := 0
	probed := 0 // circuits actually measured (a target with no remote addr is skipped)
	lastErr := ""
	var lines []string
	var events []ProbeEvent
	for _, out := range results {
		if !out.valid {
			continue
		}
		probed++
		if out.reach {
			reachable++
		}
		if out.failReason != "" {
			lastErr = out.failReason
		}
		lines = append(lines, out.lines...)
		events = append(events, out.event)
	}

	if len(lines) > 0 {
		emitMetrics(ctx, strings.Join(lines, "\n"))
	}
	forwardProbeEvents(ctx, events)

	s.mu.Lock()
	s.status.LastTick = time.Now().UTC()
	s.status.Targets = len(targets)
	s.status.Reachable = reachable
	// A cycle where most circuits answered nothing at all is not a healthy
	// cycle (see degradedReachFraction). The per-circuit truth is already in
	// circuit_loss_pct; this is the collector's own verdict, which used to be a
	// literal true with a permanently blank LastError.
	s.status.Healthy = cycleHealthy(probed, reachable)
	s.status.LastError = cycleError(probed, reachable, lastErr)
	s.mu.Unlock()
}

// echoConcurrency bounds in-flight circuit probes. Each probe holds one socket
// for up to packets×timeout; a few dozen in flight keeps a large WAN's cycle
// short without exhausting fds or CPU.
const echoConcurrency = 32

// measure runs the ICMP burst; if every echo is lost (ICMP filtered) it falls
// back to a TCP-SYN burst so a firewalled WAN path still yields latency + loss.
func (s *wanEcho) measure(ctx context.Context, tgt EchoTarget) echoResult {
	res := s.measureICMP(ctx, tgt)
	if res.recv == 0 {
		if tcp := s.measureTCP(ctx, tgt); tcp.recv > 0 {
			return tcp
		}
	}
	return res
}

// openEchoICMP binds the ICMP socket to localAddr when the host owns it, so the
// probe egresses the requested WAN interface. Falls back to an unbound socket
// (bound=false) when the address isn't local — the central-prober reality: the
// path is still measured, just not attributed to a specific local egress.
func openEchoICMP(localAddr string) (conn *icmp.PacketConn, datagram, bound bool) {
	try := func(network, addr string) *icmp.PacketConn {
		if c, err := icmp.ListenPacket(network, addr); err == nil {
			return c
		}
		return nil
	}
	if localAddr != "" {
		if c := try("udp4", localAddr); c != nil {
			return c, true, true
		}
		if c := try("ip4:icmp", localAddr); c != nil {
			return c, false, true
		}
	}
	if c := try("udp4", ""); c != nil {
		return c, true, false
	}
	if c := try("ip4:icmp", "0.0.0.0"); c != nil {
		return c, false, false
	}
	return nil, false, false
}

func (s *wanEcho) measureICMP(ctx context.Context, tgt EchoTarget) echoResult {
	res := echoResult{method: "icmp"}
	// Three states, not two (the cloud_monitor_eval.go shape): the resolver
	// FAILED / it answered with no address / it resolved. The first two used to
	// share a return with a zeroed result, so a circuit whose name would not
	// resolve was published as sent=0 recv=0 loss=0% — a perfectly healthy
	// circuit that had never been probed. A path we could not even attempt is
	// FULL LOSS (the same call stamp.go's probeAll already makes), and the cause
	// is carried out so the collector can report it.
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", tgt.RemoteAddr)
	switch {
	case err != nil:
		res.lossPct = 100
		res.failReason = "resolve " + tgt.RemoteAddr + ": " + err.Error()
		return res
	case len(ips) == 0:
		res.lossPct = 100
		res.failReason = "resolve " + tgt.RemoteAddr + ": no IPv4 address"
		return res
	}
	conn, datagram, bound := openEchoICMP(tgt.LocalAddr)
	if conn == nil {
		res.lossPct = 100
		res.failReason = "could not open an ICMP socket (needs CAP_NET_RAW or a usable udp4 socket)"
		return res
	}
	defer conn.Close()
	res.sourceBound = bound

	var dst net.Addr = &net.IPAddr{IP: ips[0]}
	if datagram {
		dst = &net.UDPAddr{IP: ips[0]}
	}
	id := os.Getpid() & 0xffff
	buf := make([]byte, 1500)
	var rtts []float64
	for i := 0; i < s.packets; i++ {
		if ctx.Err() != nil {
			break
		}
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{ID: id, Seq: i, Data: []byte("netops-wan-echo")},
		}
		wb, err := msg.Marshal(nil)
		if err != nil {
			break
		}
		start := time.Now()
		if _, err := conn.WriteTo(wb, dst); err != nil {
			continue
		}
		res.sent++
		_ = conn.SetReadDeadline(time.Now().Add(s.timeout)) // best-effort: a failed deadline set surfaces as a read/write error
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				break // timeout — lost
			}
			m, err := icmp.ParseMessage(1, buf[:n])
			if err != nil {
				continue
			}
			echo, ok := m.Body.(*icmp.Echo)
			if m.Type != ipv4.ICMPTypeEchoReply || !ok {
				continue
			}
			if !datagram && echo.ID != id {
				continue
			}
			res.recv++
			rtts = append(rtts, float64(time.Since(start))/float64(time.Millisecond))
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	summarize(&res, rtts)
	return res
}

// measureTCP times the SYN→SYN-ACK handshake per probe (a clean ~1-RTT sample),
// source-bound via the dialer's LocalAddr. A RST still counts as reached (the
// host answered) — we only care about reachability + timing here.
func (s *wanEcho) measureTCP(ctx context.Context, tgt EchoTarget) echoResult {
	res := echoResult{method: "tcp"}
	dialer := net.Dialer{Timeout: s.timeout}
	if tgt.LocalAddr != "" {
		if ip := net.ParseIP(tgt.LocalAddr); ip != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: ip}
			res.sourceBound = true
		}
	}
	addr := net.JoinHostPort(tgt.RemoteAddr, fmt.Sprintf("%d", s.tcpPort))
	var rtts []float64
	for i := 0; i < s.packets; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		res.sent++
		conn, err := dialer.DialContext(ctx, "tcp4", addr)
		if err != nil {
			// A refused connection (RST) is a reachable host, not a loss.
			if strings.Contains(err.Error(), "refused") {
				res.recv++
				rtts = append(rtts, float64(time.Since(start))/float64(time.Millisecond))
			}
			time.Sleep(20 * time.Millisecond)
			continue
		}
		res.recv++
		rtts = append(rtts, float64(time.Since(start))/float64(time.Millisecond))
		_ = conn.Close() // best-effort: probe socket; nothing actionable on close failure
		time.Sleep(20 * time.Millisecond)
	}
	summarize(&res, rtts)
	return res
}

// summarize fills latency/jitter/loss/qoe from the RTT sample series — the one
// stream, three numbers, just like BFD.
func summarize(res *echoResult, rtts []float64) {
	if res.sent == 0 {
		return
	}
	res.lossPct = lossPct(res.sent, res.recv)
	res.latencyMs = meanRTT(rtts)
	res.jitterMs = jitterMs(rtts)
	res.qoe = qoeScore(res.latencyMs, res.jitterMs, res.lossPct)
}

// ---- pure SLA math (unit-tested) ----

func lossPct(sent, recv int) float64 {
	if sent <= 0 {
		return 0
	}
	if recv > sent {
		recv = sent
	}
	return float64(sent-recv) / float64(sent) * 100
}

func meanRTT(rtts []float64) float64 {
	if len(rtts) == 0 {
		return 0
	}
	sum := 0.0
	for _, r := range rtts {
		sum += r
	}
	return sum / float64(len(rtts))
}

// jitterMs is the mean absolute consecutive RTT delta (the RFC 3550 interarrival
// jitter form) — packet delay variation reconstructed from our own samples, the
// same quantity STAMP reports per-packet.
func jitterMs(rtts []float64) float64 {
	if len(rtts) < 2 {
		return 0
	}
	sum := 0.0
	for i := 1; i < len(rtts); i++ {
		d := rtts[i] - rtts[i-1]
		if d < 0 {
			d = -d
		}
		sum += d
	}
	return sum / float64(len(rtts)-1)
}

// qoeScore maps the SLA triplet to a 0..10 quality score anchored on the voice
// SLA class (loss<1% / latency<150ms / jitter<30ms = excellent). The worst
// dimension pulls the score down (SD-WAN SLA-class behaviour), blended with the
// average so a single marginal metric doesn't zero an otherwise-good circuit.
func qoeScore(latencyMs, jitterMs, lossPct float64) float64 {
	latS := scoreLinear(latencyMs, 50, 300)
	jitS := scoreLinear(jitterMs, 10, 80)
	lossS := scoreLinear(lossPct, 0.2, 8)
	worst := latS
	for _, v := range []float64{jitS, lossS} {
		if v < worst {
			worst = v
		}
	}
	avg := (latS + jitS + lossS) / 3
	return round1(0.5*worst + 0.5*avg)
}

// scoreLinear returns 10 at/below good, 0 at/above bad, linear between.
func scoreLinear(v, good, bad float64) float64 {
	if v <= good {
		return 10
	}
	if v >= bad {
		return 0
	}
	return 10 * (bad - v) / (bad - good)
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }

func boolLabel(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
