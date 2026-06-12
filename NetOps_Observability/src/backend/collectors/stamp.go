package collectors

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// stamp.go — active path measurement via STAMP, the Simple Two-way Active
// Measurement Protocol (RFC 8762, unauthenticated mode; standardizes TWAMP-Light
// from RFC 5357 App. I). This is the modern, standards-grade way to measure
// one-way + round-trip delay, delay variation (jitter, RFC 3393), and packet
// loss (RFC 2680) — not ICMP ping. Pure stdlib UDP: no raw sockets, no new deps.
//
// Two roles, both opt-in:
//   - reflector (NewSTAMPReflector): a stateless UDP responder that timestamps
//     and reflects every test packet. Ship-our-own so any site/host can be a
//     target; interoperates with device STAMP/TWAMP-Light responders.
//   - sender (NewSTAMPSender): probes configured targets, computes RTT / one-way
//     delay / loss / PDV, emits probe_* metrics to VictoriaMetrics.
//
// Packet formats follow RFC 8762: §4.2.1 sender test packet, §4.3 reflected
// test packet (unauthenticated, 44 bytes).

// ntpEpochOffset is seconds between the NTP epoch (1900-01-01) and the Unix
// epoch (1970-01-01). STAMP timestamps are 64-bit NTP (32b seconds + 32b frac).
const ntpEpochOffset = 2208988800

const stampReflectedLen = 44 // unauthenticated reflected test packet (RFC 8762 §4.3)

// ntpNow returns the current time as a 64-bit NTP timestamp.
func ntpNow() uint64 { return ntpFromTime(time.Now()) }

func ntpFromTime(t time.Time) uint64 {
	sec := uint64(t.Unix() + ntpEpochOffset)
	frac := uint64(t.Nanosecond()) * (1 << 32) / 1_000_000_000
	return sec<<32 | (frac & 0xffffffff)
}

// ntpSeconds converts a 64-bit NTP timestamp to absolute float seconds. Deltas
// between two of these cancel the epoch offset, so they give true intervals.
func ntpSeconds(u uint64) float64 {
	return float64(u>>32) + float64(u&0xffffffff)/float64(1<<32)
}

// encodeSenderPacket builds an unauthenticated STAMP sender test packet
// (RFC 8762 §4.2.1): seq(4) | timestamp(8) | error-estimate(2) | MBZ padding.
// Padded to `size` (min 14) so probe packet size is configurable.
func encodeSenderPacket(seq uint32, t1 uint64, size int) []byte {
	if size < 14 {
		size = 14
	}
	b := make([]byte, size)
	binary.BigEndian.PutUint32(b[0:4], seq)
	binary.BigEndian.PutUint64(b[4:12], t1)
	// Error Estimate (b[12:14]): S=0, scale/multiplier left zero (unsynchronized).
	return b
}

// parseSenderPacket reads the seq + T1 from a sender test packet (reflector side).
func parseSenderPacket(b []byte) (seq uint32, t1 uint64, ok bool) {
	if len(b) < 12 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(b[0:4]), binary.BigEndian.Uint64(b[4:12]), true
}

// encodeReflectedPacket builds the unauthenticated reflected test packet
// (RFC 8762 §4.3): reflector seq(4) | T3(8) | err-est(2) | MBZ(2) | T2 rx(8) |
// sender seq(4) | T1(8) | sender err-est(2) | MBZ(2) | sender TTL(1) | MBZ(3).
func encodeReflectedPacket(rSeq uint32, t3, t2 uint64, sSeq uint32, t1 uint64, ttl uint8) []byte {
	b := make([]byte, stampReflectedLen)
	binary.BigEndian.PutUint32(b[0:4], rSeq)
	binary.BigEndian.PutUint64(b[4:12], t3)
	// b[12:14] error estimate, b[14:16] MBZ
	binary.BigEndian.PutUint64(b[16:24], t2)
	binary.BigEndian.PutUint32(b[24:28], sSeq)
	binary.BigEndian.PutUint64(b[28:36], t1)
	// b[36:38] sender error estimate, b[38:40] MBZ
	b[40] = ttl
	return b
}

// reflected holds the timestamps a sender needs from a reflected packet.
type reflected struct {
	senderSeq uint32
	t1, t2, t3 uint64
}

func parseReflectedPacket(b []byte) (reflected, bool) {
	if len(b) < stampReflectedLen {
		return reflected{}, false
	}
	return reflected{
		t3:        binary.BigEndian.Uint64(b[4:12]),
		t2:        binary.BigEndian.Uint64(b[16:24]),
		senderSeq: binary.BigEndian.Uint32(b[24:28]),
		t1:        binary.BigEndian.Uint64(b[28:36]),
	}, true
}

// reflect builds the reflected packet for a received sender packet, stamping T2
// (receive) and T3 (transmit). Stateless — STAMP unauthenticated mode.
func reflectPacket(in []byte, rSeq uint32, t2 uint64) ([]byte, bool) {
	sSeq, t1, ok := parseSenderPacket(in)
	if !ok {
		return nil, false
	}
	return encodeReflectedPacket(rSeq, ntpNow(), t2, sSeq, t1, 255), true
}

// ── Reflector ─────────────────────────────────────────────────────────────────

type stampReflector struct {
	addr   string
	mu     sync.RWMutex
	status Status
	count  uint32
}

// NewSTAMPReflector builds the STAMP/TWAMP-Light reflector. Listens on
// STAMP_REFLECTOR_PORT (default 862, the IANA STAMP port).
func NewSTAMPReflector() Collector {
	port := os.Getenv("STAMP_REFLECTOR_PORT")
	if port == "" {
		port = "862"
	}
	return &stampReflector{
		addr:   ":" + port,
		status: Status{Name: "stamp-reflector", Healthy: true, Kind: "discovery"},
	}
}

func (r *stampReflector) Name() string { return "stamp-reflector" }
func (r *stampReflector) Status() Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}

func (r *stampReflector) Run(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", r.addr)
	if err != nil {
		r.setErr(err)
		return err
	}
	defer pc.Close()
	go func() { <-ctx.Done(); _ = pc.Close() }()

	buf := make([]byte, 1500)
	var seq uint32
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, src, err := pc.ReadFrom(buf)
		t2 := ntpNow()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		out, ok := reflectPacket(buf[:n], seq, t2)
		if !ok {
			continue
		}
		seq++
		_, _ = pc.WriteTo(out, src)
		r.mu.Lock()
		r.count++
		r.status.LastTick = time.Now().UTC()
		r.status.Reachable = int(r.count)
		r.mu.Unlock()
	}
}

func (r *stampReflector) setErr(err error) {
	r.mu.Lock()
	r.status.Healthy = false
	r.status.LastError = err.Error()
	r.mu.Unlock()
}

// ── Sender ────────────────────────────────────────────────────────────────────

type stampSender struct {
	interval time.Duration
	packets  int
	mu       sync.RWMutex
	status   Status
}

// NewSTAMPSender builds the STAMP sender. Targets come from STAMP_TARGETS
// (comma-separated host[:port], default port 862); each is probed every
// STAMP_INTERVAL (default 30s) with STAMP_PACKETS test packets (default 20).
func NewSTAMPSender() Collector {
	return &stampSender{
		interval: envDuration("STAMP_INTERVAL", 30*time.Second),
		packets:  envInt("STAMP_PACKETS", 20),
		status:   Status{Name: "stamp-sender", Healthy: true, Kind: "metrics"},
	}
}

func (s *stampSender) Name() string { return "stamp-sender" }
func (s *stampSender) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *stampSender) Run(ctx context.Context) error {
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

func stampTargets() []string {
	raw := strings.TrimSpace(os.Getenv("STAMP_TARGETS"))
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, withPort(p, 862))
	}
	return out
}

func (s *stampSender) probeAll(ctx context.Context) {
	targets := stampTargets()
	now := time.Now().UnixMilli()
	prober := proberID()
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	reachable := 0
	var lines []string
	var events []ProbeEvent
	for _, tgt := range targets {
		res, err := probeSTAMP(ctx, tgt, s.packets)
		if err != nil {
			// Resolve/dial failure is still a real observation of the path:
			// forward it as full loss so the engine sees the outage, even
			// though there is no sample to render as a gauge.
			events = append(events, ProbeEvent{
				Kind: "stamp", Prober: prober, Target: tgt,
				OK: false, LossPct: 100, TS: ts,
			})
			continue
		}
		if res.recv > 0 {
			reachable++
		}
		events = append(events, ProbeEvent{
			Kind: "stamp", Prober: prober, Target: tgt,
			OK: res.recv > 0, RTTms: res.rttMs, JitterMs: res.pdvMs,
			LossPct: res.lossPct, TS: ts,
		})
		lines = append(lines,
			fmt.Sprintf(`probe_rtt_ms{dst=%q,probe="stamp"} %.3f %d`, tgt, res.rttMs, now),
			fmt.Sprintf(`probe_owd_ms{dst=%q,probe="stamp"} %.3f %d`, tgt, res.owdMs, now),
			fmt.Sprintf(`probe_pdv_ms{dst=%q,probe="stamp"} %.3f %d`, tgt, res.pdvMs, now),
			fmt.Sprintf(`probe_loss_pct{dst=%q,probe="stamp"} %.2f %d`, tgt, res.lossPct, now),
			fmt.Sprintf(`probe_sent{dst=%q,probe="stamp"} %d %d`, tgt, res.sent, now),
			fmt.Sprintf(`probe_recv{dst=%q,probe="stamp"} %d %d`, tgt, res.recv, now),
		)
	}
	if len(lines) > 0 {
		emitMetrics(ctx, strings.Join(lines, "\n"))
	}
	forwardProbeEvents(ctx, events)
	s.mu.Lock()
	s.status.LastTick = time.Now().UTC()
	s.status.Targets = len(targets)
	s.status.Reachable = reachable
	s.status.Healthy = true
	s.mu.Unlock()
}

// stampResult is the per-target measurement summary.
type stampResult struct {
	sent, recv int
	rttMs      float64 // mean round-trip (RFC 8762: (T4-T1)-(T3-T2))
	owdMs      float64 // mean forward one-way (T2-T1; valid when clocks synced)
	pdvMs      float64 // packet delay variation / jitter (RFC 3393, mean |Δrtt|)
	lossPct    float64 // RFC 2680 one-way loss
}

// probeSTAMP sends `count` STAMP test packets to a reflector and computes the
// summary. Stdlib UDP only; per-session socket with a read deadline.
func probeSTAMP(ctx context.Context, target string, count int) (stampResult, error) {
	if count <= 0 {
		count = 20
	}
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return stampResult{}, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return stampResult{}, err
	}
	defer conn.Close()

	var samples []stampSample
	sent := 0
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		seq := uint32(i)
		pkt := encodeSenderPacket(seq, ntpNow(), 44)
		if _, err := conn.Write(pkt); err != nil {
			continue
		}
		sent++
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		t4 := ntpNow()
		if err != nil {
			continue // lost / timed out
		}
		r, ok := parseReflectedPacket(buf[:n])
		if !ok || r.senderSeq != seq {
			continue
		}
		t1, t2, t3 := ntpSeconds(r.t1), ntpSeconds(r.t2), ntpSeconds(r.t3)
		rtt := ((ntpSeconds(t4) - t1) - (t3 - t2)) * 1000
		owd := (t2 - t1) * 1000
		if rtt < 0 {
			rtt = 0
		}
		samples = append(samples, stampSample{rtt: rtt, owd: owd})
		time.Sleep(20 * time.Millisecond)
	}

	res := stampResult{sent: sent, recv: len(samples)}
	if sent > 0 {
		res.lossPct = float64(sent-len(samples)) / float64(sent) * 100
	}
	if len(samples) > 0 {
		var sumRtt, sumOwd float64
		for _, s := range samples {
			sumRtt += s.rtt
			sumOwd += s.owd
		}
		res.rttMs = sumRtt / float64(len(samples))
		res.owdMs = sumOwd / float64(len(samples))
		res.pdvMs = meanAbsDiff(samples)
	}
	return res, nil
}

// stampSample is one probe's measured round-trip and forward one-way delay (ms).
type stampSample struct{ rtt, owd float64 }

// meanAbsDiff is the RFC 3393 packet-delay-variation estimator: the mean of the
// absolute differences between consecutive samples' round-trip delays.
func meanAbsDiff(s []stampSample) float64 {
	if len(s) < 2 {
		return 0
	}
	var sum float64
	for i := 1; i < len(s); i++ {
		sum += math.Abs(s[i].rtt - s[i-1].rtt)
	}
	return sum / float64(len(s)-1)
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return def
}
