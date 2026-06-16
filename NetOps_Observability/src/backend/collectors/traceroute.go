package collectors

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// traceroute.go — modern, Paris-consistent path discovery (the "which path"
// half of active measurement; STAMP is the "how good"). Classic traceroute
// varies the flow 5-tuple per probe, so on ECMP/load-balanced networks
// different probes take different paths and the result is wrong (phantom hops,
// loops). We probe with ICMP Echo at increasing TTL and a CONSTANT flow
// identifier (ICMP id fixed for a trace; only the echo sequence varies, which
// is not used for ECMP hashing) — i.e. Paris-style — so every probe in a trace
// follows one consistent path. Responses are matched to probes by the echo
// id+seq quoted inside the ICMP Time-Exceeded payload.
//
// Uses golang.org/x/net (ipv4 TTL control + icmp message parse) — capabilities
// stdlib net does not expose. Needs CAP_NET_RAW for the raw ICMP socket (or set
// TRACEROUTE_SOCKET=udp4 for unprivileged ping sockets where sysctl allows).

// Hop is one TTL position on the path. IP is "" when no router replied (a "*").
type Hop struct {
	TTL   int     `json:"ttl"`
	IP    string  `json:"ip"`
	Host  string  `json:"host,omitempty"` // rDNS hostname for IP (best-effort), so the UI shows names not IPs
	RTTms float64 `json:"rtt_ms"`         // best (min) RTT across this hop's probes
	Loss  float64 `json:"loss_pct"`
	Via   string  `json:"via,omitempty"` // priority/auto mode: fallback method that filled this hop
}

// ── reverse DNS (hop IP → hostname) ───────────────────────────────────────────
// Resolved best-effort with a short timeout and cached process-wide (PTR records
// rarely change), so the UI can label hops by name. Empty when no PTR exists.
// Disable with TRACEROUTE_RDNS=off.
var (
	rdnsMu    sync.Mutex
	rdnsCache = map[string]string{}
)

func rdnsLookup(ctx context.Context, ip string) string {
	if ip == "" || os.Getenv("TRACEROUTE_RDNS") == "off" {
		return ""
	}
	rdnsMu.Lock()
	v, ok := rdnsCache[ip]
	rdnsMu.Unlock()
	if ok {
		return v
	}
	c, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()
	name := ""
	if names, err := net.DefaultResolver.LookupAddr(c, ip); err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}
	rdnsMu.Lock()
	rdnsCache[ip] = name
	rdnsMu.Unlock()
	return name
}

// resolveHostnames fills Hop.Host for each responding hop (best-effort rDNS).
func resolveHostnames(ctx context.Context, hops []Hop) {
	for i := range hops {
		if hops[i].IP == "" || hops[i].Host != "" {
			continue
		}
		hops[i].Host = rdnsLookup(ctx, hops[i].IP)
	}
}

// PathResult is the latest trace to a destination, exposed to the API/UI. A
// destination can be traced by more than one METHOD (icmp + tcp) — they often
// diverge (ICMP-blocking firewalls, protocol-specific ECMP hashing), so each
// (dst, method) is stored and surfaced separately.
type PathResult struct {
	Dst     string    `json:"dst"`
	Method  string    `json:"method"` // "icmp" | "tcp"
	Hops    []Hop     `json:"hops"`
	Reached bool      `json:"reached"`
	Changed bool      `json:"changed"` // path differs from the previous trace
	TS      time.Time `json:"ts"`
}

// ── shared path store (collector writes, API reads) ───────────────────────────

type pathRegistry struct {
	mu sync.RWMutex
	m  map[string]PathResult
}

// Paths is the process-wide latest-trace store; the /api/probe/paths handler
// reads it, the traceroute collector writes it. Decouples the collector from
// the HTTP layer without threading a reference through the pool.
var Paths = &pathRegistry{m: make(map[string]PathResult)}

// pathKey indexes a stored trace by destination AND method so icmp and tcp
// traces to the same dst coexist instead of overwriting each other. Legacy/empty
// method normalizes to "icmp" (the historical default).
func pathKey(dst, method string) string {
	if method == "" {
		method = "icmp"
	}
	return dst + "|" + method
}

func (r *pathRegistry) set(p PathResult) {
	r.mu.Lock()
	r.m[pathKey(p.Dst, p.Method)] = p
	r.mu.Unlock()
	r.persist()
}

// persist publishes the full path set so a prober sidecar can share topology
// with the API process (ADR 0001 — workers communicate via Redis). Primary:
// Redis (TTL'd, self-expiring). Fallback: PROBE_PATHS_FILE on a shared volume.
// No-op when neither is configured (collector runs in-process with the API).
func (r *pathRegistry) persist() {
	data, err := json.Marshal(r.All())
	if err != nil {
		return
	}
	if RedisAddr() != "" {
		// Background persistence with the dialer's own 3s timeout — the
		// registry has no request context to inherit.
		_ = redisSetEX(context.Background(), probePathsKey, string(data), 300)
		return
	}
	if path := os.Getenv("PROBE_PATHS_FILE"); path != "" {
		tmp := path + ".tmp"
		if os.WriteFile(tmp, data, 0o644) == nil { // #nosec G306 -- non-secret topology
			_ = os.Rename(tmp, path)
		}
	}
}

func (r *pathRegistry) get(dst, method string) (PathResult, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.m[pathKey(dst, method)]
	return p, ok
}

// All returns every stored path, newest first.
func (r *pathRegistry) All() []PathResult {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]PathResult, 0, len(r.m))
	for _, p := range r.m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS.After(out[j].TS) })
	return out
}

// pathSignature is the ordered list of hop IPs — used to detect path changes.
func pathSignature(hops []Hop) string {
	parts := make([]string, len(hops))
	for i, h := range hops {
		parts[i] = h.IP
	}
	return strings.Join(parts, ">")
}

// ── traceroute core ───────────────────────────────────────────────────────────

type traceConfig struct {
	maxHops   int
	probes    int
	timeout   time.Duration
	method    string // "icmp" (default) | "tcp"
	socketNet string // ICMP socket: "ip4:icmp" (raw, needs CAP_NET_RAW) | "udp4"
	tcpPort   int    // TCP method: destination port (default 443)
}

// peerIP normalizes the responder address (IPAddr or UDPAddr) to a bare IP.
func peerIP(a net.Addr) string {
	switch v := a.(type) {
	case *net.IPAddr:
		return v.IP.String()
	case *net.UDPAddr:
		return v.IP.String()
	default:
		h, _, err := net.SplitHostPort(a.String())
		if err == nil {
			return h
		}
		return a.String()
	}
}

// quotedEchoIDSeq extracts the original echo id+seq from the body of an ICMP
// Time-Exceeded / Dest-Unreachable message (the quoted "IP header + 8 bytes").
func quotedEchoIDSeq(data []byte) (id, seq int, ok bool) {
	if len(data) < 1 {
		return 0, 0, false
	}
	ihl := int(data[0]&0x0f) * 4 // quoted inner IPv4 header length
	inner := data
	if len(data) >= ihl+8 {
		inner = data[ihl:] // skip the quoted IP header → inner ICMP
	}
	if len(inner) < 8 {
		return 0, 0, false
	}
	// inner: type(1) code(1) checksum(2) id(2) seq(2)
	return int(binary.BigEndian.Uint16(inner[4:6])), int(binary.BigEndian.Uint16(inner[6:8])), true
}

// traceOnce runs one full trace to dst, dispatching on the configured method.
func traceOnce(ctx context.Context, dst string, cfg traceConfig) (PathResult, error) {
	ipAddr, err := net.ResolveIPAddr("ip4", dst)
	if err != nil {
		return PathResult{}, err
	}
	var res PathResult
	if cfg.method == "tcp" {
		res, err = traceTCP(ctx, dst, ipAddr.IP, cfg)
	} else {
		res, err = traceICMP(ctx, dst, ipAddr, cfg)
	}
	if err != nil {
		return PathResult{}, err
	}
	res.Method = methodLabel(cfg.method)
	resolveHostnames(ctx, res.Hops) // rDNS so the UI shows hostnames, not IPs
	return res, nil
}

// methodLabel normalizes the configured method to its stored label.
func methodLabel(m string) string {
	if m == "tcp" {
		return "tcp"
	}
	return "icmp"
}

// isComplete reports whether a trace revealed the ENTIRE path: it reached the
// destination and every hop responded (no unresponsive "*" gaps). Priority/auto
// mode uses this to decide whether a fallback method is needed.
func isComplete(p PathResult) bool {
	if !p.Reached || len(p.Hops) == 0 {
		return false
	}
	for _, h := range p.Hops {
		if h.IP == "" {
			return false
		}
	}
	return true
}

// mergePaths fills gaps in base using alt (priority/auto mode). base's responsive
// hops are always preferred (it's the higher-priority method); any unresponsive
// hop ("*") in base is filled from alt's hop at the same TTL and tagged Via. If
// base never reached the destination but alt did, alt's tail extends base.
func mergePaths(base, alt PathResult, via string) PathResult {
	byTTL := make(map[int]Hop, len(alt.Hops))
	maxTTL := 0
	for _, h := range alt.Hops {
		byTTL[h.TTL] = h
		if h.TTL > maxTTL {
			maxTTL = h.TTL
		}
	}
	out := base
	out.Hops = make([]Hop, len(base.Hops))
	copy(out.Hops, base.Hops)
	for i := range out.Hops {
		if out.Hops[i].IP == "" {
			if a, ok := byTTL[out.Hops[i].TTL]; ok && a.IP != "" {
				a.Via = via
				out.Hops[i] = a
			}
		}
	}
	if !base.Reached && alt.Reached {
		baseMax := 0
		if len(base.Hops) > 0 {
			baseMax = base.Hops[len(base.Hops)-1].TTL
		}
		for ttl := baseMax + 1; ttl <= maxTTL; ttl++ {
			if a, ok := byTTL[ttl]; ok {
				a.Via = via
				out.Hops = append(out.Hops, a)
			}
		}
		out.Reached = alt.Reached
	}
	return out
}

// tracePriority runs methods in priority order: the first (icmp) is the base; if
// it doesn't reveal the entire path, each subsequent method (tcp) fills the gaps
// until the path is complete. Returns one merged path (Method "auto"); per-hop
// Via marks which fallback method rescued each filled hop.
func tracePriority(ctx context.Context, dst string, cfg traceConfig, methods []string) (PathResult, error) {
	var base PathResult
	var firstErr error
	have := false
	for _, m := range methods {
		c := cfg
		c.method = m
		res, err := traceOnce(ctx, dst, c)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !have {
			base, have = res, true
		} else {
			base = mergePaths(base, res, methodLabel(m))
		}
		if isComplete(base) {
			break
		}
	}
	if !have {
		return PathResult{}, firstErr
	}
	base.Method = "auto"
	return base, nil
}

// traceICMP runs a Paris-consistent ICMP-echo trace (constant id, varying seq).
func traceICMP(ctx context.Context, dst string, ipAddr *net.IPAddr, cfg traceConfig) (PathResult, error) {
	conn, err := icmp.ListenPacket(cfg.socketNet, "0.0.0.0")
	if err != nil {
		return PathResult{}, err
	}
	defer conn.Close()
	pc := conn.IPv4PacketConn()

	id := os.Getpid() & 0xffff // constant for this process → consistent flow
	var dstAddr net.Addr = ipAddr
	if cfg.socketNet == "udp4" {
		dstAddr = &net.UDPAddr{IP: ipAddr.IP}
	}

	res := PathResult{Dst: dst, TS: time.Now().UTC()}
	for ttl := 1; ttl <= cfg.maxHops; ttl++ {
		if ctx.Err() != nil {
			break
		}
		hop := Hop{TTL: ttl, Loss: 100}
		var best float64 = -1
		got := 0
		var reachedDst bool
		for p := 1; p <= cfg.probes; p++ {
			seq := (ttl<<8 | p) & 0xffff
			if err := pc.SetTTL(ttl); err != nil {
				return PathResult{}, err
			}
			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho, Code: 0,
				Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("netops-probe")},
			}
			wb, err := msg.Marshal(nil)
			if err != nil {
				continue
			}
			t0 := time.Now()
			if _, err := conn.WriteTo(wb, dstAddr); err != nil {
				continue
			}
			ip, rtt, reached, matched := awaitReply(conn, id, seq, ipAddr.IP, t0, cfg.timeout)
			if matched {
				got++
				if hop.IP == "" {
					hop.IP = ip
				}
				if best < 0 || rtt < best {
					best = rtt
				}
				if reached {
					reachedDst = true
				}
			}
		}
		if got > 0 {
			hop.RTTms = best
			hop.Loss = float64(cfg.probes-got) / float64(cfg.probes) * 100
		}
		res.Hops = append(res.Hops, hop)
		if reachedDst {
			res.Reached = true
			break
		}
	}
	return res, nil
}

// awaitReply waits up to timeout for a Time-Exceeded (intermediate hop) or
// Echo-Reply (destination) that matches our id+seq, returning the responder IP
// and RTT. reached=true when it's the destination's echo reply.
func awaitReply(conn *icmp.PacketConn, id, seq int, dstIP net.IP, t0 time.Time, timeout time.Duration) (ip string, rttMs float64, reached, matched bool) {
	deadline := time.Now().Add(timeout)
	rb := make([]byte, 1500)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(deadline)
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return "", 0, false, false // timeout
		}
		rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
		if err != nil {
			continue
		}
		switch body := rm.Body.(type) {
		case *icmp.TimeExceeded:
			if qid, qseq, ok := quotedEchoIDSeq(body.Data); ok && qid == id && qseq == seq {
				return peerIP(peer), msSince(t0), false, true
			}
		case *icmp.DstUnreach:
			if qid, qseq, ok := quotedEchoIDSeq(body.Data); ok && qid == id && qseq == seq {
				return peerIP(peer), msSince(t0), peerIP(peer) == dstIP.String(), true
			}
		case *icmp.Echo:
			if body.ID == id && body.Seq == seq {
				return peerIP(peer), msSince(t0), true, true
			}
		}
		// Not ours (another trace / unrelated ICMP) — keep waiting.
	}
	return "", 0, false, false
}

func msSince(t0 time.Time) float64 { return float64(time.Since(t0).Microseconds()) / 1000.0 }

// ── TCP SYN traceroute (firewall-friendly: ICMP/UDP are often blocked) ─────────
// Sends crafted TCP SYNs at increasing TTL with a CONSTANT flow (fixed src/dst
// port = Paris-consistent). Intermediate routers return ICMP Time-Exceeded
// (matched by the quoted TCP src-port + seq); the destination returns SYN-ACK or
// RST (= reached, matched by ack == seq+1). Raw sockets need CAP_NET_RAW.

// localSourceIPv4 returns the source IPv4 the kernel would use to reach dst.
func localSourceIPv4(ctx context.Context, dst net.IP) net.IP {
	// A connected UDP socket sends nothing; it only resolves the route.
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", net.JoinHostPort(dst.String(), "33434"))
	if err != nil {
		return nil
	}
	defer c.Close()
	if la, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return la.IP.To4()
	}
	return nil
}

// tcpChecksum computes the TCP checksum over the IPv4 pseudo-header + segment.
func tcpChecksum(src, dst net.IP, seg []byte) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[9] = 6 // protocol = TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(pseudo)
	add(seg)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildSYN builds a 20-byte TCP SYN segment with a valid checksum.
func buildSYN(src, dst net.IP, sport, dport uint16, seq uint32) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint32(b[4:8], seq)
	b[12] = 5 << 4                               // data offset = 5 32-bit words
	b[13] = 0x02                                 // SYN
	binary.BigEndian.PutUint16(b[14:16], 0xffff) // window
	binary.BigEndian.PutUint16(b[16:18], tcpChecksum(src, dst, b))
	return b
}

// quotedTCPSrcSeq parses src-port + seq from an ICMP error body that quotes the
// original IPv4 header + first 8 bytes of TCP (srcport, dstport, seq).
func quotedTCPSrcSeq(data []byte) (sport uint16, seq uint32, ok bool) {
	if len(data) < 1 {
		return 0, 0, false
	}
	ihl := int(data[0]&0x0f) * 4
	inner := data
	if len(data) >= ihl+8 {
		inner = data[ihl:]
	}
	if len(inner) < 8 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(inner[0:2]), binary.BigEndian.Uint32(inner[4:8]), true
}

// parseTCPReply extracts ports/ack/flags from a received packet, stripping a
// leading IPv4 header if the platform includes one on raw reads.
func parseTCPReply(data []byte) (sport, dport uint16, ack uint32, flags byte, ok bool) {
	seg := data
	if len(data) > 0 && data[0]>>4 == 4 {
		ihl := int(data[0]&0x0f) * 4
		if len(data) < ihl+20 {
			return 0, 0, 0, 0, false
		}
		seg = data[ihl:]
	}
	if len(seg) < 20 {
		return 0, 0, 0, 0, false
	}
	return binary.BigEndian.Uint16(seg[0:2]), binary.BigEndian.Uint16(seg[2:4]),
		binary.BigEndian.Uint32(seg[8:12]), seg[13], true
}

type tcpEvent struct {
	seq     uint32
	ip      string
	reached bool
}

func traceTCP(ctx context.Context, dst string, dstIP net.IP, cfg traceConfig) (PathResult, error) {
	src := localSourceIPv4(ctx, dstIP)
	if src == nil {
		return PathResult{}, fmt.Errorf("traceroute tcp: no source IPv4 for %s", dst)
	}
	icmpConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return PathResult{}, err
	}
	defer icmpConn.Close()
	var lc net.ListenConfig
	tcpConn, err := lc.ListenPacket(ctx, "ip4:tcp", "0.0.0.0")
	if err != nil {
		return PathResult{}, err
	}
	defer tcpConn.Close()
	rawTTL := ipv4.NewPacketConn(tcpConn)

	const sport uint16 = 33434
	dport := uint16(cfg.tcpPort)
	if dport == 0 {
		dport = 443
	}

	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan tcpEvent, 64)

	// ICMP reader → intermediate hops.
	go func() {
		rb := make([]byte, 1500)
		for rctx.Err() == nil {
			_ = icmpConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, peer, err := icmpConn.ReadFrom(rb)
			if err != nil {
				continue
			}
			rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
			if err != nil {
				continue
			}
			var body []byte
			switch t := rm.Body.(type) {
			case *icmp.TimeExceeded:
				body = t.Data
			case *icmp.DstUnreach:
				body = t.Data
			default:
				continue
			}
			if sp, seq, ok := quotedTCPSrcSeq(body); ok && sp == sport {
				select {
				case ch <- tcpEvent{seq: seq, ip: peerIP(peer)}:
				default:
				}
			}
		}
	}()
	// TCP reader → destination SYN-ACK / RST = reached.
	go func() {
		rb := make([]byte, 1500)
		for rctx.Err() == nil {
			_ = tcpConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, peer, err := tcpConn.ReadFrom(rb)
			if err != nil {
				continue
			}
			sp, dp, ack, flags, ok := parseTCPReply(rb[:n])
			if !ok || peerIP(peer) != dstIP.String() || sp != dport || dp != sport {
				continue
			}
			if flags&0x04 != 0 || flags&0x12 == 0x12 { // RST or SYN-ACK
				select {
				case ch <- tcpEvent{seq: ack - 1, ip: peerIP(peer), reached: true}:
				default:
				}
			}
		}
	}()

	res := PathResult{Dst: dst, TS: time.Now().UTC()}
	const seqBase uint32 = 0x6e657470 // "netp"
	for ttl := 1; ttl <= cfg.maxHops; ttl++ {
		if ctx.Err() != nil {
			break
		}
		hop := Hop{TTL: ttl, Loss: 100}
		var best float64 = -1
		got := 0
		reachedDst := false
		for p := 1; p <= cfg.probes; p++ {
			seq := seqBase + uint32(ttl<<8|p)
			if err := rawTTL.SetTTL(ttl); err != nil {
				return PathResult{}, err
			}
			syn := buildSYN(src, dstIP, sport, dport, seq)
			t0 := time.Now()
			if _, err := tcpConn.WriteTo(syn, &net.IPAddr{IP: dstIP}); err != nil {
				continue
			}
			ip, rtt, reached, matched := waitTCPEvent(ch, seq, t0, cfg.timeout)
			if matched {
				got++
				if hop.IP == "" {
					hop.IP = ip
				}
				if best < 0 || rtt < best {
					best = rtt
				}
				if reached {
					reachedDst = true
				}
			}
		}
		if got > 0 {
			hop.RTTms = best
			hop.Loss = float64(cfg.probes-got) / float64(cfg.probes) * 100
		}
		res.Hops = append(res.Hops, hop)
		if reachedDst {
			res.Reached = true
			break
		}
	}
	return res, nil
}

// waitTCPEvent waits for a channel event matching seq, discarding others, until
// the timeout.
func waitTCPEvent(ch <-chan tcpEvent, seq uint32, t0 time.Time, timeout time.Duration) (ip string, rttMs float64, reached, matched bool) {
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return "", 0, false, false
		}
		select {
		case ev := <-ch:
			if ev.seq == seq {
				return ev.ip, msSince(t0), ev.reached, true
			}
		case <-time.After(remaining):
			return "", 0, false, false
		}
	}
}

// ── collector ─────────────────────────────────────────────────────────────────

type tracerouteCollector struct {
	interval time.Duration
	cfg      traceConfig
	methods  []string // ordered, deduped: which methods to trace each cycle
	auto     bool     // priority mode: icmp first, fall back to tcp to fill gaps
	mu       sync.RWMutex
	status   Status
}

// parseMethods reads TRACEROUTE_METHOD as a comma-separated list so a dst can be
// traced by both protocols ("icmp,tcp" or "both"). "auto"/"priority" means try
// icmp first and fall back to tcp to fill gaps — it needs both methods available,
// so it expands to [icmp, tcp]. Default: icmp only (TCP needs a raw TCP socket /
// CAP_NET_RAW, so it stays opt-in). Order preserved, deduped.
func parseMethods(raw string) []string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return []string{"icmp"}
	}
	if raw == "both" || raw == "auto" || raw == "priority" {
		return []string{"icmp", "tcp"}
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		switch strings.TrimSpace(p) {
		case "icmp":
			if !seen["icmp"] {
				seen["icmp"] = true
				out = append(out, "icmp")
			}
		case "tcp":
			if !seen["tcp"] {
				seen["tcp"] = true
				out = append(out, "tcp")
			}
		}
	}
	if len(out) == 0 {
		return []string{"icmp"}
	}
	return out
}

// NewTraceroute builds the scheduled path-discovery collector. Targets come from
// TRACEROUTE_TARGETS (comma-separated host/IP); each is traced every
// TRACEROUTE_INTERVAL (default 60s).
func NewTraceroute() Collector {
	sock := os.Getenv("TRACEROUTE_SOCKET")
	if sock != "udp4" {
		sock = "ip4:icmp"
	}
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("TRACEROUTE_METHOD")))
	auto := raw == "auto" || raw == "priority"
	methods := parseMethods(raw)
	return &tracerouteCollector{
		interval: envDuration("TRACEROUTE_INTERVAL", 60*time.Second),
		cfg: traceConfig{
			maxHops:   envInt("TRACEROUTE_MAX_HOPS", 30),
			probes:    envInt("TRACEROUTE_PROBES", 3),
			timeout:   envDuration("TRACEROUTE_TIMEOUT", time.Second),
			method:    methods[0],
			socketNet: sock,
			tcpPort:   envInt("TRACEROUTE_TCP_PORT", 443),
		},
		methods: methods,
		auto:    auto,
		status:  Status{Name: "traceroute", Healthy: true, Kind: "metrics"},
	}
}

func (c *tracerouteCollector) Name() string { return "traceroute" }
func (c *tracerouteCollector) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *tracerouteCollector) Run(ctx context.Context) error {
	t := time.NewTicker(c.interval)
	defer t.Stop()
	c.traceAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			c.traceAll(ctx)
		}
	}
}

func tracerouteTargets() []string {
	raw := strings.TrimSpace(os.Getenv("TRACEROUTE_TARGETS"))
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c *tracerouteCollector) traceAll(ctx context.Context) {
	targets := tracerouteTargets()
	now := time.Now().UnixMilli()
	var lines []string
	var lastErr string
	reachedAny := map[string]bool{} // a target counts reachable if ANY method reaches it
	// store one trace result + emit its metrics (method label keeps icmp/tcp/auto
	// series distinct; route stability via path_changed feeds Path Health).
	emit := func(dst string, res PathResult) {
		if prev, ok := Paths.get(dst, res.Method); ok {
			res.Changed = pathSignature(prev.Hops) != pathSignature(res.Hops)
		}
		Paths.set(res)
		if res.Reached {
			reachedAny[dst] = true
		}
		ml := res.Method
		for _, h := range res.Hops {
			if h.IP == "" {
				continue
			}
			lines = append(lines, fmt.Sprintf(`probe_hop_rtt_ms{dst=%q,method=%q,ttl="%d",hop=%q,probe="traceroute"} %.3f %d`, dst, ml, h.TTL, h.IP, h.RTTms, now))
		}
		changed := 0
		if res.Changed {
			changed = 1
		}
		lines = append(lines,
			fmt.Sprintf(`probe_path_length{dst=%q,method=%q,probe="traceroute"} %d %d`, dst, ml, len(res.Hops), now),
			fmt.Sprintf(`probe_path_reached{dst=%q,method=%q,probe="traceroute"} %d %d`, dst, ml, b2i(res.Reached), now),
			fmt.Sprintf(`probe_path_changed{dst=%q,method=%q,probe="traceroute"} %d %d`, dst, ml, changed, now),
		)
	}
	for _, dst := range targets {
		if c.auto {
			// Priority mode: icmp first, fall back to tcp to fill gaps → one trace.
			res, err := tracePriority(ctx, dst, c.cfg, c.methods)
			if err != nil {
				lastErr = err.Error()
				continue
			}
			emit(dst, res)
			continue
		}
		// Parallel mode: trace each method independently → one trace per method.
		for _, method := range c.methods {
			cfg := c.cfg
			cfg.method = method
			res, err := traceOnce(ctx, dst, cfg)
			if err != nil {
				lastErr = err.Error()
				continue
			}
			emit(dst, res)
		}
	}
	reachable := len(reachedAny)
	if len(lines) > 0 {
		emitMetrics(ctx, strings.Join(lines, "\n"))
	}
	c.mu.Lock()
	c.status.LastTick = time.Now().UTC()
	c.status.Targets = len(targets)
	c.status.Reachable = reachable
	c.status.Healthy = lastErr == "" || reachable > 0
	c.status.LastError = lastErr
	c.mu.Unlock()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
