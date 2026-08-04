package collectors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// redis.go — a tiny, dependency-free RESP client (SET-with-TTL + GET only),
// used to share active-measurement results from the prober sidecar to the API
// per ADR 0001 (privileged ops isolated; workers communicate via Redis). The
// backend is stdlib-only by design, and we need just two commands, so a full
// Redis driver is unwarranted — this speaks RESP over a short-lived TCP conn.

const (
	// probePathsKey is the LEGACY single publish key. Every prober used to SET its
	// whole registry here, so N probers silently CLOBBERED each other and no path
	// carried an attribution. It is still written (rolling-upgrade compatibility)
	// but readers prefer the per-vantage keys below.
	probePathsKey = "netops:probe:paths"
	// probePathsPrefix + <vantage> is the per-vantage publish key: one prober, one
	// key. The path contract's identity includes the vantage (§2.2), so two probers
	// measuring the same destination are two DISTINCT paths that may disagree.
	probePathsPrefix = "netops:probe:paths:"
	// probeVantagesKey is the SET of vantages that have published recently. It is
	// how a reader enumerates them without a keyspace scan (no KEYS in prod).
	probeVantagesKey = "netops:probe:vantages"
	// probePathsTTL self-expires a dead prober's paths (seconds).
	probePathsTTL = 300
)

// probePathsKeyFor is the publish key for one vantage.
func probePathsKeyFor(vantage string) string {
	if vantage == "" {
		vantage = ProberID()
	}
	return probePathsPrefix + vantage
}

// RedisAddr returns host:port from REDIS_HOST/REDIS_PORT, or "" if unset — in
// which case callers fall back to file / in-process sharing.
func RedisAddr() string {
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, os.Getenv("REDIS_PORT"))
}

func redisDial(ctx context.Context) (net.Conn, error) {
	addr := RedisAddr()
	if addr == "" {
		return nil, fmt.Errorf("redis not configured")
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if pass := os.Getenv("REDIS_PASSWORD"); pass != "" {
		if _, err := redisCmd(c, "AUTH", pass); err != nil {
			c.Close()
			return nil, err
		}
	}
	return c, nil
}

// encodeRESP renders a command as a RESP array of bulk strings.
func encodeRESP(args ...string) []byte {
	b := []byte("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, a := range args {
		b = append(b, '$')
		b = append(b, strconv.Itoa(len(a))...)
		b = append(b, '\r', '\n')
		b = append(b, a...)
		b = append(b, '\r', '\n')
	}
	return b
}

// redisCmd sends one command and reads a single reply line / bulk string.
func redisCmd(c net.Conn, args ...string) (string, error) {
	if _, err := c.Write(encodeRESP(args...)); err != nil {
		return "", err
	}
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) == 0 {
		return "", fmt.Errorf("empty redis reply")
	}
	switch line[0] {
	case '+': // simple string
		return trimCRLF(line[1:]), nil
	case '-': // error
		return "", fmt.Errorf("redis: %s", trimCRLF(line[1:]))
	case '$': // bulk string
		n, err := strconv.Atoi(trimCRLF(line[1:]))
		if err != nil {
			return "", err
		}
		if n < 0 {
			return "", nil // nil bulk → empty
		}
		buf := make([]byte, n+2) // payload + CRLF
		if _, err := readFull(r, buf); err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	default:
		return trimCRLF(line[1:]), nil
	}
}

func trimCRLF(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\r' || s[len(s)-1] == '\n') {
		s = s[:len(s)-1]
	}
	return s
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// redisSetEX writes key=val with a TTL (seconds) so stale data self-expires if a
// prober dies.
func redisSetEX(ctx context.Context, key, val string, ttlSec int) error {
	c, err := redisDial(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = redisCmd(c, "SET", key, val, "EX", strconv.Itoa(ttlSec))
	return err
}

// SEC-012.1 / F-62 class: the topology/path publishers used to discard write
// errors (`_ = redisSetEX(...)`), so a failing Valkey — down, or refusing a
// bad password once auth ships — silently starved RCA of probe paths,
// LLDP/BGP-LS topology and interface maps: the "healthy process, dead data
// path" failure again. redisPublish surfaces every failure: counted always,
// logged once per minute per channel (the ingest_auth.go idiom).
var (
	redisPublishFailures sync.Map // channel string -> *int64
	redisPublishThrottle sync.Map // channel string -> *int64 (unix seconds)
)

// RedisPublishFailureCount reports the failures for one publish channel —
// the stack-health surface and tests read it; 0 = healthy.
func RedisPublishFailureCount(channel string) int64 {
	if v, ok := redisPublishFailures.Load(channel); ok {
		return atomic.LoadInt64(v.(*int64))
	}
	return 0
}

// redisPublish is redisSetEX with the error SURFACED instead of returned —
// for fire-and-forget topology/evidence publishers whose callers have nothing
// useful to do with the error except make it visible.
func redisPublish(ctx context.Context, channel, key, val string, ttlSec int) {
	err := redisSetEX(ctx, key, val, ttlSec)
	if err == nil {
		return
	}
	v, _ := redisPublishFailures.LoadOrStore(channel, new(int64))
	n := atomic.AddInt64(v.(*int64), 1)
	now := time.Now().Unix()
	lv, _ := redisPublishThrottle.LoadOrStore(channel, new(int64))
	last := atomic.LoadInt64(lv.(*int64))
	if now-last >= 60 && atomic.CompareAndSwapInt64(lv.(*int64), last, now) {
		// The error string never contains the password (AUTH errors echo the
		// server's message only), so this stays §8-clean.
		log.Printf("valkey: %s publish FAILED (key %s, %d total): %v — RCA evidence is degrading; if this is an AUTH error, REDIS_PASSWORD is wrong or unset (SEC-012)", channel, key, n, err)
	}
}

// FetchProbePaths reads the shared traceroute topology JSON published by the
// prober. Returns ("", nil) when the key is absent.
//
// DEPRECATED for multi-vantage use: it reads the single legacy key, which every
// prober overwrites. Use FetchProbePathsAll, which merges the per-vantage keys and
// preserves attribution. Kept for the single-prober fallback and for callers that
// only want an opaque blob.
func FetchProbePaths(ctx context.Context) (string, error) {
	c, err := redisDial(ctx)
	if err != nil {
		return "", err
	}
	defer c.Close()
	return redisCmd(c, "GET", probePathsKey)
}

// redisRegisterVantage records that this prober has published, so readers can
// enumerate vantages without scanning the keyspace. The set is refreshed with a TTL
// well beyond the per-key TTL: a vantage that stops publishing simply has no paths
// to read (its key expires), and eventually drops out of the set too.
func redisRegisterVantage(ctx context.Context, vantage string) error {
	c, err := redisDial(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := redisCmd(c, "SADD", probeVantagesKey, vantage); err != nil {
		return err
	}
	_, err = redisCmd(c, "EXPIRE", probeVantagesKey, strconv.Itoa(probePathsTTL*12))
	return err
}

// redisMembers reads a SET (RESP multi-bulk). The tiny client only spoke single
// replies; enumerating vantages needs an array, so this parses one — still stdlib,
// still ~20 lines, and it keeps us off KEYS/SCAN in production.
func redisMembers(c net.Conn, key string) ([]string, error) {
	if _, err := c.Write(encodeRESP("SMEMBERS", key)); err != nil {
		return nil, err
	}
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) == 0 || line[0] != '*' {
		if len(line) > 0 && line[0] == '-' {
			return nil, fmt.Errorf("redis: %s", trimCRLF(line[1:]))
		}
		return nil, nil // not an array (empty/unknown) → no members
	}
	n, err := strconv.Atoi(trimCRLF(line[1:]))
	if err != nil || n <= 0 {
		return nil, nil
	}
	if n > 1024 {
		n = 1024 // bounded (§9): a corrupted count never allocates unbounded
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return out, err
		}
		if len(hdr) == 0 || hdr[0] != '$' {
			continue
		}
		ln, err := strconv.Atoi(trimCRLF(hdr[1:]))
		if err != nil || ln < 0 {
			continue
		}
		buf := make([]byte, ln+2)
		if _, err := readFull(r, buf); err != nil {
			return out, err
		}
		out = append(out, string(buf[:ln]))
	}
	return out, nil
}

// FetchProbePathsAll merges the traceroute paths published by EVERY vantage, each
// path attributed to the prober that measured it. This is the multi-vantage read:
// the LAN vantage's client-anchored trace and the WAN prober's edge-anchored trace
// are BOTH returned, as distinct paths (contract §2.2/§8), instead of whichever one
// wrote last.
//
// Falls back to the legacy single key when no vantage has registered (a
// pre-upgrade prober, or a single in-process collector).
func FetchProbePathsAll(ctx context.Context) ([]PathResult, error) {
	c, err := redisDial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	vantages, err := redisMembers(c, probeVantagesKey)
	if err != nil {
		return nil, err
	}
	seen := map[string]PathResult{}
	add := func(raw, vantage string) {
		if raw == "" {
			return
		}
		var paths []PathResult
		if json.Unmarshal([]byte(raw), &paths) != nil {
			return
		}
		for _, p := range paths {
			if p.VantageID == "" {
				p.VantageID = vantage // a pre-upgrade prober published without attribution
			}
			k := pathKeyFor(p.VantageID, p.Dst, p.Method)
			if prev, ok := seen[k]; ok && prev.TS.After(p.TS) {
				continue // keep the newest measurement of the same path
			}
			seen[k] = p
		}
	}
	for _, v := range vantages {
		raw, err := redisCmd(c, "GET", probePathsKeyFor(v))
		if err != nil {
			continue // a dead vantage's key has expired — not an error
		}
		add(raw, v)
	}
	if len(seen) == 0 {
		raw, err := redisCmd(c, "GET", probePathsKey) // legacy single key
		if err != nil {
			return nil, err
		}
		add(raw, "")
	}
	out := make([]PathResult, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].VantageID != out[j].VantageID {
			return out[i].VantageID < out[j].VantageID
		}
		if out[i].Dst != out[j].Dst {
			return out[i].Dst < out[j].Dst
		}
		return out[i].Method < out[j].Method
	})
	return out, nil
}

// FetchTopologyLinks reads + merges the neighbour records published by every
// topology-discovery collector (LLDP, CDP, …) into one slice. LLDP is listed
// first so it wins the read-side dedup when two protocols report the same
// adjacency. A missing/empty per-protocol key is not an error (collector off).
func FetchTopologyLinks(ctx context.Context) ([]LLDPNeighbor, error) {
	c, err := redisDial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	var out []LLDPNeighbor
	for _, key := range []string{topoLinksKeyLLDP, topoLinksKeyCDP, topoLinksKeyBGPLS} {
		raw, err := redisCmd(c, "GET", key)
		if err != nil || raw == "" {
			continue
		}
		var n []LLDPNeighbor
		if json.Unmarshal([]byte(raw), &n) == nil {
			out = append(out, n...)
		}
	}
	return out, nil
}

// FetchIfAddrMap reads the interface-address map (deviceID → interface IP → ifName)
// published by the SNMP metrics collector. Empty map when absent (collector off /
// Redis down) — enrichment is best-effort, never an error.
func FetchIfAddrMap(ctx context.Context) (map[string]map[string]string, error) {
	c, err := redisDial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	raw, err := redisCmd(c, "GET", ifAddrKey)
	if err != nil || raw == "" {
		return map[string]map[string]string{}, nil
	}
	out := map[string]map[string]string{}
	_ = json.Unmarshal([]byte(raw), &out)
	return out, nil
}

// FetchRoutingDirection reads the directed forwarding pairs ([{from,to}]) computed by
// the BGP-LS collector's SPF (C7.5 routing-direction source). Empty when absent
// (no LSDB / collector off) — best-effort, never an error.
func FetchRoutingDirection(ctx context.Context) ([]RoutingPair, error) {
	c, err := redisDial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	raw, err := redisCmd(c, "GET", routingDirKey)
	if err != nil || raw == "" {
		return []RoutingPair{}, nil
	}
	var out []RoutingPair
	_ = json.Unmarshal([]byte(raw), &out)
	return out, nil
}

// FetchIfIndexMap reads the ifIndex map (deviceID → ifIndex → ifName) published by
// the SNMP metrics collector. Empty map when absent — best-effort, never an error.
func FetchIfIndexMap(ctx context.Context) (map[string]map[string]string, error) {
	c, err := redisDial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	raw, err := redisCmd(c, "GET", ifIndexKey)
	if err != nil || raw == "" {
		return map[string]map[string]string{}, nil
	}
	out := map[string]map[string]string{}
	_ = json.Unmarshal([]byte(raw), &out)
	return out, nil
}

// wanCircuitsKey holds the WAN circuit list the API's circuit projector
// publishes for the wan-echo collector to probe (TTL'd so it self-clears if the
// API stops publishing).
const wanCircuitsKey = "netops:wan:circuits"

// EchoTarget is one WAN circuit to actively probe: the local (source-bind)
// endpoint and the remote (destination) endpoint, with enough labels to tag the
// emitted per-circuit metrics. Published by the API circuit projector, consumed
// by the wan-echo collector. Network-level (cross-tenant) by design — the prober
// is platform infrastructure; the Tenant label scopes the resulting metric.
type EchoTarget struct {
	CircuitID    string `json:"circuit_id"`
	Tenant       string `json:"tenant,omitempty"`
	LocalDevice  string `json:"local_device"`
	LocalIf      string `json:"local_if"`
	LocalAddr    string `json:"local_addr"` // source-bind address (best-effort)
	RemoteDevice string `json:"remote_device"`
	RemoteIf     string `json:"remote_if"`
	RemoteAddr   string `json:"remote_addr"` // probe destination (the measurable address)
}

// PublishWANCircuits writes the circuit list for the echo collector. Best-effort;
// no-op when Redis isn't configured (the collector then falls back to env).
func PublishWANCircuits(ctx context.Context, targets []EchoTarget, ttlSec int) error {
	if RedisAddr() == "" {
		return nil
	}
	body, err := json.Marshal(targets)
	if err != nil {
		return err
	}
	return redisSetEX(ctx, wanCircuitsKey, string(body), ttlSec)
}

// FetchWANCircuits reads the circuit list published by the API. Empty (not an
// error) when absent — the collector then falls back to WAN_ECHO_TARGETS.
func FetchWANCircuits(ctx context.Context) ([]EchoTarget, error) {
	c, err := redisDial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	raw, err := redisCmd(c, "GET", wanCircuitsKey)
	if err != nil || raw == "" {
		return nil, nil
	}
	var out []EchoTarget
	_ = json.Unmarshal([]byte(raw), &out)
	return out, nil
}
