package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tunnels.go — vendor-neutral tunnel discovery (step 1: IF-MIB baseline).
//
// Mirrors how the established NMS tools (leading NMS platforms, LibreNMS, Observium) get
// broad tunnel coverage: walk the *standard* IF-MIB (RFC 2863) and treat each
// tunnel interface as an interface — ifOperStatus for up/down, ifHC*Octets for
// traffic — which works across Cisco/Juniper/Fortinet/Nokia/Linux without any
// per-vendor profile. Where the device also exposes the standard TUNNEL-MIB
// (RFC 4087) we enrich rows with the tunnel's local/remote endpoint and
// encapsulation. Vendor IPsec MIBs (Cisco cipSecTun*, Fortinet fgVpnTun*) and
// SD-WAN controller REST (for latency/jitter/loss/QoE) are later, opt-in layers.
//
// Discovered tunnels are written to ClickHouse netops.tunnels; the Tunnels tab
// reads the current state per tunnel from there. Stays stdlib-only: the SNMP
// walk is a GetNext loop over the hand-rolled BER codec in poller.go plus the
// decoder below.

// ---- Standard MIB column OIDs ---------------------------------------------

var (
	// IF-MIB (RFC 2863) ifTable / ifXTable columns.
	oidIfDescr = []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 2}
	oidIfType  = []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 3}
	oidIfOper  = []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 8}
	oidIfName  = []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1}
	oidIfHCIn  = []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6}
	oidIfHCOut = []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10}

	// TUNNEL-MIB (RFC 4087) tunnelIfTable columns — optional enrichment.
	oidTunLocal  = []int{1, 3, 6, 1, 2, 1, 10, 131, 1, 1, 1, 1}
	oidTunRemote = []int{1, 3, 6, 1, 2, 1, 10, 131, 1, 1, 1, 2}
	oidTunEncaps = []int{1, 3, 6, 1, 2, 1, 10, 131, 1, 1, 1, 3}
)

const ifTypeTunnel = 131 // IANAifType tunnel(131)

// tunnelNameRe matches common tunnel interface names when ifType/TUNNEL-MIB
// don't classify the interface (e.g. Tunnel0, Tu1, gre1, vti0, ipsec1, st0).
var tunnelNameRe = regexp.MustCompile(`(?i)(tunnel|^tu[0-9]|vti[0-9]?|gre[0-9]?|ipsec|^st[0-9])`)

// ---- BER decoding (the read side; poller.go has the write side) -----------

// readTLV parses one BER tag-length-value from b, returning the tag, its
// content, and the bytes after it. Supports short and long-form lengths.
func readTLV(b []byte) (tag byte, content, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, fmt.Errorf("snmp: truncated TLV")
	}
	tag = b[0]
	l := int(b[1])
	i := 2
	if l&0x80 != 0 { // long form: low 7 bits = number of length octets
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			return 0, nil, nil, fmt.Errorf("snmp: bad length")
		}
		l = 0
		for k := 0; k < n; k++ {
			l = l<<8 | int(b[2+k])
		}
		i = 2 + n
	}
	if len(b) < i+l {
		return 0, nil, nil, fmt.Errorf("snmp: content past end")
	}
	return tag, b[i : i+l], b[i+l:], nil
}

// decodeOID turns BER OID content into its arc slice.
func decodeOID(b []byte) []int {
	if len(b) == 0 {
		return nil
	}
	out := []int{int(b[0]) / 40, int(b[0]) % 40}
	v := 0
	for _, c := range b[1:] {
		v = v<<7 | int(c&0x7f)
		if c&0x80 == 0 {
			out = append(out, v)
			v = 0
		}
	}
	return out
}

func decodeInt(b []byte) int64 {
	var v int64
	if len(b) > 0 && b[0]&0x80 != 0 {
		v = -1 // sign-extend negatives
	}
	for _, c := range b {
		v = v<<8 | int64(c)
	}
	return v
}

func decodeUint(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

func decodeIP(b []byte) string {
	if len(b) != 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// berVal is one decoded SNMP value (its tag plus raw content).
type berVal struct {
	tag byte
	raw []byte
}

func (v berVal) int() int64   { return decodeInt(v.raw) }
func (v berVal) uint() uint64 { return decodeUint(v.raw) }
func (v berVal) str() string  { return string(v.raw) }
func (v berVal) ip() string   { return decodeIP(v.raw) }

// SNMP v2c exception value tags that end (or skip) a walk.
const (
	tagNoSuchObject   = 0x80
	tagNoSuchInstance = 0x81
	tagEndOfMibView   = 0x82
)

// firstVarbind decodes an SNMP response packet and returns the first
// variable-binding's OID and value. It skips version/community and the PDU's
// request-id/error-status/error-index, then reads varbind { OID, value }.
func firstVarbind(pkt []byte) (oid []int, valTag byte, val []byte, err error) {
	tag, msg, _, err := readTLV(pkt)
	if err != nil {
		return
	}
	if tag != 0x30 {
		return nil, 0, nil, fmt.Errorf("snmp: not a SEQUENCE")
	}
	_, _, rest, err := readTLV(msg) // version
	if err != nil {
		return
	}
	_, _, rest, err = readTLV(rest) // community
	if err != nil {
		return
	}
	_, pdu, _, err := readTLV(rest) // PDU (GetResponse 0xA2)
	if err != nil {
		return
	}
	_, _, p, err := readTLV(pdu) // request-id
	if err != nil {
		return
	}
	_, _, p, err = readTLV(p) // error-status
	if err != nil {
		return
	}
	_, _, p, err = readTLV(p) // error-index
	if err != nil {
		return
	}
	vtag, vblist, _, err := readTLV(p) // varbind list
	if err != nil {
		return
	}
	if vtag != 0x30 {
		return nil, 0, nil, fmt.Errorf("snmp: varbind list not a SEQUENCE")
	}
	_, vb, _, err := readTLV(vblist) // first varbind
	if err != nil {
		return
	}
	otag, ocontent, vrest, err := readTLV(vb) // OID
	if err != nil {
		return
	}
	if otag != 0x06 {
		return nil, 0, nil, fmt.Errorf("snmp: varbind missing OID")
	}
	oid = decodeOID(ocontent)
	valTag, val, _, err = readTLV(vrest) // value
	return
}

// ---- SNMP table-column walk -----------------------------------------------

// snmpWalkColumn GetNext-walks one MIB column subtree, returning a map keyed by
// the row index (the OID arcs trailing the column OID). One UDP socket is
// reused for the whole walk; ctx's deadline bounds the column's total time.
func snmpWalkColumn(ctx context.Context, addr string, creds snmpCreds, col []int) (map[string]berVal, error) {
	if creds.isV3() {
		return snmpWalkColumnV3(ctx, addr, creds, col)
	}
	community := creds.Community
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}

	out := make(map[string]berVal)
	cur := col
	buf := make([]byte, 8192)
	for iter := 0; iter < 4096; iter++ { // guard against a misbehaving agent
		if _, err := c.Write(buildSNMPGetNext(community, cur, iter+1)); err != nil {
			return out, err
		}
		n, err := c.Read(buf)
		if err != nil {
			return out, err
		}
		oid, valTag, val, err := firstVarbind(buf[:n])
		if err != nil {
			return out, err
		}
		if valTag == tagEndOfMibView || valTag == tagNoSuchObject || valTag == tagNoSuchInstance {
			break
		}
		if !oidUnder(oid, col) {
			break // walked out of the column subtree
		}
		out[oidSuffix(oid, col)] = berVal{tag: valTag, raw: append([]byte(nil), val...)}
		cur = oid
	}
	return out, nil
}

// oidUnder reports whether oid is a strict descendant of prefix.
func oidUnder(oid, prefix []int) bool {
	if len(oid) <= len(prefix) {
		return false
	}
	for i := range prefix {
		if oid[i] != prefix[i] {
			return false
		}
	}
	return true
}

// oidSuffix renders the arcs of oid past prefix as a dotted row index.
func oidSuffix(oid, prefix []int) string {
	parts := oid[len(prefix):]
	ss := make([]string, len(parts))
	for i, p := range parts {
		ss[i] = strconv.Itoa(p)
	}
	return strings.Join(ss, ".")
}

// ---- interface + tunnel-endpoint assembly ---------------------------------

type iface struct {
	index  string
	descr  string
	name   string
	ifType int64
	oper   int64
	inOct  uint64
	outOct uint64
}

type endpoint struct {
	local  string
	remote string
	encaps int64
}

// walkInterfaces reads the IF-MIB for one device. ifOperStatus is the required
// walk (it proves SNMP works); the rest are best-effort enrichment so a device
// missing ifXTable still yields up/down status.
func walkInterfaces(ctx context.Context, addr string, creds snmpCreds) (map[string]*iface, error) {
	oper, err := snmpWalkColumn(ctx, addr, creds, oidIfOper)
	if err != nil {
		return nil, err
	}
	ifaces := make(map[string]*iface, len(oper))
	for idx, v := range oper {
		ifaces[idx] = &iface{index: idx, oper: v.int()}
	}
	enrich := func(col []int, set func(*iface, berVal)) {
		if m, err := snmpWalkColumn(ctx, addr, creds, col); err == nil {
			for idx, v := range m {
				if f := ifaces[idx]; f != nil {
					set(f, v)
				}
			}
		}
	}
	enrich(oidIfType, func(f *iface, v berVal) { f.ifType = v.int() })
	enrich(oidIfDescr, func(f *iface, v berVal) { f.descr = v.str() })
	enrich(oidIfName, func(f *iface, v berVal) { f.name = v.str() })
	enrich(oidIfHCIn, func(f *iface, v berVal) { f.inOct = v.uint() })
	enrich(oidIfHCOut, func(f *iface, v berVal) { f.outOct = v.uint() })
	return ifaces, nil
}

// walkTunnelEndpoints reads the optional TUNNEL-MIB tunnelIfTable, keyed by
// ifIndex so it joins onto walkInterfaces. Entirely best-effort.
func walkTunnelEndpoints(ctx context.Context, addr string, creds snmpCreds) map[string]*endpoint {
	out := make(map[string]*endpoint)
	add := func(col []int, set func(*endpoint, berVal)) {
		if m, err := snmpWalkColumn(ctx, addr, creds, col); err == nil {
			for idx, v := range m {
				e := out[idx]
				if e == nil {
					e = &endpoint{}
					out[idx] = e
				}
				set(e, v)
			}
		}
	}
	add(oidTunLocal, func(e *endpoint, v berVal) { e.local = v.ip() })
	add(oidTunRemote, func(e *endpoint, v berVal) { e.remote = v.ip() })
	add(oidTunEncaps, func(e *endpoint, v berVal) { e.encaps = v.int() })
	return out
}

// isTunnelIface classifies an interface as a tunnel: present in TUNNEL-MIB,
// IANAifType tunnel(131), or a name/descr that looks like a tunnel.
func isTunnelIface(f *iface, hasEndpoint bool) bool {
	if hasEndpoint || f.ifType == ifTypeTunnel {
		return true
	}
	name := f.name
	if name == "" {
		name = f.descr
	}
	return name != "" && tunnelNameRe.MatchString(name)
}

// tunnelType derives a coarse type label from the interface name and (if
// present) the TUNNEL-MIB encapsulation method.
func tunnelType(f *iface, e *endpoint) string {
	name := strings.ToLower(f.name + " " + f.descr)
	switch {
	case strings.Contains(name, "gre"):
		return "gre"
	case strings.Contains(name, "ipsec"), strings.Contains(name, "vti"):
		return "ipsec"
	}
	if e != nil && e.encaps == 3 { // tunnelIfEncapsMethod gre(3)
		return "gre"
	}
	return "tunnel"
}

// ---- tunnel row + ClickHouse writer ---------------------------------------

// tunnelRow mirrors the netops.tunnels schema. Latency/jitter/loss/QoE are 0
// at this layer — IF-MIB carries none of those (they come from the SD-WAN
// controller layer), so we leave them honestly empty rather than fabricate.
type tunnelRow struct {
	ID           string  `json:"id"`
	Type         string  `json:"type"`
	LocalDevice  string  `json:"local_device"`
	LocalAddr    string  `json:"local_addr"`
	RemoteDevice string  `json:"remote_device"`
	RemoteAddr   string  `json:"remote_addr"`
	Status       string  `json:"status"`
	LatencyMs    float64 `json:"latency_ms"`
	JitterMs     float64 `json:"jitter_ms"`
	LossPct      float64 `json:"loss_pct"`
	QoE          float64 `json:"qoe"`
	UptimeS      uint64  `json:"uptime_s"`
}

// insertTunnels writes rows to ClickHouse via the HTTP interface using
// JSONEachRow (ts uses the column DEFAULT now64(3)). Best-effort, like the
// VictoriaMetrics emit in poller.go.
func insertTunnels(ctx context.Context, rows []tunnelRow) {
	base := chEnv("CLICKHOUSE_URL", "http://clickhouse:8123")
	if base == "" || len(rows) == 0 {
		return
	}
	var b strings.Builder
	b.WriteString("INSERT INTO netops.tunnels FORMAT JSONEachRow\n")
	for _, r := range rows {
		j, err := json.Marshal(r)
		if err != nil {
			continue
		}
		b.Write(j)
		b.WriteByte('\n')
	}
	// #nosec G704 -- base is the operator-configured CLICKHOUSE_URL backend, not user input
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/", strings.NewReader(b.String()))
	if err != nil {
		return
	}
	if user := chEnv("CLICKHOUSE_USER", "netops"); user != "" {
		req.SetBasicAuth(user, os.Getenv("CLICKHOUSE_PASSWORD"))
	}
	req.Header.Set("Content-Type", "text/plain")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func chEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ---- the collector ---------------------------------------------------------

type tunnelCollector struct {
	interval time.Duration
	targets  TargetFunc

	mu     sync.RWMutex
	status Status
}

// NewTunnels builds the tunnel-discovery collector. It SNMP-walks every device
// in the inventory (tunnels can live on any SNMP-speaking box regardless of
// preferred collection protocol) and writes discovered tunnels to ClickHouse.
func NewTunnels(targets TargetFunc) Collector {
	return &tunnelCollector{
		interval: 90 * time.Second,
		targets:  targets,
		status:   Status{Name: "tunnels", Healthy: true, Kind: "discovery"},
	}
}

func (c *tunnelCollector) Name() string { return "tunnels" }

func (c *tunnelCollector) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *tunnelCollector) Run(ctx context.Context) error {
	t := time.NewTicker(c.interval)
	defer t.Stop()
	c.pollOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			c.pollOnce(ctx)
		}
	}
}

func (c *tunnelCollector) pollOnce(ctx context.Context) {
	var targets []Target
	if c.targets != nil {
		targets = c.targets()
	}
	start := time.Now()
	reachable := 0
	var lastErr string
	var rows []tunnelRow

	for _, tg := range targets {
		addr := withPort(tg.Address, 161)
		creds := tg.creds()
		dctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		ifaces, err := walkInterfaces(dctx, addr, creds)
		if err != nil {
			cancel()
			lastErr = err.Error()
			continue
		}
		reachable++
		endpoints := walkTunnelEndpoints(dctx, addr, creds)
		cancel()

		local := hostOnly(tg.Address)
		for idx, f := range ifaces {
			ep := endpoints[idx]
			if !isTunnelIface(f, ep != nil) {
				continue
			}
			name := f.name
			if name == "" {
				name = f.descr
			}
			if name == "" {
				name = "if" + idx
			}
			row := tunnelRow{
				ID:          tg.ID + "/" + name,
				Type:        tunnelType(f, ep),
				LocalDevice: tg.ID,
				LocalAddr:   local,
				Status:      ifStatus(f.oper),
			}
			if ep != nil {
				if ep.local != "" {
					row.LocalAddr = ep.local
				}
				row.RemoteAddr = ep.remote
			}
			rows = append(rows, row)
		}
	}

	insertTunnels(ctx, rows)

	now := start.UnixMilli()
	emitMetrics(ctx, strings.Join([]string{
		fmt.Sprintf(`collector_up{collector="tunnels"} 1 %d`, now),
		fmt.Sprintf(`collector_targets{collector="tunnels"} %d %d`, len(targets), now),
		fmt.Sprintf(`collector_targets_reachable{collector="tunnels"} %d %d`, reachable, now),
		fmt.Sprintf(`collector_tunnels{collector="tunnels"} %d %d`, len(rows), now),
	}, "\n"))

	c.mu.Lock()
	c.status.LastTick = start.UTC()
	c.status.Targets = len(targets)
	c.status.Reachable = reachable
	c.status.LastPollMillis = time.Since(start).Milliseconds()
	c.status.Healthy = true
	if reachable == 0 && len(targets) > 0 {
		c.status.LastError = lastErr
	} else {
		c.status.LastError = ""
	}
	c.mu.Unlock()
}

// ifStatus maps IF-MIB ifOperStatus to the tunnel status vocabulary.
func ifStatus(oper int64) string {
	if oper == 1 { // up(1)
		return "up"
	}
	return "down"
}

// hostOnly strips any :port from a device address.
func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
