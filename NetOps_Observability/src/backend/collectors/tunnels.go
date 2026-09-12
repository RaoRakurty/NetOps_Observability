// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"netops/backend/chhttp"
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

// str renders an OCTET STRING value. It is BOUNDED and control-char scrubbed at
// the decoder (caps.go): every caller — CDP/LLDP neighbour names, ifName/ifDescr,
// sysName/sysDescr — feeds a metric label, a ClickHouse String or an OpenSearch
// document, and a device can put up to 64 KB in one varbind. Capping here means a
// new caller inherits the bound instead of having to remember it (PIPE-MED-11).
func (v berVal) str() string { return sanitizeText(string(v.raw)) }
func (v berVal) ip() string  { return decodeIP(v.raw) }

// SNMP v2c exception value tags that end (or skip) a walk.
const (
	tagNoSuchObject   = 0x80
	tagNoSuchInstance = 0x81
	tagEndOfMibView   = 0x82
)

// pduTagGetResponse is the only PDU an agent may answer a Get/GetNext with.
const pduTagGetResponse = 0xA2

// errStaleResponse marks a reply that does not belong to the request we sent —
// wrong PDU type or a request-id that does not echo ours. A walk RE-READS on
// this (a delayed retransmit from an earlier iteration must be discarded, not
// consumed as the current answer), rather than treating the stale bytes as data.
var errStaleResponse = errors.New("snmp: response does not match the request (stale/retransmit)")

// firstVarbind decodes an SNMP response packet and returns the first
// variable-binding's OID and value, AFTER validating it actually answers the
// request `expectReqID`:
//   - the PDU must be a GetResponse (0xA2) — not a request or a report echoed back;
//   - the request-id must echo the one we sent (else it is a stale retransmit from
//     an earlier walk iteration — errStaleResponse, so the caller re-reads);
//   - error-status must be 0 — an agent answering e.g. genErr echoes the request
//     varbind with a NULL value, and valueInt(NULL)=0 would otherwise be emitted
//     as a REAL sample (a false device_bgp_peer_state 0 = "peer down" alert).
func firstVarbind(pkt []byte, expectReqID int) (oid []int, valTag byte, val []byte, err error) {
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
	pduTag, pdu, _, err := readTLV(rest) // PDU
	if err != nil {
		return
	}
	if pduTag != pduTagGetResponse {
		return nil, 0, nil, fmt.Errorf("%w: PDU tag 0x%02X is not GetResponse", errStaleResponse, pduTag)
	}
	ridTag, ridContent, p, err := readTLV(pdu) // request-id
	if err != nil {
		return
	}
	if ridTag != 0x02 || int(decodeInt(ridContent)) != expectReqID {
		return nil, 0, nil, fmt.Errorf("%w: request-id %d != expected %d",
			errStaleResponse, decodeInt(ridContent), expectReqID)
	}
	esTag, esContent, p, err := readTLV(p) // error-status
	if err != nil {
		return
	}
	if esTag == 0x02 && decodeInt(esContent) != 0 {
		// A non-zero error-status means the agent could not answer (noSuchName,
		// genErr, …). The echoed varbind is not a measurement — refuse it.
		return nil, 0, nil, fmt.Errorf("snmp: agent error-status %d (not a value)", decodeInt(esContent))
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
		_ = c.SetDeadline(dl) // best-effort: a failed deadline set surfaces as a read/write error
	}

	out := make(map[string]berVal)
	cur := col
	buf := make([]byte, 8192)
	for iter := 0; iter < 4096; iter++ { // guard against a misbehaving agent
		reqID := iter + 1
		if _, err := c.Write(buildSNMPGetNext(community, cur, reqID)); err != nil {
			return out, err
		}
		// Read until we get THIS request's response: a delayed retransmit from an
		// earlier iteration echoes an older request-id and must be discarded, not
		// consumed as the current column value (which would reset `cur` backwards
		// and loop the walk). Bounded so a flood of stale packets cannot wedge us.
		var oid []int
		var valTag byte
		var val []byte
		var err error
		for stale := 0; ; stale++ {
			n, rerr := c.Read(buf)
			if rerr != nil {
				return out, rerr
			}
			oid, valTag, val, err = firstVarbind(buf[:n], reqID)
			if err == nil || !errors.Is(err, errStaleResponse) {
				break
			}
			if stale >= 8 {
				return out, fmt.Errorf("snmp walk: too many stale responses at reqID %d: %w", reqID, err)
			}
		}
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
	// TenantID stamps the owning tenant on the row (#20 / §3a.4). It was
	// missing entirely (F-56): every discovered tunnel landed as '' and was
	// therefore visible to EVERY tenant through the `OR tenant_id = ''`
	// untagged-shared clause of the tenant_iso_tunnels row policy. The
	// collector is the only place that knows which device — and so which
	// tenant — a tunnel belongs to, so it is the only place that can stamp it.
	TenantID string `json:"tenant_id"`
}

// chInsertSettings are the insert-tolerance settings EVERY ClickHouse write
// from this tier now carries (audit F-56).
//
// A repo-wide grep for these at audit time returned ZERO hits in Go and Python,
// while both Vector ClickHouse sinks set skip_unknown_fields — the discipline
// existed in the config tier and was absent from both code tiers. Without them
// a single unknown JSON key 400s the ENTIRE batch, so one schema drift between
// a deploy and a migration silently costs every row in the poll cycle.
//
//   - input_format_skip_unknown_fields=1 — a field the table does not have yet
//     is dropped, not fatal to its batch.
//   - date_time_input_format=best_effort — a timestamp in a slightly different
//     shape parses instead of failing the batch.
//
// input_format_allow_errors_num/ratio are DELIBERATELY NOT SET: they make
// ClickHouse silently discard malformed ROWS, which trades a loud batch failure
// for exactly the invisible partial loss this audit exists to eliminate.
var chInsertSettings = map[string]string{
	"input_format_skip_unknown_fields": "1",
	"date_time_input_format":           "best_effort",
	// tenant_scope: the tenant_iso_tunnels row policy is re-evaluated on INSERT
	// in the inserting connection's context. Unset, it admits only tenant_id=''
	// rows — so stamping a real tenant_id without this would make every insert
	// fail. __all__ is the platform-writer scope the Go DDL path already uses.
	"tenant_scope": "__all__",
}

// insertTunnels writes rows to ClickHouse via the HTTP interface using
// JSONEachRow (ts uses the column DEFAULT now64(3)).
//
// F-56: this function used to end with
//
//	resp, err := client.Do(req)
//	if err != nil { return }
//	_ = resp.Body.Close()
//
// The status code was NEVER inspected. A 400 (schema drift), a 401 (rotated
// password) or a 500 was indistinguishable from success — no log, no counter,
// no retry — so the Tunnels tab would simply show stale data forever while the
// collector reported itself healthy. It now returns an error the caller
// surfaces on the collector's Status and counts as a metric.
func insertTunnels(ctx context.Context, rows []tunnelRow) error {
	base := chEnv("CLICKHOUSE_URL", "http://clickhouse:8123")
	if base == "" || len(rows) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("INSERT INTO netops.tunnels FORMAT JSONEachRow\n")
	for _, r := range rows {
		j, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("encode tunnel row %q: %w", r.ID, err)
		}
		b.Write(j)
		b.WriteByte('\n')
	}
	// Routed through the shared chhttp seam: transport, bounded read, drain and
	// — the part this could not do on its own — classification, so a caller can
	// distinguish TOO_MANY_PARTS backpressure (retry) from a schema fault (do
	// not). tenant_scope travels in chInsertSettings; see its comment.
	settings := make(map[string]string, len(chInsertSettings))
	for k, v := range chInsertSettings {
		settings[k] = v
	}
	scope := settings["tenant_scope"]
	delete(settings, "tenant_scope") // carried explicitly by Request.Scope
	_, err := (&chhttp.Client{
		Base:     base,
		User:     chEnv("CLICKHOUSE_USER", "netops"),
		Password: os.Getenv("CLICKHOUSE_PASSWORD"),
		HTTP:     meshHTTPClient(12 * time.Second),
	}).Exec(ctx, chhttp.Request{
		SQL:      b.String(),
		Op:       "insert netops.tunnels",
		Scope:    scope,
		Settings: settings,
		Budget:   10 * time.Second,
	})
	return err
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
				// §3a.2: the owner comes from the device inventory, never from
				// anything on the wire. '' stays '' — a device with no tenant
				// is genuinely platform-global, which the row policy's
				// untagged-shared clause already expresses.
				TenantID: tg.TenantID,
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

	// F-56: the write result is now observed. A failed insert makes the
	// collector UNHEALTHY and names the cause — previously the cycle reported
	// success while every row was thrown away by ClickHouse.
	writeErr := insertTunnels(ctx, rows)
	writeFailed := 0
	if writeErr != nil {
		writeFailed = 1
		log.Printf("collector tunnels: clickhouse write failed: %v", writeErr)
	}

	now := start.UnixMilli()
	// The write result already drove Healthy (F-56); collector_up must carry the
	// SAME verdict — it was a literal 1, so CollectorDown could not fire even
	// when every insert was rejected and every device unreachable.
	healthy := writeErr == nil && cycleHealthy(len(targets), reachable)
	emitMetrics(ctx, strings.Join([]string{
		collectorUpLine("tunnels", healthy, now),
		fmt.Sprintf(`collector_targets{collector="tunnels"} %d %d`, len(targets), now),
		fmt.Sprintf(`collector_targets_reachable{collector="tunnels"} %d %d`, reachable, now),
		fmt.Sprintf(`collector_tunnels{collector="tunnels"} %d %d`, len(rows), now),
		// §10: the failure must be alertable, not just logged. Without this
		// counter a persistently rejected insert is invisible to the platform's
		// own monitoring — the exact shape of F-41's 167 unalertable cycles.
		fmt.Sprintf(`collector_store_write_failed{collector="tunnels",store="clickhouse"} %d %d`, writeFailed, now),
		fmt.Sprintf(`collector_store_rows{collector="tunnels",store="clickhouse"} %d %d`, len(rows), now),
	}, "\n"))

	c.mu.Lock()
	c.status.LastTick = start.UTC()
	c.status.Targets = len(targets)
	c.status.Reachable = reachable
	c.status.LastPollMillis = time.Since(start).Milliseconds()
	c.status.Healthy = healthy
	switch {
	case writeErr != nil:
		c.status.LastError = writeErr.Error()
	default:
		// Partial blackout included: 9 of 10 devices refusing the walk used to
		// report healthy AND blank.
		c.status.LastError = cycleError(len(targets), reachable, lastErr)
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
