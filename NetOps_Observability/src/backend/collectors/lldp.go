package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// lldp.go — LLDP neighbour discovery (Layer-1 base topology, per the topology-rca
// design). For each device it walks the standard LLDP-MIB remote table and emits
// raw neighbour records (local device + port ↔ remote system name + port). The
// API (/api/topology/links) resolves remote system-names to managed devices,
// dedups bidirectional adjacencies, and tenant-scopes — so this collector stays a
// dumb, source-agnostic observer (CDP / BGP-LS can publish the same record shape).
//
// Why SNMP LLDP-MIB and not inference: real links must come from the devices
// themselves. The Device Topology previously drew a full mesh between role tiers
// (wrong). lldpRemTable is the multi-vendor standard; vendors without it simply
// yield no neighbours (graceful — the UI keeps the labelled tier-inference
// fallback). Dormant by default (ENABLE_LLDP_DISCOVERY); UDP/161, no raw socket.
//
// OID notes (verified against the LLDP-MIB): the remote table is indexed by the
// composite { lldpRemTimeMark, lldpRemLocalPortNum, lldpRemIndex }, so each walked
// row's OID suffix is "timeMark.localPortNum.remIndex" — we split out localPortNum
// to map the neighbour to a local port via lldpLocPortTable. Chassis/Port IDs are
// rendered per their subtype (MAC → hex, ifName/local → string).

// LLDP-MIB columns (1.0.8802.1.1.2.1 …). Remote table = .4.1.1.<col>, local port
// table = .3.7.1.<col>.
var (
	lldpRemChassisIdSubtype = []int{1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 4}
	lldpRemChassisIdOID     = []int{1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 5}
	lldpRemPortIdSubtype    = []int{1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 6}
	lldpRemPortIdOID        = []int{1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 7}
	lldpRemPortDescOID      = []int{1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 8}
	lldpRemSysNameOID       = []int{1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 9}
	lldpLocPortIdSubtype    = []int{1, 0, 8802, 1, 1, 2, 1, 3, 7, 1, 2}
	lldpLocPortIdOID        = []int{1, 0, 8802, 1, 1, 2, 1, 3, 7, 1, 3}
	lldpLocPortDescOID      = []int{1, 0, 8802, 1, 1, 2, 1, 3, 7, 1, 4}
)

// LLDPNeighbor is one raw observed adjacency (a directed half-link: this device
// saw that neighbour on this local port). The API normalizes + dedups these.
//
// LLDP/CDP populate LocalDevice with the polled device's id (we know it — we
// polled it). BGP-LS is different: it learns the WHOLE topology from a peer, so
// neither endpoint is "the device we polled". For Proto=="bgp_ls" LocalDevice is
// left empty and LocalName/LocalAddr carry the local node's identity so the API
// can resolve BOTH ends through the same tenant-scoped inventory maps.
type LLDPNeighbor struct {
	LocalDevice string `json:"local_device"`         // polled device id (lldp/cdp); "" for bgp_ls
	LocalName   string `json:"local_name,omitempty"` // bgp_ls local node hostname / rendered System-ID
	LocalAddr   string `json:"local_addr,omitempty"` // bgp_ls local node IPv4 Router-ID (addr resolution)
	LocalPort   string `json:"local_port"`           // local port name (lldpLocPort* / "port N" / iface addr)
	RemSysName  string `json:"rem_sysname"`          // neighbour hostname (lldpRemSysName / node name / System-ID)
	RemChassis  string `json:"rem_chassis"`          // neighbour chassis id / IPv4 router-id (rendered by subtype)
	RemPort     string `json:"rem_port"`             // neighbour port (rendered by subtype / iface addr)
	RemPortDesc string `json:"rem_portdesc"`         // neighbour port description (free text)
	Proto       string `json:"proto"`                // source protocol: "lldp" | "cdp" | "bgp_ls"
	IGP         string `json:"igp,omitempty"`        // bgp_ls IGP origin: isis-l1|isis-l2|ospfv2|ospfv3|direct|static
	Area        string `json:"area,omitempty"`       // bgp_ls IGP area / IS-IS area (display)
	TS          int64  `json:"ts"`                   // last-observed unix millis
}

// Per-protocol topology keys — each discovery collector publishes its own, and
// the API (FetchTopologyLinks) merges them. LLDP first → wins read-side dedup.
const (
	topoLinksKeyLLDP  = "netops:topology:lldp"
	topoLinksKeyCDP   = "netops:topology:cdp"
	topoLinksKeyBGPLS = "netops:topology:bgpls"
	// ifAddrKey holds deviceID → (interface IP → ifName), published by the SNMP
	// metrics collector, for enriching topology links (esp. BGP-LS, which keys
	// interfaces by IP). TTL-expiring like the link keys.
	ifAddrKey = "netops:topology:ifaddr"
	// ifIndexKey holds deviceID → (ifIndex → ifName), published by the SNMP metrics
	// collector. The bridge a flow exporter's in/out ifIndex needs to resolve to a
	// real port (correlation entity device:ifName) — feeds the C7.1 EntityResolver.
	ifIndexKey = "netops:topology:ifindex"
	// routingDirKey holds the directed forwarding pairs ([{from,to}]) computed by the
	// BGP-LS collector's SPF over the link-state DB — the C7.5 routing-direction
	// source. Empty until the LSDB has data (peer must redistribute link-state).
	routingDirKey = "netops:topology:routing_dir"
)

type lldpCollector struct {
	interval time.Duration
	targets  TargetFunc

	mu     sync.RWMutex
	status Status
}

// NewLLDP builds the LLDP neighbour-discovery collector.
func NewLLDP(targets TargetFunc) Collector {
	return &lldpCollector{
		interval: 5 * time.Minute,
		targets:  targets,
		status:   Status{Name: "lldp", Healthy: true, Kind: "discovery"},
	}
}

func (c *lldpCollector) Name() string { return "lldp" }

func (c *lldpCollector) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *lldpCollector) Run(ctx context.Context) error {
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

func (c *lldpCollector) pollOnce(ctx context.Context) {
	pollNeighborsOnce(ctx, "lldp", c.targets, topoLinksKeyLLDP, pollLLDP, &c.mu, &c.status)
}

// pollNeighborsOnce is the shared LLDP/CDP poll cycle (#147 T4): walk every
// target with a 10s budget, publish the full neighbour set to redisKey
// (replace, not merge — stale devices drop off; the TTL self-expires the
// topology if the collector dies, ADR 0001 share-via-Redis), emit the cycle's
// health metrics, and stamp the collector status.
//
// answered counts devices whose walk SUCCEEDED, which is the health signal;
// reachable counts the subset that actually reported neighbours. A device with
// no neighbours (e.g. a non-Cisco box with no CDP) answered fine and must not
// count as a failure.
func pollNeighborsOnce(ctx context.Context, name string, targetsFn TargetFunc, redisKey string,
	poll func(ctx context.Context, addr string, creds snmpCreds, devID string, now int64) ([]LLDPNeighbor, error),
	mu *sync.RWMutex, status *Status) {
	var targets []Target
	if targetsFn != nil {
		targets = targetsFn()
	}
	start := time.Now()
	now := start.UnixMilli()
	reachable := 0
	answered := 0
	var all []LLDPNeighbor
	var lastErr string

	for _, tg := range targets {
		addr := withPort(tg.Address, 161)
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		neigh, err := poll(dctx, addr, tg.creds(), tg.ID, now)
		cancel()
		if err != nil {
			lastErr = err.Error()
			continue
		}
		answered++
		if len(neigh) > 0 {
			reachable++
			all = append(all, neigh...)
		}
	}

	if all == nil {
		all = []LLDPNeighbor{} // store "[]" not "null" when empty
	}
	if b, err := json.Marshal(all); err == nil {
		redisPublish(ctx, "lldp-neighbors", redisKey, string(b), 1800)
	}

	healthy := cycleHealthy(len(targets), answered)
	emitMetrics(ctx, strings.Join([]string{
		collectorUpLine(name, healthy, now),
		fmt.Sprintf(`collector_targets{collector=%q} %d %d`, name, len(targets), now),
		fmt.Sprintf(`collector_targets_reachable{collector=%q} %d %d`, name, reachable, now),
		fmt.Sprintf(`collector_%s_neighbors{collector=%q} %d %d`, name, name, len(all), now),
	}, "\n"))

	mu.Lock()
	status.LastTick = start.UTC()
	status.Targets = len(targets)
	status.Reachable = reachable
	status.LastPollMillis = time.Since(start).Milliseconds()
	status.Healthy = healthy
	status.LastError = cycleError(len(targets), answered, lastErr)
	mu.Unlock()
}

// pollLLDP walks the LLDP remote + local-port tables for one device and assembles
// neighbour records. Best-effort: a device with no LLDP-MIB yields nil (no error
// when simply empty); only a hard transport failure on the lead column errors.
func pollLLDP(ctx context.Context, addr string, creds snmpCreds, devID string, now int64) ([]LLDPNeighbor, error) {
	sysNames, err := snmpWalkColumn(ctx, addr, creds, lldpRemSysNameOID)
	if err != nil {
		return nil, err
	}
	if len(sysNames) == 0 {
		return nil, nil // device reachable but no LLDP neighbours / no LLDP-MIB
	}
	// Remaining remote columns (best-effort — keyed by the same composite index).
	portIDs, _ := snmpWalkColumn(ctx, addr, creds, lldpRemPortIdOID)
	portSubs, _ := snmpWalkColumn(ctx, addr, creds, lldpRemPortIdSubtype)       // best-effort: a failed walk yields an empty column (partial neighbors)
	portDescs, _ := snmpWalkColumn(ctx, addr, creds, lldpRemPortDescOID)        // best-effort: a failed walk yields an empty column (partial neighbors)
	chassis, _ := snmpWalkColumn(ctx, addr, creds, lldpRemChassisIdOID)         // best-effort: a failed walk yields an empty column (partial neighbors)
	chassisSubs, _ := snmpWalkColumn(ctx, addr, creds, lldpRemChassisIdSubtype) // best-effort: a failed walk yields an empty column (partial neighbors)
	// Local port table, keyed by lldpLocPortNum (the 2nd component of the index).
	locDescs, _ := snmpWalkColumn(ctx, addr, creds, lldpLocPortDescOID)  // best-effort: a failed walk yields an empty column (partial neighbors)
	locIDs, _ := snmpWalkColumn(ctx, addr, creds, lldpLocPortIdOID)      // best-effort: a failed walk yields an empty column (partial neighbors)
	locSubs, _ := snmpWalkColumn(ctx, addr, creds, lldpLocPortIdSubtype) // best-effort: a failed walk yields an empty column (partial neighbors)

	out := make([]LLDPNeighbor, 0, len(sysNames))
	for idx, name := range sysNames {
		locPortNum := lldpLocalPortNum(idx)
		if locPortNum == "" {
			continue
		}
		out = append(out, LLDPNeighbor{
			LocalDevice: devID,
			LocalPort:   lldpLocalPortName(locDescs[locPortNum], locIDs[locPortNum], locSubs[locPortNum], locPortNum),
			RemSysName:  strings.TrimSpace(name.str()),
			RemChassis:  lldpRenderChassis(chassis[idx], chassisSubs[idx]),
			RemPort:     lldpRemotePort(portIDs[idx], portSubs[idx], portDescs[idx]),
			RemPortDesc: strings.TrimSpace(portDescs[idx].str()),
			Proto:       "lldp",
			TS:          now,
		})
	}
	return out, nil
}

// lldpLocalPortNum extracts lldpRemLocalPortNum — the 2nd arc of the composite
// remote-table index "timeMark.localPortNum.remIndex". "" if the suffix is malformed.
func lldpLocalPortNum(suffix string) string {
	parts := strings.Split(suffix, ".")
	if len(parts) < 3 {
		return ""
	}
	return parts[1]
}

// lldpLocalPortName resolves the local port a neighbour was seen on. Prefer
// lldpLocPortDesc (usually the IF-MIB ifName/ifDescr), else render lldpLocPortId by
// its (port) subtype, else fall back to "port <num>".
func lldpLocalPortName(desc, id, sub berVal, num string) string {
	if s := strings.TrimSpace(desc.str()); s != "" {
		return s
	}
	if s := lldpRenderPort(id, sub); s != "" {
		return s
	}
	return "port " + num
}

// lldpRemotePort renders the neighbour's port: prefer the typed port-id (ifName /
// local string, or a MAC), else the free-text port description.
func lldpRemotePort(id, sub, desc berVal) string {
	if s := lldpRenderPort(id, sub); s != "" {
		return s
	}
	return strings.TrimSpace(desc.str())
}

// lldpRenderChassis renders an LLDP CHASSIS id by LldpChassisIdSubtype:
// 4=macAddress (→ colon-hex), 5=networkAddress (→ dotted IPv4), everything else
// (1 chassisComponent · 2 interfaceAlias · 6 interfaceName · 7 local) → the string
// if printable, else hex. NOTE the chassis and port subtype enums DIFFER, so they
// have separate renderers (a port subtype 5 = interfaceName, NOT networkAddress).
func lldpRenderChassis(v, sub berVal) string {
	if len(v.raw) == 0 {
		return ""
	}
	switch sub.int() {
	case 4: // macAddress
		return macString(v.raw)
	case 5: // networkAddress: 1 addr-family octet + address
		return lldpNetworkAddr(v.raw)
	default:
		return lldpStringOrHex(v.raw)
	}
}

// lldpRenderPort renders an LLDP PORT id by LldpPortIdSubtype: 3=macAddress,
// 4=networkAddress, everything else (1 interfaceAlias · 2 portComponent ·
// 5 interfaceName · 6 agentCircuitId · 7 local) → string if printable, else hex.
func lldpRenderPort(v, sub berVal) string {
	if len(v.raw) == 0 {
		return ""
	}
	switch sub.int() {
	case 3: // macAddress
		return macString(v.raw)
	case 4: // networkAddress
		return lldpNetworkAddr(v.raw)
	default:
		return lldpStringOrHex(v.raw)
	}
}

func lldpStringOrHex(raw []byte) string {
	// sanitizeLabel, not TrimSpace: this is a neighbour-supplied chassis/port id
	// that becomes a topology node/edge label and a metric label.
	if s := sanitizeLabel(string(raw)); isPrintableASCII(raw) && s != "" {
		return s
	}
	return macString(raw)
}

func lldpNetworkAddr(raw []byte) string {
	if len(raw) == 5 { // addr-family octet (1=ipv4) + IPv4
		return fmt.Sprintf("%d.%d.%d.%d", raw[1], raw[2], raw[3], raw[4])
	}
	return macString(raw)
}

// macString renders bytes as colon-hex. It is ALSO the hex fallback for a
// non-printable chassis/port id, where the input is attacker-shaped rather than
// a 6-byte MAC — so the RAW BYTES are bounded first (colon-hex triples the
// length) and the result is a label-class value (caps.go, audit PIPE-MED-11).
func macString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) > maxLabelChars/3 {
		b = b[:maxLabelChars/3]
	}
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}

func isPrintableASCII(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
