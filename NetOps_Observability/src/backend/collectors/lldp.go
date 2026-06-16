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
	var targets []Target
	if c.targets != nil {
		targets = c.targets()
	}
	start := time.Now()
	now := start.UnixMilli()
	reachable := 0
	var all []LLDPNeighbor
	var lastErr string

	for _, tg := range targets {
		addr := withPort(tg.Address, 161)
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		neigh, err := pollLLDP(dctx, addr, tg.creds(), tg.ID, now)
		cancel()
		if err != nil {
			lastErr = err.Error()
			continue
		}
		if len(neigh) > 0 {
			reachable++
			all = append(all, neigh...)
		}
	}

	// Publish the full neighbour set (replace, not merge — stale devices drop off).
	// TTL self-expires the topology if the collector dies (ADR 0001 share-via-Redis).
	if all == nil {
		all = []LLDPNeighbor{} // store "[]" not "null" when empty
	}
	if b, err := json.Marshal(all); err == nil {
		_ = redisSetEX(ctx, topoLinksKeyLLDP, string(b), 1800)
	}

	emitMetrics(ctx, strings.Join([]string{
		fmt.Sprintf(`collector_up{collector="lldp"} 1 %d`, now),
		fmt.Sprintf(`collector_targets{collector="lldp"} %d %d`, len(targets), now),
		fmt.Sprintf(`collector_targets_reachable{collector="lldp"} %d %d`, reachable, now),
		fmt.Sprintf(`collector_lldp_neighbors{collector="lldp"} %d %d`, len(all), now),
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
	portSubs, _ := snmpWalkColumn(ctx, addr, creds, lldpRemPortIdSubtype)
	portDescs, _ := snmpWalkColumn(ctx, addr, creds, lldpRemPortDescOID)
	chassis, _ := snmpWalkColumn(ctx, addr, creds, lldpRemChassisIdOID)
	chassisSubs, _ := snmpWalkColumn(ctx, addr, creds, lldpRemChassisIdSubtype)
	// Local port table, keyed by lldpLocPortNum (the 2nd component of the index).
	locDescs, _ := snmpWalkColumn(ctx, addr, creds, lldpLocPortDescOID)
	locIDs, _ := snmpWalkColumn(ctx, addr, creds, lldpLocPortIdOID)
	locSubs, _ := snmpWalkColumn(ctx, addr, creds, lldpLocPortIdSubtype)

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
	if s := strings.TrimSpace(string(raw)); isPrintableASCII(raw) && s != "" {
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

func macString(b []byte) string {
	if len(b) == 0 {
		return ""
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
