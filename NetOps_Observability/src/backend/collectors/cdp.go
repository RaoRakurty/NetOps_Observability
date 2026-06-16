package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// cdp.go — CDP neighbour discovery (Cisco Discovery Protocol), the Cisco-native
// companion to LLDP. Same job, same published record shape (LLDPNeighbor with
// Proto="cdp"), so the API merges and dedups it against LLDP transparently. Useful
// where a Cisco device runs CDP but not LLDP. Dormant by default
// (ENABLE_CDP_DISCOVERY); reuses the per-device SNMP creds, UDP/161.
//
// Source: CISCO-CDP-MIB cdpCacheTable (1.3.6.1.4.1.9.9.23.1.2.1.1), indexed by
// { cdpCacheIfIndex, cdpCacheDeviceIndex }. The 1st arc is the LOCAL ifIndex, which
// we resolve to a port name via IF-MIB ifName/ifDescr (ifNameMap, shared with the
// metrics collector). cdpCacheDeviceId is the neighbour hostname; cdpCacheDevicePort
// its port; cdpCacheAddress its (usually IPv4) management address.

var (
	cdpCacheAddress     = []int{1, 3, 6, 1, 4, 1, 9, 9, 23, 1, 2, 1, 1, 4}
	cdpCacheDeviceID    = []int{1, 3, 6, 1, 4, 1, 9, 9, 23, 1, 2, 1, 1, 6}
	cdpCacheDevicePort  = []int{1, 3, 6, 1, 4, 1, 9, 9, 23, 1, 2, 1, 1, 7}
	cdpCacheAddressType = []int{1, 3, 6, 1, 4, 1, 9, 9, 23, 1, 2, 1, 1, 2}
)

type cdpCollector struct {
	interval time.Duration
	targets  TargetFunc

	mu     sync.RWMutex
	status Status
}

// NewCDP builds the CDP neighbour-discovery collector.
func NewCDP(targets TargetFunc) Collector {
	return &cdpCollector{
		interval: 5 * time.Minute,
		targets:  targets,
		status:   Status{Name: "cdp", Healthy: true, Kind: "discovery"},
	}
}

func (c *cdpCollector) Name() string { return "cdp" }

func (c *cdpCollector) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *cdpCollector) Run(ctx context.Context) error {
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

func (c *cdpCollector) pollOnce(ctx context.Context) {
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
		neigh, err := pollCDP(dctx, addr, tg.creds(), tg.ID, now)
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

	if all == nil {
		all = []LLDPNeighbor{} // store "[]" not "null" when empty
	}
	if b, err := json.Marshal(all); err == nil {
		_ = redisSetEX(ctx, topoLinksKeyCDP, string(b), 1800)
	}

	emitMetrics(ctx, strings.Join([]string{
		fmt.Sprintf(`collector_up{collector="cdp"} 1 %d`, now),
		fmt.Sprintf(`collector_targets{collector="cdp"} %d %d`, len(targets), now),
		fmt.Sprintf(`collector_targets_reachable{collector="cdp"} %d %d`, reachable, now),
		fmt.Sprintf(`collector_cdp_neighbors{collector="cdp"} %d %d`, len(all), now),
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

// pollCDP walks the CDP cache for one device. Best-effort: a device with no CDP
// (non-Cisco / CDP disabled) yields nil and no error.
func pollCDP(ctx context.Context, addr string, creds snmpCreds, devID string, now int64) ([]LLDPNeighbor, error) {
	deviceIDs, err := snmpWalkColumn(ctx, addr, creds, cdpCacheDeviceID)
	if err != nil {
		return nil, err
	}
	if len(deviceIDs) == 0 {
		return nil, nil
	}
	devicePorts, _ := snmpWalkColumn(ctx, addr, creds, cdpCacheDevicePort)
	addrs, _ := snmpWalkColumn(ctx, addr, creds, cdpCacheAddress)
	addrTypes, _ := snmpWalkColumn(ctx, addr, creds, cdpCacheAddressType)
	ifNames := ifNameMap(ctx, addr, creds) // ifIndex → port name

	out := make([]LLDPNeighbor, 0, len(deviceIDs))
	for idx, dev := range deviceIDs {
		ifIndex := cdpLocalIfIndex(idx)
		if ifIndex == "" {
			continue
		}
		localPort := ifNames[ifIndex]
		if localPort == "" {
			localPort = "ifIndex " + ifIndex
		}
		out = append(out, LLDPNeighbor{
			LocalDevice: devID,
			LocalPort:   localPort,
			RemSysName:  cdpTrimDomain(strings.TrimSpace(dev.str())),
			RemChassis:  cdpAddr(addrs[idx], addrTypes[idx]),
			RemPort:     strings.TrimSpace(devicePorts[idx].str()),
			Proto:       "cdp",
			TS:          now,
		})
	}
	return out, nil
}

// cdpLocalIfIndex extracts cdpCacheIfIndex — the 1st arc of the composite index
// "ifIndex.deviceIndex". "" if malformed.
func cdpLocalIfIndex(suffix string) string {
	parts := strings.Split(suffix, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[0]
}

// cdpAddr renders a cdpCacheAddress. Type 1 (ip) is 4 raw octets → dotted IPv4;
// anything else falls back to hex.
func cdpAddr(v, typ berVal) string {
	if len(v.raw) == 0 {
		return ""
	}
	if typ.int() == 1 && len(v.raw) == 4 { // ip
		return fmt.Sprintf("%d.%d.%d.%d", v.raw[0], v.raw[1], v.raw[2], v.raw[3])
	}
	if len(v.raw) == 4 { // many agents omit/!=1 the type but still send IPv4
		return fmt.Sprintf("%d.%d.%d.%d", v.raw[0], v.raw[1], v.raw[2], v.raw[3])
	}
	return macString(v.raw)
}

// cdpTrimDomain drops a trailing DNS domain CDP often appends to the device-id
// ("spine1.lab.example.com" → "spine1") so it matches inventory hostnames; an
// FQDN that is actually an address (all-numeric labels) is left intact.
func cdpTrimDomain(name string) string {
	i := strings.IndexByte(name, '.')
	if i <= 0 {
		return name
	}
	head := name[:i]
	// keep IP-like first labels intact (don't truncate 10 from 10.0.0.1)
	allDigits := true
	for _, c := range head {
		if c < '0' || c > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return name
	}
	return head
}
