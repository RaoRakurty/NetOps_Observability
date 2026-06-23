package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// snmpmetrics.go — the multivendor stats collector. For each device it detects
// the vendor via sysObjectID (enterpriseOf), selects the matching profiles
// (generic + vendor), polls their OIDs (scalar GET / table walk), and emits
// named metrics to VictoriaMetrics tagged device + vendor. This is what makes
// "onboard a Juniper, see Juniper CPU/temp/memory" actually work — alert rules
// then reference the metric names (device_cpu_percent, …), not OIDs.

type metricsCollector struct {
	interval time.Duration
	targets  TargetFunc
	profiles []SNMPProfile

	mu     sync.RWMutex
	status Status
}

// NewSNMPMetrics builds the profile-driven SNMP stats collector.
func NewSNMPMetrics(targets TargetFunc) Collector {
	return &metricsCollector{
		interval: 60 * time.Second,
		targets:  targets,
		profiles: loadProfiles(),
		status:   Status{Name: "snmpmetrics", Healthy: true, Kind: "metrics"},
	}
}

func (c *metricsCollector) Name() string { return "snmpmetrics" }

func (c *metricsCollector) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *metricsCollector) Run(ctx context.Context) error {
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

func (c *metricsCollector) pollOnce(ctx context.Context) {
	var targets []Target
	if c.targets != nil {
		targets = c.targets()
	}
	start := time.Now()
	now := start.UnixMilli()
	reachable := 0
	samples := 0
	meBuilt, meSent := 0, 0 // metric-event lane observability (built vs sent)
	var lastErr string
	ifaddr := map[string]map[string]string{}    // deviceID → (interface IP → ifName), for topology enrichment
	ifindexMap := map[string]map[string]string{} // deviceID → (ifIndex → ifName), for the C7.1 EntityResolver

	for _, tg := range targets {
		addr := withPort(tg.Address, 161)
		// Per-device credentials (v2c community or full v3 USM) resolved from the
		// device's credential profile by the target builder. Essential for a
		// multi-vendor fleet where each device has its own creds.
		creds := tg.creds()
		dctx, cancel := context.WithTimeout(ctx, 8*time.Second)

		ent, entOK := 0, false
		if v, err := snmpGet(dctx, addr, creds, sysObjectIDOID); err == nil && v.tag == 0x06 {
			ent, entOK = enterpriseOf(decodeOID(v.raw))
		} else if err != nil {
			cancel()
			lastErr = err.Error()
			continue
		}
		reachable++
		vendor := vendorLabel(ent, entOK)

		var lines []string
		// Canonical metric events for the correlation bus (RCA families only;
		// buildMetricEvent applies the allowlist filter). Forwarded per device.
		var events []MetricEvent
		// ifIndex→ifName map, walked lazily once per device the first time an
		// interface metric is emitted. Without it interface counters are labelled
		// by bare ifIndex — which a NOC operator can't map to a physical port
		// (Gi0/1 / ge-0/0/1 / Ethernet1 / ethernet-1/1) and which renumbers on a
		// reboot or line-card change. The name is the operator-facing identity.
		var ifNames map[string]string
		// ifIndex→ifAlias (operator circuit ID, ifXTable). Walked lazily with the
		// names; empty when the operator configured no interface description.
		var ifAliases map[string]string
		for _, prof := range selectProfiles(c.profiles, ent, entOK) {
			for _, m := range prof.Metrics {
				// Single-contract ownership: yield a metric to the transport that owns
				// it on this device (gNMI owns BGP/IS-IS where present); SNMP stays the
				// universal floor on devices without that transport (agentless fallback).
				if m.ownedElsewhere(tg) {
					continue
				}
				// Canonical index label (e.g. bgpPeerTable → "peer") so an SNMP-owned
				// series matches the contract the richer transport uses; "" → "index".
				idxLabel := m.indexLabel()
				if m.Table {
					rows, err := snmpWalkColumn(dctx, addr, creds, m.OID)
					if err != nil {
						continue
					}
					isIface := strings.HasPrefix(m.Name, "device_if_")
					if isIface && ifNames == nil {
						ifNames = ifNameMap(dctx, addr, creds)
						ifAliases = ifAliasMap(dctx, addr, creds)
					}
					for idx, v := range rows {
						if isIface {
							// Keep index for series stability; add ifName for humans.
							name := ifNames[idx]
							if name == "" {
								name = "ifIndex " + idx // honest: device named no port
							}
							alias := ifAliases[idx] // "" when no description configured
							lines = append(lines, fmt.Sprintf(
								"%s{device=%q,vendor=%q,index=%q,ifName=%q,ifAlias=%q} %d %d",
								m.Name, tg.ID, vendor, idx, name, alias, valueInt(v), now))
							if ev, ok := buildMetricEvent(m.Name, tg.ID, vendor, idx, name, alias, valueInt(v), now); ok {
								events = append(events, ev)
							}
						} else {
							lines = append(lines, fmt.Sprintf("%s{device=%q,vendor=%q,%s=%q} %d %d",
								m.Name, tg.ID, vendor, idxLabel, idx, valueInt(v), now))
							if ev, ok := buildMetricEvent(m.Name, tg.ID, vendor, idx, "", "", valueInt(v), now); ok {
								events = append(events, ev)
							}
						}
					}
				} else {
					v, err := snmpGet(dctx, addr, creds, append(append([]int(nil), m.OID...), 0))
					if err != nil {
						continue
					}
					lines = append(lines, fmt.Sprintf("%s{device=%q,vendor=%q} %d %d",
						m.Name, tg.ID, vendor, valueInt(v), now))
					if ev, ok := buildMetricEvent(m.Name, tg.ID, vendor, "", "", "", valueInt(v), now); ok {
						events = append(events, ev)
					}
				}
			}
		}
		// FRU inventory (ENTITY-MIB) — info series, VM-only, best-effort. Devices
		// without ENTITY-MIB yield nothing.
		lines = append(lines, collectEntityInventory(dctx, addr, creds, tg.ID, vendor, now)...)
		// Topology enrichment: interface IP → ifName (reuses the ifName map already
		// walked for interface metrics; one extra ipAddrTable walk). Lets BGP-LS
		// links (interface IPs) resolve to real port names + join to metrics.
		if ifNames != nil {
			if m := ipIfNameMap(dctx, addr, creds, ifNames); len(m) > 0 {
				ifaddr[tg.ID] = m
			}
			ifindexMap[tg.ID] = ifNames // ifIndex → ifName, for the EntityResolver (C7.1)
		}
		cancel()
		samples += len(lines)
		if len(lines) > 0 {
			emitMetrics(ctx, strings.Join(lines, "\n"))
		}
		// Forward the RCA-filtered canonical subset to the correlation bus
		// (best-effort, separate from the VM path above).
		meBuilt += len(events)
		meSent += forwardMetricEvents(ctx, events)
	}

	// Publish the merged interface-address map (replace; TTL self-expires if the
	// collector dies). Read by the topology API to enrich BGP-LS links.
	if len(ifaddr) > 0 {
		if b, err := json.Marshal(ifaddr); err == nil {
			_ = redisSetEX(ctx, ifAddrKey, string(b), 1800)
		}
	}
	// ifIndex → ifName per device, for the C7.1 EntityResolver (flow exporter
	// in/out ifIndex → device:ifName). Same replace+TTL discipline as ifaddr.
	if len(ifindexMap) > 0 {
		if b, err := json.Marshal(ifindexMap); err == nil {
			_ = redisSetEX(ctx, ifIndexKey, string(b), 1800)
		}
	}

	emitMetrics(ctx, strings.Join([]string{
		fmt.Sprintf(`collector_up{collector="snmpmetrics"} 1 %d`, now),
		fmt.Sprintf(`collector_targets{collector="snmpmetrics"} %d %d`, len(targets), now),
		fmt.Sprintf(`collector_targets_reachable{collector="snmpmetrics"} %d %d`, reachable, now),
		fmt.Sprintf(`collector_samples{collector="snmpmetrics"} %d %d`, samples, now),
		// Metric-event bus lane: built = passed the RCA filter, sent = POSTed to
		// Vector ok; built-sent = failed/dropped (bus unreachable). Proves the
		// netops.metrics producer is alive and where it loses events.
		fmt.Sprintf(`collector_metric_events_built{collector="snmpmetrics"} %d %d`, meBuilt, now),
		fmt.Sprintf(`collector_metric_events_sent{collector="snmpmetrics"} %d %d`, meSent, now),
		fmt.Sprintf(`collector_metric_events_failed{collector="snmpmetrics"} %d %d`, meBuilt-meSent, now),
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

// vendorLabel resolves the metric's vendor tag from the enterprise number.
func vendorLabel(enterprise int, ok bool) string {
	if !ok {
		return "generic"
	}
	if v := enterpriseVendor[enterprise]; v != "" {
		return v
	}
	return "unknown"
}

// IF-MIB columns for interface-name translation. ifName is the short,
// operator-facing port name (Gi0/1, ge-0/0/1, Ethernet1, ethernet-1/1);
// ifDescr is the fallback for platforms that leave ifName blank.
var (
	ifNameOID  = []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1}  // IF-MIB::ifName
	ifDescrOID = []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 2}      // IF-MIB::ifDescr
	ifAliasOID = []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18} // IF-MIB::ifAlias (operator circuit ID)
	// ipAdEntIfIndex (IP-MIB ipAddrTable): index = the interface's IPv4 address,
	// value = its ifIndex. Maps interface IP → ifName, the bridge BGP-LS needs
	// (its link descriptors identify interfaces by IP, not name) so a Logical-
	// topology link can show real port names + join to interface metrics.
	ipAdEntIfIndexOID = []int{1, 3, 6, 1, 2, 1, 4, 20, 1, 2}
)

// ipIfNameMap walks ipAddrTable and resolves each interface IPv4 to its ifName via
// the already-walked ifIndex→ifName map (no extra ifName walk). Best-effort: a
// device with no ipAddrTable yields an empty map.
func ipIfNameMap(ctx context.Context, addr string, creds snmpCreds, ifNames map[string]string) map[string]string {
	rows, err := snmpWalkColumn(ctx, addr, creds, ipAdEntIfIndexOID)
	if err != nil || len(rows) == 0 {
		return nil
	}
	out := make(map[string]string, len(rows))
	for ip, v := range rows {
		if name := ifNames[strconv.FormatInt(valueInt(v), 10)]; name != "" {
			out[ip] = name
		}
	}
	return out
}

// ifAliasMap walks ifAlias keyed by ifIndex — the operator-assigned interface
// description / circuit ID (RFC 2863). Unlike ifName/ifDescr it is the human's
// own label ("WAN-to-AWS", "Circuit ID 7Y-XYZ"), reboot-persistent, and a
// grounding token that can intersect a seam/intent. Best-effort: a device with
// no descriptions configured yields an empty map and metrics carry ifAlias="".
func ifAliasMap(ctx context.Context, addr string, creds snmpCreds) map[string]string {
	out := map[string]string{}
	if rows, err := snmpWalkColumn(ctx, addr, creds, ifAliasOID); err == nil {
		for idx, v := range rows {
			if s := strings.TrimSpace(string(v.raw)); s != "" {
				out[idx] = s
			}
		}
	}
	return out
}

// ifNameMap walks ifName keyed by ifIndex, filling any blank from ifDescr, so
// interface metrics carry the physical port a NOC operator actually reads.
// Best-effort: an unreachable/blank table yields an empty map and the caller
// falls back to "ifIndex N" rather than dropping the metric.
func ifNameMap(ctx context.Context, addr string, creds snmpCreds) map[string]string {
	out := map[string]string{}
	if rows, err := snmpWalkColumn(ctx, addr, creds, ifNameOID); err == nil {
		for idx, v := range rows {
			if s := strings.TrimSpace(string(v.raw)); s != "" {
				out[idx] = s
			}
		}
	}
	if descr, err := snmpWalkColumn(ctx, addr, creds, ifDescrOID); err == nil {
		for idx, v := range descr {
			if _, ok := out[idx]; ok {
				continue
			}
			if s := strings.TrimSpace(string(v.raw)); s != "" {
				out[idx] = s
			}
		}
	}
	return out
}

// valueInt coerces an SNMP value to an integer for metric emission. Counters,
// gauges, timeticks are unsigned; INTEGER is signed.
func valueInt(v berVal) int64 {
	switch v.tag {
	case 0x41, 0x42, 0x43, 0x46: // Counter32, Gauge32, TimeTicks, Counter64
		return int64(decodeUint(v.raw))  // #nosec G115 -- SNMP counter; int64 range covers Counter32/64 telemetry
	default:
		return decodeInt(v.raw)
	}
}
