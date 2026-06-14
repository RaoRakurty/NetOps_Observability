package collectors

import (
	"context"
	"fmt"
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
	var lastErr string

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
		for _, prof := range selectProfiles(c.profiles, ent, entOK) {
			for _, m := range prof.Metrics {
				if m.Table {
					rows, err := snmpWalkColumn(dctx, addr, creds, m.OID)
					if err != nil {
						continue
					}
					isIface := strings.HasPrefix(m.Name, "device_if_")
					if isIface && ifNames == nil {
						ifNames = ifNameMap(dctx, addr, creds)
					}
					for idx, v := range rows {
						if isIface {
							// Keep index for series stability; add ifName for humans.
							name := ifNames[idx]
							if name == "" {
								name = "ifIndex " + idx // honest: device named no port
							}
							lines = append(lines, fmt.Sprintf(
								"%s{device=%q,vendor=%q,index=%q,ifName=%q} %d %d",
								m.Name, tg.ID, vendor, idx, name, valueInt(v), now))
							if ev, ok := buildMetricEvent(m.Name, tg.ID, vendor, idx, name, valueInt(v), now); ok {
								events = append(events, ev)
							}
						} else {
							lines = append(lines, fmt.Sprintf("%s{device=%q,vendor=%q,index=%q} %d %d",
								m.Name, tg.ID, vendor, idx, valueInt(v), now))
							if ev, ok := buildMetricEvent(m.Name, tg.ID, vendor, idx, "", valueInt(v), now); ok {
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
					if ev, ok := buildMetricEvent(m.Name, tg.ID, vendor, "", "", valueInt(v), now); ok {
						events = append(events, ev)
					}
				}
			}
		}
		cancel()
		samples += len(lines)
		if len(lines) > 0 {
			emitMetrics(ctx, strings.Join(lines, "\n"))
		}
		// Forward the RCA-filtered canonical subset to the correlation bus
		// (best-effort, separate from the VM path above).
		forwardMetricEvents(ctx, events)
	}

	emitMetrics(ctx, strings.Join([]string{
		fmt.Sprintf(`collector_up{collector="snmpmetrics"} 1 %d`, now),
		fmt.Sprintf(`collector_targets{collector="snmpmetrics"} %d %d`, len(targets), now),
		fmt.Sprintf(`collector_targets_reachable{collector="snmpmetrics"} %d %d`, reachable, now),
		fmt.Sprintf(`collector_samples{collector="snmpmetrics"} %d %d`, samples, now),
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
	ifNameOID  = []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1} // IF-MIB::ifName
	ifDescrOID = []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 2}     // IF-MIB::ifDescr
)

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
