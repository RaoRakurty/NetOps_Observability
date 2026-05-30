package collectors

import (
	"context"
	"fmt"
	"os"
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
	community := os.Getenv("SNMP_COMMUNITY")
	if community == "" {
		community = "public"
	}

	start := time.Now()
	now := start.UnixMilli()
	reachable := 0
	samples := 0
	var lastErr string

	for _, tg := range targets {
		addr := withPort(tg.Address, 161)
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)

		ent, entOK := 0, false
		if v, err := snmpGet(dctx, addr, community, sysObjectIDOID); err == nil && v.tag == 0x06 {
			ent, entOK = enterpriseOf(decodeOID(v.raw))
		} else if err != nil {
			cancel()
			lastErr = err.Error()
			continue
		}
		reachable++
		vendor := vendorLabel(ent, entOK)

		var lines []string
		for _, prof := range selectProfiles(c.profiles, ent, entOK) {
			for _, m := range prof.Metrics {
				if m.Table {
					rows, err := snmpWalkColumn(dctx, addr, community, m.OID)
					if err != nil {
						continue
					}
					for idx, v := range rows {
						lines = append(lines, fmt.Sprintf("%s{device=%q,vendor=%q,index=%q} %d %d",
							m.Name, tg.ID, vendor, idx, valueInt(v), now))
					}
				} else {
					v, err := snmpGet(dctx, addr, community, append(append([]int(nil), m.OID...), 0))
					if err != nil {
						continue
					}
					lines = append(lines, fmt.Sprintf("%s{device=%q,vendor=%q} %d %d",
						m.Name, tg.ID, vendor, valueInt(v), now))
				}
			}
		}
		cancel()
		samples += len(lines)
		if len(lines) > 0 {
			emitMetrics(strings.Join(lines, "\n"))
		}
	}

	emitMetrics(strings.Join([]string{
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

// valueInt coerces an SNMP value to an integer for metric emission. Counters,
// gauges, timeticks are unsigned; INTEGER is signed.
func valueInt(v berVal) int64 {
	switch v.tag {
	case 0x41, 0x42, 0x43, 0x46: // Counter32, Gauge32, TimeTicks, Counter64
		return int64(decodeUint(v.raw))
	default:
		return decodeInt(v.raw)
	}
}
