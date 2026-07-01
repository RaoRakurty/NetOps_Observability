package main

import "context"

// path_metric_resolver.go — the ONE source-agnostic path-metric resolver
// (#3 of the WAN path-metrics program), rebuilt on the MEASUREMENT SOURCE RANKING
// (5-tier taxonomy).
//
// Principle: rank a metric's source by PROXIMITY TO THE USER/APPLICATION
// EXPERIENCE, not by protocol precision. What the application actually
// experienced is the most authoritative SLA number; a device-native probe is
// precise but a step removed; a flow-derived indicator is only an inference.
//
//	Tier 1  Application / user experience   HTTP/DNS/TLS synthetic · RUM · DB probe
//	Tier 2  Agent-to-agent active path      ICMP/UDP/TCP · custom UDP · TCP connect · HTTP-through-path
//	Tier 3  Device-native active probe      STAMP · TWAMP · OWAMP · IP SLA · RPM
//	Tier 4  Passive network telemetry       iface drops/errors · queue · tunnel · firewall · SD-WAN · BGP/OSPF/ISIS
//	Tier 5  Flow-derived indicators         TCP retransmits · retry rates · byte/pkt deltas · app-to-DB · east-west
//
// "Absent tier → next tier" falls out of the first-with-data-wins fold: whichever
// highest tier has a series for a destination wins that field, per field. Keyed by
// destination host (port stripped), the common identity across every source's
// `{dst}` label. This REPLACES the old STAMP-first ladder: agent probes (Tier 2)
// now outrank STAMP (Tier 3), and HTTP/DNS/TLS synthetics (Tier 1) outrank both.

// MeasurementTier is the source-ranking tier (1 = closest to user experience).
type MeasurementTier int

const (
	TierUnknown        MeasurementTier = 0
	Tier1AppExperience MeasurementTier = 1
	Tier2AgentActive   MeasurementTier = 2
	Tier3DeviceNative  MeasurementTier = 3
	Tier4Passive       MeasurementTier = 4
	Tier5FlowDerived   MeasurementTier = 5
)

// Label is the operator-facing tier name.
func (t MeasurementTier) Label() string {
	switch t {
	case Tier1AppExperience:
		return "Application experience"
	case Tier2AgentActive:
		return "Active path probe"
	case Tier3DeviceNative:
		return "Device-native probe"
	case Tier4Passive:
		return "Passive telemetry"
	case Tier5FlowDerived:
		return "Flow-derived"
	default:
		return "—"
	}
}

// PathSource is the measurement METHOD that produced a metric (provenance). The
// method's protocol determines its tier (HTTP → Tier 1, ICMP → Tier 2, STAMP →
// Tier 3, …). Some sources are reserved (no collector yet) but declared so the
// taxonomy + provenance are complete and future collectors slot in by tier.
type PathSource string

const (
	// Tier 1 — application / user experience
	SrcHTTPSynthetic PathSource = "http_synthetic"
	SrcDNSSynthetic  PathSource = "dns_synthetic"
	SrcTLSHandshake  PathSource = "tls_synthetic"
	SrcRUM           PathSource = "rum"      // reserved
	SrcDBProbe       PathSource = "db_probe" // reserved
	// Tier 2 — agent-to-agent active path probes
	SrcEcho         PathSource = "echo"        // wan-echo source-bound ICMP/TCP circuit probe
	SrcSynthetic    PathSource = "icmp"        // synthetic ICMP service check (wire value kept "icmp")
	SrcSyntheticTCP PathSource = "tcp_connect" // synthetic TCP-connect check
	SrcTraceroute   PathSource = "traceroute"  // traceroute-TCP path measurement
	SrcUDPProbe     PathSource = "udp_probe"   // reserved (custom timestamped UDP)
	// Tier 3 — device-native active probes
	SrcSTAMP PathSource = "stamp"
	SrcTWAMP PathSource = "twamp" // reserved
	SrcOWAMP PathSource = "owamp" // reserved
	SrcIPSLA PathSource = "ipsla" // reserved (on-device IP SLA / SD-WAN controller)
	SrcRPM   PathSource = "rpm"   // reserved (Juniper RPM)
	// Tier 4 — passive network telemetry
	SrcInterface PathSource = "interface"     // iface drops/errors/oper-status
	SrcTunnel    PathSource = "tunnel"        // reserved (tunnel SLA from controller)
	SrcFirewall  PathSource = "firewall"      // reserved
	SrcSDWANPath PathSource = "sdwan_path"    // reserved
	SrcRouting   PathSource = "routing_state" // reserved (BGP/OSPF/ISIS)
	// Tier 5 — flow-derived indicators
	SrcFlow PathSource = "flow" // reserved (retransmits / retries / deltas)
	SrcNone PathSource = ""
)

// Tier maps a source to its ranking tier.
func (p PathSource) Tier() MeasurementTier {
	switch p {
	case SrcHTTPSynthetic, SrcDNSSynthetic, SrcTLSHandshake, SrcRUM, SrcDBProbe:
		return Tier1AppExperience
	case SrcEcho, SrcSynthetic, SrcSyntheticTCP, SrcTraceroute, SrcUDPProbe:
		return Tier2AgentActive
	case SrcSTAMP, SrcTWAMP, SrcOWAMP, SrcIPSLA, SrcRPM:
		return Tier3DeviceNative
	case SrcInterface, SrcTunnel, SrcFirewall, SrcSDWANPath, SrcRouting:
		return Tier4Passive
	case SrcFlow:
		return Tier5FlowDerived
	default:
		return TierUnknown
	}
}

// Label is the customer-facing method name (no raw tokens — customer-language rule).
func (p PathSource) Label() string {
	switch p {
	case SrcHTTPSynthetic:
		return "HTTP synthetic"
	case SrcDNSSynthetic:
		return "DNS synthetic"
	case SrcTLSHandshake:
		return "TLS handshake"
	case SrcRUM:
		return "Real-user telemetry"
	case SrcDBProbe:
		return "Database probe"
	case SrcEcho:
		return "Active echo"
	case SrcSynthetic:
		return "ICMP"
	case SrcSyntheticTCP:
		return "TCP connect"
	case SrcTraceroute:
		return "Traceroute"
	case SrcUDPProbe:
		return "UDP probe"
	case SrcSTAMP:
		return "STAMP"
	case SrcTWAMP:
		return "TWAMP"
	case SrcOWAMP:
		return "OWAMP"
	case SrcIPSLA:
		return "IP SLA"
	case SrcRPM:
		return "RPM"
	case SrcInterface:
		return "Interface counters"
	case SrcTunnel:
		return "Tunnel stats"
	case SrcFirewall:
		return "Firewall stats"
	case SrcSDWANPath:
		return "SD-WAN path stats"
	case SrcRouting:
		return "Routing state"
	case SrcFlow:
		return "Flow-derived"
	default:
		return "—"
	}
}

// TierLabel is the source's tier name ("Active path probe"), for a provenance
// chip that shows the RANK, not just the method.
func (p PathSource) TierLabel() string { return p.Tier().Label() }

// ResolvedPathMetric is one destination's current SLA with per-field provenance.
// Availability (new) is % of the window the path was reachable — distinct from
// loss (packet-level): a path can be 100% available but lossy.
type ResolvedPathMetric struct {
	Latency, Jitter, Loss, QoE, Availability float64
	HasLatency, HasJitter, HasLoss           bool
	HasQoE, HasAvailability                  bool
	LatencySource, JitterSource, LossSource  PathSource
	QoESource, AvailabilitySource            PathSource
}

// Source is the headline provenance: whatever produced latency, else availability,
// else loss (a total-loss/down path has no latency sample but is a real signal).
func (m *ResolvedPathMetric) Source() PathSource {
	switch {
	case m.LatencySource != SrcNone:
		return m.LatencySource
	case m.AvailabilitySource != SrcNone:
		return m.AvailabilitySource
	default:
		return m.LossSource
	}
}

// Tier is the headline tier (of the headline source).
func (m *ResolvedPathMetric) Tier() MeasurementTier { return m.Source().Tier() }

// resolveCurrentByDst runs the tier cascade once (a handful of VM vector queries)
// and returns host → resolved current metric. Best-effort: a query error or a
// missing tier simply leaves the lower tier (or nothing) in place.
func (s *server) resolveCurrentByDst(ctx context.Context) map[string]*ResolvedPathMetric {
	out := map[string]*ResolvedPathMetric{}
	get := func(h string) *ResolvedPathMetric {
		m := out[h]
		if m == nil {
			m = &ResolvedPathMetric{}
			out[h] = m
		}
		return m
	}
	// fold applies one query in priority order via a field setter; a dst already
	// filled by a higher tier is left untouched (the setter no-ops), so the first
	// tier with data wins — per field.
	fold := func(query string, src PathSource, set func(m *ResolvedPathMetric, v float64, src PathSource)) {
		samples, err := s.vmInstant(ctx, query)
		if err != nil {
			return
		}
		for _, sm := range samples {
			h := hostOnly(sm.Labels["dst"])
			if h == "" {
				continue
			}
			set(get(h), sm.Value, src)
		}
	}
	setLat := func(m *ResolvedPathMetric, v float64, src PathSource) {
		if !m.HasLatency {
			m.Latency, m.HasLatency, m.LatencySource = v, true, src
		}
	}
	setJit := func(m *ResolvedPathMetric, v float64, src PathSource) {
		if !m.HasJitter {
			m.Jitter, m.HasJitter, m.JitterSource = v, true, src
		}
	}
	setLoss := func(m *ResolvedPathMetric, v float64, src PathSource) {
		if !m.HasLoss {
			m.Loss, m.HasLoss, m.LossSource = v, true, src
		}
	}
	setQoE := func(m *ResolvedPathMetric, v float64, src PathSource) {
		if !m.HasQoE {
			m.QoE, m.HasQoE, m.QoESource = v, true, src
		}
	}
	setAvail := func(m *ResolvedPathMetric, v float64, src PathSource) {
		if !m.HasAvailability {
			m.Availability, m.HasAvailability, m.AvailabilitySource = v, true, src
		}
	}

	// ── LATENCY: Tier 1 (HTTP total) → Tier 2 (echo → ICMP → TCP → traceroute) → Tier 3 (STAMP) ──
	fold(`quantile_over_time(0.95, synthetic_http_total_ms[5m])`, SrcHTTPSynthetic, setLat)                   // T1: full app response
	fold(`quantile_over_time(0.95, circuit_latency_ms[5m])`, SrcEcho, setLat)                                 // T2
	fold(`quantile_over_time(0.95, synthetic_icmp_rtt_ms[5m])`, SrcSynthetic, setLat)                         // T2
	fold(`quantile_over_time(0.95, synthetic_tcp_connect_ms[5m])`, SrcSyntheticTCP, setLat)                   // T2
	fold(`max(quantile_over_time(0.95, probe_hop_rtt_ms{method="tcp"}[5m])) by (dst)`, SrcTraceroute, setLat) // T2 (coarse e2e proxy)
	fold(`quantile_over_time(0.95, probe_rtt_ms[5m])`, SrcSTAMP, setLat)                                      // T3

	// ── JITTER: Tier 2 (echo) → Tier 3 (STAMP pdv). Only these measure per-packet delay variation. ──
	fold(`quantile_over_time(0.95, circuit_jitter_ms[5m])`, SrcEcho, setJit) // T2
	fold(`quantile_over_time(0.95, probe_pdv_ms[5m])`, SrcSTAMP, setJit)     // T3

	// ── LOSS: Tier 1 (HTTP fail) → Tier 2 (echo → ICMP → traceroute) → Tier 3 (STAMP) ──
	fold(`(1 - avg_over_time(synthetic_up{check="http"}[5m])) * 100`, SrcHTTPSynthetic, setLoss)    // T1
	fold(`avg_over_time(circuit_loss_pct[5m])`, SrcEcho, setLoss)                                   // T2
	fold(`avg_over_time(synthetic_icmp_loss_pct[5m])`, SrcSynthetic, setLoss)                       // T2
	fold(`(1 - avg_over_time(probe_path_reached{method="tcp"}[5m])) * 100`, SrcTraceroute, setLoss) // T2
	fold(`avg_over_time(probe_loss_pct[5m])`, SrcSTAMP, setLoss)                                    // T3

	// ── AVAILABILITY: % of window the path was reachable (distinct from loss). ──
	// Tier 1 HTTP up → Tier 2 (icmp/tcp up, echo recv) → Tier 3 (STAMP recv).
	fold(`avg_over_time(synthetic_up{check="http"}[5m]) * 100`, SrcHTTPSynthetic, setAvail)  // T1
	fold(`avg_over_time(synthetic_up{check=~"icmp|tcp"}[5m]) * 100`, SrcSynthetic, setAvail) // T2
	fold(`avg_over_time((circuit_recv > bool 0)[5m]) * 100`, SrcEcho, setAvail)              // T2 (any echo received)
	fold(`avg_over_time((probe_recv > bool 0)[5m]) * 100`, SrcSTAMP, setAvail)               // T3

	// ── QoE: the echo probe scores it today (Tier 2). ──
	fold(`avg_over_time(circuit_qoe[5m])`, SrcEcho, setQoE)

	return out
}

// sourceTierOrder is the canonical priority order (Tier 1 → Tier 5, and by
// precision within a tier) — the single place the ranking is enumerated, used by
// resolvedSources so a "measured by" summary lists sources highest-tier first.
var sourceTierOrder = []PathSource{
	SrcHTTPSynthetic, SrcDNSSynthetic, SrcTLSHandshake, SrcRUM, SrcDBProbe, // T1
	SrcEcho, SrcSynthetic, SrcSyntheticTCP, SrcTraceroute, SrcUDPProbe, // T2
	SrcSTAMP, SrcTWAMP, SrcOWAMP, SrcIPSLA, SrcRPM, // T3
	SrcInterface, SrcTunnel, SrcFirewall, SrcSDWANPath, SrcRouting, // T4
	SrcFlow, // T5
}

// resolvedSources returns the distinct sources present, highest-tier first —
// handy for a "measured by: HTTP synthetic, echo" summary.
func resolvedSources(ms map[string]*ResolvedPathMetric) []PathSource {
	seen := map[PathSource]bool{}
	for _, m := range ms {
		if src := m.Source(); src != SrcNone {
			seen[src] = true
		}
	}
	var out []PathSource
	for _, s := range sourceTierOrder {
		if seen[s] {
			out = append(out, s)
		}
	}
	return out
}
