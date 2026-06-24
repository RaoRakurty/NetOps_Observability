package timeintel

import "strings"

// owner.go — classify an incident's responsible OWNER DOMAIN (ISP / LAN / SD-WAN /
// Cloud / App / Internal Platform / Unknown) and detect internal-platform self-
// monitoring. The NOC's first question is "is this ours, the provider's, the cloud's,
// or the app team's?" — this answers it, and lets the default view exclude Correlix's
// own stack so the demo isn't dominated by api/clickhouse/netbox/nginx noise.

type OwnerDomain string

const (
	DomainISP      OwnerDomain = "ISP"
	DomainLAN      OwnerDomain = "LAN"
	DomainSDWAN    OwnerDomain = "SD-WAN"
	DomainCloud    OwnerDomain = "Cloud"
	DomainApp      OwnerDomain = "App"
	DomainInternal OwnerDomain = "Internal Platform"
	DomainUnknown  OwnerDomain = "Unknown"
)

// internalTokens identify Correlix's own stack services (and lab infra) appearing as
// an incident's object — these are platform self-monitoring, not customer-impacting.
var internalTokens = []string{
	"clickhouse", "netbox", "nginx", "prober", "grafana", "redis", "postgres",
	"victoria", "victoriametrics", "opensearch", "vector", "correlation",
	"redpanda", "kafka", "loki", "promtail", "swtpm", "frontend", "keycloak",
}

// looksInternal reports whether an object identity belongs to the platform stack.
// "api" is matched only as a standalone path component (it's too short to substring-
// match safely).
func looksInternal(group map[string]string) bool {
	for _, v := range group {
		low := strings.ToLower(v)
		for _, t := range internalTokens {
			if strings.Contains(low, t) {
				return true
			}
		}
		// "api" as a whole path node (api->x, x->api, "api")
		for _, part := range strings.FieldsFunc(low, func(r rune) bool {
			return r == '>' || r == '-' || r == ':' || r == '/' || r == ' '
		}) {
			if part == "api" {
				return true
			}
		}
	}
	return false
}

// ClassifyOwnerDomain maps the engine's seam owner (+ object identity) to one of the
// seven NOC owner domains, and reports whether the incident is internal-platform.
//
// The engine's EXPLICIT external owner is authoritative: an ISP/SD-WAN/Cloud/App-owned
// incident is a real customer incident even if its path traverses platform infra, so
// the internal-token heuristic must NOT override it. Internal detection only applies
// to platform/internal owners and to ambiguous ones (netops / empty / unknown), which
// is where Correlix's own self-monitoring noise actually lives.
func ClassifyOwnerDomain(owner string, group map[string]string) (OwnerDomain, bool) {
	o := strings.ToLower(strings.TrimSpace(owner))
	// A platform/internal owner, OR an object that is unambiguously one of Correlix's
	// own stack services (clickhouse/netbox/prober/api/…), is self-monitoring — this
	// WINS over the engine's seam owner: an incident "on" the flow store can't be an
	// ISP incident even if the engine labelled it isp. Real fabric (spine1/leaf1/
	// wan-r2) carries no such token, so genuine customer incidents are unaffected.
	if o == "platform" || o == "internal" || looksInternal(group) {
		return DomainInternal, true
	}
	switch o {
	case "isp", "carrier", "wan_provider", "provider":
		return DomainISP, false
	case "sdwan_vendor", "sdwan", "sd-wan":
		return DomainSDWAN, false
	case "cloud_provider", "cloud":
		return DomainCloud, false
	case "saas", "app_team", "app":
		return DomainApp, false
	case "netops", "network_ops", "lan", "colo_provider", "dc":
		return DomainLAN, false
	default: // "" / unknown / unrecognised
		return DomainUnknown, false
	}
}

// OwnerLabel renders a seam owner for operator-facing copy (exported wrapper).
func OwnerLabel(owner string) string { return ownerLabel(owner) }

// DomainStat is one owner domain's reliability summary for the Owner Domain Breakdown.
type DomainStat struct {
	Domain        OwnerDomain    `json:"domain"`
	IncidentCount int            `json:"incident_count"`
	MTTIp90ms     int64          `json:"mtti_p90_ms"`
	RecoveryP90ms int64          `json:"recovery_p90_ms"` // 0 = no recovery evidence
	RepeatRate    float64        `json:"repeat_incident_rate"`
	TopDelay      TimeLossDriver `json:"top_delay_driver"`
}

// RollupByDomain produces one DomainStat per owner domain present. Domains with no
// incidents are omitted. MTTI/Recovery p90 use only incidents that completed that
// phase (Recovery stays 0 until recovery evidence exists — honest, not fabricated).
func RollupByDomain(incidents []IncidentSummary) []DomainStat {
	type acc struct {
		tti, rec []int64
		drivers  map[TimeLossDriver]int
		members  []IncidentSummary
	}
	byDomain := map[OwnerDomain]*acc{}
	for _, in := range incidents {
		d := in.OwnerDomain
		if d == "" {
			d = DomainUnknown
		}
		a := byDomain[d]
		if a == nil {
			a = &acc{drivers: map[TimeLossDriver]int{}}
			byDomain[d] = a
		}
		if v, ok := in.Durations[MetricTTI]; ok {
			a.tti = append(a.tti, v)
		}
		if v, ok := in.Durations[MetricTTRRecovery]; ok {
			a.rec = append(a.rec, v)
		}
		if in.TimeLossDriver != "" && in.TimeLossDriver != DriverUnknown {
			a.drivers[in.TimeLossDriver]++
		}
		a.members = append(a.members, in)
	}
	// Stable domain order for the UI.
	order := []OwnerDomain{DomainISP, DomainLAN, DomainSDWAN, DomainCloud, DomainApp, DomainInternal, DomainUnknown}
	out := make([]DomainStat, 0, len(byDomain))
	for _, d := range order {
		a := byDomain[d]
		if a == nil {
			continue
		}
		rate, _ := repeatAndMTBF(a.members)
		best, bestN := DriverUnknown, 0
		for dr, n := range a.drivers {
			if n > bestN {
				best, bestN = dr, n
			}
		}
		out = append(out, DomainStat{
			Domain:        d,
			IncidentCount: len(a.members),
			MTTIp90ms:     statOf(a.tti).P90ms,
			RecoveryP90ms: statOf(a.rec).P90ms,
			RepeatRate:    rate,
			TopDelay:      best,
		})
	}
	return out
}
