package cloud

import (
	"sort"
	"strings"
	"time"
)

// Tag-key conventions (case-insensitive), in precedence order. Operators tag for
// cost/governance already, so these are the common keys we read.
var (
	appTagKeys   = []string{"app", "application", "app_name", "app-name", "service", "workload"}
	ownerTagKeys = []string{"owner", "team", "owner_team", "managed_by"}
	envTagKeys   = []string{"env", "environment", "stage", "tier"}
)

// lookupTag does a case-insensitive lookup over the candidate keys.
func lookupTag(tags map[string]string, keys []string) string {
	if tags == nil {
		return ""
	}
	lower := make(map[string]string, len(tags))
	for k, v := range tags {
		lower[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	for _, k := range keys {
		if v := lower[k]; v != "" {
			return v
		}
	}
	return ""
}

// AttributeResource sets r.AppID/AppName/Owner/Env/Source/Confidence from the
// resource's tags (authoritative) or, failing that, its resource-graph name
// (strong). No attribution → Confidence=Unknown, AppID="" (first-class unknown).
// Pure; operates on the resource in place.
func AttributeResource(r *CloudResource) {
	r.Owner = firstNonEmpty(r.Owner, lookupTag(r.Tags, ownerTagKeys))
	r.Env = firstNonEmpty(r.Env, lookupTag(r.Tags, envTagKeys))

	if app := lookupTag(r.Tags, appTagKeys); app != "" {
		r.AppName = app
		r.AppID = appIDFromName(app)
		r.Source = SrcCloudTag
		r.Confidence = Confirmed
		return
	}
	// No app tag — fall back to the resource-graph name (ASG/ECS service/Lambda/etc).
	if r.ResourceName != "" {
		r.AppName = r.ResourceName
		r.AppID = appIDFromName(r.ResourceName)
		r.Source = SrcCloudGraph
		r.Confidence = Strong
		return
	}
	r.AppID = ""
	r.AppName = ""
	r.Source = SrcUnknown
	r.Confidence = Unknown
}

// IdentityMappings expands an (already-attributed) resource into the (match_key →
// app) rows that flow/log enrichment joins on — one per private IP, ENI/NIC,
// resource id, and ARN. Unknown resources still emit mappings (app=""), so flow
// enrichment can say "this IP is resource R, app unknown" and coverage can see it.
func IdentityMappings(r CloudResource) []CloudIdentityMapping {
	reason := attributionReason(r)
	now := r.LastSeenAt
	if now.IsZero() {
		now = r.DiscoveredAt
	}
	mk := func(t MatchKeyType, key string) CloudIdentityMapping {
		return CloudIdentityMapping{
			TenantID: r.TenantID, MatchKeyType: t, MatchKey: key,
			AppID: r.AppID, AppName: r.AppName, Owner: r.Owner, Env: r.Env,
			ResourceID: r.ResourceID, Source: r.Source, Confidence: r.Confidence,
			AttributionReason: reason, UpdatedAt: now,
		}
	}
	var out []CloudIdentityMapping
	for _, ip := range r.PrivateIPs {
		if ip != "" {
			out = append(out, mk(MatchPrivateIP, ip))
		}
	}
	for _, eni := range r.NetworkInterfaceIDs {
		if eni != "" {
			out = append(out, mk(matchKeyForNIC(r.Provider), eni))
		}
	}
	if r.ResourceID != "" {
		out = append(out, mk(MatchResourceID, r.ResourceID))
	}
	if r.ResourceURI != "" {
		out = append(out, mk(MatchARN, r.ResourceURI))
	}
	return out
}

// Resolve picks the single best attribution among candidate mappings for one key:
// highest confidence wins, ties broken by source trust then by being non-empty.
// This is the precedence guarantee — tag > graph/firewall > domain > ip_catalog >
// unknown — so an IP-catalog guess can NEVER override a cloud tag.
func Resolve(candidates []CloudIdentityMapping) (CloudIdentityMapping, bool) {
	if len(candidates) == 0 {
		return CloudIdentityMapping{}, false
	}
	sorted := append([]CloudIdentityMapping(nil), candidates...)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := sorted[i].Confidence.rank(), sorted[j].Confidence.rank()
		if ri != rj {
			return ri > rj
		}
		si, sj := sourceTrust(sorted[i].Source), sourceTrust(sorted[j].Source)
		if si != sj {
			return si > sj
		}
		return sorted[i].AppID != "" && sorted[j].AppID == ""
	})
	return sorted[0], true
}

func attributionReason(r CloudResource) string {
	switch r.Source {
	case SrcCloudTag:
		return "cloud tag → app=" + r.AppName
	case SrcCloudGraph:
		return "cloud resource-graph name → " + r.AppName + " (" + r.ResourceType + ")"
	default:
		return "no tag or resource-graph name — unattributed"
	}
}

func matchKeyForNIC(p Provider) MatchKeyType {
	if p == Azure {
		return MatchNIC
	}
	return MatchENI
}

// sourceTrust orders sources for tie-breaking within the same confidence band.
func sourceTrust(s Source) int {
	switch s {
	case SrcCloudTag, SrcOperatorCatalog:
		return 5
	case SrcCloudGraph:
		return 4
	case SrcFirewallAppID:
		return 3
	case SrcDomain:
		return 2
	case SrcIPCatalog:
		return 1
	default:
		return 0
	}
}

func appIDFromName(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r == ' ', r == '_', r == '-', r == '.', r == '/':
			return '-'
		default:
			return -1
		}
	}, s)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Trim(s, "-")
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// nowFallback keeps timestamps sane in fixtures that omit them.
func nowFallback(t time.Time, fallback time.Time) time.Time {
	if t.IsZero() {
		return fallback
	}
	return t
}
