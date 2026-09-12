// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloud

import (
	"sort"
	"strings"
	"time"
)

// Tag-key conventions (case-insensitive), in precedence order. Operators tag for
// cost/governance already, so these are the common keys we read.
var (
	// app_id / component are common in the wild (and are exactly what this lab's
	// own account uses) — omitting them made every tagged resource look untagged.
	// TODO(connectors): make this list operator-configurable per connector;
	// hardcoding key names guarantees we are wrong at the first customer.
	appTagKeys = []string{
		"app", "application", "app_id", "app-id", "appid",
		"app_name", "app-name", "service", "workload", "component",
		// AWS's own first-party application tag (Service Catalog AppRegistry).
		"awsapplication",
	}
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
	// No app tag — but a tag is not the ONLY way to attribute. The built-in
	// service mapping (service_infer.py) may have inferred a BusinessService from
	// the resource's RELATIONSHIPS (resource-group naming + subnet/hostname
	// structure) with no tag and no write access. That is a real, confidence-
	// tagged attribution (unlike a bare name copy) — honor it so the read-only,
	// untagged Azure fleet stops reading as "Untagged". strong/suspected count as
	// attributed (AppID set); weak carries the display hint only (AppID stays ""
	// so the coverage funnel does not over-claim on the weakest signal).
	if svc := strings.TrimSpace(r.InferredService); svc != "" {
		conf := confidenceFromInference(r.InferredServiceConfidence)
		if conf.rank() >= Suspected.rank() {
			r.AppName = svc
			r.AppID = appIDFromName(svc)
			r.Source = SrcInferredService
			r.Confidence = conf
			return
		}
		if conf == Weak {
			r.AppName = svc
			r.AppID = "" // display hint only — not counted as attributed
			r.Source = SrcInferredService
			r.Confidence = Weak
			return
		}
	}
	// No app tag. A resource's own NAME is not an application identity — copying
	// it and calling the result "strong resource-graph attribution" made the
	// coverage funnel report ~100% on an account with 0% real attribution, which
	// is precisely the lie the funnel exists to expose (audit 2026-07-13, P0-1).
	//
	// Real resource-graph attribution means STRUCTURE (ALB → target group →
	// instances; ASG → instances; ECS service → tasks) — a relationship, not a
	// string copy. Until that exists, a name-only guess is SUSPECTED at best, and
	// the resource stays in the unknown bucket so the operator is told to tag it.
	if r.ResourceName != "" {
		r.AppName = r.ResourceName
		r.AppID = "" // NOT an app identity — keeps it counted as unattributed
		r.Source = SrcSuspectedName
		r.Confidence = Suspected
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

// confidenceFromInference maps the poller's inference-confidence string to the
// Confidence ladder. Unknown/empty/"none" → Unknown (no attribution). Inference
// NEVER reaches Confirmed — a tag is the only confirmed source.
func confidenceFromInference(s string) Confidence {
	switch Confidence(strings.ToLower(strings.TrimSpace(s))) {
	case Strong:
		return Strong
	case Suspected:
		return Suspected
	case Weak:
		return Weak
	default:
		return Unknown
	}
}

func attributionReason(r CloudResource) string {
	switch r.Source {
	case SrcCloudTag:
		return "cloud tag → app=" + r.AppName
	case SrcCloudGraph:
		return "cloud resource-graph name → " + r.AppName + " (" + r.ResourceType + ")"
	case SrcInferredService:
		basis := r.InferredServiceBasis
		if basis == "" {
			basis = "resource relationships"
		}
		return "inferred service → " + r.AppName + " (" + string(r.Confidence) + "; " + basis + ")"
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

// AppIDFromName is the exported slug normalizer, so callers outside the package
// (e.g. the manual-override overlay) derive an app id the same way attribution does.
func AppIDFromName(name string) string { return appIDFromName(name) }

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
