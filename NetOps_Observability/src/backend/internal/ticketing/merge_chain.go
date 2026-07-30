package ticketing

// merge_chain.go — the canonical-id merge walk, the incident-policy input
// bounds, and the ticket status projection (extracted P2 RA.12 from main's
// ticketing HTTP surface). The walk decides WHAT CANONICAL ID GETS DISCLOSED
// to a caller, so its invariants (bounded, cycle-safe, never across the owning
// tenant boundary) are the security core; the ClickHouse read arrives as an
// injected hop reader.

import (
	"context"
	"strings"

	"netops/backend/internal/applog"
)

// ValidateIncidentPolicy bounds the operator-supplied policy (zero-trust input).
func ValidateIncidentPolicy(p IncidentPolicy) error {
	switch p.ExternalSystem {
	case "servicenow", "pagerduty", "slack", "jira":
	default:
		return errPolicy("external_system must be servicenow, pagerduty, slack, or jira")
	}
	if p.MinVerdict != "suspected" && p.MinVerdict != "confirmed" {
		return errPolicy("min_verdict must be suspected or confirmed")
	}
	if len(p.Name) > 160 {
		return errPolicy("name too long (max 160)")
	}
	if p.RequirePersistenceSeconds < 0 || p.RequirePersistenceSeconds > 86400 {
		return errPolicy("require_persistence_seconds out of range [0, 86400]")
	}
	if p.SuppressFlappingSeconds < 0 || p.SuppressFlappingSeconds > 86400 {
		return errPolicy("suppress_flapping_seconds out of range [0, 86400]")
	}
	if p.DefaultImpact < 0 || p.DefaultImpact > 4 || p.DefaultUrgency < 0 || p.DefaultUrgency > 4 {
		return errPolicy("default impact/urgency out of range [0, 4]")
	}
	for _, v := range []int{p.ImpactConfirmedCritical, p.UrgencyConfirmedCritical, p.ImpactConfirmed, p.UrgencyConfirmed} {
		if v < 0 || v > 4 {
			return errPolicy("priority mapping impact/urgency out of range [0, 4] (0 = automatic)")
		}
	}
	if len(p.AssignmentGroup) > 120 {
		return errPolicy("assignment_group too long (max 120)")
	}
	return nil
}

type policyErr string

func errPolicy(s string) error    { return policyErr(s) }
func (e policyErr) Error() string { return string(e) }

// StatusView projects a ticket link into the status surface the correlation
// detail + RCA Inspector render. No link → not_created (an honest empty state).
func StatusView(l Link, found bool) map[string]any {
	if !found {
		return map[string]any{"state": "not_created"}
	}
	// Links written before the InstanceURL fix stored the FULL incident URL
	// (…/nav_to.do?…) instead of the bare instance; strip the path so the
	// deep-link below isn't doubled (found live against a real PDI, 2026-07-10).
	base := l.InstanceURL
	if i := strings.Index(base, "/nav_to.do"); i >= 0 {
		base = base[:i]
	}
	out := map[string]any{
		"state":          orDefaultStr(l.Status, "pending"),
		"system":         l.ExternalSystem,
		"ticket_number":  l.TicketNumber,
		"sys_id":         l.SysID,
		"instance_url":   base,
		"last_verdict":   l.LastVerdict,
		"last_synced_at": l.LastSyncedAt,
	}
	if l.SysID != "" && base != "" && orDefaultStr(l.ExternalSystem, "servicenow") == "servicenow" {
		out["url"] = strings.TrimRight(base, "/") + "/nav_to.do?uri=incident.do?sys_id=" + l.SysID
	}
	return out
}

// MergeHop is one merge-chain row as read by the injected hop reader (raw
// values; the walk canonicalizes the tenant itself).
type MergeHop struct {
	Found      bool
	Tenant     string
	State      string
	MergedInto string
}

// ResolveMergeChain follows merged_into pointers from `first` to the terminal
// surviving correlation object. Bounded (≤ 5 hops) and cycle-safe; it never
// follows a pointer across the owning tenant boundary — a hop that resolves to
// a foreign-owned row stops the walk at the last same-owner id (the first
// pointer itself came from the caller-authorized row, so returning it
// discloses nothing new). Best-effort: an unreadable hop terminates the walk
// at the last known id rather than failing the caller's 409. Returns the most
// canonical id reached plus the number of hops it represents (1 = direct).
// validID gates the id shape; readHop is the caller's scoped projection read.
func ResolveMergeChain(ctx context.Context, owner, requested, first string,
	validID func(string) bool,
	readHop func(ctx context.Context, id string) (MergeHop, error)) (string, int) {
	const maxMergeDepth = 5
	// The requested id is seeded too: a cycle back to it (A→B→A) must stop the
	// walk rather than "canonicalize" to the very object the caller started from.
	seen := map[string]bool{requested: true, first: true}
	cur, depth := first, 1
	for depth < maxMergeDepth {
		if validID == nil || readHop == nil || !validID(cur) {
			return cur, depth
		}
		hop, err := readHop(ctx, cur)
		if err != nil {
			// The projection did not answer. The walk still stops at the last
			// known id (best-effort by design — the caller's 409 must not fail),
			// but "this id is terminal" and "we could not read the next hop" are
			// different facts, and the second is now visible (§10).
			applog.Warn("ticketing", "merge-chain hop unreadable — canonical id resolution stopped early",
				map[string]any{"correlation_id": cur, "tenant": owner, "merge_depth": depth, "err": err.Error()})
			return cur, depth
		}
		if !hop.Found {
			return cur, depth // answered: no such object → cur is the last known id
		}
		if CanonicalCorrTenant(hop.Tenant) != owner {
			// Merge pointer crossed a tenant boundary — an engine invariant
			// violation. Stop at the last same-owner id, never disclose further.
			applog.Warn("ticketing", "INVARIANT VIOLATION: merge chain crossed tenant boundary — walk stopped",
				map[string]any{"correlation_id": cur, "tenant": owner, "merge_depth": depth})
			return cur, depth
		}
		next := hop.MergedInto
		if hop.State != "merged" || next == "" {
			return cur, depth // terminal survivor
		}
		if seen[next] {
			applog.Warn("ticketing", "INVARIANT VIOLATION: merge chain cycle — walk stopped",
				map[string]any{"correlation_id": next, "tenant": owner, "merge_depth": depth})
			return cur, depth
		}
		seen[next] = true
		cur, depth = next, depth+1
	}
	return cur, depth
}
