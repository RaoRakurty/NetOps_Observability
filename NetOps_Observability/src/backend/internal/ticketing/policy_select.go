package ticketing

// policy_select.go — the single policy-selection brain (P2 RA.5): the sweeper,
// the manual path and the simulator all resolve a tenant's governing incident
// policy through here — never a "first row wins".

import (
	"context"
	"strings"
	"time"

	"netops/backend/internal/applog"
)

// TicketSystems are the destinations the RCA policy engine can drive. Each
// system resolves its OWN governing policy (the one-enabled invariant is per
// (tenant, external_system)); ServiceNow keeps its default-on MVP fallback,
// every other system is strictly opt-in (no policy → no delivery).
var TicketSystems = []string{"servicenow", "pagerduty", "slack", "jira"}

// PolicyResolution is ResolvePolicyState's outcome: the governing policy plus
// HOW it came to govern, so callers (simulator, observability) can tell an
// active configured policy from a fallback, an opt-out, or a held conflict.
type PolicyResolution struct {
	Policy IncidentPolicy
	State  string // PolicyStateDefault | PolicyStateActive | PolicyStateOptedOut | PolicyStateHeld
}

const (
	PolicyStateDefault  = "default"   // tenant has no policy; safe MVP default governs
	PolicyStateActive   = "active"    // exactly one enabled configured policy governs
	PolicyStateOptedOut = "opted_out" // policies exist but all are disabled — tenant opted out
	PolicyStateHeld     = "held"      // invariant violated (multiple enabled) — ticketing held
)

// ResolvePolicyState returns the incident policy that governs a tenant for one
// destination system: a configured enabled policy wins; an explicitly
// configured (but disabled) policy is honored so a tenant can opt OUT; only a
// tenant with NO policy at all falls back to the default-on MVP policy
// (ServiceNow only — every other system is opt-in). onMultiEnabled (nil-safe)
// is bumped when the one-enabled invariant is found violated.
func ResolvePolicyState(ctx context.Context, store Store, tenant, system string, onMultiEnabled func()) PolicyResolution {
	system = orDefaultStr(system, "servicenow")
	all, err := store.ListPolicies(ctx, tenant, false)
	var policies []IncidentPolicy
	for _, p := range all {
		if orDefaultStr(p.ExternalSystem, "servicenow") == system {
			policies = append(policies, p)
		}
	}
	if err != nil || len(policies) == 0 {
		if system == "servicenow" {
			// ServiceNow keeps the historical default-on MVP policy.
			return PolicyResolution{Policy: DefaultIncidentPolicy(tenant), State: PolicyStateDefault}
		}
		// Paging (and any future system) is OPT-IN: no policy, no delivery.
		off := DefaultIncidentPolicy(tenant)
		off.Enabled = false
		off.ExternalSystem = system
		off.Name = "no " + system + " policy (opt-in)"
		return PolicyResolution{Policy: off, State: PolicyStateOptedOut}
	}
	var enabled []IncidentPolicy
	for _, p := range policies {
		if p.Enabled {
			enabled = append(enabled, p)
		}
	}
	switch len(enabled) {
	case 1:
		return PolicyResolution{Policy: enabled[0], State: PolicyStateActive}
	case 0:
		// Explicitly configured but all disabled = the tenant opted OUT.
		return PolicyResolution{Policy: policies[0], State: PolicyStateOptedOut}
	}
	// >1 enabled should be impossible (partial unique index + write-path 409) —
	// if legacy data or drift ever violates it, FAIL CLOSED: hold all ticketing
	// for the tenant and say so loudly, never silently pick a winner by row
	// order (live incident 2026-07-10: a shadowed permissive policy flooded a
	// real PDI at ~7 tickets/min while a confirmed-only policy appeared active).
	ids := make([]string, len(enabled))
	for i, p := range enabled {
		ids[i] = p.ID
	}
	applog.Warn("ticketing", "INVARIANT VIOLATION: multiple enabled incident policies — ticketing held (fail closed)",
		map[string]any{"tenant": tenant, "policy_ids": strings.Join(ids, ","), "system": orDefaultStr(enabled[0].ExternalSystem, "servicenow")})
	if onMultiEnabled != nil {
		onMultiEnabled()
	}
	held := DefaultIncidentPolicy(tenant)
	held.Enabled = false
	held.Name = "HELD: conflicting enabled policies"
	return PolicyResolution{Policy: held, State: PolicyStateHeld}
}

// CanonicalCorrTenant maps a correlation object's stored tenant to the
// canonical app tenant key used by the ticketing stores. The correlation
// engine writes "" for platform/global-owned (untagged) telemetry, but the
// platform admin manages that tenant's incident policy + connection under the
// canonical global id ("global" — pinned in lock-step with the entrypoint's
// TenantGlobal). Collapse ""→global here so policy resolution, the ticket
// link, and the outbox all key the SAME tenant the operator configured. A
// real (non-global) tenant id passes through unchanged (lowercased/trimmed —
// the app layer is already case-insensitive on tenant keys), so isolation is
// intact: it never collapses two distinct real tenant ids.
func CanonicalCorrTenant(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" {
		return "global"
	}
	return t
}

// SweepAction is the pure outcome of evaluating one object: enqueue nothing, a
// create, or an update — with the assembled payload for the latter two. A
// SuppressionReason means the consistency gate HELD an action the policy would
// otherwise have emitted; the caller must surface it (log), never drop it.
type SweepAction struct {
	Kind              string // "" | "create" | "update"
	Payload           Payload
	SuppressionReason string // non-empty = consistency gate held the action
}

// DecideSweepAction is the I/O-free decision for one already-loaded object. A
// create when the incident policy opens a ticket; otherwise an update when an
// already-open ticket's RCA state moved on (payload hash changed) so an
// unchanged state is a no-op. Deterministic. The payload is assembled lazily
// through build (the caller closes over its view/baseURL), so the decision
// itself never sees the entrypoint's RCA view types.
//
// Consistency gate (audit D11 at the emitter boundary): an action the policy
// approves is still HELD when the object's facts carry a P1 contradiction
// (facts.ConsistencyIssues) — contradictory state never reaches an external
// system. The hold carries its reason; validation-scenario suppression (§11,
// the rca-canary contract) already happened inside EvalDecision and is
// unaffected: a canary never gets this far.
func DecideSweepAction(facts CorrFacts, policy IncidentPolicy, link *Link, now time.Time, build func() Payload) SweepAction {
	held := func() SweepAction {
		return SweepAction{SuppressionReason: "consistency gate (P1): " + strings.Join(facts.ConsistencyIssues, "; ")}
	}
	if dec := EvalDecision(facts, policy, link, now); dec.Create {
		if len(facts.ConsistencyIssues) > 0 {
			return held()
		}
		return SweepAction{Kind: "create", Payload: build()}
	}
	if link != nil && link.Open() {
		p := build()
		if PayloadHash(p) != link.LastPayloadHash {
			if len(facts.ConsistencyIssues) > 0 {
				return held()
			}
			return SweepAction{Kind: "update", Payload: p}
		}
	}
	return SweepAction{}
}
