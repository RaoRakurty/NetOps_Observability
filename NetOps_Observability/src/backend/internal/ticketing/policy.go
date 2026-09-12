// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

import (
	"fmt"
	"strings"
	"time"
)

// policy.go — the pure incident-policy decision: given the RCA facts,
// the deciding policy, and any existing ticket link, decide whether to OPEN a
// new external ticket and why. I/O-free and deterministic, so it is unit-tested
// against the guardrail matrix (decision #76: internal/debug, active-check-only
// low-authority, undetermined, flapping-cleared → never a customer ticket).
//
// This decides CREATE-worthiness only. Updating an already-open ticket on a
// verdict change is a separate path (the sync flow, P3) — an existing open link
// here short-circuits to "already open" so we never double-create.

var verdictRank = map[string]int{"undetermined": 0, "suspected": 1, "confirmed": 2}

// EvalDecision applies the policy. The Reason is operator-readable and is
// surfaced verbatim in the UI's blocked-reason text — no raw-alert language.
func EvalDecision(facts CorrFacts, policy IncidentPolicy, link *Link, now time.Time) Decision {
	hold := func(reason string) Decision { return Decision{Create: false, Reason: reason} }

	if !policy.Enabled {
		return hold("ticketing policy disabled")
	}

	// An object the engine could not ground has no defensible cause to ticket.
	if facts.Verdict == "" || facts.Verdict == "undetermined" {
		return hold("undetermined — no grounded cause yet")
	}

	// Internal/debug-only monitoring never opens a customer-facing ticket (#76).
	if facts.Internal && !policy.AllowInternalMonitoring {
		return hold("internal monitoring only — not customer-impacting")
	}

	// §11: a validation/lab/fault-injection scenario NEVER files production
	// tickets or pages unless the tenant explicitly opted in. This is the
	// backstop even when the scenario reaches a confirmed verdict.
	if facts.Validation && !policy.AllowValidationScenarios {
		return hold("validation scenario — production ticket side effects suppressed")
	}

	// Single low-authority active check is not corroborated evidence; ticketing
	// it would overclaim (the ≥2-independent-stream rule). Held unless allowed.
	if facts.LowAuthorityProbe && !policy.AllowProbeOnly {
		return hold("active-check-only (low authority) — awaiting independent corroboration")
	}
	if facts.ProbeOnly && !policy.AllowProbeOnly {
		return hold("single active-probe plane — awaiting independent corroboration")
	}

	// Nothing to scope a ticket to.
	if policy.RequireCustomerFacing && !facts.HasAffectedEntity {
		return hold("no meaningful affected entity to scope a ticket to")
	}

	// Verdict threshold.
	min := policy.MinVerdict
	if min == "" {
		min = "suspected"
	}
	if verdictRank[facts.Verdict] < verdictRank[min] {
		return hold(fmt.Sprintf("below policy threshold (verdict %q < required %q)", facts.Verdict, min))
	}

	// A suspected (not yet confirmed) verdict needs critical severity to ticket,
	// unless the policy relaxes it — keeps noise out while letting real outages
	// page before the independent confirmation lands.
	if facts.Verdict == "suspected" && policy.SuspectedRequiresCritical && facts.PeakSeverity != "crit" {
		return hold("suspected but severity below critical — held below threshold")
	}

	// Persistence gate (flap suppression on the way in).
	if policy.RequirePersistenceSeconds > 0 && facts.PersistenceSeconds() < policy.RequirePersistenceSeconds {
		return hold(fmt.Sprintf("not yet persistent (%ds < required %ds)",
			facts.PersistenceSeconds(), policy.RequirePersistenceSeconds))
	}

	// Dedupe / suppression against any existing link for this object+system.
	if link != nil {
		if link.Open() {
			ref := link.TicketNumber
			if ref == "" {
				ref = "pending"
			}
			return hold("ticket already open (" + ref + ")")
		}
		if link.Status == "resolved" && policy.SuppressFlappingSeconds > 0 && link.LastSyncedAt != nil &&
			now.Sub(*link.LastSyncedAt) < time.Duration(policy.SuppressFlappingSeconds)*time.Second {
			return hold("recently cleared — within flapping-suppression window")
		}
	}

	system := policy.ExternalSystem
	if system == "" {
		system = "servicenow"
	}
	verdict := facts.Verdict
	return Decision{
		Create: true,
		Reason: fmt.Sprintf("customer-facing %s fault — opening %s incident", verdict, strings.ToLower(system)),
	}
}
