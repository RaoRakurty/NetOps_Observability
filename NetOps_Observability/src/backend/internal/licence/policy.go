// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package licence

import "netops/backend/internal/entitlement"

// policy.go — the ISSUANCE policy: what a licence gets when the issuer does not
// say otherwise.
//
// It lives here, not in cmd/correlix-licence, because CLAUDE.md §2 puts no
// business logic in an entrypoint — and because the numbers must be readable by
// a test and by the docs generator, not only by whoever runs the CLI.
//
// The distinction that matters most in this file: these are ISSUER defaults,
// not FORMAT defaults. `correlix-licence sign` applies them and writes an
// explicit number into the signed document. Nothing on the reading side ever
// substitutes a default for a missing `grace_days` — a file that carries zero
// means zero, for ever, whatever policy is current. That is what keeps a signed
// licence a complete statement of its own terms, and it is why a policy change
// can never silently extend or shorten a licence somebody is already holding.
//
// Owner decision, 2026-09-05 (docs/design/TIERING_PLAN_2026-09-03.md §9, rows
// "Paid expiry / grace (adopted)" and "Trials").

const (
	// PaidGraceDays is the administrative grace a paid licence is issued with:
	// 30 days after expiry during which nothing changes for the customer.
	//
	// It is an ADMINISTRATIVE window, not a commercial one — long enough for a
	// renewal PO to clear a finance department, which is the actual failure
	// mode a grace period exists for.
	PaidGraceDays = 30
	// TrialGraceDays is the grace an evaluation licence is issued with. Shorter
	// than a paid one on purpose: there is no PO to wait for, and a trial that
	// quietly ran a further month would not be a 30-day trial.
	TrialGraceDays = 7
	// TrialDays is an evaluation licence's length: 30 days from issue, no card,
	// offline after issuance.
	TrialDays = 30
)

// GraceDaysUnset is the sentinel a caller passes for "the issuer said nothing".
// It is -1 rather than 0 because 0 is a legitimate, meaningful choice — a
// licence with no grace at all — and the two must stay distinguishable.
const GraceDaysUnset = -1

// DefaultGraceDays is the grace period a licence is ISSUED with.
//
//	explicit >= 0  → exactly that, including 0. The issuer's word always wins.
//	trial          → TrialGraceDays (7).
//	team/enterprise → PaidGraceDays (30).
//	community      → 0. A free licence has nothing to lapse from; a grace
//	                 period on it would describe a transition that cannot happen.
func DefaultGraceDays(tier entitlement.Tier, trial bool, explicit int) int {
	if explicit >= 0 {
		return explicit
	}
	if trial {
		return TrialGraceDays
	}
	if tier == entitlement.TierCommunity {
		return 0
	}
	return PaidGraceDays
}
