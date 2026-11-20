// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisaction

// policy.go — gate 2, ELIGIBILITY: the policy decision for one proposed write.
//
// The vocabulary is the plan's four decisions (Part 1 §40). The table, in
// order — the first row that matches decides:
//
//	kind not in the closed vocabulary            → DENY
//	console kill switch IRIS_AI_ACTIONS off
//	  (or the AI add-on / investigations off)    → DENY
//	workspace toggle off                         → DENY
//	kind not on the workspace's allowlist        → DENY   (default allowlist: EMPTY)
//	workspace set to dry runs only               → DRY_RUN_ONLY
//	otherwise                                    → REQUIRE_APPROVAL
//
// ALLOW — "run without a person" — is part of the vocabulary and is NEVER
// returned for a write: no input to Evaluate yields it (pinned by a test). It
// is named so a read tier or a future reviewed consumer can be expressed in
// the same terms, not so a write can skip gate 3.

// Decision is a policy outcome.
type Decision string

const (
	Allow           Decision = "allow"
	Deny            Decision = "deny"
	RequireApproval Decision = "require_approval"
	DryRunOnly      Decision = "dry_run_only"
)

// Decisions lists the vocabulary (the migration's CHECK names exactly these).
var Decisions = []Decision{Allow, Deny, RequireApproval, DryRunOnly}

// Settings is one workspace's own action settings. The zero value is the
// default posture: off, nothing allowed.
type Settings struct {
	Enabled    bool   `json:"enabled"`
	Kinds      []Kind `json:"kinds"`
	DryRunOnly bool   `json:"dry_run_only"`
}

// Allows reports whether k is on the workspace's allowlist.
func (s Settings) Allows(k Kind) bool {
	for _, x := range s.Kinds {
		if x == k {
			return true
		}
	}
	return false
}

// Normalized keeps known kinds only, deduplicated, in vocabulary order.
func (s Settings) Normalized() Settings {
	out := Settings{Enabled: s.Enabled, DryRunOnly: s.DryRunOnly, Kinds: []Kind{}}
	for _, k := range Kinds {
		if s.Allows(k) {
			out.Kinds = append(out.Kinds, k)
		}
	}
	return out
}

// Env is everything the policy reads for one caller: the platform half
// (Platform: the kill switch, the AI add-on and investigations all on;
// PlatformReason says which is off) and the workspace's own settings.
type Env struct {
	Platform       bool
	PlatformReason string
	Settings       Settings
}

// Evaluate decides one kind under one environment. The reason is operator
// words, shown when an action is not proposed or not executed.
func Evaluate(k Kind, env Env) (Decision, string) {
	switch {
	case !ValidKind(k):
		return Deny, "that is not an action Iris can propose"
	case !env.Platform:
		r := env.PlatformReason
		if r == "" {
			r = "Iris actions are turned off on this installation (Features page: Iris actions)"
		}
		return Deny, r
	case !env.Settings.Enabled:
		return Deny, "this workspace has not turned Iris actions on (Administration → Iris → Investigations)"
	case !env.Settings.Allows(k):
		return Deny, "this workspace has not allowed this kind of action (Administration → Iris → Investigations)"
	case env.Settings.DryRunOnly:
		return DryRunOnly, "this workspace allows dry runs only: Iris shows what it would send and sends nothing"
	}
	return RequireApproval, "someone other than the person Iris answered must approve it"
}
