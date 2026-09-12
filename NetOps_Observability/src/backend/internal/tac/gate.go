// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// gate.go — the CLOSED COMMAND TABLE for TAC plans: the second of the three
// safety guards.
//
// The loader proved every authored command is a read-only show. This proves, at
// the moment a command is about to go on a wire, that the string in hand is a
// RENDERING OF AN AUTHORED TEMPLATE FOR THIS DEVICE'S DIALECT and nothing else.
// The two are different questions and both are load-bearing: `show running-config
// | include password` is a perfectly read-only command that is not in any plan,
// and a runner that accepted it would have widened this feature from "reviewed
// per-vendor plans" into "arbitrary device reads".
//
// The matcher works on TOKENS, not on the rendered string, because rendering
// collapses whitespace and an empty placeholder vanishes entirely. Each template
// token is matched against the command's tokens with a placeholder consuming
// zero or one argument token ({vrf-scope}: zero, one, or the two-token
// `vrf X` / `instance X` qualifier). It backtracks, so an argument that happens
// to look like the next literal cannot desynchronise the match.
//
// It is the same design as internal/protocoldiag/commandtable.go, and it is a
// SEPARATE table on purpose: merging the two would let a diagnostics call reach
// a TAC command and the reverse, and the whole value of a closed table is that
// it is exactly as wide as the feature it serves.

import (
	"strings"

	"netops/backend/internal/protocoldiag"
)

// Gate is the catalog's closed table, keyed on the device's resolved dialect.
// It implements protocoldiag.CommandGate, so the TAC collector reuses that
// package's whole policy layer (read-only shape, one in flight per device,
// bounded time and output) over THIS table.
type Gate struct {
	byDialect map[string][][]string
	// exemptByDialect is the SUBSET of byDialect whose bindings carry a CITED
	// `read_only_exception`, or are documented session-scoped setters (and their
	// teardowns). It answers protocoldiag.ReadOnlyExemptGate.
	//
	// It is a second table rather than a flag on the first because the question
	// is different: byDialect answers "could an authored plan have produced
	// this?", this one answers "is this one of the few commands whose READ
	// spelling the grammar cannot recognise?". A command must be in BOTH to skip
	// the grammar, and the output-only policy is applied to it either way.
	exemptByDialect map[string][][]string
	// policy is the owner's OUTPUT-ONLY command policy, re-applied here. It is a
	// SEPARATE authority from the table: the table says "an authored plan could
	// have produced this", the policy says "Correlix does not do this at all".
	// Keeping both is what makes the rule structural — a hand-edited plan file
	// widens the table, and the policy still refuses the command.
	policy *Policy
	// reviews is the CLOSED TABLE OF THE MOMENT (templates.go): the exact
	// command strings a human approved and the server re-validated, for one
	// device, for the length of one collection. It is consulted AFTER the
	// authored table and never before the policy, so a reviewed line still
	// cannot be a config/restart/daemon command or an unbounded probe. It is nil
	// on a build with no review registry wired, and a nil registry allows
	// nothing — the authored table alone then stands, which is the pre-review
	// behaviour exactly.
	reviews *ReviewRegistry
}

// GateOption configures a Gate.
type GateOption func(*Gate)

// WithReviewRegistry attaches the per-collection allow set. Without it the gate
// is the authored table alone; with it, a command a NAMED HUMAN approved and the
// server re-validated is admitted for that device while its collection runs.
func WithReviewRegistry(r *ReviewRegistry) GateOption {
	return func(g *Gate) { g.reviews = r }
}

// NewGate compiles the closed table from a catalog. It is built once and never
// mutated (the review registry it may hold has its own lock), so it is safe to
// share across goroutines.
func NewGate(c *Catalog, opts ...GateOption) *Gate {
	g := &Gate{byDialect: map[string][][]string{}, exemptByDialect: map[string][][]string{}}
	for _, o := range opts {
		o(g)
	}
	if c == nil {
		return g
	}
	g.policy = c.policy
	for _, d := range c.planOrder {
		p := c.plans[d]
		seen := map[string]bool{}
		add := func(toks []string) {
			key := strings.Join(toks, " ")
			if key == "" || seen[key] {
				return
			}
			seen[key] = true
			g.byDialect[d] = append(g.byDialect[d], append([]string(nil), toks...))
		}
		exemptSeen := map[string]bool{}
		addExempt := func(toks []string) {
			key := strings.Join(toks, " ")
			if key == "" || exemptSeen[key] {
				return
			}
			exemptSeen[key] = true
			g.exemptByDialect[d] = append(g.exemptByDialect[d], append([]string(nil), toks...))
		}
		for _, b := range p.Bindings {
			add(b.tokens)
			// A session-scoped setter's teardown is run by the collector, so it
			// must be in the table too — the runner gates every string it puts
			// on a wire, and an ungated teardown would simply never run.
			add(b.teardownTokens)
			// The exemption table. The loader has ALREADY proved each of these:
			// a `read_only_exception` without a citation is a load error
			// (load.go), and a teardown that is not the policy's documented one
			// for that setter is a load error too. So this is a projection of
			// data that was validated, never a new decision.
			if b.ReadOnlyException != "" {
				addExempt(b.tokens)
			}
			if b.Teardown != "" {
				addExempt(b.tokens)
				addExempt(b.teardownTokens)
			}
		}
	}
	return g
}

// Allows implements protocoldiag.CommandGate. A device whose platform resolves
// to NO dialect is refused: there is no fallback dialect here, so there is no
// command to allow, and borrowing another vendor's table is precisely the
// mistake this feature refuses to make.
func (g *Gate) Allows(dev protocoldiag.Device, command string) bool {
	dialect, _, ok := DialectForPlatform(dev.Platform)
	if !ok {
		return false
	}
	if g.AllowsDialect(dialect, command) {
		return true
	}
	// The reviewed allow set is per DEVICE, so it can only be consulted here —
	// AllowsDialect has no device to key on, and that is deliberate: a dialect
	// is not an authorisation subject. The policy and probe bounds have already
	// been applied by AllowsDialect and are re-applied below, so a reviewed line
	// is admitted only if it is still an output command at this instant.
	if g.reviews == nil || !g.reviews.allows(reviewKey(dev), command) {
		return false
	}
	if _, forbidden := g.policy.Match(dialect, command); forbidden {
		return false
	}
	if protocoldiag.IsProbeCommand(command) {
		return protocoldiag.ValidateBoundedProbe(command) == nil
	}
	return protocoldiag.ValidateReadOnly(command) == nil
}

// reviewKey is the registry key for one device: its id, or its hostname when the
// inventory row carries no id. It mirrors the collector's own busy key, so the
// allow set and the one-collection-per-device claim name the same device.
func reviewKey(dev protocoldiag.Device) string {
	if dev.ID != "" {
		return dev.ID
	}
	return dev.Hostname
}

// AllowsDialect is Allows for a dialect slug the caller already resolved.
//
// THE POLICY IS APPLIED FIRST, and it is applied to the RENDERED string. A
// command in the config / restart / daemon families is refused here even if the
// plan data somehow carried it, and a probe is refused unless every one of its
// parameters is inside the bounded-probe grammar — a `count 5` template that
// rendered as `count 5000` never reaches a device.
func (g *Gate) AllowsDialect(dialect, command string) bool {
	cmd := strings.Fields(command)
	if len(cmd) == 0 {
		return false
	}
	if _, forbidden := g.policy.Match(dialect, command); forbidden {
		return false
	}
	if protocoldiag.IsProbeCommand(command) && protocoldiag.ValidateBoundedProbe(command) != nil {
		return false
	}
	for _, tmpl := range g.byDialect[dialect] {
		if matchTemplate(tmpl, cmd) {
			return true
		}
	}
	return false
}

// Name implements protocoldiag.CommandGate.
func (g *Gate) Name() string { return "TAC escalation command plan" }

// ReadOnlyExempt implements protocoldiag.ReadOnlyExemptGate.
//
// It answers true ONLY for a rendering of an authored binding that carries a
// CITED `read_only_exception` (FortiOS spells several pure status prints
// `diagnose debug …`; Junos spells its documented support collection `request
// support information`; FortiOS spells its own `execute tac report`), or for a
// documented session-scoped setter and its teardown.
//
// It is not a way around anything. The output-only policy is applied HERE, to
// the rendered string, before the table is consulted at all — so a config,
// restart or daemon command can never be exempted — and the caller still has to
// pass the closed-table check separately. A reviewed CUSTOM command is
// deliberately NOT exempt: a line a customer typed has no citation behind it, so
// it must be a read the grammar itself recognises.
func (g *Gate) ReadOnlyExempt(dev protocoldiag.Device, command string) bool {
	dialect, _, ok := DialectForPlatform(dev.Platform)
	if !ok {
		return false
	}
	if _, forbidden := g.policy.Match(dialect, command); forbidden {
		return false
	}
	cmd := strings.Fields(command)
	if len(cmd) == 0 {
		return false
	}
	for _, tmpl := range g.exemptByDialect[dialect] {
		if matchTemplate(tmpl, cmd) {
			return true
		}
	}
	return false
}

// matchTemplate reports whether the command token list cmd is a rendering of the
// template token list tmpl. Literals must match exactly; a placeholder consumes
// zero or one argument token; {vrf-scope} may additionally consume the two-token
// dialect qualifier. Backtracking is bounded by the template length (never more
// than a dozen tokens), so recursion is cheap and terminates.
func matchTemplate(tmpl, cmd []string) bool {
	if len(tmpl) == 0 {
		return len(cmd) == 0
	}
	head := tmpl[0]
	if _, isPlaceholder := placeholders[head]; !isPlaceholder {
		if len(cmd) == 0 || cmd[0] != head {
			return false
		}
		return matchTemplate(tmpl[1:], cmd[1:])
	}
	// Empty argument: the placeholder collapsed to nothing.
	if matchTemplate(tmpl[1:], cmd) {
		return true
	}
	// One argument token.
	if len(cmd) >= 1 && argTokenRE.MatchString(cmd[0]) && matchTemplate(tmpl[1:], cmd[1:]) {
		return true
	}
	// {vrf-scope} only: the dialect qualifier plus the instance name.
	if head == "{vrf-scope}" && len(cmd) >= 2 {
		if _, ok := vrfQualifiers[strings.ToLower(cmd[0])]; ok && argTokenRE.MatchString(cmd[1]) {
			return matchTemplate(tmpl[1:], cmd[2:])
		}
	}
	return false
}

var (
	_ protocoldiag.CommandGate        = (*Gate)(nil)
	_ protocoldiag.ReadOnlyExemptGate = (*Gate)(nil)
)
