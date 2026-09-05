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
}

// NewGate compiles the closed table from a catalog. It is built once and never
// mutated, so it is safe to share across goroutines.
func NewGate(c *Catalog) *Gate {
	g := &Gate{byDialect: map[string][][]string{}}
	if c == nil {
		return g
	}
	for _, d := range c.planOrder {
		p := c.plans[d]
		seen := map[string]bool{}
		for _, b := range p.Bindings {
			key := strings.Join(b.tokens, " ")
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			g.byDialect[d] = append(g.byDialect[d], append([]string(nil), b.tokens...))
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
	return g.AllowsDialect(dialect, command)
}

// AllowsDialect is Allows for a dialect slug the caller already resolved.
func (g *Gate) AllowsDialect(dialect, command string) bool {
	cmd := strings.Fields(command)
	if len(cmd) == 0 {
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

var _ protocoldiag.CommandGate = (*Gate)(nil)
