package processors

// generate.go — the pure processor-chain → Vector-config compiler. Emits the
// router's processors.yaml: per lane, an ORDERED remap chain plus a drop filter
// and a per-processor match counter.
//
// Ordering (spec principle 1 + 4): processors run by (Order asc, CreatedAt,
// ID) — a total order, so the same rule set always compiles to the same
// program, byte for byte. The writer content-compares before writing so
// --watch-config never sees a phantom change.
//
// Injection posture: user input reaches the output ONLY through vrlString()
// (escaped string literal) or a validated RE2 pattern — never as syntax.
//
// Observability (spec: execution metrics): every processor that fires appends
// its id to `.cx_applied`, and a log_to_metric transform turns that into a
// per-processor counter on the router's existing Prometheus exporter. That
// gives per-processor match rates without writing an execution-log row per
// event (which at ingest volume would cost more than the processing itself).

import (
	"fmt"
	"sort"
	"strings"
)

// laneInputs maps a lane to the router transform its chain consumes.
var laneInputs = map[string]string{
	"applogs":   "applogs_tagged",
	"syslog":    "syslog_tagged",
	"snmptrap":  "snmptrap_tagged",
	"cloudlogs": "cloudlogs_tagged",
	"flows":     "flows_decoded",
}

// laneOrder is LaneOrder (rule.go) — the single lane source (review B3).
var laneOrder = LaneOrder

// HookName is the transform the lane's storage sinks read (post-filter).
func HookName(lane string) string { return lane + "_rules" }

// applyName is the remap that runs the ordered processor chain.
func applyName(lane string) string { return lane + "_rules_apply" }

// DropField is the marker a drop_event processor sets; the lane's filter drops
// the event on it. A filter (not `abort`) keeps intentional drops out of the
// dead-letter lane, which is reserved for MALFORMED records — an operator's
// deliberate drop is not a pipeline failure.
const DropField = "cx_drop"

// AppliedField collects the ids of processors that fired (execution metrics).
const AppliedField = "cx_applied"

// escapeEnv protects a generated literal from Vector's CONFIG-FILE environment
// interpolation, which runs before VRL ever sees the text: an unescaped `$`
// makes Vector look for a variable and refuse to start
// ("Missing environment variable in config. name = 1"). That means a regex
// end-anchor (`^auth$`) or a capture reference (`$1`) in a REPLACEMENT would
// take the whole processors config down — every tenant's processors with it.
// `$$` is Vector's escape for a literal `$`. Found by boot-validating the
// generated config against the real binary.
func escapeEnv(s string) string { return strings.ReplaceAll(s, "$", "$$") }

// vrlString renders s as a double-quoted VRL string literal.
func vrlString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + escapeEnv(s) + `"`
}

// vrlPath renders a validated dot-path as a VRL field accessor.
func vrlPath(field string) string { return "." + field }

// regexEscape escapes a literal for embedding inside a regex.
func regexEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// vrlRegex renders a pattern as a VRL raw-regex literal. Patterns containing a
// single quote are rejected at validation (validateRegex) precisely so this
// function has no unsafe fallback: a quoted-string fallback either failed to
// compile (matchers) or silently degraded to literal matching (replace).
// Literal patterns are regex-escaped before they reach here, and the escaper
// does not introduce quotes, so the guard is a belt-and-braces no-op.
func vrlRegex(pattern string) (expr string, raw bool) {
	if strings.ContainsRune(pattern, '\'') {
		// Unreachable via the API; compile to nothing rather than emit VRL that
		// would take the whole lane's config down.
		return "", false
	}
	return "r'" + escapeEnv(pattern) + "'", true
}

// resolvePattern returns the RE2 source for a processor's pattern field.
func resolvePattern(r Rule) string {
	switch r.PatternKind {
	case PatternBuiltin:
		if mr, ok := ManagedRuleByID(r.Pattern); ok {
			return mr.Pattern
		}
		return ""
	case PatternLiteral:
		return regexEscape(r.Pattern)
	default: // PatternRegex
		return r.Pattern
	}
}

// ruleVRL renders one processor: tenant guard + optional match guard + action,
// plus the execution-metrics stamp. Action and matcher compilation come from
// the REGISTRIES (registry.go) — the same definitions the simulator evaluates,
// so preview and pipeline cannot diverge. The rule must be validated.
func ruleVRL(r Rule) string {
	spec, ok := lookupAction(r.Type)
	if !ok {
		return ""
	}
	action := spec.CompileVRL(r)
	if action == "" {
		// "" = not expressible at the edge (unknown managed rule today; a
		// service-side detector tomorrow). Compile to nothing rather than
		// emitting broken VRL that would fail the whole lane's config load.
		return ""
	}
	guards := []string{tenantGuardVRL(r.TenantID)}
	if r.Match != nil {
		m, ok := lookupMatcher(r.Match.Op)
		if !ok {
			return ""
		}
		g := m.CompileVRL(*r.Match)
		if g == "" {
			return "" // matcher runs service-side only
		}
		guards = append(guards, g)
	}
	// The stamp is what the counter transform reads: one entry per processor
	// that actually fired on this event.
	stamp := fmt.Sprintf(".%s = push(array(.%s) ?? [], %s)", AppliedField, AppliedField, vrlString(r.ID))
	// Single-line actions join with "; " as they always have. A MULTI-LINE
	// action (seal) must join on a newline instead: its trailing newline would
	// otherwise leave the separator at line start, and a leading ";" is a VRL
	// syntax error (F-6 follow-up, proven against the live router 2026-08-09).
	sep := "; "
	if strings.Contains(action, "\n") {
		action = strings.TrimRight(action, " \n")
		sep = "\n"
	}
	return "if " + strings.Join(guards, " && ") + " { " + action + sep + stamp + " }"
}

// orderRules sorts a lane's processors into the deterministic execution order.
func orderRules(rs []Rule) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Order != rs[j].Order {
			return rs[i].Order < rs[j].Order
		}
		if !rs[i].CreatedAt.Equal(rs[j].CreatedAt) {
			return rs[i].CreatedAt.Before(rs[j].CreatedAt)
		}
		return rs[i].ID < rs[j].ID
	})
}

// GenerateRouterConfig renders the full processors.yaml from the enabled
// processor set (disabled ones are filtered here — spec: short-circuit
// disabled processors, so a disabled rule costs nothing at the edge).
//
// It FAILS — rather than degrading — when sealing is configured but the
// quarantine stage for a device-attribution lane cannot be rendered
// (F-11 review fix 2026-08-14): a config silently missing that stage lets
// registry-MISS events flow plaintext with no exit-78 backstop, no error and
// no metric. On error the caller must keep the last-good config live.
func GenerateRouterConfig(rules []Rule) (string, error) {
	byLane := map[string][]Rule{}
	total := 0
	for _, r := range rules {
		if !r.Enabled || !Lanes[r.Lane] {
			continue
		}
		byLane[r.Lane] = append(byLane[r.Lane], r)
		total++
	}
	for _, lane := range laneOrder {
		orderRules(byLane[lane])
	}

	var b strings.Builder
	b.WriteString("# GENERATED by the Correlix API (Pipeline Processors, item 121).\n")
	b.WriteString("# Do not edit: the api service rewrites this file when processors change.\n")
	fmt.Fprintf(&b, "# Active processors: %d\n", total)
	b.WriteString("#\n")
	b.WriteString("# Per lane: <lane>_rules_apply runs the ordered chain, <lane>_rules\n")
	b.WriteString("# filters events a drop_event processor marked, and the sinks read\n")
	b.WriteString("# <lane>_rules. ALL lanes always exist — a lane with no processors is\n")
	b.WriteString("# an explicit no-op, never an absent component.\n")
	b.WriteString("transforms:\n")

	// F-11 seal-or-quarantine: with sealing configured, the device-attribution
	// lanes get a quarantine stage between the lane input and the rules chain.
	// Emitted per-lane only when the engine can seal the quarantine scope —
	// see quarantine.go for the invariant and the fail-closed shape.
	engine := currentSealEngine()

	for _, lane := range laneOrder {
		rs := byLane[lane]
		chainInput := laneInputs[lane]
		if engine != nil && quarantineLanes[lane] {
			body, err := quarantineStageVRL(lane, engine)
			if err != nil {
				// Never render a config WITHOUT the quarantine stage while
				// sealing is configured — see quarantineStageVRL. The caller
				// keeps the last-good config (its stage intact) and surfaces
				// the failure loudly.
				return "", fmt.Errorf("quarantine stage for lane %s: %w", lane, err)
			}
			qn := quarantineName(lane)
			fmt.Fprintf(&b, "  %s:\n", qn)
			b.WriteString("    type: remap\n")
			fmt.Fprintf(&b, "    inputs: [%s]\n", laneInputs[lane])
			// Abort/error ⇒ DROP (counted by vector's component error
			// metrics), never a reroute: the deadletter index is durable
			// plaintext and must not receive an unsealed payload.
			b.WriteString("    drop_on_abort: true\n")
			b.WriteString("    drop_on_error: true\n")
			b.WriteString("    source: |\n")
			fmt.Fprintf(&b, "      %s\n", strings.ReplaceAll(body, "\n", "\n      "))
			chainInput = qn
		}
		// 1. the ordered apply chain
		fmt.Fprintf(&b, "  %s:\n", applyName(lane))
		b.WriteString("    type: remap\n")
		fmt.Fprintf(&b, "    inputs: [%s]\n", chainInput)
		b.WriteString("    source: |\n")
		// Explicit no-op keeps the program non-empty (an empty VRL program is a
		// compile error) and costs nothing.
		fmt.Fprintf(&b, "      del(.__cx_noop__)\n")
		for _, r := range rs {
			if line := ruleVRL(r); line != "" {
				// An action may compile to multi-line VRL (seal does); every
				// continuation line must carry the block scalar's indent or it
				// escapes the `source: |` block and the whole file stops
				// parsing (F-6, assurance run 2026-08-09).
				fmt.Fprintf(&b, "      %s\n", strings.ReplaceAll(line, "\n", "\n      "))
			}
		}
		// 2. the drop filter (intentional drops — counted, not dead-lettered)
		fmt.Fprintf(&b, "  %s:\n", HookName(lane))
		b.WriteString("    type: filter\n")
		fmt.Fprintf(&b, "    inputs: [%s]\n", applyName(lane))
		fmt.Fprintf(&b, "    condition: '!(to_bool(.%s) ?? false)'\n", DropField)
	}

	// 3. execution metrics: one counter per processor that fired, tagged by
	// processor id and lane. Reads the apply stage (BEFORE the drop filter) so
	// a drop_event processor's own matches are still counted.
	//
	// The counter is fed through a filter that keeps only events a processor
	// actually touched: log_to_metric emits "Field does not exist" and counts
	// an UNINTENTIONAL drop for every event without the field, which kept
	// VectorEventsDiscarded (F-18) firing continuously on ordinary untouched
	// traffic — burying the exact alert that exists to catch real loss. A
	// filter's discards are intentional=true, which F-18 correctly ignores.
	b.WriteString("  cx_applied_only:\n")
	b.WriteString("    type: filter\n")
	b.WriteString("    inputs: [")
	for i, lane := range laneOrder {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(applyName(lane))
	}
	b.WriteString("]\n")
	fmt.Fprintf(&b, "    condition: 'exists(.%s)'\n", AppliedField)
	b.WriteString("  cx_processor_metrics:\n")
	b.WriteString("    type: log_to_metric\n")
	b.WriteString("    inputs: [cx_applied_only]\n")
	b.WriteString("    metrics:\n")
	b.WriteString("      - type: counter\n")
	fmt.Fprintf(&b, "        field: %s\n", AppliedField)
	b.WriteString("        name: netops_pipeline_processor_applied\n")
	b.WriteString("        tags:\n")
	fmt.Fprintf(&b, "          processor: \"{{ %s }}\"\n", AppliedField)
	b.WriteString("          topic: \"{{ topic }}\"\n")
	return b.String(), nil
}
