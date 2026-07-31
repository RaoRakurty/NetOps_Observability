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

// laneOrder keeps output stable.
var laneOrder = []string{"applogs", "syslog", "snmptrap", "cloudlogs", "flows"}

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

// vrlString renders s as a double-quoted VRL string literal.
func vrlString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
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

// vrlRegex renders a pattern as a VRL regex literal. r'…' cannot escape a
// single quote, so a pattern containing one falls back to a quoted string
// (which VRL's regex-taking functions accept for the string forms we use).
func vrlRegex(pattern string) (expr string, raw bool) {
	if strings.ContainsRune(pattern, '\'') {
		return vrlString(pattern), false
	}
	return "r'" + pattern + "'", true
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
	guards := []string{
		fmt.Sprintf("(downcase(to_string(.tenant_id) ?? \"\") == %s)",
			vrlString(strings.ToLower(strings.TrimSpace(r.TenantID)))),
	}
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
	return "if " + strings.Join(guards, " && ") + " { " + action + "; " + stamp + " }"
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
func GenerateRouterConfig(rules []Rule) string {
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

	for _, lane := range laneOrder {
		rs := byLane[lane]
		// 1. the ordered apply chain
		fmt.Fprintf(&b, "  %s:\n", applyName(lane))
		b.WriteString("    type: remap\n")
		fmt.Fprintf(&b, "    inputs: [%s]\n", laneInputs[lane])
		b.WriteString("    source: |\n")
		// Explicit no-op keeps the program non-empty (an empty VRL program is a
		// compile error) and costs nothing.
		fmt.Fprintf(&b, "      del(.__cx_noop__)\n")
		for _, r := range rs {
			if line := ruleVRL(r); line != "" {
				fmt.Fprintf(&b, "      %s\n", line)
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
	b.WriteString("  cx_processor_metrics:\n")
	b.WriteString("    type: log_to_metric\n")
	b.WriteString("    inputs: [")
	for i, lane := range laneOrder {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(applyName(lane))
	}
	b.WriteString("]\n")
	b.WriteString("    metrics:\n")
	b.WriteString("      - type: counter\n")
	fmt.Fprintf(&b, "        field: %s\n", AppliedField)
	b.WriteString("        name: netops_pipeline_processor_applied\n")
	b.WriteString("        tags:\n")
	fmt.Fprintf(&b, "          processor: \"{{ %s }}\"\n", AppliedField)
	b.WriteString("          topic: \"{{ topic }}\"\n")
	return b.String()
}

// MetricSinkInput is the transform name the router's Prometheus exporter must
// include so the per-processor counters are actually exported (the generated
// file cannot edit the base config's sink, so the base wires this name).
const MetricSinkInput = "cx_processor_metrics"
