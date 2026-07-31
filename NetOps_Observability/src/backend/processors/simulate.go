package processors

// simulate.go — DRY RUN. Not a parallel implementation: it runs the ordered
// chain through the SAME registries (registry.go) the compiler emits VRL from,
// so "what the preview showed" and "what the pipeline does" are one definition
// read twice (spec §7). generate_test.go pins the pair on golden cases.
//
// Nothing here mutates the caller's event: the chain runs on a deep copy.

import (
	"strconv"
	"strings"
)

// ── path helpers (shared with the action registry) ──────────────────────────

func getPath(ev map[string]any, field string) (any, bool) {
	if ev == nil || field == "" {
		return nil, false
	}
	segs := strings.Split(field, ".")
	cur := any(ev)
	for i, s := range segs {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok := m[s]
		if !ok {
			return nil, false
		}
		if i == len(segs)-1 {
			return v, true
		}
		cur = v
	}
	return nil, false
}

func parentOf(ev map[string]any, field string) (map[string]any, string, bool) {
	if ev == nil || field == "" {
		return nil, "", false
	}
	segs := strings.Split(field, ".")
	cur := ev
	for _, s := range segs[:len(segs)-1] {
		v, ok := cur[s].(map[string]any)
		if !ok {
			return nil, "", false
		}
		cur = v
	}
	return cur, segs[len(segs)-1], true
}

// toStr mirrors VRL's to_string for the value shapes JSON carries.
func toStr(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

// Applied is one processor that fired during a simulation.
type Applied struct {
	RuleID      string `json:"rule_id"`
	Processor   string `json:"processor"` // display name (spec's `processor`)
	Type        string `json:"type"`
	Field       string `json:"field,omitempty"`
	Description string `json:"description,omitempty"`
	// ManagedRule names the catalog detector when the processor adopted one
	// (the spec's "matched: Email Detector").
	ManagedRule string `json:"managed_rule,omitempty"`
}

// SimResult is the dry-run answer (spec §7 shape).
type SimResult struct {
	Event   map[string]any `json:"event"`
	Applied []Applied      `json:"applied"`
	// Dropped reports that a drop_event processor matched — the event would not
	// be stored. Stated explicitly: a preview that just showed a shaped event
	// would hide the most consequential outcome of all.
	Dropped bool `json:"dropped"`
}

// SimulateChain is Simulate with the full result (including the drop verdict).
func SimulateChain(rules []Rule, lane, tenant string, event map[string]any) SimResult {
	out := deepCopy(event)
	applied := []Applied{}
	tenant = strings.ToLower(strings.TrimSpace(tenant))

	// Same ordering the compiler uses — determinism is the whole contract.
	chain := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if r.Enabled && r.Lane == lane {
			chain = append(chain, r)
		}
	}
	orderRules(chain)

	for _, r := range chain {
		spec, ok := lookupAction(r.Type)
		if !ok {
			continue
		}
		// Tenant guard — literally the same definition the compiler emits.
		if !tenantGuardEval(out, r.TenantID, tenant) {
			continue
		}
		if r.Match != nil {
			m, ok := lookupMatcher(r.Match.Op)
			if !ok || !m.Eval(out, *r.Match) {
				continue
			}
		}
		if !spec.Apply(out, r) {
			continue
		}
		applied = append(applied, Applied{
			RuleID: r.ID, Processor: r.DisplayName(), Type: r.Type,
			Field: r.Field, Description: r.Description, ManagedRule: r.ManagedRuleID,
		})
	}

	dropped := false
	if v, ok := out[DropField]; ok {
		dropped = v == true
		delete(out, DropField) // the marker is pipeline plumbing, not part of the event
	}
	return SimResult{Event: out, Applied: applied, Dropped: dropped}
}

func deepCopy(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			out[k] = deepCopy(sub)
			continue
		}
		if arr, ok := v.([]any); ok {
			cp := make([]any, len(arr))
			copy(cp, arr)
			out[k] = cp
			continue
		}
		out[k] = v
	}
	return out
}
