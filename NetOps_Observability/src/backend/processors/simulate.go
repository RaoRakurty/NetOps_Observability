package processors

// simulate.go — the Go-side preview of what the generated VRL will do to a
// sample event ("dry-run before the pipeline", the incident-policy simulator
// pattern). It mirrors ruleVRL's semantics rule-for-rule: same tenant guard,
// same match ops, same builtin regexes, same mask. generate_test.go pins the
// two together on golden cases so they cannot drift silently.

import (
	"regexp"
	"strconv"
	"strings"
)

var builtinCompiled = func() map[string]*regexp.Regexp {
	m := make(map[string]*regexp.Regexp, len(BuiltinPatterns))
	for name, p := range BuiltinPatterns {
		m[name] = regexp.MustCompile(p)
	}
	return m
}()

// getPath / setPath / delPath walk a validated dot-path over a JSON-shaped map.
func getPath(ev map[string]any, field string) (any, bool) {
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
		// JSON numbers arrive as float64; render like VRL's to_string (integral
		// values without a decimal point).
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

// Applied describes one rule that fired during a simulation.
type Applied struct {
	RuleID      string `json:"rule_id"`
	Type        string `json:"type"`
	Field       string `json:"field"`
	Description string `json:"description,omitempty"`
}

// Simulate applies the tenant's enabled rules for one lane to a sample event
// and returns the shaped copy plus which rules fired. The input map is not
// mutated. Semantics mirror the generated VRL exactly.
func Simulate(rules []Rule, lane, tenant string, event map[string]any) (map[string]any, []Applied) {
	out := deepCopy(event)
	var applied []Applied
	tenant = strings.ToLower(strings.TrimSpace(tenant))
	for _, r := range rules {
		if !r.Enabled || r.Lane != lane {
			continue
		}
		// tenant guard: the event's own tenant_id must equal the rule's owner
		// (the router evaluates the same predicate).
		evTenant := strings.ToLower(toStr(func() any { v, _ := getPath(out, "tenant_id"); return v }()))
		if evTenant != strings.ToLower(strings.TrimSpace(r.TenantID)) || evTenant != tenant {
			continue
		}
		if r.Match != nil {
			mv, _ := getPath(out, r.Match.Field)
			s := toStr(mv)
			okMatch := false
			switch r.Match.Op {
			case "equals":
				okMatch = s == r.Match.Value
			case "contains":
				okMatch = strings.Contains(s, r.Match.Value)
			case "prefix":
				okMatch = strings.HasPrefix(s, r.Match.Value)
			}
			if !okMatch {
				continue
			}
		}
		fired := false
		switch r.Type {
		case TypeRedactField:
			if _, ok := getPath(out, r.Field); ok {
				if p, leaf, ok := parentOf(out, r.Field); ok {
					p[leaf] = Mask
					fired = true
				}
			}
		case TypeDropField:
			if p, leaf, ok := parentOf(out, r.Field); ok {
				if _, had := p[leaf]; had {
					delete(p, leaf)
					fired = true
				}
			}
		case TypeSetField:
			if p, leaf, ok := parentOf(out, r.Field); ok {
				p[leaf] = r.Value
				fired = true
			}
		case TypeRedactPattern:
			v, ok := getPath(out, r.Field)
			if !ok {
				break
			}
			s := toStr(v)
			var next string
			if r.PatternKind == "builtin" {
				next = builtinCompiled[r.Pattern].ReplaceAllString(s, Mask)
			} else {
				next = strings.ReplaceAll(s, r.Pattern, Mask)
			}
			if p, leaf, ok := parentOf(out, r.Field); ok {
				p[leaf] = next // the write happens even when nothing matched, like VRL
				fired = true
			}
		}
		if fired {
			applied = append(applied, Applied{RuleID: r.ID, Type: r.Type, Field: r.Field, Description: r.Description})
		}
	}
	return out, applied
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
