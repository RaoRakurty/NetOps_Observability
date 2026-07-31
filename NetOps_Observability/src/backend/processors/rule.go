// Package processors holds the per-tenant ingest processor rules (tracker item
// 121, the #53 "UI processor editor" remnant): operator-declared redact /
// drop-field / set-field shaping applied in the Vector ROUTER, just before the
// storage sinks (OpenSearch / ClickHouse), scoped to the owning tenant.
//
// Zero-trust design decisions (§3, §15-adjacent):
//   - Rules are STRUCTURED, never free-form VRL and never free-form regex. A
//     pattern is either a built-in (email / ipv4 / mac) whose regex is a fixed
//     constant of this package, or a LITERAL string. User input is only ever
//     embedded as an escaped VRL string literal — there is no way to write
//     syntax through a rule.
//   - Every generated action is wrapped in a tenant guard derived from the
//     rule's server-stamped TenantID; a rule can never touch another tenant's
//     events.
//   - Attribution/lifecycle fields the pipeline itself stamps are protected —
//     a rule cannot target them, so shaping can never break tenancy routing.
//
// Known v1 limitation (documented in docs/design/pipeline-processors.md): the
// hooks run in the router, the terminal writer for stored data. The Python
// correlation engine consumes the Kafka topics BEFORE the router, so derived
// corr_signals are not shaped by these rules.
package processors

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Lanes a rule may attach to — exactly the router lanes with a storage sink.
var Lanes = map[string]bool{
	"applogs": true, "syslog": true, "snmptrap": true, "cloudlogs": true, "flows": true,
}

// Types of shaping a rule can do.
const (
	TypeRedactField   = "redact_field"   // field value → "***"
	TypeRedactPattern = "redact_pattern" // builtin/literal pattern inside a field → "***"
	TypeDropField     = "drop_field"     // delete the field
	TypeSetField      = "set_field"      // set the field to a literal value
)

var ruleTypes = map[string]bool{
	TypeRedactField: true, TypeRedactPattern: true, TypeDropField: true, TypeSetField: true,
}

// Builtin patterns — the ONLY regexes a rule can invoke. RE2-safe and equally
// valid in Rust's regex crate (the syntax used is the shared subset), so the Go
// preview and the Vector runtime agree.
var BuiltinPatterns = map[string]string{
	"email": `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`,
	"ipv4":  `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
	"mac":   `\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`,
}

// Mask replaces redacted content (mirrors ai/redact.go's dialect).
const Mask = "***"

// protectedFields are pipeline-stamped attribution/lifecycle fields a rule may
// never TARGET (matching on them read-only is fine). Touching these could
// re-route another tenant's documents or corrupt the time axis.
var protectedFields = map[string]bool{
	"tenant_id": true, "tenant_seg": true, "tenant_attribution": true,
	"log_index_base": true, "ts": true, "ts_source": true, "ts_invalid": true,
	"timestamp": true, "topic": true,
}

// fieldPattern bounds a dot-path: identifier segments only — no quotes, no
// spaces, no indexing syntax. What matches here embeds verbatim as a VRL path.
var fieldPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,3}$`)

// Match is an optional per-rule guard: apply only when the event field matches.
type Match struct {
	Field string `json:"field"`
	Op    string `json:"op"` // equals | contains | prefix
	Value string `json:"value"`
}

var matchOps = map[string]bool{"equals": true, "contains": true, "prefix": true}

// Rule is one tenant-owned shaping rule.
type Rule struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id,omitempty"`

	Lane        string `json:"lane"`
	Type        string `json:"type"`
	Field       string `json:"field"`                  // target (all types)
	Pattern     string `json:"pattern,omitempty"`      // redact_pattern: builtin name or literal
	PatternKind string `json:"pattern_kind,omitempty"` // "builtin" | "literal"
	Value       string `json:"value,omitempty"`        // set_field
	Match       *Match `json:"match,omitempty"`
	Description string `json:"description,omitempty"`

	Enabled   bool      `json:"enabled"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func printable(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func validLiteral(name, v string, maxLen int) error {
	if len(v) > maxLen || !printable(v) {
		return fmt.Errorf("%s must be a single line of at most %d printable chars", name, maxLen)
	}
	return nil
}

func validField(name, f string) error {
	if !fieldPattern.MatchString(f) {
		return fmt.Errorf("%s must be a dot-path of identifiers (a-z, 0-9, _), max 4 segments", name)
	}
	return nil
}

// Validate checks and normalizes the operator-supplied fields (zero-trust on
// the payload). Server-owned stamps (id/tenant/created_*) are not touched.
func (r *Rule) Validate() error {
	r.Lane = strings.ToLower(strings.TrimSpace(r.Lane))
	if !Lanes[r.Lane] {
		return errors.New("lane must be one of applogs, syslog, snmptrap, cloudlogs, flows")
	}
	r.Type = strings.ToLower(strings.TrimSpace(r.Type))
	if !ruleTypes[r.Type] {
		return errors.New("type must be one of redact_field, redact_pattern, drop_field, set_field")
	}
	r.Field = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r.Field), "."))
	if err := validField("field", r.Field); err != nil {
		return err
	}
	if protectedFields[strings.ToLower(r.Field)] {
		return fmt.Errorf("field %q is pipeline-owned (tenancy/time attribution) and cannot be targeted", r.Field)
	}
	r.Description = strings.TrimSpace(r.Description)
	if err := validLiteral("description", r.Description, 256); err != nil {
		return err
	}
	switch r.Type {
	case TypeRedactPattern:
		r.PatternKind = strings.ToLower(strings.TrimSpace(r.PatternKind))
		r.Pattern = strings.TrimSpace(r.Pattern)
		switch r.PatternKind {
		case "builtin":
			if _, ok := BuiltinPatterns[r.Pattern]; !ok {
				return fmt.Errorf("unknown builtin pattern %q (use email, ipv4, mac)", r.Pattern)
			}
		case "literal":
			if r.Pattern == "" {
				return errors.New("a literal pattern must not be empty")
			}
			if err := validLiteral("pattern", r.Pattern, 256); err != nil {
				return err
			}
		default:
			return errors.New("pattern_kind must be builtin or literal")
		}
	case TypeSetField:
		if err := validLiteral("value", r.Value, 256); err != nil {
			return err
		}
	default:
		if r.Pattern != "" || r.PatternKind != "" {
			return fmt.Errorf("%s does not take a pattern", r.Type)
		}
	}
	if r.Match != nil {
		r.Match.Field = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r.Match.Field), "."))
		if err := validField("match.field", r.Match.Field); err != nil {
			return err
		}
		r.Match.Op = strings.ToLower(strings.TrimSpace(r.Match.Op))
		if !matchOps[r.Match.Op] {
			return errors.New("match.op must be equals, contains or prefix")
		}
		if err := validLiteral("match.value", r.Match.Value, 256); err != nil {
			return err
		}
	}
	return nil
}
