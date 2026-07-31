// Package processors is the Pipeline Processors framework (tracker item 121 +
// the 2026-07-31 framework spec): tenant-scoped, ordered, versioned log
// processing that runs against incoming events BEFORE storage.
//
//	Incoming logs → router → per-tenant processor chain → storage
//
// Division of responsibility (deliberate, and the reason this scales):
//   - Go OWNS the model: types, matchers, actions, ordering, validation,
//     managed-rule catalog, versioning, and the dry-run simulator.
//   - Vector EXECUTES: the pure generator (generate.go) compiles the ordered
//     chain into VRL the router runs at the edge. The Go backend has no Kafka
//     client by design (CLAUDE.md §6), so an inline Go stage on the ingest path
//     would mean a new service and a new dependency; compiling to the executor
//     already in the path costs neither and keeps hot-reload + fail-safe
//     rollback (Vector keeps the previous topology if a config fails to load).
//   - simulate.go mirrors the generator's semantics exactly so dry-run answers
//     what the pipeline will actually do (generate_test.go pins the two).
//
// Zero-trust posture (§3, §15-adjacent):
//   - user input reaches the generated config ONLY as an escaped VRL string
//     literal or a validated regex — never as syntax;
//   - every action is wrapped in a tenant guard from the server-stamped owner;
//   - pipeline-owned fields (tenancy/time/index routing) cannot be targeted.
//
// On regex safety: Go's regexp and Vector's Rust engine are both RE2-family —
// linear time, no backtracking — so catastrophic backtracking is STRUCTURALLY
// impossible here. Custom patterns are therefore accepted, bounded and
// compile-checked (validateRegex) rather than forbidden.
package processors

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Lanes a processor may attach to — exactly the router lanes with a storage sink.
var Lanes = map[string]bool{
	"applogs": true, "syslog": true, "snmptrap": true, "cloudlogs": true, "flows": true,
}

// Processor types. The first four shipped in the initial cut; mask and
// drop_event complete the spec's set. The framework is open by construction:
// a new type is a case in the generator + simulator and an entry here.
const (
	TypeRedactField   = "redact_field"   // whole field value → replacement
	TypeRedactPattern = "redact_pattern" // matches inside a field → replacement
	TypeMask          = "mask"           // partial hide: keep the last N chars
	TypeDropField     = "drop_field"     // delete the field
	TypeSetField      = "set_field"      // set the field to a literal
	TypeDropEvent     = "drop_event"     // drop the whole event (counted, never silent)
)

var ruleTypes = map[string]bool{
	TypeRedactField: true, TypeRedactPattern: true, TypeMask: true,
	TypeDropField: true, TypeSetField: true, TypeDropEvent: true,
}

// TypeLabel is the operator-facing name of a processor type (UI + audit).
var TypeLabel = map[string]string{
	TypeRedactField:   "Redact field",
	TypeRedactPattern: "Redact pattern",
	TypeMask:          "Mask",
	TypeDropField:     "Remove field",
	TypeSetField:      "Set field",
	TypeDropEvent:     "Drop event",
}

// Matcher operators. equals/contains/prefix shipped first; regex + attribute
// complete the spec's matching engine. `attribute` is equals on a named field
// (service=authentication) — kept distinct from `equals` so the UI can offer
// the operator's vocabulary and future attribute semantics can diverge.
const (
	MatchEquals    = "equals"
	MatchContains  = "contains"
	MatchPrefix    = "prefix"
	MatchRegex     = "regex"
	MatchAttribute = "attribute"
)

// Processor provenance (spec §1 "source").
const (
	SourceCustom  = "custom"
	SourceManaged = "managed"
)

// Pattern kinds for redact_pattern / regex matchers.
const (
	PatternBuiltin = "builtin" // a Managed Rule id (managed.go) — versioned, read-only
	PatternLiteral = "literal" // exact text, regex-escaped before use
	PatternRegex   = "regex"   // operator-supplied RE2 pattern (validated)
)

// Mask replaces redacted content when a processor declares no replacement.
const Mask = "***"

// Limits (bounded by construction, §9).
const (
	MaxReplacementLen = 64
	MaxPatternLen     = 256
	MaxCaptureGroups  = 9
	MaxOrder          = 9999
)

// protectedFields are pipeline-stamped attribution/lifecycle fields a processor
// may never TARGET (matching on them read-only is fine). Touching these could
// re-route another tenant's documents or corrupt the time axis.
var protectedFields = map[string]bool{
	"tenant_id": true, "tenant_seg": true, "tenant_attribution": true,
	"log_index_base": true, "ts": true, "ts_source": true, "ts_invalid": true,
	"timestamp": true, "topic": true,
}

// fieldPattern bounds a dot-path: identifier segments only — no quotes, no
// spaces, no indexing syntax. What matches here embeds verbatim as a VRL path.
var fieldPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,3}$`)

// Match is the optional per-processor guard: apply only when the event matches.
type Match struct {
	Field string `json:"field"`
	Op    string `json:"op"` // equals | contains | prefix | regex | attribute
	Value string `json:"value"`
}

// Rule is one tenant-owned processor. (Named Rule for wire compatibility with
// the shipped API; it IS the spec's Processor entity.)
type Rule struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id,omitempty"`

	// Name is the operator-facing label ("Redact customer emails"). Optional for
	// wire compatibility — DisplayName() falls back to a derived description.
	Name string `json:"name,omitempty"`

	Lane        string `json:"lane"`
	Type        string `json:"type"`
	Field       string `json:"field"`                  // target (all types except drop_event)
	Pattern     string `json:"pattern,omitempty"`      // managed-rule id, literal, or regex
	PatternKind string `json:"pattern_kind,omitempty"` // builtin | literal | regex
	Value       string `json:"value,omitempty"`        // set_field
	// Replacement is what redact/mask writes ("[EMAIL]"); "" → Mask ("***").
	Replacement string `json:"replacement,omitempty"`
	// KeepLast is mask's tail length: 4 → "************1111". 0 → 4 (the
	// PCI-style default operators expect).
	KeepLast    int    `json:"keep_last,omitempty"`
	Match       *Match `json:"match,omitempty"`
	Description string `json:"description,omitempty"`

	// Order is the execution priority within a lane (ascending; ties broken by
	// created_at then id, so execution is DETERMINISTIC — spec principle 4).
	Order int `json:"order"`

	// ManagedRuleID records that this processor was cloned from a managed rule,
	// so the catalog can show adoption and a future rule-version bump can offer
	// an upgrade. Empty for hand-authored processors.
	ManagedRuleID string `json:"managed_rule_id,omitempty"`
	// Source is the provenance badge: "custom" (hand-authored) or "managed"
	// (adopted from the catalog). Derived on write from ManagedRuleID.
	Source string `json:"source,omitempty"`
	// Version increments on every saved edit; processor_versions keeps the
	// history and rollback restores one (immutable audit — spec §10).
	Version int `json:"version"`

	Enabled   bool      `json:"enabled"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DisplayName is the processor's operator-facing name (never empty).
func (r Rule) DisplayName() string {
	if n := strings.TrimSpace(r.Name); n != "" {
		return n
	}
	if d := strings.TrimSpace(r.Description); d != "" {
		return d
	}
	return TypeLabel[r.Type] + " · " + r.Field
}

// ReplacementOrDefault is what a redact/mask action writes.
func (r Rule) ReplacementOrDefault() string {
	if s := strings.TrimSpace(r.Replacement); s != "" {
		return s
	}
	return Mask
}

// KeepLastOrDefault is mask's retained tail length.
func (r Rule) KeepLastOrDefault() int {
	if r.KeepLast > 0 {
		return r.KeepLast
	}
	return 4
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

// validateRegex accepts an operator-supplied pattern.
//
// Both execution engines are RE2-family (Go regexp here, the Rust regex crate
// in Vector): matching is LINEAR in input length with no backtracking, so the
// classic "catastrophic backtracking" DoS is impossible by construction — the
// safety bar is therefore compile-correctness and bounded size, not a
// hand-rolled complexity heuristic. Lookaround/backreferences are rejected by
// the RE2 compiler itself, which is exactly what we want: patterns that would
// behave differently in the two engines are refused here rather than silently
// disabling a customer's redaction at the edge.
func validateRegex(name, pattern string) error {
	if strings.TrimSpace(pattern) == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if len(pattern) > MaxPatternLen {
		return fmt.Errorf("%s is capped at %d characters", name, MaxPatternLen)
	}
	if !printable(pattern) {
		return fmt.Errorf("%s must be a single line of printable characters", name)
	}
	// The VRL raw-literal form r'…' cannot escape a single quote; the generator
	// falls back to a quoted literal for those, so reject only what neither
	// form can carry.
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("%s is not a valid pattern: %w", name, err)
	}
	if n := re.NumSubexp(); n > MaxCaptureGroups {
		return fmt.Errorf("%s uses %d capture groups (max %d)", name, n, MaxCaptureGroups)
	}
	return nil
}

// Validate checks and normalizes the operator-supplied fields (zero-trust on
// the payload). Server-owned stamps (id/tenant/created_*) are not touched.
func (r *Rule) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	if err := validLiteral("name", r.Name, 128); err != nil {
		return err
	}
	r.Lane = strings.ToLower(strings.TrimSpace(r.Lane))
	if !Lanes[r.Lane] {
		return errors.New("lane must be one of applogs, syslog, snmptrap, cloudlogs, flows")
	}
	r.Type = strings.ToLower(strings.TrimSpace(r.Type))
	if !ruleTypes[r.Type] {
		return errors.New("type must be one of redact_field, redact_pattern, mask, drop_field, set_field, drop_event")
	}
	if r.Order < 0 || r.Order > MaxOrder {
		return fmt.Errorf("order must be 0..%d", MaxOrder)
	}
	r.Description = strings.TrimSpace(r.Description)
	if err := validLiteral("description", r.Description, 256); err != nil {
		return err
	}
	r.Replacement = strings.TrimSpace(r.Replacement)
	if err := validLiteral("replacement", r.Replacement, MaxReplacementLen); err != nil {
		return err
	}

	// Provenance badge (spec §1): managed = adopted from the catalog.
	if strings.TrimSpace(r.ManagedRuleID) != "" {
		r.Source = SourceManaged
	} else {
		r.Source = SourceCustom
	}

	action, ok := lookupAction(r.Type)
	if !ok {
		return fmt.Errorf("unknown processor type %q", r.Type)
	}

	// An action that acts on the WHOLE event takes no target field.
	if !action.TargetsField() {
		r.Field = ""
	} else {
		r.Field = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r.Field), "."))
		if err := validField("field", r.Field); err != nil {
			return err
		}
		if protectedFields[strings.ToLower(r.Field)] {
			return fmt.Errorf("field %q is pipeline-owned (tenancy/time attribution) and cannot be targeted", r.Field)
		}
	}

	// Type-specific validation is the ACTION's own (registry.go) — one
	// definition per action, shared by the compiler and the simulator.
	r.PatternKind = strings.ToLower(strings.TrimSpace(r.PatternKind))
	r.Pattern = strings.TrimSpace(r.Pattern)
	if r.Type != TypeRedactPattern && (r.Pattern != "" || r.PatternKind != "") {
		return fmt.Errorf("%s does not take a pattern", r.Type)
	}
	if err := action.Validate(*r); err != nil {
		return err
	}

	if r.Match != nil {
		r.Match.Field = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r.Match.Field), "."))
		if err := validField("match.field", r.Match.Field); err != nil {
			return err
		}
		r.Match.Op = strings.ToLower(strings.TrimSpace(r.Match.Op))
		matcher, ok := lookupMatcher(r.Match.Op)
		if !ok {
			return errors.New("match.op must be equals, contains, prefix, regex or attribute")
		}
		if err := matcher.Validate(*r.Match); err != nil {
			return err
		}
	}
	return nil
}
