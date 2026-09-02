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

// LaneOrder is THE lane list — exactly the router lanes with a storage sink,
// in generation order. Everything else (the Lanes set, the compiler's input
// map, the catalog response, error messages) derives from it, so adding a lane
// is one edit here plus its router input (review B3).
//
// `security` is the P3-L1 findings lane (netops.security → netops-secfindings-*).
// Its hook pair was declared STATICALLY in the router config while this list did
// not know it; the generator now owns it and the static pair is gone — Vector
// refuses to boot on a duplicate component id across its two --config files, so
// the two can never coexist (tests/test_security_lane.py pins that).
var LaneOrder = []string{"applogs", "syslog", "snmptrap", "cloudlogs", "security", "flows"}

// Lanes is the membership set derived from LaneOrder.
var Lanes = func() map[string]bool {
	m := make(map[string]bool, len(LaneOrder))
	for _, l := range LaneOrder {
		m[l] = true
	}
	return m
}()

// Processor types. The first four shipped in the initial cut; mask and
// drop_event complete the spec's set. The framework is open by construction:
// a new type is a case in the generator + simulator and an entry here.
const (
	TypeRedactField   = "redact_field"   // whole field value → replacement
	TypeRedactPattern = "redact_pattern" // matches inside a field → replacement
	TypeMask          = "mask"           // partial hide: keep the last N chars
	TypeDropField     = "drop_field"     // delete the field
	TypeSetField      = "set_field"      // set the field to a literal
	TypeRedactKeys    = "redact_keys"    // redact fields by KEY NAME (password, api_key, …)
	TypeHash          = "hash"           // stable digest: unreadable but still joinable
	TypeTag           = "tag"            // detect-only: stamp a marker, change nothing
	TypeDropEvent     = "drop_event"     // drop the whole event (counted, never silent)
	TypeSeal          = "seal"           // REVERSIBLE: encrypt, recoverable via audited unmask
)

// TagField collects the markers a tag processor stamps (the scan-only mode).
const TagField = "cx_sensitive"

var ruleTypes = map[string]bool{
	TypeRedactField: true, TypeRedactPattern: true, TypeMask: true,
	TypeDropField: true, TypeSetField: true, TypeDropEvent: true,
	TypeHash: true, TypeTag: true, TypeRedactKeys: true, TypeSeal: true,
}

// TypeLabel is the operator-facing name of a processor type (UI + audit).
var TypeLabel = map[string]string{
	TypeRedactField:   "Redact field",
	TypeRedactPattern: "Redact pattern",
	TypeMask:          "Mask",
	TypeDropField:     "Remove field",
	TypeSetField:      "Set field",
	TypeDropEvent:     "Drop event",
	TypeRedactKeys:    "Redact by field name",
	TypeHash:          "Hash",
	TypeTag:           "Tag (detect only)",
	TypeSeal:          "Seal (reversible)",
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

// DefaultRedaction is what a redact/mask writes when the processor declares no
// replacement. (Was `Mask`, which read as a sibling of TypeMask — an unrelated
// keep-last-N action. Review B7.)
const DefaultRedaction = "***"

// Limits (bounded by construction, §9).
const (
	MaxReplacementLen = 64
	MaxPatternLen     = 256
	MaxCaptureGroups  = 9
	MaxOrder          = 9999
)

// FieldAll targets EVERY string field in the event (recursively) instead of one
// path. This is what makes a managed detector useful out of the box: "redact
// emails" should find them wherever they are, not only in the field the
// operator happened to name. Pipeline-owned fields are preserved across the
// sweep (see the compiler + simulator), so tenancy/time routing is never
// rewritten by a content rule.
const FieldAll = "*"

// protectedFields are pipeline-stamped attribution/lifecycle fields a processor
// may never TARGET (matching on them read-only is fine). Touching these could
// re-route another tenant's documents or corrupt the time axis.
var protectedFields = map[string]bool{
	"tenant_id": true, "tenant_seg": true, "tenant_attribution": true,
	"log_index_base": true, "ts": true, "ts_source": true, "ts_invalid": true,
	"timestamp": true, "topic": true,
}

// protectedFieldOrder is protectedFields in a STABLE order — the compiler emits
// save/restore statements from it, and generated config must be deterministic.
var protectedFieldOrder = []string{
	"tenant_id", "tenant_seg", "tenant_attribution", "log_index_base",
	"ts", "ts_source", "ts_invalid", "timestamp", "topic",
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

// Processor is one tenant-owned processor — the spec's entity, and the name
// used everywhere in prose, the UI and the API path. `Rule` remains as an
// ALIAS below because the shipped JSON/DB field names (rule_id, rule_type,
// "rules") predate the rename and changing them would break stored data for no
// user-visible gain (review B7).
type Processor struct {
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
	// Keys is the field-NAME list a redact_keys processor redacts. Value
	// patterns cannot see keys: in a real application log the secret is
	// `"password": "hunter2"` — the value alone is just "hunter2" and matches
	// nothing. Key-scoped redaction is the only thing that catches it.
	Keys []string `json:"keys,omitempty"`
	// KeepLast is mask's tail length: 4 → "************1111". 0 → 4 (the
	// PCI-style default operators expect).
	KeepLast int `json:"keep_last,omitempty"`
	// DataType is the SEMANTIC kind of the value ("card", "email", "ssn"). It is
	// part of what a sealed token is cryptographically bound to, so changing it
	// on an existing processor makes previously sealed values unreadable — which
	// is the intended behaviour, not a bug: a token minted as a card number must
	// not become readable as something else. It also drives audit records and
	// how the UI labels a revealed value.
	DataType    string `json:"data_type,omitempty"`
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

// Rule is the historical name of Processor, kept so existing call sites and
// the wire format stay valid.
type Rule = Processor

// DisplayName is the processor's operator-facing name (never empty).
func (r Processor) DisplayName() string {
	if n := strings.TrimSpace(r.Name); n != "" {
		return n
	}
	if d := strings.TrimSpace(r.Description); d != "" {
		return d
	}
	return TypeLabel[r.Type] + " · " + r.Field
}

// ReplacementOrDefault is what a redact/mask action writes.
func (r Processor) ReplacementOrDefault() string {
	if s := strings.TrimSpace(r.Replacement); s != "" {
		return s
	}
	return DefaultRedaction
}

// DataTypeOrField is the semantic type bound into a sealed value, falling back
// to the field name when the operator did not pick one. It must never be empty:
// an empty binding component would make two different processors' tokens
// interchangeable.
func (r Processor) DataTypeOrField() string {
	if r.DataType != "" {
		return r.DataType
	}
	return r.Field
}

// KeepLastOrDefault is mask's retained tail length.
func (r Processor) KeepLastOrDefault() int {
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
	// A single quote is REFUSED, not worked around. VRL's raw-regex literal
	// r'…' cannot escape one, and the old fallback to a double-quoted literal
	// had two unacceptable outcomes: for a matcher, VRL's `match()` demands a
	// regex type, so the generated program failed to compile and Vector
	// rejected the WHOLE processors.yaml — one tenant's pattern freezing every
	// tenant's processors; for a replace, VRL treats a string pattern as
	// LITERAL text, so the preview would show a regex redaction the edge never
	// performs — a redaction that "previewed green" while leaking data. A clear
	// 400 beats either. (Quotes are vanishingly rare in RE2 patterns.)
	if strings.ContainsRune(pattern, '\'') {
		return fmt.Errorf("%s must not contain a single quote (the ingest runtime cannot carry one safely)", name)
	}
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
func (r *Processor) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	if err := validLiteral("name", r.Name, 128); err != nil {
		return err
	}
	r.Lane = strings.ToLower(strings.TrimSpace(r.Lane))
	if !Lanes[r.Lane] {
		return fmt.Errorf("lane must be one of %s", strings.Join(LaneOrder, ", "))
	}
	r.Type = strings.ToLower(strings.TrimSpace(r.Type))
	if !ruleTypes[r.Type] {
		return fmt.Errorf("type must be one of %s", strings.Join(ActionTypes(), ", "))
	}
	if r.Order < 0 || r.Order > MaxOrder {
		return fmt.Errorf("order must be 0..%d", MaxOrder)
	}
	r.Description = strings.TrimSpace(r.Description)
	if err := validLiteral("description", r.Description, 256); err != nil {
		return err
	}
	if r.Type == TypeRedactKeys {
		// The key list IS the target, so the generic field validation is skipped
		// (Field stays empty); each key is bounded like any identifier.
		clean := r.Keys[:0]
		for _, k := range r.Keys {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if err := validField("keys", k); err != nil {
				return err
			}
			if protectedFields[strings.ToLower(k)] {
				return fmt.Errorf("key %q is pipeline-owned and cannot be redacted", k)
			}
			clean = append(clean, k)
		}
		r.Keys = clean
		if len(r.Keys) == 0 {
			return errors.New("a redact_keys processor needs at least one field name")
		}
		if len(r.Keys) > 64 {
			return errors.New("keys is capped at 64 field names")
		}
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
		if r.Field == FieldAll {
			// "*" is only meaningful for CONTENT rules — dropping or setting
			// "every field" is not an operation anyone means to perform.
			if r.Type != TypeRedactPattern && r.Type != TypeTag {
				return fmt.Errorf("%s needs a specific field; only redact_pattern can target every field (*)", r.Type)
			}
		} else {
			if err := validField("field", r.Field); err != nil {
				return err
			}
			if protectedFields[strings.ToLower(r.Field)] {
				return fmt.Errorf("field %q is pipeline-owned (tenancy/time attribution) and cannot be targeted", r.Field)
			}
		}
	}

	// Type-specific validation is the ACTION's own (registry.go) — one
	// definition per action, shared by the compiler and the simulator.
	r.PatternKind = strings.ToLower(strings.TrimSpace(r.PatternKind))
	r.Pattern = strings.TrimSpace(r.Pattern)
	if !action.UsesPattern() && (r.Pattern != "" || r.PatternKind != "") {
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
			return fmt.Errorf("match.op must be one of %s", strings.Join(MatcherTypes(), ", "))
		}
		if err := matcher.Validate(*r.Match); err != nil {
			return err
		}
	}
	return nil
}
