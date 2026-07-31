package processors

// registry.go — the MATCHER and ACTION registries: the extensibility spine of
// the Pipeline Processors engine.
//
// THE INVARIANT THIS FILE EXISTS TO ENFORCE: every matcher/action defines its
// validation, its VRL compilation and its Go evaluation IN ONE PLACE. The
// compiler (generate.go) and the dry-run simulator (simulate.go) both dispatch
// through these registries, so "what the preview showed" and "what the pipeline
// does" cannot drift — they are the same definition read twice. Adding a
// matcher or action is a single Register call plus tests; no other file changes.
//
// Future detectors (ML / dictionary / checksum) plug in as MatcherSpecs whose
// CompileVRL returns "" — meaning "not expressible at the edge". The engine
// then knows to evaluate them service-side (SDS) instead of compiling them,
// without any caller learning the difference.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// MatcherSpec is one matcher plugin (regex / field / contains / attribute / …).
type MatcherSpec interface {
	Type() string
	// Label is the operator-facing name for the UI picker.
	Label() string
	// Validate checks the operator's configuration.
	Validate(m Match) error
	// EdgeCapable reports whether this matcher compiles to VRL at all. A future
	// service-side detector (ML/dictionary) declares false; the catalog reads
	// this instead of probing CompileVRL with a fabricated Match (review B5).
	EdgeCapable() bool
	// CompileVRL returns the guard EXPRESSION (must evaluate to a boolean).
	// "" means this particular configuration cannot run at the edge.
	CompileVRL(m Match) string
	// Eval is the SAME predicate in Go — used by the simulator.
	Eval(ev map[string]any, m Match) bool
}

// ActionSpec is one action plugin (redact / mask / replace / remove / drop / …).
type ActionSpec interface {
	Type() string
	Label() string
	// TargetsField reports whether the action needs a target field (drop_event
	// does not) — the model's validator uses this instead of special-casing.
	TargetsField() bool
	// UsesPattern reports whether the action takes a pattern/pattern_kind, so
	// the model no longer special-cases redact_pattern by name (review B6).
	UsesPattern() bool
	Validate(r Rule) error
	// CompileVRL returns the action STATEMENT(S).
	CompileVRL(r Rule) string
	// Apply mutates the simulated event, returning whether it fired.
	Apply(ev map[string]any, r Rule) bool
}

var (
	registryMu      sync.RWMutex
	matcherRegistry = map[string]MatcherSpec{}
	actionRegistry  = map[string]ActionSpec{}
)

// RegisterMatcher / RegisterAction install a plugin. Called from init below;
// exported so a future package (SDS detectors) can extend the engine.
func RegisterMatcher(m MatcherSpec) {
	registryMu.Lock()
	defer registryMu.Unlock()
	matcherRegistry[m.Type()] = m
}

func RegisterAction(a ActionSpec) {
	registryMu.Lock()
	defer registryMu.Unlock()
	actionRegistry[a.Type()] = a
}

func lookupMatcher(t string) (MatcherSpec, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	m, ok := matcherRegistry[t]
	return m, ok
}

func lookupAction(t string) (ActionSpec, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	a, ok := actionRegistry[t]
	return a, ok
}

// MatcherCatalog / ActionCatalog describe the registered plugins for the UI
// wizard (so the picker is generated from the engine, never hardcoded).
type PluginInfo struct {
	Type  string `json:"type"`
	Label string `json:"label"`
	// EdgeCapable=false → evaluated service-side (future SDS detectors).
	EdgeCapable bool `json:"edge_capable"`
	// TargetsField is meaningful for actions only.
	TargetsField bool `json:"targets_field,omitempty"`
}

func MatcherCatalog() []PluginInfo {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]PluginInfo, 0, len(matcherRegistry))
	for _, m := range matcherRegistry {
		out = append(out, PluginInfo{Type: m.Type(), Label: m.Label(), EdgeCapable: m.EdgeCapable()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// MatcherTypes / ActionTypes are the registered type ids, sorted — used for
// operator-facing error messages so they can never list a stale set.
func MatcherTypes() []string {
	out := make([]string, 0, len(MatcherCatalog()))
	for _, m := range MatcherCatalog() {
		out = append(out, m.Type)
	}
	return out
}

func ActionTypes() []string {
	out := make([]string, 0, len(ActionCatalog()))
	for _, a := range ActionCatalog() {
		out = append(out, a.Type)
	}
	return out
}

func ActionCatalog() []PluginInfo {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]PluginInfo, 0, len(actionRegistry))
	for _, a := range actionRegistry {
		out = append(out, PluginInfo{
			Type: a.Type(), Label: a.Label(), EdgeCapable: true, TargetsField: a.TargetsField(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// sweepStrings rewrites every string value in the event (recursively) except
// the pipeline-owned fields — the Go twin of the map_values sweep the compiler
// emits, so the preview and the pipeline agree.
func sweepStrings(ev map[string]any, re *regexp.Regexp, repl string) bool {
	changed := false
	var walk func(m map[string]any, top bool)
	walk = func(m map[string]any, top bool) {
		for k, v := range m {
			if top && protectedFields[strings.ToLower(k)] {
				continue
			}
			switch t := v.(type) {
			case string:
				if next := re.ReplaceAllString(t, repl); next != t {
					m[k] = next
					changed = true
				}
			case map[string]any:
				walk(t, false)
			}
		}
	}
	walk(ev, true)
	return changed
}

// nestedContainers are the object fields real telemetry nests payload under.
// A key-scoped redaction reaches one level into each of them, which covers the
// shapes this platform actually indexes (a trap's `fields.mac`, an HTTP log's
// `headers.authorization`) without needing unbounded recursion in VRL.
var nestedContainers = []string{"fields", "body", "headers", "attributes", "labels", "params"}

// redactKeysAction redacts a field by its NAME rather than its content. This
// exists because a value pattern is blind to keys: an application log carries
// `"password": "hunter2"`, and "hunter2" on its own matches no secret pattern.
// Key-scoped redaction is the only thing that catches that shape — which is
// exactly the gap the real-log acceptance suite exposed.
type redactKeysAction struct{}

func (redactKeysAction) Type() string        { return TypeRedactKeys }
func (redactKeysAction) Label() string       { return TypeLabel[TypeRedactKeys] }
func (redactKeysAction) TargetsField() bool  { return false }
func (redactKeysAction) UsesPattern() bool   { return false }
func (redactKeysAction) Validate(Rule) error { return nil }
func (redactKeysAction) CompileVRL(r Rule) string {
	repl := vrlString(r.ReplacementOrDefault())
	var b strings.Builder
	for _, k := range r.Keys {
		paths := []string{"." + k}
		for _, c := range nestedContainers {
			paths = append(paths, "."+c+"."+k)
		}
		for _, p := range paths {
			fmt.Fprintf(&b, "if exists(%s) { %s = %s }; ", p, p, repl)
		}
	}
	return strings.TrimSuffix(b.String(), "; ")
}
func (redactKeysAction) Apply(ev map[string]any, r Rule) bool {
	want := make(map[string]bool, len(r.Keys))
	for _, k := range r.Keys {
		want[strings.ToLower(k)] = true
	}
	repl := r.ReplacementOrDefault()
	changed := false
	var walk func(m map[string]any, top bool)
	walk = func(m map[string]any, top bool) {
		for k, v := range m {
			if top && protectedFields[strings.ToLower(k)] {
				continue
			}
			if want[strings.ToLower(k)] {
				if _, isObj := v.(map[string]any); !isObj {
					m[k] = repl
					changed = true
					continue
				}
			}
			if sub, ok := v.(map[string]any); ok {
				walk(sub, false)
			}
		}
	}
	walk(ev, true)
	return changed
}

// hashAction replaces a value with a stable digest — the field stops being
// readable but stays JOINABLE: the same input always yields the same token, so
// an operator can still correlate "all events from this user" without the
// platform ever storing the user. sha2 is VRL-native, and Go's crypto/sha256
// gives the simulator the identical digest.
type hashAction struct{}

func (hashAction) Type() string        { return TypeHash }
func (hashAction) Label() string       { return TypeLabel[TypeHash] }
func (hashAction) TargetsField() bool  { return true }
func (hashAction) UsesPattern() bool   { return false }
func (hashAction) Validate(Rule) error { return nil }
func (hashAction) CompileVRL(r Rule) string {
	t := vrlPath(r.Field)
	// Truncated to 16 hex chars: enough to keep collisions negligible for
	// correlation, short enough to stay readable in a log line.
	return fmt.Sprintf("if exists(%s) { %s = slice!(sha2(to_string(%s) ?? \"\", variant: \"SHA-256\"), 0, 16) }", t, t, t)
}
func (hashAction) Apply(ev map[string]any, r Rule) bool {
	v, ok := getPath(ev, r.Field)
	if !ok {
		return false
	}
	p, leaf, ok := parentOf(ev, r.Field)
	if !ok {
		return false
	}
	sum := sha256.Sum256([]byte(toStr(v)))
	p[leaf] = hex.EncodeToString(sum[:])[:16]
	return true
}

// tagAction leaves the value ALONE and stamps a marker field instead — the
// "detect, don't destroy" mode. It is how an operator finds where sensitive
// data is flowing before deciding what to redact, and it is what makes a
// scan-only rollout possible.
type tagAction struct{}

func (tagAction) Type() string       { return TypeTag }
func (tagAction) Label() string      { return TypeLabel[TypeTag] }
func (tagAction) TargetsField() bool { return true }
func (tagAction) UsesPattern() bool  { return true }
func (tagAction) Validate(r Rule) error {
	// A tag rule is a detector: it needs something to detect.
	return redactPatternAction{}.Validate(r)
}
func (tagAction) CompileVRL(r Rule) string {
	pat := resolvePattern(r)
	if pat == "" {
		return ""
	}
	rex, _ := vrlRegex(pat)
	if rex == "" {
		return ""
	}
	tag := r.ReplacementOrDefault()
	if r.Field == FieldAll {
		// Whole-event detection: encode the event and test the pattern against
		// the encoded form. Cheap, and it cannot mutate anything by construction.
		return fmt.Sprintf("if match(encode_json(.), %s) { .%s = push(array(.%s) ?? [], %s) }",
			rex, TagField, TagField, vrlString(tag))
	}
	t := vrlPath(r.Field)
	return fmt.Sprintf("if exists(%s) && match(to_string(%s) ?? \"\", %s) { .%s = push(array(.%s) ?? [], %s) }",
		t, t, rex, TagField, TagField, vrlString(tag))
}
func (tagAction) Apply(ev map[string]any, r Rule) bool {
	re := compiled(resolvePattern(r))
	if re == nil {
		return false
	}
	hit := false
	if r.Field == FieldAll {
		hit = anyString(ev, func(s string) bool { return re.MatchString(s) })
	} else {
		v, ok := getPath(ev, r.Field)
		hit = ok && re.MatchString(toStr(v))
	}
	if !hit {
		return false
	}
	tags, _ := ev[TagField].([]any)
	ev[TagField] = append(tags, r.ReplacementOrDefault())
	return true
}

// anyString reports whether any string value in the event satisfies fn.
func anyString(ev map[string]any, fn func(string) bool) bool {
	for _, v := range ev {
		switch t := v.(type) {
		case string:
			if fn(t) {
				return true
			}
		case map[string]any:
			if anyString(t, fn) {
				return true
			}
		}
	}
	return false
}

// ── the tenant guard ────────────────────────────────────────────────────────
//
// Every compiled processor is wrapped in this predicate, and the simulator
// evaluates the same thing. It was the ONE compile/eval pair defined in two
// files (generate.go + simulate.go) — exactly the drift the registries exist to
// prevent — so it lives here as a matched pair with an equivalence test
// (review B4).

// tenantGuardVRL is the compiled form: the event's own tenant must equal the
// processor's server-stamped owner.
func tenantGuardVRL(tenantID string) string {
	return fmt.Sprintf("(downcase(to_string(.tenant_id) ?? \"\") == %s)",
		vrlString(normTenant(tenantID)))
}

// tenantGuardEval is the SAME predicate in Go. `scope` is the caller's tenant:
// a simulation must not apply a processor the caller could not see.
func tenantGuardEval(ev map[string]any, tenantID, scope string) bool {
	v, _ := getPath(ev, "tenant_id")
	evTenant := strings.ToLower(toStr(v))
	return evTenant == normTenant(tenantID) && evTenant == normTenant(scope)
}

// ── shared helpers ──────────────────────────────────────────────────────────

// compiledCache memoizes operator-supplied patterns (compile ONCE — the
// simulator runs per preview, and a busy tenant may hold hundreds of rules).
var (
	compiledMu    sync.RWMutex
	compiledCache = map[string]*regexp.Regexp{}
)

func compiled(pattern string) *regexp.Regexp {
	compiledMu.RLock()
	re, ok := compiledCache[pattern]
	compiledMu.RUnlock()
	if ok {
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	compiledMu.Lock()
	if len(compiledCache) > 1024 { // bounded (§9)
		compiledCache = map[string]*regexp.Regexp{}
	}
	compiledCache[pattern] = re
	compiledMu.Unlock()
	return re
}

// ── matchers ────────────────────────────────────────────────────────────────

type equalsMatcher struct{ t, label string }

func (m equalsMatcher) Type() string      { return m.t }
func (m equalsMatcher) Label() string     { return m.label }
func (m equalsMatcher) EdgeCapable() bool { return true }
func (m equalsMatcher) Validate(mm Match) error {
	return validLiteral("match.value", mm.Value, MaxPatternLen)
}
func (m equalsMatcher) CompileVRL(mm Match) string {
	return fmt.Sprintf("((to_string(%s) ?? \"\") == %s)", vrlPath(mm.Field), vrlString(mm.Value))
}
func (m equalsMatcher) Eval(ev map[string]any, mm Match) bool {
	v, _ := getPath(ev, mm.Field)
	return toStr(v) == mm.Value
}

type containsMatcher struct{}

func (containsMatcher) Type() string      { return MatchContains }
func (containsMatcher) Label() string     { return "Field contains" }
func (containsMatcher) EdgeCapable() bool { return true }
func (containsMatcher) Validate(m Match) error {
	return validLiteral("match.value", m.Value, MaxPatternLen)
}
func (containsMatcher) CompileVRL(m Match) string {
	return fmt.Sprintf("contains(to_string(%s) ?? \"\", %s)", vrlPath(m.Field), vrlString(m.Value))
}
func (containsMatcher) Eval(ev map[string]any, m Match) bool {
	v, _ := getPath(ev, m.Field)
	return strings.Contains(toStr(v), m.Value)
}

type prefixMatcher struct{}

func (prefixMatcher) Type() string      { return MatchPrefix }
func (prefixMatcher) Label() string     { return "Field starts with" }
func (prefixMatcher) EdgeCapable() bool { return true }
func (prefixMatcher) Validate(m Match) error {
	return validLiteral("match.value", m.Value, MaxPatternLen)
}
func (prefixMatcher) CompileVRL(m Match) string {
	return fmt.Sprintf("starts_with(to_string(%s) ?? \"\", %s)", vrlPath(m.Field), vrlString(m.Value))
}
func (prefixMatcher) Eval(ev map[string]any, m Match) bool {
	v, _ := getPath(ev, m.Field)
	return strings.HasPrefix(toStr(v), m.Value)
}

type regexMatcher struct{}

func (regexMatcher) Type() string      { return MatchRegex }
func (regexMatcher) Label() string     { return "Field matches regex" }
func (regexMatcher) EdgeCapable() bool { return true }
func (regexMatcher) Validate(m Match) error {
	return validateRegex("match.value", m.Value)
}
func (regexMatcher) CompileVRL(m Match) string {
	rex, _ := vrlRegex(m.Value)
	if rex == "" {
		return "" // not expressible at the edge; never emit uncompilable VRL
	}
	return fmt.Sprintf("match(to_string(%s) ?? \"\", %s)", vrlPath(m.Field), rex)
}
func (regexMatcher) Eval(ev map[string]any, m Match) bool {
	re := compiled(m.Value)
	if re == nil {
		return false
	}
	v, _ := getPath(ev, m.Field)
	return re.MatchString(toStr(v))
}

func init() {
	RegisterMatcher(equalsMatcher{t: MatchEquals, label: "Field equals"})
	// `attribute` is equals with the operator's vocabulary (service=auth); kept
	// as its own registry entry so its semantics can diverge later without
	// touching every caller.
	RegisterMatcher(equalsMatcher{t: MatchAttribute, label: "Attribute equals"})
	RegisterMatcher(containsMatcher{})
	RegisterMatcher(prefixMatcher{})
	RegisterMatcher(regexMatcher{})

	RegisterAction(redactFieldAction{})
	RegisterAction(redactPatternAction{})
	RegisterAction(maskAction{})
	RegisterAction(dropFieldAction{})
	RegisterAction(setFieldAction{})
	RegisterAction(redactKeysAction{})
	RegisterAction(hashAction{})
	RegisterAction(tagAction{})
	RegisterAction(dropEventAction{})
	RegisterAction(sealAction{})
}

// ── actions ─────────────────────────────────────────────────────────────────

type redactFieldAction struct{}

func (redactFieldAction) Type() string       { return TypeRedactField }
func (redactFieldAction) Label() string      { return TypeLabel[TypeRedactField] }
func (redactFieldAction) UsesPattern() bool  { return false }
func (redactFieldAction) TargetsField() bool { return true }
func (redactFieldAction) Validate(Rule) error {
	return nil
}
func (redactFieldAction) CompileVRL(r Rule) string {
	t := vrlPath(r.Field)
	return fmt.Sprintf("if exists(%s) { %s = %s }", t, t, vrlString(r.ReplacementOrDefault()))
}
func (redactFieldAction) Apply(ev map[string]any, r Rule) bool {
	if _, ok := getPath(ev, r.Field); !ok {
		return false
	}
	p, leaf, ok := parentOf(ev, r.Field)
	if !ok {
		return false
	}
	p[leaf] = r.ReplacementOrDefault()
	return true
}

type redactPatternAction struct{}

func (redactPatternAction) Type() string       { return TypeRedactPattern }
func (redactPatternAction) Label() string      { return TypeLabel[TypeRedactPattern] }
func (redactPatternAction) UsesPattern() bool  { return true }
func (redactPatternAction) TargetsField() bool { return true }
func (redactPatternAction) Validate(r Rule) error {
	switch r.PatternKind {
	case PatternBuiltin:
		if _, ok := ManagedRuleByID(r.Pattern); !ok {
			return fmt.Errorf("unknown managed rule %q", r.Pattern)
		}
	case PatternLiteral:
		if strings.TrimSpace(r.Pattern) == "" {
			return fmt.Errorf("a literal pattern must not be empty")
		}
		return validLiteral("pattern", r.Pattern, MaxPatternLen)
	case PatternRegex:
		return validateRegex("pattern", r.Pattern)
	default:
		return fmt.Errorf("pattern_kind must be builtin, literal or regex")
	}
	return nil
}
func (redactPatternAction) CompileVRL(r Rule) string {
	pat := resolvePattern(r)
	if pat == "" {
		return ""
	}
	rex, _ := vrlRegex(pat)
	if rex == "" {
		return ""
	}
	repl := vrlString(r.ReplacementOrDefault())
	if r.Field == FieldAll {
		// Whole-event sweep: rewrite every string value, then put the
		// pipeline-owned fields back exactly as they were. map_values cannot
		// see keys, so save/restore is the only way to keep a content rule from
		// touching tenancy, time or index routing.
		var save, restore strings.Builder
		for i, f := range protectedFieldOrder {
			fmt.Fprintf(&save, "_p%d = .%s; ", i, f)
			fmt.Fprintf(&restore, "; .%s = _p%d", f, i)
		}
		return fmt.Sprintf(
			"%s. = map_values(., recursive: true) -> |_v| { if is_string(_v) { replace(to_string(_v) ?? \"\", %s, %s) } else { _v } }%s",
			save.String(), rex, repl, restore.String())
	}
	t := vrlPath(r.Field)
	return fmt.Sprintf("if exists(%s) { %s = replace(to_string(%s) ?? \"\", %s, %s) }",
		t, t, t, rex, repl)
}
func (redactPatternAction) Apply(ev map[string]any, r Rule) bool {
	pat := resolvePattern(r)
	re := compiled(pat)
	if re == nil {
		return false
	}
	if r.Field == FieldAll {
		return sweepStrings(ev, re, r.ReplacementOrDefault())
	}
	v, ok := getPath(ev, r.Field)
	if !ok {
		return false
	}
	s := toStr(v)
	next := re.ReplaceAllString(s, r.ReplacementOrDefault())
	p, leaf, ok := parentOf(ev, r.Field)
	if !ok {
		return false
	}
	p[leaf] = next
	// "fired" means the field was rewritten — a pattern that matched nothing is
	// reported honestly as not applied (the preview must not claim a redaction
	// that did not happen).
	return next != s
}

type maskAction struct{}

func (maskAction) Type() string       { return TypeMask }
func (maskAction) Label() string      { return TypeLabel[TypeMask] }
func (maskAction) UsesPattern() bool  { return false }
func (maskAction) TargetsField() bool { return true }
func (maskAction) Validate(r Rule) error {
	if r.KeepLast < 0 || r.KeepLast > 64 {
		return fmt.Errorf("keep_last must be 0..64")
	}
	return nil
}

// maskGlyphs is the source the mask head is sliced from. VRL (0.40) has NO
// repeat() — caught by boot-validating the generated config against the real
// Vector binary — so the head is a slice of this constant, which also bounds
// the work per event. A value longer than MaskHeadCap masks to a capped head
// plus its tail; the value is still fully hidden, the head just stops growing.
const maskGlyphs = "****************************************************************"

// MaskHeadCap is len(maskGlyphs) — the longest mask head the engine emits.
const MaskHeadCap = 64

// maskedValue is THE mask semantics, shared by the simulator and (mirrored in
// VRL) the compiler, so preview and pipeline agree character for character.
// Operates on RUNES, not bytes: VRL's strlen/slice! are character-oriented, so
// a byte-based mask would preview differently than it ships for any multibyte
// value — and could split a UTF-8 rune into invalid output (review B10).
func maskedValue(s string, keep int) string {
	r := []rune(s)
	n := len(r)
	head := n
	tail := ""
	if n > keep {
		head = n - keep
		tail = string(r[n-keep:])
	}
	if head > MaskHeadCap {
		head = MaskHeadCap
	}
	return maskGlyphs[:head] + tail
}

func (maskAction) CompileVRL(r Rule) string {
	keep := r.KeepLastOrDefault()
	t := vrlPath(r.Field)
	g := vrlString(maskGlyphs)
	// _h is the mask-head length, clamped to MaskHeadCap so slice! can never
	// index past the constant (an aborting VRL statement would drop the event).
	return fmt.Sprintf(
		"if exists(%s) { _v = to_string(%s) ?? \"\"; _n = strlen(_v); "+
			"_h = if _n > %d { _n - %d } else { _n }; if _h > %d { _h = %d }; "+
			"_t = if _n > %d { slice!(_v, _n - %d) } else { \"\" }; "+
			"%s = slice!(%s, 0, _h) + _t }",
		t, t, keep, keep, MaskHeadCap, MaskHeadCap, keep, keep, t, g)
}
func (maskAction) Apply(ev map[string]any, r Rule) bool {
	v, ok := getPath(ev, r.Field)
	if !ok {
		return false
	}
	p, leaf, ok := parentOf(ev, r.Field)
	if !ok {
		return false
	}
	p[leaf] = maskedValue(toStr(v), r.KeepLastOrDefault())
	return true
}

type dropFieldAction struct{}

func (dropFieldAction) Type() string        { return TypeDropField }
func (dropFieldAction) Label() string       { return TypeLabel[TypeDropField] }
func (dropFieldAction) UsesPattern() bool   { return false }
func (dropFieldAction) TargetsField() bool  { return true }
func (dropFieldAction) Validate(Rule) error { return nil }
func (dropFieldAction) CompileVRL(r Rule) string {
	return fmt.Sprintf("del(%s)", vrlPath(r.Field))
}
func (dropFieldAction) Apply(ev map[string]any, r Rule) bool {
	p, leaf, ok := parentOf(ev, r.Field)
	if !ok {
		return false
	}
	if _, had := p[leaf]; !had {
		return false
	}
	delete(p, leaf)
	return true
}

type setFieldAction struct{}

func (setFieldAction) Type() string       { return TypeSetField }
func (setFieldAction) Label() string      { return TypeLabel[TypeSetField] }
func (setFieldAction) UsesPattern() bool  { return false }
func (setFieldAction) TargetsField() bool { return true }
func (setFieldAction) Validate(r Rule) error {
	return validLiteral("value", r.Value, 256)
}
func (setFieldAction) CompileVRL(r Rule) string {
	return fmt.Sprintf("%s = %s", vrlPath(r.Field), vrlString(r.Value))
}
func (setFieldAction) Apply(ev map[string]any, r Rule) bool {
	p, leaf, ok := parentOf(ev, r.Field)
	if !ok {
		return false
	}
	p[leaf] = r.Value
	return true
}

type dropEventAction struct{}

func (dropEventAction) Type() string       { return TypeDropEvent }
func (dropEventAction) Label() string      { return TypeLabel[TypeDropEvent] }
func (dropEventAction) UsesPattern() bool  { return false }
func (dropEventAction) TargetsField() bool { return false }
func (dropEventAction) Validate(r Rule) error {
	if r.Match == nil {
		return fmt.Errorf("a drop_event processor requires a match condition (an unguarded drop would discard the whole lane)")
	}
	return nil
}
func (dropEventAction) CompileVRL(Rule) string {
	return fmt.Sprintf(".%s = true", DropField)
}
func (dropEventAction) Apply(ev map[string]any, _ Rule) bool {
	ev[DropField] = true
	return true
}
