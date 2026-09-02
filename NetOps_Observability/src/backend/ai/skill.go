package ai

// skill.go — the SKILLS LAYER (IRIS Phase A): troubleshooting method as DATA,
// not as Go control flow.
//
// Each skill is one `skills/<name>/SKILL.md` file compiled into the binary by
// the embed directive below. A skill states, in frontmatter, WHEN it applies,
// WHICH of our governed read-only tools to gather with, WHAT to look for, and
// WHERE to go next; the prose body below the frontmatter is the method itself,
// handed to the model as reference material.
//
// Why data and not code:
//   - the method is reviewable by a network engineer without reading Go;
//   - the tool plan is DETERMINISTIC and inspectable before a model ever runs;
//   - a decision that points at a skill or a tool which does not exist fails the
//     loader (and therefore CI), so the method cannot drift away from the
//     platform's actual capabilities.
//
// Security stance (CLAUDE.md §15). A skill is server-owned content, never
// client-supplied: it is compiled in, it cannot be uploaded, and nothing in a
// skill can widen what the caller may run. Every gather step is re-gated at
// execution by the Policy Engine and the caller's Principal, and every tool it
// may name is read-only by construction (§4/LLM07 least privilege, LLM08 no
// excessive agency).
//
// FORMAT (a deliberately tiny, strict dialect — not general YAML, so there is no
// parser surface to be surprised by):
//
//	---
//	name: bgp-session-down          # must equal the directory name
//	layer: bgp                      # one of the SkillLayer constants
//	version: 1                      # integer >= 1
//	when_to_use: bgp down, peer idle # comma-separated match phrases
//	symptom_kinds: bgp, routing      # comma-separated symptom classes
//	tools: get_rca_verdict, search_logs   # this skill's tool allowlist
//	gather:
//	  - get_rca_verdict(correlation_id)
//	  - search_logs(device, query=BGP, window=6h)
//	look_for:
//	  - one observation per bullet
//	decisions:
//	  - next=interface-down when the link beneath it is down
//	  - verdict=what a conclusion must state
//	  - escalate=who to hand it to
//	---
//	prose body …
//
// In a gather step, a BARE identifier binds that tool argument from the
// server-resolved entity of the same name (never from the model); `k=v` is a
// literal the skill author chose. A step whose bound entity is unavailable is
// skipped honestly rather than guessed at.

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed skills/*/SKILL.md
var skillsFS embed.FS

// SkillLayer is the OSI-ish layer a skill owns. The eight domain layers are the
// bisection order; `method` is reserved for the single top-level entry skill
// (osi-bisection), which selects among the others rather than owning a layer.
type SkillLayer string

const (
	LayerMethod      SkillLayer = "method"
	LayerPhysical    SkillLayer = "physical"
	LayerL2          SkillLayer = "l2"
	LayerIGP         SkillLayer = "igp"
	LayerBGP         SkillLayer = "bgp"
	LayerPathSeam    SkillLayer = "path_seam"
	LayerApplication SkillLayer = "application"
	LayerSecurity    SkillLayer = "security"
	LayerLogs        SkillLayer = "logs"
)

// skillLayerOrder is the bisection order the method skill follows. Index 0 is
// the entry method; the rest are checked bottom-up.
var skillLayerOrder = []SkillLayer{
	LayerMethod, LayerPhysical, LayerL2, LayerIGP, LayerBGP,
	LayerPathSeam, LayerApplication, LayerSecurity, LayerLogs,
}

func validSkillLayer(l SkillLayer) bool {
	for _, v := range skillLayerOrder {
		if v == l {
			return true
		}
	}
	return false
}

// LayerRank is the bisection position of a layer (lower = checked earlier).
// Unknown layers sort last so they can never pre-empt a real layer.
func LayerRank(l SkillLayer) int {
	for i, v := range skillLayerOrder {
		if v == l {
			return i
		}
	}
	return len(skillLayerOrder)
}

// skillEntities is the closed set of entity names a gather step may bind from.
// The server resolves each of these deterministically (UI context + the
// caller's tenant-scoped inventory) BEFORE any tool runs — the model never
// supplies one, which is what keeps a skill from becoming an injection vector.
var skillEntities = map[string]bool{
	"correlation_id": true, // the RCA case in scope
	"device_id":      true, // canonical inventory id of the resolved device
	"device":         true, // operator-facing name of the resolved device
	"seam":           true, // seam id/type in scope
}

// skillToolAllowlist is the closed set of tool names a skill may name. Every
// entry is READ-ONLY (CapRead) and governed by the Policy Engine at execution.
// A skill naming anything else fails the loader — this is the structural half of
// "the model can never request a device write" (the Policy Engine is the other).
var skillToolAllowlist = map[string]bool{
	// Phase-A additions.
	"run_protocol_diagnostic": true,
	"get_security_findings":   true,
	"get_topology_context":    true,
	"get_case_timeline":       true,
	"get_rca_verdict":         true,
	// Pre-existing governed reads a skill may lean on.
	"get_device_health":          true,
	"search_logs":                true,
	"get_metric_anomalies":       true,
	"get_problem_evidence":       true,
	"get_active_major_incidents": true,
}

// GatherStep is one planned tool call: which tool, which arguments bind from
// resolved entities, and which are literals the skill author fixed.
type GatherStep struct {
	Tool string
	// Bind maps a TOOL ARGUMENT NAME to the entity name it binds from. Today the
	// two are always equal (a bare identifier), but keeping them distinct means a
	// rename on either side is a data edit, not a code edit.
	Bind map[string]string
	// Args are literal argument values chosen by the skill author.
	Args map[string]string
}

// BindOrder is the deterministic (sorted) list of bound argument names, so a
// step renders and audits identically on every run.
func (g GatherStep) BindOrder() []string {
	out := make([]string, 0, len(g.Bind))
	for k := range g.Bind {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SkillDecisionKind is what a decision line does.
type SkillDecisionKind string

const (
	DecisionNext     SkillDecisionKind = "next"     // hand off to another skill
	DecisionVerdict  SkillDecisionKind = "verdict"  // what a conclusion must state
	DecisionEscalate SkillDecisionKind = "escalate" // who owns it beyond us
)

// SkillDecision is one authored decision. Target is the next skill's name for
// DecisionNext and empty otherwise.
type SkillDecision struct {
	Kind   SkillDecisionKind
	Target string
	Reason string
}

// Skill is one parsed, validated troubleshooting method.
type Skill struct {
	Name         string
	Layer        SkillLayer
	Version      int
	WhenToUse    []string // lowercased match phrases
	SymptomKinds []string // lowercased symptom classes
	Tools        []string // this skill's tool allowlist (subset of skillToolAllowlist)
	Gather       []GatherStep
	LookFor      []string
	Decisions    []SkillDecision
	Body         string
}

// Ref is the provenance stamp returned with an answer so the UI can show which
// method produced it.
func (s *Skill) Ref() SkillRef {
	return SkillRef{Name: s.Name, Layer: string(s.Layer), Version: s.Version}
}

// NextSkills lists the skills this one hands off to, in authored order.
func (s *Skill) NextSkills() []string {
	var out []string
	for _, d := range s.Decisions {
		if d.Kind == DecisionNext && d.Target != "" {
			out = append(out, d.Target)
		}
	}
	return out
}

// SkillRef is the answer-level provenance stamp (name + layer + version).
type SkillRef struct {
	Name    string `json:"name"`
	Layer   string `json:"layer"`
	Version int    `json:"version"`
}

// SkillSet is the loaded, validated skill catalog. Immutable after load.
type SkillSet struct {
	byName map[string]*Skill
	order  []string
}

// Names returns every skill name in sorted order.
func (s *SkillSet) Names() []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// Get returns a skill by name.
func (s *SkillSet) Get(name string) (*Skill, bool) {
	if s == nil {
		return nil, false
	}
	sk, ok := s.byName[name]
	return sk, ok
}

// Len reports how many skills loaded.
func (s *SkillSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.order)
}

var reSkillName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// LoadSkills parses and validates every embedded skill. Validation is STRICT and
// whole-set: an unknown layer, an undeclared tool, an unsatisfiable required
// argument, or a `next=` pointing at a skill that does not exist is an error,
// not a warning. A silently-skipped skill would make the assistant claim a
// method it cannot actually run.
func LoadSkills() (*SkillSet, error) {
	entries, err := fs.Glob(skillsFS, "skills/*/SKILL.md")
	if err != nil {
		return nil, fmt.Errorf("skills: glob: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("skills: no SKILL.md files are embedded")
	}
	sort.Strings(entries)
	set := &SkillSet{byName: make(map[string]*Skill, len(entries))}
	for _, p := range entries {
		raw, rerr := skillsFS.ReadFile(p)
		if rerr != nil {
			return nil, fmt.Errorf("skills: read %s: %w", p, rerr)
		}
		dir := path.Base(path.Dir(p))
		sk, perr := parseSkill(dir, string(raw))
		if perr != nil {
			return nil, fmt.Errorf("skills: %s: %w", p, perr)
		}
		if _, dup := set.byName[sk.Name]; dup {
			return nil, fmt.Errorf("skills: duplicate skill %q", sk.Name)
		}
		set.byName[sk.Name] = sk
		set.order = append(set.order, sk.Name)
	}
	sort.Strings(set.order)
	// Whole-set drift check: every `next=` must name a skill that exists.
	for _, n := range set.order {
		for _, d := range set.byName[n].Decisions {
			if d.Kind != DecisionNext {
				continue
			}
			if _, ok := set.byName[d.Target]; !ok {
				return nil, fmt.Errorf("skills: %s: decision next=%q names a skill that does not exist", n, d.Target)
			}
		}
	}
	// Exactly one entry method, so selection always has a deterministic default.
	methods := 0
	for _, n := range set.order {
		if set.byName[n].Layer == LayerMethod {
			methods++
		}
	}
	if methods != 1 {
		return nil, fmt.Errorf("skills: expected exactly 1 method-layer entry skill, found %d", methods)
	}
	return set, nil
}

// parseSkill splits frontmatter from body and validates one skill.
func parseSkill(dir, raw string) (*Skill, error) {
	front, body, err := splitSkillFrontmatter(raw)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("body is empty — a skill without prose teaches nothing")
	}
	fields, blocks, err := parseFrontmatter(front)
	if err != nil {
		return nil, err
	}
	sk := &Skill{Body: strings.TrimSpace(body)}

	sk.Name = strings.TrimSpace(fields["name"])
	switch {
	case sk.Name == "":
		return nil, fmt.Errorf("name is required")
	case !reSkillName.MatchString(sk.Name):
		return nil, fmt.Errorf("name %q must match %s", sk.Name, reSkillName)
	case sk.Name != dir:
		return nil, fmt.Errorf("name %q must equal its directory %q", sk.Name, dir)
	}

	sk.Layer = SkillLayer(strings.TrimSpace(fields["layer"]))
	if !validSkillLayer(sk.Layer) {
		return nil, fmt.Errorf("layer %q is not one of %v", sk.Layer, skillLayerOrder)
	}

	v, verr := strconv.Atoi(strings.TrimSpace(fields["version"]))
	if verr != nil || v < 1 {
		return nil, fmt.Errorf("version must be an integer >= 1 (got %q)", fields["version"])
	}
	sk.Version = v

	sk.WhenToUse = lowerList(splitCommaList(fields["when_to_use"]))
	if len(sk.WhenToUse) == 0 {
		return nil, fmt.Errorf("when_to_use is required — a skill that never matches is dead weight")
	}
	sk.SymptomKinds = lowerList(splitCommaList(fields["symptom_kinds"]))
	if len(sk.SymptomKinds) == 0 {
		return nil, fmt.Errorf("symptom_kinds is required")
	}

	sk.Tools = splitCommaList(fields["tools"])
	if len(sk.Tools) == 0 {
		return nil, fmt.Errorf("tools is required — declare the skill's read-only allowlist")
	}
	declared := make(map[string]bool, len(sk.Tools))
	for _, t := range sk.Tools {
		if !skillToolAllowlist[t] {
			return nil, fmt.Errorf("tool %q is not on the skill tool allowlist (read-only tools only)", t)
		}
		if _, ok := toolMetas[t]; !ok {
			return nil, fmt.Errorf("tool %q has no declared argument schema (toolspec.go)", t)
		}
		declared[t] = true
	}

	sk.LookFor = blocks["look_for"]
	if len(sk.LookFor) == 0 {
		return nil, fmt.Errorf("look_for is required")
	}

	for _, line := range blocks["gather"] {
		step, gerr := parseGatherStep(line, declared)
		if gerr != nil {
			return nil, fmt.Errorf("gather %q: %w", line, gerr)
		}
		sk.Gather = append(sk.Gather, step)
	}
	if len(sk.Gather) == 0 {
		return nil, fmt.Errorf("gather is required — a skill must say what evidence it collects")
	}
	if len(sk.Gather) > MaxSkillToolCalls {
		return nil, fmt.Errorf("gather declares %d steps; the per-turn tool budget is %d", len(sk.Gather), MaxSkillToolCalls)
	}

	for _, line := range blocks["decisions"] {
		d, derr := parseDecision(line)
		if derr != nil {
			return nil, fmt.Errorf("decisions %q: %w", line, derr)
		}
		sk.Decisions = append(sk.Decisions, d)
	}
	if len(sk.Decisions) == 0 {
		return nil, fmt.Errorf("decisions is required — a skill must say where it hands off")
	}
	hasVerdict := false
	for _, d := range sk.Decisions {
		if d.Kind == DecisionVerdict {
			hasVerdict = true
		}
	}
	if !hasVerdict {
		return nil, fmt.Errorf("decisions must include a verdict= line stating what a conclusion says")
	}
	return sk, nil
}

// splitSkillFrontmatter returns the text between the leading `---` fence and
// the closing one, plus everything after it. Named apart from docs_index.go's
// splitFrontmatter: that one parses the docs corpus's own (different) header
// dialect and returns a parsed map — the two must not be confused.
func splitSkillFrontmatter(raw string) (front, body string, err error) {
	s := strings.ReplaceAll(raw, "\r\n", "\n")
	if !strings.HasPrefix(s, "---\n") {
		return "", "", fmt.Errorf("file must start with a --- frontmatter fence")
	}
	rest := s[len("---\n"):]
	end := strings.Index(rest, "\n---\n")
	if end < 0 {
		return "", "", fmt.Errorf("frontmatter fence is not closed")
	}
	return rest[:end], rest[end+len("\n---\n"):], nil
}

// parseFrontmatter reads the strict dialect: `key: value` scalars and `key:` +
// two-space `  - item` blocks. Anything else is an error, so a typo cannot be
// silently dropped.
func parseFrontmatter(front string) (fields map[string]string, blocks map[string][]string, err error) {
	fields = map[string]string{}
	blocks = map[string][]string{}
	current := ""
	for i, line := range strings.Split(front, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "  - ") {
			if current == "" {
				return nil, nil, fmt.Errorf("line %d: list item outside a block key", i+1)
			}
			item := strings.TrimSpace(line[len("  - "):])
			if item == "" {
				return nil, nil, fmt.Errorf("line %d: empty list item", i+1)
			}
			blocks[current] = append(blocks[current], item)
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			return nil, nil, fmt.Errorf("line %d: unexpected indentation (list items use exactly \"  - \")", i+1)
		}
		colon := strings.Index(line, ":")
		if colon <= 0 {
			return nil, nil, fmt.Errorf("line %d: expected \"key: value\" or \"key:\"", i+1)
		}
		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])
		if _, dup := fields[key]; dup {
			return nil, nil, fmt.Errorf("line %d: duplicate key %q", i+1, key)
		}
		if _, dup := blocks[key]; dup {
			return nil, nil, fmt.Errorf("line %d: duplicate key %q", i+1, key)
		}
		if val == "" {
			blocks[key] = nil
			current = key
			continue
		}
		fields[key] = val
		current = ""
	}
	return fields, blocks, nil
}

var reGatherCall = regexp.MustCompile(`^([a-z0-9_]+)\((.*)\)$`)

// parseGatherStep parses `tool(arg, k=v)` and validates it against the tool's
// declared argument schema (toolspec.go) and the skill's own allowlist.
func parseGatherStep(line string, declared map[string]bool) (GatherStep, error) {
	m := reGatherCall.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return GatherStep{}, fmt.Errorf("expected tool(arg, key=value)")
	}
	step := GatherStep{Tool: m[1], Bind: map[string]string{}, Args: map[string]string{}}
	if !declared[step.Tool] {
		return GatherStep{}, fmt.Errorf("tool %q is not in this skill's tools: list", step.Tool)
	}
	meta := toolMetas[step.Tool]
	argOK := make(map[string]bool, len(meta.args))
	for _, a := range meta.args {
		argOK[a.name] = true
	}
	for _, part := range strings.Split(m[2], ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, isLiteral := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		if !argOK[name] {
			return GatherStep{}, fmt.Errorf("%q is not a declared argument of %s", name, step.Tool)
		}
		if _, dup := step.Bind[name]; dup {
			return GatherStep{}, fmt.Errorf("argument %q given twice", name)
		}
		if _, dup := step.Args[name]; dup {
			return GatherStep{}, fmt.Errorf("argument %q given twice", name)
		}
		if isLiteral {
			v := strings.TrimSpace(value)
			if v == "" {
				return GatherStep{}, fmt.Errorf("literal %q has an empty value", name)
			}
			step.Args[name] = v
			continue
		}
		if !skillEntities[name] {
			return GatherStep{}, fmt.Errorf("%q is not a resolvable entity (%v)", name, sortedKeys(skillEntities))
		}
		step.Bind[name] = name
	}
	// Every REQUIRED argument must be satisfiable, or the step could only ever
	// fail at runtime.
	for _, a := range meta.args {
		if !a.required {
			continue
		}
		if _, bound := step.Bind[a.name]; bound {
			continue
		}
		if _, lit := step.Args[a.name]; lit {
			continue
		}
		return GatherStep{}, fmt.Errorf("required argument %q of %s is neither bound nor literal", a.name, step.Tool)
	}
	return step, nil
}

// parseDecision parses `kind=target reason` / `kind=reason`.
func parseDecision(line string) (SkillDecision, error) {
	kindRaw, rest, ok := strings.Cut(strings.TrimSpace(line), "=")
	if !ok {
		return SkillDecision{}, fmt.Errorf("expected kind=…")
	}
	kind := SkillDecisionKind(strings.TrimSpace(kindRaw))
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return SkillDecision{}, fmt.Errorf("decision has no content")
	}
	switch kind {
	case DecisionNext:
		target, reason, _ := strings.Cut(rest, " ")
		target = strings.TrimSpace(target)
		if !reSkillName.MatchString(target) {
			return SkillDecision{}, fmt.Errorf("next= must name a skill (got %q)", target)
		}
		reason = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(reason), "when "))
		return SkillDecision{Kind: kind, Target: target, Reason: reason}, nil
	case DecisionVerdict, DecisionEscalate:
		return SkillDecision{Kind: kind, Reason: rest}, nil
	default:
		return SkillDecision{}, fmt.Errorf("kind %q must be next, verdict or escalate", kind)
	}
}

func splitCommaList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func lowerList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(s))
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
