package processors

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validRule(t *testing.T, r Rule) Rule {
	t.Helper()
	if err := r.Validate(); err != nil {
		t.Fatalf("rule must validate: %v (%+v)", err, r)
	}
	return r
}

// mustGenerate wraps GenerateRouterConfig for the tests that exercise a
// HEALTHY generation path — since the F-11 review fix the generator can fail
// (quarantine stage unrenderable), and these tests must notice, not ignore it.
func mustGenerate(t *testing.T, rules []Rule) string {
	t.Helper()
	out, err := GenerateRouterConfig(rules)
	if err != nil {
		t.Fatalf("GenerateRouterConfig: %v", err)
	}
	return out
}

func TestValidateRejectsUnsafeShapes(t *testing.T) {
	bad := []struct {
		why string
		r   Rule
	}{
		{"VRL injection through the target field", Rule{Lane: "syslog", Type: TypeRedactField, Field: `msg" } del(.) if true { "`}},
		{"protected tenancy field", Rule{Lane: "syslog", Type: TypeRedactField, Field: "tenant_id"}},
		{"protected index-routing field", Rule{Lane: "syslog", Type: TypeRedactField, Field: "log_index_base"}},
		{"path too deep", Rule{Lane: "syslog", Type: TypeSetField, Field: "a.b.c.d.e"}},
		{"unknown managed rule", Rule{Lane: "syslog", Type: TypeRedactPattern, Field: "message", PatternKind: PatternBuiltin, Pattern: "not_a_rule"}},
		{"unknown pattern kind", Rule{Lane: "syslog", Type: TypeRedactPattern, Field: "message", PatternKind: "wat", Pattern: ".*"}},
		{"unknown lane", Rule{Lane: "nope", Type: TypeRedactField, Field: "message"}},
		{"unknown processor type", Rule{Lane: "syslog", Type: "vrl", Field: "message"}},
		{"multi-line value", Rule{Lane: "syslog", Type: TypeSetField, Field: "message", Value: "line1\nline2"}},
		{"unknown match op", Rule{Lane: "syslog", Type: TypeRedactField, Field: "message", Match: &Match{Field: "sev", Op: "sql", Value: "x"}}},
		{"uncompilable regex", Rule{Lane: "syslog", Type: TypeRedactPattern, Field: "message", PatternKind: PatternRegex, Pattern: "([a-z"}},
		{"regex over the length cap", Rule{Lane: "syslog", Type: TypeRedactPattern, Field: "message", PatternKind: PatternRegex, Pattern: strings.Repeat("a", MaxPatternLen+1)}},
		{"too many capture groups", Rule{Lane: "syslog", Type: TypeRedactPattern, Field: "message", PatternKind: PatternRegex, Pattern: strings.Repeat("(a)", MaxCaptureGroups+1)}},
		{"drop_event without a guard", Rule{Lane: "syslog", Type: TypeDropEvent}},
		{"mask keep_last out of range", Rule{Lane: "syslog", Type: TypeMask, Field: "card", KeepLast: 999}},
		{"pattern on a non-pattern type", Rule{Lane: "syslog", Type: TypeDropField, Field: "x", PatternKind: PatternRegex, Pattern: ".*"}},
	}
	for _, c := range bad {
		if err := c.r.Validate(); err == nil {
			t.Errorf("must be rejected (%s): %+v", c.why, c.r)
		}
	}
}

func TestValidateAcceptsCustomRegex(t *testing.T) {
	// Policy (2026-07-31): custom RE2 patterns ARE allowed. Both engines are
	// RE2-family — linear time, no backtracking — so catastrophic backtracking
	// is structurally impossible; the bar is compile-correctness + bounds.
	r := Rule{Lane: "syslog", Type: TypeRedactPattern, Field: "message",
		PatternKind: PatternRegex, Pattern: `Bearer\s+[A-Za-z0-9._-]+`, Replacement: "[TOKEN]"}
	if err := r.Validate(); err != nil {
		t.Fatalf("a safe custom pattern must be accepted: %v", err)
	}
	m := Rule{Lane: "syslog", Type: TypeRedactField, Field: "message",
		Match: &Match{Field: "service", Op: MatchRegex, Value: `^auth(-svc)?$`}}
	if err := m.Validate(); err != nil {
		t.Fatalf("a safe regex matcher must be accepted: %v", err)
	}
}

func TestGenerateEscapesUserInput(t *testing.T) {
	r := validRule(t, Rule{
		TenantID: "acme", Lane: "syslog", Type: TypeSetField, Enabled: true,
		Field: "note", Value: `x" } .tenant_id = "evil" if true { "`,
	})
	out := mustGenerate(t, []Rule{r})
	if !strings.Contains(out, `\" } .tenant_id = \"evil\" if true { \"`) {
		t.Fatalf("value must be escaped into a string literal:\n%s", out)
	}
	if strings.Contains(out, `.tenant_id = "evil"`) {
		t.Fatalf("INJECTION: unescaped user input reached the VRL:\n%s", out)
	}
}

func TestGenerateShapeAndOrdering(t *testing.T) {
	base := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	rules := []Rule{
		validRule(t, Rule{ID: "c", TenantID: "acme", Lane: "syslog", Type: TypeDropField, Enabled: true,
			Field: "secret_c", Order: 30, CreatedAt: base}),
		validRule(t, Rule{ID: "a", TenantID: "acme", Lane: "syslog", Type: TypeRedactPattern, Enabled: true,
			Field: "message", PatternKind: PatternBuiltin, Pattern: "email", Order: 10, CreatedAt: base}),
		validRule(t, Rule{ID: "b", TenantID: "acme", Lane: "syslog", Type: TypeMask, Enabled: true,
			Field: "card", KeepLast: 4, Order: 20, CreatedAt: base}),
		{ID: "off", TenantID: "acme", Lane: "syslog", Type: TypeDropField, Field: "x", Enabled: false},
	}
	out := mustGenerate(t, rules)

	for _, lane := range []string{"applogs", "syslog", "snmptrap", "cloudlogs", "flows"} {
		if !strings.Contains(out, lane+"_rules:") || !strings.Contains(out, lane+"_rules_apply:") {
			t.Fatalf("lane %s missing its apply+filter pair:\n%s", lane, out)
		}
	}
	// Execution ORDER is the contract: order 10 → 20 → 30.
	iA, iB, iC := strings.Index(out, `"a"`), strings.Index(out, `"b"`), strings.Index(out, `"c"`)
	if !(iA > 0 && iA < iB && iB < iC) {
		t.Fatalf("processors must compile in Order sequence (a<b<c): %d %d %d\n%s", iA, iB, iC, out)
	}
	if !strings.Contains(out, `downcase(to_string(.tenant_id) ?? "") == "acme"`) {
		t.Fatalf("tenant guard missing:\n%s", out)
	}
	if strings.Contains(out, "del(.x)") {
		t.Fatalf("disabled processor leaked into the config:\n%s", out)
	}
	// Execution metrics + drop filter must be wired.
	if !strings.Contains(out, "cx_processor_metrics:") || !strings.Contains(out, AppliedField) {
		t.Fatalf("per-processor metrics transform missing:\n%s", out)
	}
	if !strings.Contains(out, "type: filter") || !strings.Contains(out, DropField) {
		t.Fatalf("drop filter missing:\n%s", out)
	}
	if out != mustGenerate(t, rules) {
		t.Fatal("generator must be deterministic (watch-config sees phantom diffs otherwise)")
	}
}

// The core anti-drift guarantee: compiler and simulator dispatch through the
// SAME registry entry, so every action/matcher that compiles also evaluates.
func TestEveryRegisteredPluginCompilesAndEvaluates(t *testing.T) {
	for _, a := range ActionCatalog() {
		r := Rule{TenantID: "acme", Lane: "syslog", Type: a.Type, Enabled: true, Field: "message"}
		if !a.TargetsField {
			r.Field = ""
			r.Match = &Match{Field: "service", Op: MatchEquals, Value: "x"}
		}
		// Pattern-bearing actions (redact_pattern, tag) need a detector;
		// key-scoped actions need a key list.
		if spec, ok := lookupAction(a.Type); ok && spec.UsesPattern() {
			r.PatternKind, r.Pattern = PatternBuiltin, "email"
		}
		if a.Type == TypeRedactKeys {
			r.Keys = []string{"password"}
		}
		// seal needs a configured engine and a data type; without custody the
		// action is unavailable by design (see seal.go), so the guard installs a
		// stub rather than exempting seal from the coverage requirement.
		if a.Type == TypeSeal {
			withSealEngine(t, newStubSealEngine())
			r.DataType = "card"
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("action %s: representative rule must validate: %v", a.Type, err)
		}
		spec, ok := lookupAction(a.Type)
		if !ok {
			t.Fatalf("action %s registered in the catalog but not the registry", a.Type)
		}
		if spec.CompileVRL(r) == "" {
			t.Errorf("action %s compiles to nothing", a.Type)
		}
	}
	for _, m := range MatcherCatalog() {
		val := "x"
		if m.Type == MatchRegex {
			val = "^x$"
		}
		mm := Match{Field: "service", Op: m.Type, Value: val}
		spec, ok := lookupMatcher(m.Type)
		if !ok {
			t.Fatalf("matcher %s registered in the catalog but not the registry", m.Type)
		}
		if err := spec.Validate(mm); err != nil {
			t.Errorf("matcher %s: representative config must validate: %v", m.Type, err)
		}
		if spec.CompileVRL(mm) == "" {
			t.Errorf("matcher %s compiles to nothing", m.Type)
		}
		if !spec.Eval(map[string]any{"service": "x"}, mm) {
			t.Errorf("matcher %s must evaluate true on its own representative case", m.Type)
		}
	}
}

func TestSimulateRunsTheOrderedChain(t *testing.T) {
	base := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	rules := []Rule{
		validRule(t, Rule{ID: "r1", Name: "Redact emails", TenantID: "acme", Lane: "syslog",
			Type: TypeRedactPattern, Enabled: true, Field: "message",
			PatternKind: PatternBuiltin, Pattern: "email", Replacement: "[EMAIL]", Order: 10, CreatedAt: base}),
		validRule(t, Rule{ID: "r2", TenantID: "acme", Lane: "syslog", Type: TypeDropField,
			Enabled: true, Field: "password", Order: 20, CreatedAt: base}),
		validRule(t, Rule{ID: "r3", TenantID: "acme", Lane: "syslog", Type: TypeMask,
			Enabled: true, Field: "card", KeepLast: 4, Order: 30, CreatedAt: base}),
		validRule(t, Rule{ID: "r4", TenantID: "acme", Lane: "syslog", Type: TypeRedactField,
			Enabled: true, Field: "user", Replacement: "[USER]", Order: 40, CreatedAt: base,
			Match: &Match{Field: "vendor", Op: MatchEquals, Value: "fortinet"}}),
	}
	ev := map[string]any{
		"tenant_id": "acme", "vendor": "fortinet",
		"message": "login by jsmith@mercy.org failed", "password": "hunter2",
		"card": "4111111111111111", "user": "jsmith",
	}
	res := SimulateChain(rules, "syslog", "acme", ev)

	if got := res.Event["message"]; got != "login by [EMAIL] failed" {
		t.Fatalf("managed-rule redaction with a custom token: %v", got)
	}
	if _, ok := res.Event["password"]; ok {
		t.Fatal("password field must be removed")
	}
	if got := res.Event["card"]; got != "************1111" {
		t.Fatalf("mask must keep the last 4: %v", got)
	}
	if res.Event["user"] != "[USER]" {
		t.Fatalf("guarded redact must fire on a match: %v", res.Event["user"])
	}
	if len(res.Applied) != 4 || res.Applied[0].RuleID != "r1" || res.Applied[3].RuleID != "r4" {
		t.Fatalf("applied list must follow execution order: %+v", res.Applied)
	}
	if res.Applied[0].Processor != "Redact emails" {
		t.Fatalf("applied entry must carry the display name: %+v", res.Applied[0])
	}
	if res.Dropped {
		t.Fatal("no drop_event processor fired")
	}
	if ev["password"] != "hunter2" || ev["user"] != "jsmith" {
		t.Fatalf("dry-run must not mutate its input: %+v", ev)
	}

	// Another tenant's event is untouched even given the same rules.
	other := SimulateChain(rules, "syslog", "globex", map[string]any{"tenant_id": "globex", "message": "a@b.co"})
	if other.Event["message"] != "a@b.co" || len(other.Applied) != 0 {
		t.Fatalf("TENANT LEAK in simulation: %+v", other)
	}
}

func TestSimulateReportsDrop(t *testing.T) {
	r := validRule(t, Rule{ID: "d", TenantID: "acme", Lane: "syslog", Type: TypeDropEvent, Enabled: true,
		Match: &Match{Field: "level", Op: MatchEquals, Value: "debug"}})
	res := SimulateChain([]Rule{r}, "syslog", "acme", map[string]any{"tenant_id": "acme", "level": "debug"})
	if !res.Dropped {
		t.Fatal("a matching drop_event must report the event as dropped")
	}
	if _, leaked := res.Event[DropField]; leaked {
		t.Fatal("the drop marker is plumbing and must not appear in the previewed event")
	}
	keep := SimulateChain([]Rule{r}, "syslog", "acme", map[string]any{"tenant_id": "acme", "level": "error"})
	if keep.Dropped {
		t.Fatal("a non-matching drop_event must not drop")
	}
}

func TestManagedRulesCatalog(t *testing.T) {
	cat := ManagedRules()
	if len(cat) < 6 {
		t.Fatalf("catalog looks empty: %d", len(cat))
	}
	for _, r := range cat {
		if r.ID == "" || r.Name == "" || r.Version < 1 {
			t.Errorf("managed rule incomplete: %+v", r)
		}
		// A detector is EITHER content-scoped (a pattern) or key-scoped (a key
		// list) — never neither.
		if r.Pattern == "" && len(r.Keys) == 0 {
			t.Errorf("managed rule %s has neither a pattern nor keys", r.ID)
		}
		if r.Pattern != "" && compiled(r.Pattern) == nil {
			t.Errorf("managed rule %s has an uncompilable pattern", r.ID)
		}
	}
	// Cloning produces a NORMAL processor that validates and records provenance.
	clone, ok := CloneManagedRule("jwt", "syslog", "message")
	if !ok {
		t.Fatal("clone must succeed for a known rule")
	}
	clone.TenantID = "acme"
	if err := clone.Validate(); err != nil {
		t.Fatalf("a cloned processor must validate: %v", err)
	}
	if clone.Source != SourceManaged || clone.ManagedRuleID != "jwt" {
		t.Fatalf("clone must be badged managed: %+v", clone)
	}
	if _, ok := CloneManagedRule("nope", "syslog", "message"); ok {
		t.Fatal("cloning an unknown rule must fail")
	}
}

func TestSensitiveDataDetectorExtensionPoint(t *testing.T) {
	var d SensitiveDataDetector = ManagedRuleDetector{RuleID: "email"}
	found := d.Detect(map[string]any{
		"message": "contact jsmith@mercy.org",
		"nested":  map[string]any{"cc": "nothing here"},
	})
	if len(found) != 1 || !found[0].Detected || found[0].Location != "message" {
		t.Fatalf("detector must locate the finding: %+v", found)
	}
	if strings.Contains(found[0].Sample, "jsmith@mercy.org") {
		t.Fatalf("a finding must not carry the raw secret: %+v", found[0])
	}
	// A checksum-bearing rule reports a CANDIDATE, not a certainty.
	cc := ManagedRuleDetector{RuleID: "credit_card"}.Detect(map[string]any{"m": "4111 1111 1111 1111"})
	if len(cc) != 1 || cc[0].Confidence >= 1 {
		t.Fatalf("checksum-pending finding must be < 1.0 confidence: %+v", cc)
	}
}

func TestFileStoreTenantIsolation(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore(filepath.Join(t.TempDir(), "processors.json"))
	mk := func(tenant string) Rule {
		r, err := s.Create(ctx, tenant, false, validRule(t, Rule{
			TenantID: tenant, Lane: "syslog", Type: TypeDropField, Field: "secret", Enabled: true,
		}))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	ra := mk("acme")
	rb := mk("globex")

	la, _ := s.List(ctx, "acme", false)
	if len(la) != 1 || la[0].ID != ra.ID {
		t.Fatalf("acme must list only its own processor: %+v", la)
	}
	if _, found, _ := s.Get(ctx, "acme", false, rb.ID); found {
		t.Fatal("TENANT LEAK: acme read globex's processor")
	}
	if _, found, _ := s.Update(ctx, "acme", false, rb.ID, rb); found {
		t.Fatal("TENANT LEAK: acme updated globex's processor")
	}
	if found, _ := s.Delete(ctx, "acme", false, rb.ID); found {
		t.Fatal("TENANT LEAK: acme deleted globex's processor")
	}
	if all, _ := s.AllEnabled(ctx); len(all) != 2 {
		t.Fatalf("the config writer must see every tenant's enabled processors: %+v", all)
	}

	s2 := NewFileStore(s.path)
	l2, _ := s2.List(ctx, "globex", false)
	if len(l2) != 1 {
		t.Fatalf("reload must keep processors: %+v", l2)
	}
}

// The checked-in seed the installer copies (and preflight boot-validates) IS
// the generator's zero-rule output. Without this pin, any generator change
// silently desynchronizes them — a cold start would boot yesterday's topology
// while the api writes today's (review B11).
func TestDefaultConfigMatchesGenerator(t *testing.T) {
	const seed = "../../../deployment/docker/vector-router/processors-default.yaml"
	want, err := os.ReadFile(seed)
	if err != nil {
		t.Skipf("seed file not readable from this tree: %v", err)
	}
	if got := mustGenerate(t, nil); got != string(want) {
		t.Errorf("processors-default.yaml is stale — regenerate it from GenerateRouterConfig(nil).\n"+
			"got %d bytes, seed %d bytes", len(got), len(want))
	}
}

// Mask must agree between the compiler and the simulator for MULTIBYTE values
// too: VRL's strlen/slice! are character-oriented, so a byte-based Go mask
// would preview differently than it ships — and could emit an invalid rune.
func TestMaskIsRuneSafe(t *testing.T) {
	r := validRule(t, Rule{ID: "m", TenantID: "acme", Lane: "syslog", Type: TypeMask,
		Enabled: true, Field: "who", KeepLast: 2})
	res := SimulateChain([]Rule{r}, "syslog", "acme",
		map[string]any{"tenant_id": "acme", "who": "café-naïve"})
	got, _ := res.Event["who"].(string)
	if []rune(got)[len([]rune(got))-2:][0] != 'v' {
		t.Fatalf("mask must keep the last 2 RUNES: %q", got)
	}
	if strings.ContainsRune(got, '\uFFFD') {
		t.Fatalf("mask split a UTF-8 rune: %q", got)
	}
}

// Vector interpolates $VAR in the CONFIG FILE before VRL parses it, so a `$`
// in a generated literal — a regex end-anchor, or a capture reference in a
// replacement — makes the router refuse to start and freezes EVERY tenant's
// processors. Both must be escaped as `$$`.
func TestGeneratedLiteralsEscapeDollar(t *testing.T) {
	r := validRule(t, Rule{
		ID: "d", TenantID: "acme", Lane: "syslog", Type: TypeRedactPattern, Enabled: true,
		Field: "message", PatternKind: PatternRegex, Pattern: `secret=[a-z]+$`,
		Replacement: "$1[GONE]",
	})
	out := mustGenerate(t, []Rule{r})
	for _, bad := range []string{"[a-z]+$'", `"$1[GONE]"`} {
		if strings.Contains(out, bad) {
			t.Fatalf("unescaped $ reached the config (%q) — Vector would refuse to start:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "[a-z]+$$'") || !strings.Contains(out, `$$1[GONE]`) {
		t.Fatalf("both the pattern and the replacement must escape $ as $$:\n%s", out)
	}
}

// The compiler and the simulator must agree about WHAT a processor targets, not
// just how it transforms. A whole-event sweep that compiled to the single-field
// form emitted `.*` — invalid VRL that took the entire lane's config down,
// while the simulator happily previewed a correct sweep. (That drift shipped
// once; this test is why it cannot again.)
func TestFieldAllCompilesAsASweep(t *testing.T) {
	r := validRule(t, Rule{
		ID: "s", TenantID: "acme", Lane: "syslog", Type: TypeRedactPattern, Enabled: true,
		Field: FieldAll, PatternKind: PatternBuiltin, Pattern: "email",
	})
	out := mustGenerate(t, []Rule{r})
	if strings.Contains(out, ".*") {
		t.Fatalf("FieldAll must not compile to the single-field form (invalid VRL):\n%s", out)
	}
	if !strings.Contains(out, "map_values(., recursive: true)") {
		t.Fatalf("FieldAll must compile to a recursive sweep:\n%s", out)
	}
	// The sweep must save AND restore every pipeline-owned field.
	for _, f := range protectedFieldOrder {
		if !strings.Contains(out, "= ."+f+";") && !strings.Contains(out, "."+f+" = _p") {
			t.Fatalf("sweep must preserve pipeline-owned field %q:\n%s", f, out)
		}
	}
}

// TestGeneratedConfigSurvivesMultilineActionVRL is the F-6 regression pin
// (assurance run 2026-08-09): the seal action compiles to MULTI-LINE VRL, and
// the generator used to splice it into the `source: |` block scalar without
// re-indenting — continuation lines landed at column 1, the YAML never parsed,
// and Vector refused every processor config for every tenant while a seal rule
// existed. Vector kept the old topology (fail-safe held), but the whole
// processors plane was undeliverable.
//
// The pin is structural, not a YAML library round-trip (§6: no yaml dependency):
// inside every `source: |` block, each non-empty line must be indented past the
// block scalar's own indentation, or YAML terminates the block early and reads
// the remainder as keys.
func TestGeneratedConfigSurvivesMultilineActionVRL(t *testing.T) {
	withSealEngine(t, newStubSealEngine()) // stub emits a multi-line snippet, like the real sealing.SealVRL
	rules := []Rule{
		validRule(t, Rule{ID: "s1", TenantID: "acme", Lane: "snmptrap", Type: TypeSeal, Enabled: true,
			Field: "secret_note", DataType: "note", Order: 1}),
	}
	out := mustGenerate(t, rules)

	if !strings.Contains(out, "<enc:v1:stub>") {
		t.Fatalf("seal rule did not compile into the config:\n%s", out)
	}

	// An escaped snippet line is indistinguishable from a legitimate next
	// element by indent alone (the escape IS a dedent), so pin the generator's
	// actual emission grammar: the only column-0 lines it writes are comments
	// and the single `transforms:` key, and everything inside a rule chain sits
	// at indent >= 6. Any other shallow line is VRL that fell out of its block.
	lines := strings.Split(out, "\n")
	indentOf := func(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }
	for i, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		ind := indentOf(ln)
		if ind == 0 && trimmed != "transforms:" {
			t.Fatalf("line %d sits at column 0 but is not a generator top-level key — VRL escaped its `source: |` block (the F-6 YAML break):\n%q\ncontext:\n%s",
				i+1, ln, strings.Join(lines[max(0, i-3):min(len(lines), i+2)], "\n"))
		}
		if ind == 1 || ind == 3 || ind == 5 {
			t.Fatalf("line %d has indent %d, which the generator never emits — VRL escaped its block:\n%q", i+1, ind, ln)
		}
	}
	// And the snippet's own lines must be inside the chain body (>= 6).
	for i, ln := range lines {
		if strings.Contains(ln, "<enc:v1:stub>") && indentOf(ln) < 6 {
			t.Fatalf("line %d: seal snippet line sits at indent %d (< 6), outside the source block:\n%q", i+1, indentOf(ln), ln)
		}
	}
	// VRL discipline for the composed rule: a multi-line action's trailing
	// newline must not push the "; stamp" separator to line start — a leading
	// ";" is a VRL syntax error the real router refuses (proven live
	// 2026-08-09, the F-6 follow-up).
	for i, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), ";") {
			t.Fatalf("line %d starts with ';' — VRL rejects a leading semicolon:\n%q", i+1, ln)
		}
	}
}
