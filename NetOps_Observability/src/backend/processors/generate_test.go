package processors

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func validRule(t *testing.T, r Rule) Rule {
	t.Helper()
	if err := r.Validate(); err != nil {
		t.Fatalf("rule must validate: %v (%+v)", err, r)
	}
	return r
}

func TestValidateRejectsInjectionShapes(t *testing.T) {
	bad := []Rule{
		{Lane: "syslog", Type: "redact_field", Field: `msg" } del(.) if true { "`},
		{Lane: "syslog", Type: "redact_field", Field: "tenant_id"},          // protected
		{Lane: "syslog", Type: "redact_field", Field: "log_index_base"},     // protected (index routing)
		{Lane: "syslog", Type: "set_field", Field: "a.b.c.d.e"},             // too deep
		{Lane: "syslog", Type: "redact_pattern", Field: "message", PatternKind: "builtin", Pattern: "not_a_builtin"},
		{Lane: "syslog", Type: "redact_pattern", Field: "message", PatternKind: "regex", Pattern: ".*"}, // no free regex
		{Lane: "nope", Type: "redact_field", Field: "message"},
		{Lane: "syslog", Type: "vrl", Field: "message"}, // no free VRL
		{Lane: "syslog", Type: "set_field", Field: "message", Value: "line1\nline2"},
		{Lane: "syslog", Type: "redact_field", Field: "message", Match: &Match{Field: "sev", Op: "regex", Value: "x"}},
	}
	for i, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("case %d must be rejected: %+v", i, r)
		}
	}
}

func TestGenerateEscapesUserInput(t *testing.T) {
	r := validRule(t, Rule{
		TenantID: "acme", Lane: "syslog", Type: TypeSetField, Enabled: true,
		Field: "note", Value: `x" } .tenant_id = "evil" if true { "`,
	})
	out := GenerateRouterConfig([]Rule{r})
	// The hostile value must appear only inside an escaped string literal.
	if !strings.Contains(out, `\" } .tenant_id = \"evil\" if true { \"`) {
		t.Fatalf("value must be escaped into a string literal:\n%s", out)
	}
	if strings.Contains(out, `.tenant_id = "evil"`) {
		t.Fatalf("INJECTION: unescaped user input reached the VRL:\n%s", out)
	}
}

func TestGenerateShape(t *testing.T) {
	rules := []Rule{
		validRule(t, Rule{TenantID: "acme", Lane: "syslog", Type: TypeRedactPattern, Enabled: true,
			Field: "message", PatternKind: "builtin", Pattern: "email"}),
		validRule(t, Rule{TenantID: "acme", Lane: "syslog", Type: TypeDropField, Enabled: true,
			Field: "secret_field", Match: &Match{Field: "vendor", Op: "equals", Value: "fortinet"}}),
		validRule(t, Rule{TenantID: "globex", Lane: "flows", Type: TypeRedactField, Enabled: true, Field: "note"}),
		{TenantID: "acme", Lane: "syslog", Type: TypeDropField, Field: "x", Enabled: false}, // disabled → absent
	}
	out := GenerateRouterConfig(rules)

	// All five hooks must ALWAYS exist (base config routes sinks through them).
	for _, lane := range []string{"applogs", "syslog", "snmptrap", "cloudlogs", "flows"} {
		if !strings.Contains(out, lane+"_rules:") {
			t.Fatalf("hook %s_rules missing:\n%s", lane, out)
		}
	}
	// Tenant guard wraps every action.
	if !strings.Contains(out, `downcase(to_string(.tenant_id) ?? "") == "acme"`) {
		t.Fatalf("tenant guard missing:\n%s", out)
	}
	// Match guard renders.
	if !strings.Contains(out, `(to_string(.vendor) ?? "") == "fortinet"`) {
		t.Fatalf("match guard missing:\n%s", out)
	}
	// Disabled rule stays out.
	if strings.Contains(out, "del(.x)") {
		t.Fatalf("disabled rule leaked into the config:\n%s", out)
	}
	// Determinism.
	if out != GenerateRouterConfig(rules) {
		t.Fatal("generator must be deterministic (watch-config sees phantom diffs otherwise)")
	}
}

func TestSimulateMirrorsGenerator(t *testing.T) {
	rules := []Rule{
		validRule(t, Rule{ID: "r1", TenantID: "acme", Lane: "syslog", Type: TypeRedactPattern, Enabled: true,
			Field: "message", PatternKind: "builtin", Pattern: "email"}),
		validRule(t, Rule{ID: "r2", TenantID: "acme", Lane: "syslog", Type: TypeDropField, Enabled: true,
			Field: "password"}),
		validRule(t, Rule{ID: "r3", TenantID: "acme", Lane: "syslog", Type: TypeRedactField, Enabled: true,
			Field: "user", Match: &Match{Field: "vendor", Op: "equals", Value: "fortinet"}}),
	}
	ev := map[string]any{
		"tenant_id": "acme", "vendor": "fortinet",
		"message": "login by jsmith@mercy.org failed", "password": "hunter2", "user": "jsmith",
	}
	out, applied := Simulate(rules, "syslog", "acme", ev)
	if got := out["message"]; got != "login by *** failed" {
		t.Fatalf("email must be redacted: %v", got)
	}
	if _, ok := out["password"]; ok {
		t.Fatal("password field must be dropped")
	}
	if out["user"] != Mask {
		t.Fatalf("matched redact_field must mask: %v", out["user"])
	}
	if len(applied) != 3 {
		t.Fatalf("all three rules fired: %+v", applied)
	}
	// The input event is not mutated.
	if ev["password"] != "hunter2" || ev["user"] != "jsmith" {
		t.Fatalf("Simulate must not mutate its input: %+v", ev)
	}

	// Another tenant's event is untouched even if handed the same rules.
	other := map[string]any{"tenant_id": "globex", "message": "a@b.co"}
	out2, applied2 := Simulate(rules, "syslog", "globex", other)
	if out2["message"] != "a@b.co" || len(applied2) != 0 {
		t.Fatalf("TENANT LEAK: acme's rules shaped globex's event: %+v", out2)
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
		t.Fatalf("acme must list only its own rule: %+v", la)
	}
	if _, found, _ := s.Get(ctx, "acme", false, rb.ID); found {
		t.Fatal("TENANT LEAK: acme read globex's rule")
	}
	if _, found, _ := s.Update(ctx, "acme", false, rb.ID, rb); found {
		t.Fatal("TENANT LEAK: acme updated globex's rule")
	}
	if found, _ := s.Delete(ctx, "acme", false, rb.ID); found {
		t.Fatal("TENANT LEAK: acme deleted globex's rule")
	}
	if all, _ := s.AllEnabled(ctx); len(all) != 2 {
		t.Fatalf("the config writer must see every tenant's enabled rules: %+v", all)
	}

	// Persistence round-trip.
	s2 := NewFileStore(s.path)
	l2, _ := s2.List(ctx, "globex", false)
	if len(l2) != 1 {
		t.Fatalf("reload must keep rules: %+v", l2)
	}
}
