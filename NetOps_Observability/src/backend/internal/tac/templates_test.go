package tac

// templates_test.go — the command REVIEW and TEMPLATE guarantees (tracker 250).
//
// The one property this file exists to prove, over and over from different
// angles: an edit CHOOSES AMONG OUTPUT COMMANDS and never widens what may run.
// Every other assertion here supports that one.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/protocoldiag"
)

func testValidator(t *testing.T) *TemplateValidator {
	t.Helper()
	v, err := NewTemplateValidator(mustCatalog(t))
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	return v
}

// TestValidatorRefusesEveryForbiddenFamilyOnEveryDialect walks the LOADED policy
// itself rather than a hand-written list, so a rule added to forbidden.yaml
// tomorrow is covered by this test today. For each rule it builds the smallest
// command that hits it and asserts the validator refuses it BY FAMILY.
func TestValidatorRefusesEveryForbiddenFamilyOnEveryDialect(t *testing.T) {
	v := testValidator(t)
	pol := v.cat.Policy()
	if pol == nil {
		t.Fatal("the catalog carries no command policy")
	}
	rules := pol.Rules()
	if len(rules) == 0 {
		t.Fatal("the policy has no rules — this guard would be vacuous")
	}
	families := map[string]int{}
	checked := 0
	for _, r := range rules {
		cmd := strings.Join(r.Tokens, " ")
		// A rule with an `except:` leaf may be exempted by a longer form; the
		// bare rule text itself must still be refused.
		for _, dialect := range append([]string{r.Dialect}, "cisco-iosxe") {
			if dialect == "" {
				dialect = "cisco-iosxe"
			}
			lv := v.ValidateOne(dialect, cmd)
			if lv.OK {
				t.Errorf("%s: %q was ACCEPTED — the output-only policy must refuse it", dialect, cmd)
				continue
			}
			if r.Dialect == "" || r.Dialect == dialect {
				if lv.Family != r.Family {
					// A longer rule may have matched first; that is still a
					// refusal by the policy, which is what matters. Only a
					// refusal with NO family would mean the policy was bypassed
					// and some other check happened to catch it.
					if lv.Family == "" {
						t.Errorf("%s: %q was refused, but not by the policy (%q)", dialect, cmd, lv.Reason)
					}
				}
				if lv.Family != "" && lv.Rule == "" {
					t.Errorf("%s: %q was refused without naming the rule", dialect, cmd)
				}
			}
			checked++
		}
		families[r.Family]++
	}
	for _, f := range forbiddenFamilies {
		if families[f] == 0 {
			t.Errorf("the policy carries no %q rule — this test cannot prove that family is refused", f)
		}
	}
	if checked == 0 {
		t.Fatal("nothing was checked")
	}
}

// TestValidatorAcceptsBoundedProbesAndRefusesFloods — the owner allowed ping and
// traceroute, not floods, and the boundary is the bounded-probe grammar.
func TestValidatorAcceptsBoundedProbesAndRefusesFloods(t *testing.T) {
	v := testValidator(t)
	for _, ok := range []string{
		"ping 10.0.0.1 repeat 5",
		"traceroute 10.0.0.1",
	} {
		if lv := v.ValidateOne("cisco-iosxe", ok); !lv.OK {
			t.Errorf("%q must be accepted (bounded probe): %s", ok, lv.Reason)
		}
	}
	for _, bad := range []string{
		"ping 10.0.0.1 repeat 100000",
		"ping",
		"ping 10.0.0.1 size 90000",
	} {
		if lv := v.ValidateOne("cisco-iosxe", bad); lv.OK {
			t.Errorf("%q must be refused — it is outside the bounded-probe limits", bad)
		}
	}
}

// TestValidatorRefusesNonOutputCommands — the read-only grammar, which is what
// keeps "flexibility" from meaning "any command".
func TestValidatorRefusesNonOutputCommands(t *testing.T) {
	v := testValidator(t)
	for _, bad := range []string{
		"traceroute 10.0.0.1; show version",
		"show version > /tmp/x",
		"show version | tee /tmp/x",
		"bash",
		"show run\nconfigure terminal",
		strings.Repeat("show ", 200),
		"show ver\x00sion",
	} {
		if lv := v.ValidateOne("cisco-iosxe", bad); lv.OK {
			t.Errorf("%q must be refused by the read-only grammar", bad)
		}
	}
}

// TestValidatorLabelsCatalogAndCustomOrigins — the honesty label. A catalog line
// carries the intent; a custom line carries the "never run here" caveat.
func TestValidatorLabelsCatalogAndCustomOrigins(t *testing.T) {
	v := testValidator(t)
	lv := v.ValidateOne("cisco-iosxe", "show version")
	if !lv.OK || lv.Origin != OriginCatalog {
		t.Fatalf("`show version` on IOS-XE should be a catalog line, got ok=%v origin=%q", lv.OK, lv.Origin)
	}
	custom := v.ValidateOne("cisco-iosxe", "show ip nhrp brief detail summary")
	if !custom.OK {
		t.Fatalf("a read-only custom command must be accepted: %s", custom.Reason)
	}
	if custom.Origin != OriginCustom {
		t.Fatalf("expected a custom origin, got %q", custom.Origin)
	}
	if !strings.Contains(custom.Note, "never run it on this platform") {
		t.Fatalf("a custom line must carry the unverified caveat, got %q", custom.Note)
	}
}

// TestDefaultTemplatesAreDeterministic — the defaults are GENERATED, so the same
// catalog must always produce byte-identical templates in the same order. A
// generator that drifted would silently change what an operator's saved fork is
// diffed against.
func TestDefaultTemplatesAreDeterministic(t *testing.T) {
	cat := mustCatalog(t)
	a := cat.DefaultTemplates()
	b := cat.DefaultTemplates()
	if len(a) == 0 {
		t.Fatal("the catalog generated no default templates")
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("DefaultTemplates is not deterministic")
	}
	seen := map[string]bool{}
	for _, tpl := range a {
		if seen[tpl.ID] {
			t.Fatalf("duplicate default template id %q", tpl.ID)
		}
		seen[tpl.ID] = true
		if tpl.Source != SourceCorrelixDefault {
			t.Fatalf("%s is not marked as a Correlix default", tpl.ID)
		}
		if tpl.Editable() {
			t.Fatalf("%s reports itself editable", tpl.ID)
		}
		if !IsDefaultTemplateID(tpl.ID) {
			t.Fatalf("%s is outside the correlix: id namespace", tpl.ID)
		}
		if len(tpl.Steps) == 0 {
			t.Fatalf("%s has no commands", tpl.ID)
		}
	}
}

// TestEveryDefaultCommandPassesTheOutputOnlyPolicy is the load-bearing one: the
// defaults Correlix SHIPS are held to exactly the rule a customer's own commands
// are held to. It also proves a default never carries an unfilled placeholder,
// a consent command or a session-scoped setter.
func TestEveryDefaultCommandPassesTheOutputOnlyPolicy(t *testing.T) {
	cat := mustCatalog(t)
	v := testValidator(t)
	n := 0
	for _, tpl := range cat.DefaultTemplates() {
		for i, st := range tpl.Steps {
			lv := v.ValidateOne(tpl.Dialect, st.Command)
			if !lv.OK {
				t.Errorf("%s step %d (%q) fails the policy Correlix applies to customers: %s",
					tpl.ID, i, st.Command, lv.Reason)
			}
			if lv.Origin != OriginCatalog {
				t.Errorf("%s step %d (%q) is not a rendering of an authored command", tpl.ID, i, st.Command)
			}
			if hasUnfilledPlaceholder(st.Command) {
				t.Errorf("%s step %d (%q) carries an unfilled placeholder", tpl.ID, i, st.Command)
			}
			n++
		}
	}
	if n == 0 {
		t.Fatal("no default command was checked")
	}
}

// ── the review ──────────────────────────────────────────────────────────────

func reviewPlan(t *testing.T) *Plan {
	t.Helper()
	p := testPlan(t)
	if len(p.Steps) < 3 {
		t.Fatalf("the IOS-XE ospf-adjacency plan has only %d steps; this test needs at least 3", len(p.Steps))
	}
	return p
}

// TestReviewKeepsExactlyTheApprovedList — remove two, add one, reorder.
func TestReviewKeepsExactlyTheApprovedList(t *testing.T) {
	v := testValidator(t)
	p := reviewPlan(t)
	// Keep the plan's DISTINCT commands except the first two, in reverse order,
	// plus one custom output command the catalog does not carry. Distinct
	// matters: two intents can legitimately bind the same command (`show
	// version` is both system.version and system.uptime on IOS-XE), and dropping
	// one of those changes nothing about the command set.
	var distinct []string
	seenCmd := map[string]bool{}
	for _, st := range p.Steps {
		k := normCommandKey(st.Command)
		if seenCmd[k] {
			continue
		}
		seenCmd[k] = true
		distinct = append(distinct, st.Command)
	}
	if len(distinct) < 3 {
		t.Fatalf("the plan has only %d distinct commands; this test needs at least 3", len(distinct))
	}
	var steps []ReviewedStep
	for i := len(distinct) - 1; i >= 2; i-- {
		steps = append(steps, ReviewedStep{Command: distinct[i]})
	}
	const custom = "show ip nhrp brief detail summary"
	steps = append(steps, ReviewedStep{Command: custom, Note: "the tunnel is the suspect"})

	out, res, err := v.Review(p, steps, TemplateRef{ID: "correlix:cisco-iosxe:baseline", Name: "x", Source: SourceCorrelixDefault, Version: 1})
	if err != nil {
		t.Fatalf("review: %v (%s)", err, firstRefusal(res))
	}
	if len(out.Steps) != len(steps) {
		t.Fatalf("the reviewed plan has %d steps, the operator approved %d", len(out.Steps), len(steps))
	}
	for i, s := range steps {
		if out.Steps[i].Command != strings.TrimSpace(s.Command) {
			t.Fatalf("step %d is %q, the operator approved %q", i, out.Steps[i].Command, s.Command)
		}
	}
	if !out.Reviewed {
		t.Fatal("the reviewed plan is not marked reviewed")
	}
	if out.Template.ID != "correlix:cisco-iosxe:baseline" {
		t.Fatalf("the template ref was lost: %+v", out.Template)
	}
	// The edits must name BOTH removals and the addition.
	removed, added := 0, 0
	for _, e := range out.Edits {
		switch e.Kind {
		case EditRemoved:
			removed++
		case EditAdded:
			added++
			if e.Command == custom && e.Origin != OriginCustom {
				t.Errorf("the added custom command is not labelled custom: %+v", e)
			}
		}
	}
	if removed != 2 {
		t.Fatalf("expected 2 removals in the edit list, got %d (%+v)", removed, out.Edits)
	}
	if added != 1 {
		t.Fatalf("expected 1 addition in the edit list, got %d (%+v)", added, out.Edits)
	}
	// The custom step inherits the package budgets — a client cannot raise them.
	last := out.Steps[len(out.Steps)-1]
	if last.MaxBytes != defaultMaxOutputBytes || last.TimeoutSeconds != int(defaultCommandTimeout/time.Second) {
		t.Fatalf("a custom step did not inherit the package budgets: %+v", last)
	}
	if !strings.Contains(last.Note, "the tunnel is the suspect") {
		t.Fatalf("the operator's per-step note was dropped: %q", last.Note)
	}
}

// TestReviewRecordsAReorderOnItsOwn — the same set in a different order is still
// an edit a bundle reader is entitled to see.
func TestReviewRecordsAReorderOnItsOwn(t *testing.T) {
	v := testValidator(t)
	p := reviewPlan(t)
	seenCmd := map[string]bool{}
	var distinct []string
	for _, st := range p.Steps {
		k := normCommandKey(st.Command)
		if seenCmd[k] {
			continue
		}
		seenCmd[k] = true
		distinct = append(distinct, st.Command)
	}
	steps := make([]ReviewedStep, 0, len(distinct))
	for i := len(distinct) - 1; i >= 0; i-- {
		steps = append(steps, ReviewedStep{Command: distinct[i]})
	}
	out, _, err := v.Review(p, steps, TemplateRef{})
	if err != nil {
		t.Fatalf("review: %v", err)
	}
	if len(out.Edits) != 1 || out.Edits[0].Kind != EditReordered {
		t.Fatalf("expected exactly one reorder edit, got %+v", out.Edits)
	}
}

// TestReviewRefusesATamperedListAsAWhole — the acceptance case. A client that
// slips a config command into the approved list is refused ENTIRELY, and the
// refusal names the line. Nothing is silently dropped.
func TestReviewRefusesATamperedListAsAWhole(t *testing.T) {
	v := testValidator(t)
	p := reviewPlan(t)
	steps := []ReviewedStep{
		{Command: p.Steps[0].Command},
		{Command: "configure terminal"},
		{Command: p.Steps[1].Command},
	}
	out, res, err := v.Review(p, steps, TemplateRef{})
	if err == nil {
		t.Fatal("a tampered list was accepted")
	}
	if out != nil {
		t.Fatal("a refused review still produced a plan")
	}
	if res.OK || res.Refused != 1 {
		t.Fatalf("expected exactly one refused line, got ok=%v refused=%d", res.OK, res.Refused)
	}
	line := res.Lines[1]
	if line.OK || line.Family != FamilyConfig {
		t.Fatalf("the config command was not refused by the config family: %+v", line)
	}
	if !strings.Contains(firstRefusal(res), "configure terminal") {
		t.Fatalf("the refusal does not name the line: %q", firstRefusal(res))
	}
	// And the other two lines are reported as fine, so the operator can see
	// exactly which one is the problem.
	if !res.Lines[0].OK || !res.Lines[2].OK {
		t.Fatal("the refusal contaminated the lines that were valid")
	}
}

// TestReviewRefusesARestartAndADaemonLine — the other two families, through the
// same path, because "config only" would be a partial rule.
func TestReviewRefusesARestartAndADaemonLine(t *testing.T) {
	v := testValidator(t)
	p := reviewPlan(t)
	for _, bad := range []string{"reload", "clear ip bgp *"} {
		_, res, err := v.Review(p, []ReviewedStep{{Command: p.Steps[0].Command}, {Command: bad}}, TemplateRef{})
		if err == nil {
			t.Fatalf("%q was accepted into a reviewed collection", bad)
		}
		if res.Lines[1].Family == "" {
			t.Fatalf("%q was refused without naming a policy family: %+v", bad, res.Lines[1])
		}
	}
}

// ── the per-collection allow set ────────────────────────────────────────────

// TestReviewRegistryOpensAndClosesWithTheCollection — a custom command reaches
// the wire ONLY while its collection runs, and only for its own device.
func TestReviewRegistryOpensAndClosesWithTheCollection(t *testing.T) {
	reg := NewReviewRegistry()
	g := NewGate(mustCatalog(t), WithReviewRegistry(reg))
	src := iosxeDevice()
	dev := protocoldiag.Device{ID: src.ID, Hostname: src.Hostname, Platform: src.Platform, TenantID: src.TenantID}
	const custom = "show ip nhrp brief detail summary"

	if g.Allows(dev, custom) {
		t.Fatal("a custom command is allowed with no review registered")
	}
	reg.Register(dev.ID, []string{custom})
	if !g.Allows(dev, custom) {
		t.Fatal("a registered, re-validated custom command is refused at the gate")
	}
	// Another device does not inherit it.
	other := dev
	other.ID = "some-other-device"
	if g.Allows(other, custom) {
		t.Fatal("one device's reviewed command leaked to another device")
	}
	// A forbidden command can NEVER be admitted, even if it somehow got into
	// the registry — the policy is re-applied at the wire.
	reg.Register(dev.ID, []string{"configure terminal", "reload"})
	for _, bad := range []string{"configure terminal", "reload"} {
		if g.Allows(dev, bad) {
			t.Fatalf("%q was admitted through the review registry — the policy must still refuse it", bad)
		}
	}
	reg.Release(dev.ID)
	if reg.Size() != 0 {
		t.Fatal("Release did not release")
	}
	if g.Allows(dev, custom) {
		t.Fatal("a custom command is still allowed after its collection ended")
	}
}

// TestGateWithoutARegistryIsUnchanged — the pre-review behaviour is exactly the
// authored table, so wiring the registry cannot widen a build that has none.
func TestGateWithoutARegistryIsUnchanged(t *testing.T) {
	g := NewGate(mustCatalog(t))
	src := iosxeDevice()
	dev := protocoldiag.Device{ID: src.ID, Hostname: src.Hostname, Platform: src.Platform}
	if g.Allows(dev, "show ip nhrp brief detail summary") {
		t.Fatal("the authored table admitted a command it never authored")
	}
	if !g.Allows(dev, "show version") {
		t.Fatal("the authored table refused one of its own commands")
	}
}

// ── the store ───────────────────────────────────────────────────────────────

func TestFileTemplateStoreIsTenantKeyed(t *testing.T) {
	ctx := context.Background()
	s := NewFileTemplateStore("")
	mk := func(tenant, name string) Template {
		return Template{TenantID: tenant, Dialect: "cisco-iosxe", Name: name,
			Steps: []TemplateStep{{Command: "show version"}}, CreatedBy: "u-" + tenant}
	}
	a, err := s.Create(ctx, mk("tenant-a", "A baseline"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Create(ctx, mk("tenant-b", "B baseline")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.Source != SourceTenant {
		t.Fatal("the store did not stamp the source")
	}
	if a.Version != 1 {
		t.Fatalf("a new template starts at version %d", a.Version)
	}
	if IsDefaultTemplateID(a.ID) {
		t.Fatalf("a tenant row was minted inside the correlix: namespace: %q", a.ID)
	}
	rows, err := s.List(ctx, "tenant-a")
	if err != nil || len(rows) != 1 || rows[0].ID != a.ID {
		t.Fatalf("own-only list: %v %+v", err, rows)
	}
	if _, gerr := s.Get(ctx, "tenant-b", a.ID); gerr == nil {
		t.Fatal("tenant B read tenant A's template")
	}
	if _, uerr := s.Update(ctx, "tenant-b", a.ID, mk("tenant-b", "hijack")); uerr == nil {
		t.Fatal("tenant B updated tenant A's template")
	}
	if derr := s.Delete(ctx, "tenant-b", a.ID); derr == nil {
		t.Fatal("tenant B deleted tenant A's template")
	}
	// A wildcard or empty scope owns nothing and may write nothing.
	for _, scope := range []string{"", "*"} {
		if _, cerr := s.Create(ctx, mk(scope, "wildcard")); cerr == nil {
			t.Fatalf("a %q scope was allowed to own a template", scope)
		}
		if rows, lerr := s.List(ctx, scope); lerr != nil || len(rows) != 0 {
			t.Fatalf("a %q scope listed %d rows", scope, len(rows))
		}
	}
	// Identity is immutable across an update; the version increments.
	upd, err := s.Update(ctx, "tenant-a", a.ID, Template{
		TenantID: "tenant-a", Dialect: "arista-eos", Name: "renamed",
		Steps: []TemplateStep{{Command: "show version"}}, CreatedBy: "someone-else",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.ID != a.ID || upd.TenantID != "tenant-a" || upd.CreatedBy != a.CreatedBy || !upd.CreatedAt.Equal(a.CreatedAt) {
		t.Fatalf("an update changed identity: %+v", upd)
	}
	if upd.Version != 2 {
		t.Fatalf("the version did not increment: %d", upd.Version)
	}
}

// ── the HTTP surface ────────────────────────────────────────────────────────

type tplTestAPI struct {
	api    *TemplateAPI
	store  TemplateStore
	tenant string
	cross  bool
	audits []string
}

func newTplTestAPI(t *testing.T) *tplTestAPI {
	t.Helper()
	h := &tplTestAPI{store: NewFileTemplateStore(""), tenant: "tenant-a"}
	cat := mustCatalog(t)
	v := testValidator(t)
	api, err := NewTemplateAPI(TemplateAPIDeps{
		Authz: func(_ http.ResponseWriter, _ *http.Request, _ TemplateGate) (TemplatePrincipal, bool) {
			return TemplatePrincipal{Tenant: h.tenant, Cross: h.cross, Subject: "operator"}, true
		},
		Store: h.store, Validator: v, Catalog: cat,
		Audit: func(_ *http.Request, _ TemplatePrincipal, action string, _ map[string]any) {
			h.audits = append(h.audits, action)
		},
		WriteJSON: func(w http.ResponseWriter, status int, body any) { writeTestJSON(w, status, body) },
		WriteError: func(w http.ResponseWriter, status int, err error) {
			writeTestJSON(w, status, map[string]any{"error": err.Error()})
		},
		Now: func() time.Time { return time.Unix(0, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	h.api = api
	return h
}

func writeTestJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(mustJSON(body))
}

func (h *tplTestAPI) do(method, path, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	w := httptest.NewRecorder()
	switch {
	case strings.HasPrefix(r.URL.Path, TemplatesValidatePath):
		h.api.HandleValidate(w, r)
	case strings.HasPrefix(r.URL.Path, TemplatesDefaultsPath):
		h.api.HandleDefaults(w, r)
	case r.URL.Path == TemplatesPath:
		h.api.HandleTemplates(w, r)
	default:
		h.api.HandleTemplateItem(w, r)
	}
	return w
}

// TestTemplateAPIRefusesAForbiddenCommandWithPerLineVerdicts.
func TestTemplateAPIRefusesAForbiddenCommandWithPerLineVerdicts(t *testing.T) {
	h := newTplTestAPI(t)
	w := h.do("POST", TemplatesPath, `{"dialect":"cisco-iosxe","name":"bad","description":"","based_on":"","steps":[
		{"intent":"","title":"","command":"show version","section":"","note":""},
		{"intent":"","title":"","command":"configure terminal","section":"","note":""}]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a template with a config command was saved: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{"configure terminal", `"family": "config"`, `"rule"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal does not carry %q: %s", want, body)
		}
	}
	if len(h.audits) != 0 {
		t.Fatalf("a refused write was audited as a change: %v", h.audits)
	}
}

// TestTemplateAPISavesLoadsAndStampsTheOwner.
func TestTemplateAPISavesLoadsAndStampsTheOwner(t *testing.T) {
	h := newTplTestAPI(t)
	w := h.do("POST", TemplatesPath, `{"dialect":"arista-eos","name":"ACME EOS baseline","description":"ours","based_on":"correlix:arista-eos:baseline","steps":[
		{"intent":"","title":"","command":"show version","section":"baseline","note":""},
		{"intent":"","title":"","command":"show ip nhrp brief detail summary","section":"","note":"our tunnels"}]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	rows, _ := h.store.List(context.Background(), "tenant-a")
	if len(rows) != 1 {
		t.Fatalf("the template was not stored: %+v", rows)
	}
	if rows[0].TenantID != "tenant-a" || rows[0].CreatedBy != "operator" {
		t.Fatalf("the owner was not stamped from the principal: %+v", rows[0])
	}
	// The listing carries the tenant's row AND the Correlix defaults.
	list := h.do("GET", TemplatesPath+"?dialect=arista-eos", "").Body.String()
	if !strings.Contains(list, "ACME EOS baseline") || !strings.Contains(list, "correlix:arista-eos:baseline") {
		t.Fatalf("the listing is missing the tenant row or the defaults: %s", list)
	}
	if h.audits[0] != "tac.template.create" {
		t.Fatalf("the create was not audited: %v", h.audits)
	}
}

// TestTemplateAPIDefaultsAreImmutable — a tenant may read a default and fork it,
// never write it.
func TestTemplateAPIDefaultsAreImmutable(t *testing.T) {
	h := newTplTestAPI(t)
	const id = "correlix:arista-eos:baseline"
	if w := h.do("GET", TemplateItemPath+id, ""); w.Code != http.StatusOK {
		t.Fatalf("a default must be readable: %d %s", w.Code, w.Body.String())
	}
	for _, m := range []string{"PUT", "DELETE"} {
		w := h.do(m, TemplateItemPath+id, `{"dialect":"arista-eos","name":"x","description":"","based_on":"","steps":[{"intent":"","title":"","command":"show version","section":"","note":""}]}`)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s on a Correlix default: %d %s, want 403", m, w.Code, w.Body.String())
		}
	}
}

// TestTemplateAPIRefusesACrossTenantPrincipal — default-closed: the platform
// owner must scope into a tenant before touching per-tenant data.
func TestTemplateAPIRefusesACrossTenantPrincipal(t *testing.T) {
	h := newTplTestAPI(t)
	h.cross = true
	if w := h.do("GET", TemplatesPath, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("a cross-tenant list was served: %d %s", w.Code, w.Body.String())
	}
	// The DEFAULTS, by contrast, carry no tenant data and stay readable.
	if w := h.do("GET", TemplatesDefaultsPath, ""); w.Code != http.StatusOK {
		t.Fatalf("the defaults must be readable by any authorised caller: %d", w.Code)
	}
}

// TestTemplateAPIValidateIsTheSameCheckAsTheWritePath.
func TestTemplateAPIValidateIsTheSameCheckAsTheWritePath(t *testing.T) {
	h := newTplTestAPI(t)
	w := h.do("POST", TemplatesValidatePath, `{"dialect":"cisco-iosxe","commands":["show version","reload","ping 10.0.0.1 repeat 5"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("validate: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"refused": 1`) {
		t.Fatalf("expected exactly one refused line: %s", body)
	}
	if !strings.Contains(body, `"family": "restart"`) {
		t.Fatalf("the reload was not attributed to the restart family: %s", body)
	}
}

// TestTemplateAPIRefusesUnknownQueryAndUnknownFields — §3 fail-closed. A typo in
// a field name must fail rather than be silently dropped, and a tenant smuggled
// into the body is a 400.
func TestTemplateAPIRefusesUnknownQueryAndUnknownFields(t *testing.T) {
	h := newTplTestAPI(t)
	if w := h.do("GET", TemplatesPath+"?tenant=other", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("an unknown query parameter was accepted: %d", w.Code)
	}
	if w := h.do("POST", TemplatesPath, `{"dialect":"cisco-iosxe","name":"x","tenant_id":"tenant-b","steps":[{"command":"show version"}]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("a tenant in the body was not refused: %d %s", w.Code, w.Body.String())
	}
}

// TestDiffAgainstDefaultNamesTheChanges — the Knowledge tab's honesty: a fork
// says what it changed, and a template with no parent says so instead of
// pretending to be identical.
func TestDiffAgainstDefaultNamesTheChanges(t *testing.T) {
	cat := mustCatalog(t)
	parent, ok := cat.DefaultTemplate("correlix:arista-eos:baseline")
	if !ok {
		t.Skip("this build ships no arista-eos baseline default")
	}
	// Drop a step whose command is UNIQUE in the parent: the baseline dedupes by
	// intent, not by command, so two intents can legitimately share one command
	// and dropping either of them changes nothing about the command set.
	count := map[string]int{}
	for _, st := range parent.Steps {
		count[normCommandKey(st.Command)]++
	}
	drop := -1
	for i, st := range parent.Steps {
		if count[normCommandKey(st.Command)] == 1 {
			drop = i
			break
		}
	}
	if drop < 0 {
		t.Skip("every command in this default appears more than once; nothing to drop uniquely")
	}
	steps := []TemplateStep{{Command: "show ip nhrp brief detail summary"}}
	for i, st := range parent.Steps {
		if i != drop {
			steps = append(steps, st)
		}
	}
	fork := Template{
		ID: "tpl-1", Source: SourceTenant, Dialect: "arista-eos", BasedOn: parent.ID,
		Steps: steps,
	}
	diff, ok := cat.DiffAgainstDefault(fork)
	if !ok {
		t.Fatal("a fork of a shipped default must be diffable")
	}
	var added, removed int
	for _, d := range diff {
		switch d.Kind {
		case EditAdded:
			added++
		case EditRemoved:
			removed++
		}
	}
	if added != 1 || removed != 1 {
		t.Fatalf("expected one add and one remove, got %+v", diff)
	}
	if _, ok := cat.DiffAgainstDefault(Template{ID: "tpl-2", Source: SourceTenant}); ok {
		t.Fatal("a template with no parent must not report a diff")
	}
}

// TestManifestRecordsTheTemplateAndEveryEdit — the provenance a TAC engineer
// reads. A bundle must say which template ran, at which version, and exactly
// what a human changed about Correlix's own proposal.
func TestManifestRecordsTheTemplateAndEveryEdit(t *testing.T) {
	v := testValidator(t)
	cat := mustCatalog(t)
	p, err := cat.Plan("bgp-session", iosxeDevice(), PlanOptions{Target: Target{Peer: "192.0.2.1"}})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	p.IncidentID = "inc-1"

	const custom = "show ip nhrp brief detail summary"
	steps := []ReviewedStep{{Command: p.Steps[0].Command}, {Command: custom, Note: "our tunnels"}}
	ref := TemplateRef{ID: "tpl-abc", Name: "ACME EOS baseline", Source: SourceTenant, Version: 4}
	reviewed, _, rerr := v.Review(p, steps, ref)
	if rerr != nil {
		t.Fatalf("review: %v", rerr)
	}

	f := newFake()
	for _, s := range reviewed.Steps {
		f.out[s.Command] = "line one\n"
	}
	capt, cerr := testCollector(t, f, WithClock(fixedClock())).Collect(context.Background(), reviewed, nil, nil)
	if cerr != nil {
		t.Fatalf("collect: %v", cerr)
	}
	if !capt.Reviewed || capt.Template.ID != ref.ID || capt.Template.Version != ref.Version {
		t.Fatalf("the capture lost the review provenance: %+v", capt.Template)
	}

	in := fixtureBundleInput(t)
	in.Capture = capt
	in.Plan = reviewed
	b, berr := BuildBundle(context.Background(), in, nil, fixedClock())
	if berr != nil {
		t.Fatalf("bundle: %v", berr)
	}
	m := b.Manifest.CommandReview
	if !m.Reviewed {
		t.Fatal("the MANIFEST does not record that a human reviewed the command list")
	}
	if m.Template.ID != ref.ID || m.Template.Name != ref.Name || m.Template.Version != ref.Version ||
		m.Template.Source != SourceTenant {
		t.Fatalf("the MANIFEST does not name the template that ran: %+v", m.Template)
	}
	if m.Policy == "" || !strings.Contains(m.Policy, "OUTPUT-ONLY") {
		t.Fatalf("the MANIFEST does not state the command policy: %q", m.Policy)
	}
	var added, removed int
	for _, e := range m.Edits {
		switch e.Kind {
		case EditAdded:
			added++
			if e.Command != custom || e.Origin != OriginCustom {
				t.Errorf("the added custom command is misrecorded: %+v", e)
			}
		case EditRemoved:
			removed++
		}
	}
	if added != 1 {
		t.Fatalf("the MANIFEST does not record the added command: %+v", m.Edits)
	}
	if removed == 0 {
		t.Fatalf("the MANIFEST does not record what the operator removed: %+v", m.Edits)
	}
	// The bundle's own command rows must be exactly the reviewed list.
	if len(b.Manifest.Commands) != len(reviewed.Steps) {
		t.Fatalf("the bundle ran %d commands, the operator approved %d",
			len(b.Manifest.Commands), len(reviewed.Steps))
	}
}
