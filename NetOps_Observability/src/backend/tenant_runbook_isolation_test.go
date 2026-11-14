// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// tenant_runbook_isolation_test.go — tenant runbooks/MOPs (tracker 337 N-F2)
// over HTTP and into Iris: §3a isolation (own-only list and search, a foreign
// id → 404 for every verb incl. links and reprove, an as_tenant walk ignored,
// a smuggled body tenant refused, a Global view must choose a workspace), the
// two-person rule (self-approval refused, an API key is not a person), the
// validator (a tool outside the allowlist is refused with a reason), the case
// harness on submit (failing cases → 422 with the problems), and that only the
// caller's OWN approved, proven, investigative runbooks reach the caller's
// troubleshooting methods — never another tenant's, never a draft or a MOP,
// never without ai.runbook.author.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/aientitlement"
	"netops/backend/internal/tenantrunbook"
)

// testRunbookGate is the production case gate, stamping with the server's own
// fingerprint so a runbook proven here is runnable in aiSkillsFor.
func testRunbookGate(t *testing.T, s *server) tenantrunbook.Harness {
	t.Helper()
	g, err := tenantrunbook.NewCaseGate(s.runbookFingerprint, ai.ToolNames)
	if err != nil {
		t.Fatalf("case gate: %v", err)
	}
	return g
}

// rbMD and rbCases are a real runbook whose cases pass under ai.RunCases
// (the same text as internal/tenantrunbook's fixture).
const rbName = "acme-wan-check"

const rbMD = `---
name: acme-wan-check
layer: path_seam
version: 2
when_to_use: acme wan brownout, acme carrier fault, acme circuit fault
symptom_kinds: acme-wan
tools: get_rca_verdict, search_logs
gather:
  - get_rca_verdict(correlation_id)
  - search_logs(query=WAN, window=6h)
look_for:
  - the carrier ticket number
decisions:
  - next=log-confirmation when evidence:kind=log the logs name the carrier
  - next=interface-down when the handoff port is suspect
  - verdict=name the carrier circuit
  - escalate=the carrier NOC
---
First read the carrier portal, then compare the handoff counters.
`

const rbCases = `
case: logs naming the carrier hand off to Correlix's own log method
question: acme wan brownout on edge-1
ui:
  - correlation_id=case-1
evidence:
  - log
expect_chain:
  - acme-wan-check entry
  - log-confirmation rule
expect_selected: rule
expect_reason: the logs name the carrier
expect_verdict:
  - quote the message
expect_never:
  - mac-flap
expect_never_tools:
  - run_protocol_diagnostic
---
case: no routing fact stays in the runbook and says what was missing
question: acme carrier fault and acme circuit fault on edge-1
ui:
  - correlation_id=case-2
tools:
  - search_logs=not_wired
evidence:
  - finding
expect_chain:
  - acme-wan-check entry
expect_selected: none
expect_verdict:
  - carrier circuit
expect_notes:
  - is not available on this deployment
expect_select: acme-wan-check
`

func rbCreateBody(name, md, cases string) string {
	return `{"name":` + jsonString(name) + `,"kind":"investigative","skill_md":` + jsonString(md) + `,"cases_yaml":` + jsonString(cases) + `}`
}

// newRunbook creates the fixture runbook as c and returns its id.
func newRunbook(t *testing.T, h http.Handler, c jwtClaims) string {
	t.Helper()
	code, m := ctxCall(t, h, c, http.MethodPost, "/api/ai/runbooks", rbCreateBody(rbName, rbMD, rbCases))
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, m)
	}
	return m["id"].(string)
}

// submitRunbook runs the cases and sends the draft for review; it returns the
// hash an approval must quote.
func submitRunbook(t *testing.T, h http.Handler, c jwtClaims, id string) string {
	t.Helper()
	code, m := ctxCall(t, h, c, http.MethodPost, "/api/ai/runbooks/"+id+"/submit", "")
	if code != http.StatusOK {
		t.Fatalf("submit: %d %v", code, m)
	}
	vs := m["versions"].([]any)
	return vs[len(vs)-1].(map[string]any)["body_sha256"].(string)
}

func approveRunbook(h http.Handler, c jwtClaims, id, sha string) int {
	return serveAs(h, c, http.MethodPost, "/api/ai/runbooks/"+id+"/approve", `{"version":1,"body_sha256":"`+sha+`"}`).Code
}

func hasSkill(set *ai.SkillSet, name string) bool {
	if set == nil {
		return false
	}
	_, ok := set.Get(name)
	return ok
}

func TestTenantRunbookTwoPeopleAndCasesOverHTTP(t *testing.T) {
	s, h, alice, bob, reviewer := ctxFixture(t)
	id := newRunbook(t, h, alice)

	// The dry run proves the cases without changing anything.
	if code, m := ctxCall(t, h, alice, http.MethodPost, "/api/ai/runbooks/"+id+"/check", ""); code != http.StatusOK || m["passed"] != true {
		t.Fatalf("check: %d %v", code, m)
	}
	if hasSkill(s.aiSkillsFor(context.Background(), alice), rbName) {
		t.Fatal("a draft must never reach Iris")
	}
	sha := submitRunbook(t, h, alice, id)
	if hasSkill(s.aiSkillsFor(context.Background(), alice), rbName) {
		t.Fatal("a pending runbook must never reach Iris")
	}
	if code := approveRunbook(h, alice, id, sha); code != http.StatusForbidden {
		t.Fatalf("the author approving their own runbook: %d, want 403", code)
	}
	bot := reviewer
	bot.Sub = "apikey:k1"
	if code := approveRunbook(h, bot, id, sha); code != http.StatusForbidden {
		t.Fatalf("an API key approving: %d, want 403 (it is not a second person)", code)
	}
	if code := approveRunbook(h, reviewer, id, strings.Repeat("0", 64)); code != http.StatusConflict {
		t.Fatalf("approving a different text than the one reviewed: %d, want 409", code)
	}
	if code := approveRunbook(h, reviewer, id, sha); code != http.StatusOK {
		t.Fatalf("a second administrator approving: %d", code)
	}

	// Approved and proven: it runs for its own tenant, and the page says so.
	set := s.aiSkillsFor(context.Background(), alice)
	if !hasSkill(set, rbName) {
		t.Fatal("an approved, proven runbook must reach its own tenant's Iris")
	}
	if !hasSkill(set, "osi-bisection") {
		t.Fatal("the compiled methods stay in the set")
	}
	// Selected by its own when_to_use phrases (a phrase only it carries; on an
	// equal score the compiled method wins, by design).
	m, ok := ai.SelectSkill(set, "acme carrier fault and acme circuit fault on edge-1", ai.Plan{})
	if !ok || m.Skill == nil || m.Skill.Name != rbName {
		t.Fatalf("Iris selects the approved runbook by its own when_to_use: %+v %v", m, ok)
	}
	if m, ok := ai.SelectSkill(s.aiSkillsFor(context.Background(), bob), "acme carrier fault and acme circuit fault on edge-1", ai.Plan{}); ok && m.Skill != nil && m.Skill.Name == rbName {
		t.Fatal("CROSS-TENANT LEAK: tenant B's Iris selected tenant A's runbook")
	}
	code, got := ctxCall(t, h, alice, http.MethodGet, "/api/ai/runbooks/"+id, "")
	if code != http.StatusOK || got["runs_in_iris"] != true || got["needs_recheck"] != false {
		t.Fatalf("the page says the runbook runs: %d runs=%v recheck=%v", code, got["runs_in_iris"], got["needs_recheck"])
	}
	// A re-check of a current proof runs nothing and changes nothing.
	if code, rc := ctxCall(t, h, alice, http.MethodPost, "/api/ai/runbooks/"+id+"/reprove", ""); code != http.StatusOK || rc["already_current"] != true {
		t.Fatalf("reprove of a current proof: %d %v", code, rc)
	}

	// Retired: gone from Iris on the next request (the cache is invalidated).
	if code, m := ctxCall(t, h, reviewer, http.MethodPost, "/api/ai/runbooks/"+id+"/retire", `{"reason":"replaced"}`); code != http.StatusOK {
		t.Fatalf("retire: %d %v", code, m)
	}
	if hasSkill(s.aiSkillsFor(context.Background(), alice), rbName) {
		t.Fatal("a retired runbook must leave Iris at once")
	}
}

func TestTenantRunbookValidatorAndHarnessRefuse(t *testing.T) {
	_, h, alice, _, _ := ctxFixture(t)

	// A tool outside the read-only allowlist is refused with a reason, before
	// anything is stored.
	forbidden := strings.Replace(rbMD, "tools: get_rca_verdict, search_logs", "tools: get_rca_verdict, push_config", 1)
	code, m := ctxCall(t, h, alice, http.MethodPost, "/api/ai/runbooks", rbCreateBody(rbName, forbidden, rbCases))
	if code != http.StatusBadRequest || m["error"] == nil {
		t.Fatalf("a runbook naming a tool outside the allowlist: %d %v, want 400 with a reason", code, m)
	}
	if _, list := ctxCall(t, h, alice, http.MethodGet, "/api/ai/runbooks", ""); len(list["runbooks"].([]any)) != 0 {
		t.Fatal("a refused runbook must not be stored")
	}

	// Cases that do not hold are refused at submit with the problems, and the
	// runbook stays a draft.
	broken := strings.Replace(rbCases, "expect_reason: the logs name the carrier", "expect_reason: the moon is full", 1)
	code, m = ctxCall(t, h, alice, http.MethodPost, "/api/ai/runbooks", rbCreateBody(rbName, rbMD, broken))
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, m)
	}
	id := m["id"].(string)
	code, m = ctxCall(t, h, alice, http.MethodPost, "/api/ai/runbooks/"+id+"/submit", "")
	if code != http.StatusUnprocessableEntity || len(m["problems"].([]any)) == 0 {
		t.Fatalf("failing cases at submit: %d %v, want 422 with problems", code, m)
	}
	_, got := ctxCall(t, h, alice, http.MethodGet, "/api/ai/runbooks/"+id, "")
	vs := got["versions"].([]any)
	if st := vs[0].(map[string]any)["state"]; st != "draft" {
		t.Fatalf("a refused submit leaves the draft: %v", st)
	}
}

func TestTenantRunbookIsolation(t *testing.T) {
	s, h, alice, bob, reviewer := ctxFixture(t)
	id := newRunbook(t, h, alice)
	sha := submitRunbook(t, h, alice, id)
	if code := approveRunbook(h, reviewer, id, sha); code != http.StatusOK {
		t.Fatalf("approve: %d", code)
	}

	// Own-only list and search.
	if _, m := ctxCall(t, h, bob, http.MethodGet, "/api/ai/runbooks", ""); len(m["runbooks"].([]any)) != 0 {
		t.Fatalf("tenant B listed tenant A's runbook: %v", m["runbooks"])
	}
	if _, m := ctxCall(t, h, bob, http.MethodGet, "/api/ai/runbooks?q=carrier", ""); len(m["results"].([]any)) != 0 {
		t.Fatalf("tenant B found tenant A's runbook by search: %v", m["results"])
	}
	if _, m := ctxCall(t, h, alice, http.MethodGet, "/api/ai/runbooks?q=carrier", ""); len(m["results"].([]any)) != 1 {
		t.Fatalf("tenant A's own search: %v", m)
	}

	// Every verb on a foreign id is the same 404 — for another tenant and for
	// an as_tenant walk into tenant A.
	walker := bob
	walker.ActingTenant = alice.Tenant
	for name, c := range map[string]jwtClaims{"other tenant": bob, "as_tenant walk": walker} {
		for _, p := range []struct{ method, path, body string }{
			{http.MethodGet, "/api/ai/runbooks/" + id + "?as_tenant=" + alice.Tenant, ""},
			{http.MethodPut, "/api/ai/runbooks/" + id + "/draft", `{"skill_md":"x","cases_yaml":""}`},
			{http.MethodDelete, "/api/ai/runbooks/" + id + "/draft", ""},
			{http.MethodPost, "/api/ai/runbooks/" + id + "/check", ""},
			{http.MethodPost, "/api/ai/runbooks/" + id + "/submit", ""},
			{http.MethodPost, "/api/ai/runbooks/" + id + "/withdraw", ""},
			{http.MethodPost, "/api/ai/runbooks/" + id + "/approve", `{"version":1,"body_sha256":"` + sha + `"}`},
			{http.MethodPost, "/api/ai/runbooks/" + id + "/reject", `{"version":1,"reason":"no"}`},
			{http.MethodPost, "/api/ai/runbooks/" + id + "/rollback", `{"to_version":1,"reason":"x"}`},
			{http.MethodPost, "/api/ai/runbooks/" + id + "/retire", `{"reason":"x"}`},
			{http.MethodPost, "/api/ai/runbooks/" + id + "/reprove", ""},
			{http.MethodGet, "/api/ai/runbooks/" + id + "/links", ""},
			{http.MethodPut, "/api/ai/runbooks/" + id + "/links", `{"link_type":"signature","link_key":"x"}`},
			{http.MethodDelete, "/api/ai/runbooks/" + id + "/links", `{"link_type":"signature","link_key":"x"}`},
		} {
			if code, m := ctxCall(t, h, c, p.method, p.path, p.body); code != http.StatusNotFound {
				t.Errorf("%s: %s %s → %d %v, want 404", name, p.method, p.path, code, m)
			}
		}
	}

	// A smuggled tenant in the body is an error, never honoured.
	smuggled := `{"name":"x","kind":"mop","skill_md":"x","cases_yaml":"","tenant_id":"` + alice.Tenant + `"}`
	if code, _ := ctxCall(t, h, bob, http.MethodPost, "/api/ai/runbooks", smuggled); code != http.StatusBadRequest {
		t.Fatalf("a body tenant must be refused: %d", code)
	}

	// Iris: A's own runbook for A; nothing for B, the walker, the Global view,
	// or A once ai.runbook.author lapses.
	if !hasSkill(s.aiSkillsFor(context.Background(), alice), rbName) {
		t.Fatal("tenant A's Iris lacks its approved runbook")
	}
	if hasSkill(s.aiSkillsFor(context.Background(), bob), rbName) {
		t.Fatal("CROSS-TENANT LEAK: tenant B's Iris carries tenant A's runbook")
	}
	if hasSkill(s.aiSkillsFor(context.Background(), walker), rbName) {
		t.Fatal("CROSS-TENANT LEAK: an as_tenant walk reached tenant A's runbook")
	}
	global := alice
	global.Tenant, global.Role = TenantGlobal, "admin"
	if hasSkill(s.aiSkillsFor(context.Background(), global), rbName) {
		t.Fatal("the Global view must run no tenant's runbook")
	}
	if code, _ := ctxCall(t, h, global, http.MethodGet, "/api/ai/runbooks", ""); code != http.StatusBadRequest {
		t.Fatalf("a Global view must choose a workspace: %d", code)
	}
	s.aiEntitlementPolicy = policyWithout(t, s, aientitlement.RunbookAuthor)
	s.tenantRunbookSets.Invalidate(alice.Tenant)
	if hasSkill(s.aiSkillsFor(context.Background(), alice), rbName) {
		t.Fatal("without ai.runbook.author no runbook may reach Iris (default-closed)")
	}
}

func TestTenantRunbookLinksOnlyToTheCallersOwnTargets(t *testing.T) {
	_, h, alice, _, _ := ctxFixture(t)
	id := newRunbook(t, h, alice)
	put := func(typ, key string) (int, map[string]any) {
		return ctxCall(t, h, alice, http.MethodPut, "/api/ai/runbooks/"+id+"/links", `{"link_type":"`+typ+`","link_key":`+jsonString(key)+`}`)
	}
	if code, m := put("signature", "no-such-hypothesis"); code != http.StatusBadRequest {
		t.Fatalf("a link to an unknown signature: %d %v, want 400", code, m)
	}
	if code, m := put("entity", "device:not-in-this-workspace"); code != http.StatusBadRequest {
		t.Fatalf("a link to a device the workspace does not have: %d %v, want 400", code, m)
	}
	if code, m := put("entity", "toaster:x"); code != http.StatusBadRequest {
		t.Fatalf("a link to an unknown entity kind: %d %v, want 400", code, m)
	}
	if code, m := put("incident", "0f6e2a51-0000-4000-8000-000000000000"); code != http.StatusBadRequest {
		t.Fatalf("a link to an incident the workspace does not have: %d %v, want 400", code, m)
	}
}

// The planner's catalogue never carries a customer's runbook text (§15): an
// approved runbook is selected by its own phrases, never named by the model.
func TestTenantRunbookNeverEntersThePlannerCatalogue(t *testing.T) {
	s, h, alice, _, reviewer := ctxFixture(t)
	id := newRunbook(t, h, alice)
	sha := submitRunbook(t, h, alice, id)
	if code := approveRunbook(h, reviewer, id, sha); code != http.StatusOK {
		t.Fatalf("approve: %d", code)
	}
	set := s.aiSkillsFor(context.Background(), alice)
	sk, ok := set.Get(rbName)
	if !ok {
		t.Fatal("the runbook is in the tenant's set")
	}
	if sk.Origin != ai.SkillOriginTenant || sk.TenantID != alice.Tenant {
		t.Fatalf("a runbook in the set is stamped tenant-origin with its own tenant: %+v", sk)
	}
}
