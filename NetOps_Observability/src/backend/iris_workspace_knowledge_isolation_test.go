// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_workspace_knowledge_isolation_test.go — CLAUDE.md §3a rule 5 for
// Iris's retrieval over the workspace's recorded knowledge,
// search_workspace_knowledge (tracker 337 N-F3). org_isolation_test.go is the
// template; iris_probe_results_isolation_test.go is the sibling.
//
// The adversarial fixture: the runbook, time-metrics and resolution stores
// are stubs that IGNORE the tenant they are asked for and return BOTH
// tenants' rows — exactly what a broken store would do — and the two tenants
// own SAME-NAMED runbooks and incidents on the same device name. Every read
// must still stay inside the caller: the seam re-checks each row, and
// ai.RankKnowledge re-checks each document. The platform's "All tenants"
// view reads nothing, the owner narrowed into a tenant reads only that
// tenant, a forged acting tenant never widens, a restricted tenant is
// unreachable, no address leaves the seam, an unapproved draft is never
// retrievable, and an operator's resolution note never enters the path.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/orgcontext"
	"netops/backend/internal/rcaresolution"
	"netops/backend/internal/tenantrunbook"
	"netops/backend/timeintel"
)

// kbLeakyRunbooks returns every tenant's runbooks whatever tenant is asked.
type kbLeakyRunbooks struct {
	tenantrunbook.Store // only List is used; anything else would panic
	rows                []tenantrunbook.Runbook
}

func (k kbLeakyRunbooks) List(context.Context, string) ([]tenantrunbook.Runbook, error) {
	return append([]tenantrunbook.Runbook(nil), k.rows...), nil
}

// kbLeakyMetrics returns every tenant's incidents whatever tenant is asked.
type kbLeakyMetrics struct {
	timeintel.MetricsStore
	rows []timeintel.MetricRow
}

func (k kbLeakyMetrics) ListWindow(context.Context, string, bool, time.Time, string, int) ([]timeintel.MetricRow, error) {
	return append([]timeintel.MetricRow(nil), k.rows...), nil
}

// kbLeakyFixes returns every tenant's resolutions whatever tenant is asked.
type kbLeakyFixes struct {
	rcaresolution.Store
	fixes map[string]rcaresolution.Resolution
}

func (k kbLeakyFixes) Latest(context.Context, string, []string) (map[string]rcaresolution.Resolution, error) {
	return k.fixes, nil
}

func kbRunbookRow(id, tenant, name, when string, state orgcontext.State) tenantrunbook.Runbook {
	decided := time.Now().Add(-48 * time.Hour)
	return tenantrunbook.Runbook{
		Doc: orgcontext.Doc{ID: id, TenantID: tenant, Key: name, Scope: orgcontext.ScopeTenant, CreatedAt: decided,
			Versions: []orgcontext.Version{{Version: 1, Body: "---\nname: " + name + "\n---\n" + when, State: state, DecidedAt: &decided}}},
		WhenToUse: when,
	}
}

func kbFixture(t *testing.T) *restrictedAIFixture {
	t.Helper()
	f := newRestrictedAIFixture(t)
	f.s.tenantRunbooks = kbLeakyRunbooks{rows: []tenantrunbook.Runbook{
		kbRunbookRow("rb-acme-1", f.acme, "mpls-transport-brownout", "mpls bfd flapping carrier ticket acme-procedure", orgcontext.StateActive),
		kbRunbookRow("rb-acme-draft", f.acme, "mpls-draft", "mpls bfd flapping carrier draft-only", orgcontext.StateDraft),
		kbRunbookRow("rb-globex-1", f.globex, "mpls-transport-brownout", "mpls bfd flapping carrier ticket globex-procedure", orgcontext.StateActive),
	}}
	occurred := time.Now().Add(-5 * 24 * time.Hour)
	f.s.incidentTimeMetrics = kbLeakyMetrics{rows: []timeintel.MetricRow{
		{TenantID: f.acme, CorrelationID: "aaaaaaaa-0000-4000-8000-000000000001", OccurredAt: occurred, OwnerDomain: "carrier", State: "closed",
			Group: map[string]string{"signature": "bfd-transport-loss", "device": "vEdge-51", "app_path": "mpls"}},
		{TenantID: f.acme, CorrelationID: "aaaaaaaa-0000-4000-8000-000000000002", OccurredAt: occurred, OwnerDomain: "carrier", State: "closed",
			Group: map[string]string{"signature": "bfd-transport-loss", "device": "10.9.9.9", "app_path": "mpls"}},
		{TenantID: f.acme, CorrelationID: "aaaaaaaa-0000-4000-8000-000000000003", OccurredAt: occurred, State: "open",
			Group: map[string]string{"signature": "bfd-transport-loss", "device": "vEdge-51"}},
		{TenantID: f.globex, CorrelationID: "bbbbbbbb-0000-4000-8000-000000000001", OccurredAt: occurred, OwnerDomain: "carrier", State: "closed",
			Group: map[string]string{"signature": "bfd-transport-loss", "device": "vEdge-51", "app_path": "mpls"}},
	}}
	f.s.rcaResolutions = kbLeakyFixes{fixes: map[string]rcaresolution.Resolution{
		"aaaaaaaa-0000-4000-8000-000000000001": {TenantID: f.acme, CorrelationID: "aaaaaaaa-0000-4000-8000-000000000001",
			Kind: rcaresolution.Kind("provider_ticket"), Note: "SECRET-OPERATOR-NOTE", ChangeID: "CHG-2210", CreatedAt: occurred},
		"bbbbbbbb-0000-4000-8000-000000000001": {TenantID: f.globex, CorrelationID: "bbbbbbbb-0000-4000-8000-000000000001",
			Kind: rcaresolution.Kind("reboot"), Note: "GLOBEX-NOTE", CreatedAt: occurred},
	}}
	return f
}

// kbRead runs the seam for claims and renders a search for q.
func kbRead(t *testing.T, s *server, claims jwtClaims, q string) (ai.KnowledgeCorpus, string, bool) {
	t.Helper()
	deps := s.aiTroubleshootDeps(aiTSRequest(claims), claims)
	if deps.WorkspaceKnowledge == nil {
		return ai.KnowledgeCorpus{}, "", false
	}
	layers := []ai.KnowledgeLayer{ai.LayerRunbook, ai.LayerIncident}
	// aiTSPrincipal is deliberately WRONG: the seam must scope by the token.
	c, err := deps.WorkspaceKnowledge(context.Background(), aiTSPrincipal(), layers)
	if err != nil {
		t.Fatalf("WorkspaceKnowledge: %v", err)
	}
	return c, fmt.Sprintf("%+v", ai.RenderKnowledge(c, q, layers, time.Now())), true
}

func kbDocTenants(c ai.KnowledgeCorpus) map[string]bool {
	out := map[string]bool{}
	for _, d := range c.Docs {
		out[d.Tenant] = true
	}
	return out
}

func TestIrisWorkspaceKnowledgeStaysInsideTheCallersTenant(t *testing.T) {
	f := kbFixture(t)
	for _, tc := range []struct {
		name        string
		claims      jwtClaims
		own, other  string
		ownTenantID string
	}{
		{"acme", jwtClaims{Sub: "a@acme", Role: RoleOrgAdmin, Tenant: f.acme}, "acme-procedure", "globex-procedure", f.acme},
		{"globex", jwtClaims{Sub: "g@globex", Role: RoleOrgAdmin, Tenant: f.globex}, "globex-procedure", "acme-procedure", f.globex},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, text, wired := kbRead(t, f.s, tc.claims, "mpls bfd flapping carrier ticket")
			if !wired || !c.Scoped {
				t.Fatalf("the knowledge read must be wired and scoped for a tenant user: %+v", c)
			}
			if got := kbDocTenants(c); len(got) != 1 || !got[tc.ownTenantID] {
				t.Fatalf("TENANT LEAK at the seam: documents of %v reached %s", got, tc.name)
			}
			if strings.Contains(text, tc.other) || strings.Contains(text, "GLOBEX-NOTE") && tc.name == "acme" {
				t.Fatalf("TENANT LEAK: the other tenant's knowledge reached %s: %s", tc.name, text)
			}
			layers := map[ai.KnowledgeLayer]int{}
			for _, d := range c.Docs {
				layers[d.Layer]++
			}
			if layers[ai.LayerRunbook] != 1 || layers[ai.LayerIncident] == 0 {
				t.Fatalf("both layers must be read (one approved runbook, the closed incidents): %v", layers)
			}
			if !strings.Contains(text, tc.own) {
				t.Fatalf("the caller's own runbook must be found: %s", text)
			}
		})
	}
}

// A forged acting tenant on a NON-owner token never widens its reach.
func TestIrisWorkspaceKnowledgeIgnoresActingTenantForANonOwner(t *testing.T) {
	f := kbFixture(t)
	forged := jwtClaims{Sub: "a@acme", Role: RoleOrgAdmin, Tenant: f.acme, ActingTenant: f.globex}
	c, text, wired := kbRead(t, f.s, forged, "mpls bfd flapping carrier ticket")
	if !wired {
		t.Fatal("the read must be wired for a tenant user")
	}
	if got := kbDocTenants(c); got[f.globex] {
		t.Fatalf("TENANT LEAK: a forged acting tenant reached globex: %v", got)
	}
	if strings.Contains(text, "globex-procedure") {
		t.Fatalf("TENANT LEAK in the rendered result: %s", text)
	}
}

// The platform owner's "All tenants" view reads nothing; narrowed into one
// tenant it reads exactly that tenant.
func TestIrisWorkspaceKnowledgePlatformScopes(t *testing.T) {
	f := kbFixture(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	c, text, wired := kbRead(t, f.s, owner, "mpls bfd flapping")
	if !wired {
		t.Fatal("the read must be wired for the owner (it then answers per workspace)")
	}
	if c.Scoped || len(c.Docs) != 0 || !strings.Contains(text, "read per workspace") {
		t.Fatalf("the All-tenants view must read nothing: %+v %s", c, text)
	}
	if c, _, _ := kbRead(t, f.s, ownerActing(owner, TenantGlobal), "mpls"); c.Scoped || len(c.Docs) != 0 {
		t.Fatalf("the Provider scope owns no customer knowledge: %+v", c)
	}
	c, _, _ = kbRead(t, f.s, ownerActing(owner, f.globex), "mpls bfd flapping")
	if !c.Scoped || len(c.Docs) == 0 {
		t.Fatalf("owner narrowed into globex must read globex: %+v", c)
	}
	if got := kbDocTenants(c); len(got) != 1 || !got[f.globex] {
		t.Fatalf("owner narrowed into globex must read globex ONLY: %v", got)
	}
}

// An operator-restricted tenant is unreachable for the platform owner.
func TestIrisWorkspaceKnowledgeHonoursTheOperatorRestriction(t *testing.T) {
	f := kbFixture(t)
	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	if c, _, wired := kbRead(t, f.s, ownerActing(owner, f.acme), "mpls"); wired && (c.Scoped || len(c.Docs) > 0) {
		t.Fatalf("RESTRICTION LEAK: the owner read acme's knowledge: %+v", c)
	}
	own := jwtClaims{Sub: "a@acme", Role: RoleOrgAdmin, Tenant: f.acme}
	if c, _, wired := kbRead(t, f.s, own, "mpls"); !wired || !c.Scoped || len(c.Docs) == 0 {
		t.Fatalf("acme's own user must still read acme's knowledge: %+v", c)
	}
}

// §15 and the corpus rules: no address, no draft, no open incident, and the
// operator's free-text note never enters the path — only the fix's kind,
// change id and date.
func TestIrisWorkspaceKnowledgeCorpusRules(t *testing.T) {
	f := kbFixture(t)
	acme := jwtClaims{Sub: "a@acme", Role: RoleOrgAdmin, Tenant: f.acme}
	c, text, _ := kbRead(t, f.s, acme, "vedge-51 bfd transport loss mpls")
	all := fmt.Sprintf("%+v", c)
	for _, banned := range []string{"10.9.9.9", "SECRET-OPERATOR-NOTE", "draft-only", "aaaaaaaa-0000-4000-8000-000000000003"} {
		if strings.Contains(all, banned) || strings.Contains(text, banned) {
			t.Errorf("%q must never reach the knowledge corpus or result", banned)
		}
	}
	if !strings.Contains(all, "an address") {
		t.Errorf("a device named by an address must read \"an address\": %s", all)
	}
	if !strings.Contains(text, "fixed by:") || !strings.Contains(text, "CHG-2210") {
		t.Errorf("the recorded fix's kind and change id must be said: %s", text)
	}
}
