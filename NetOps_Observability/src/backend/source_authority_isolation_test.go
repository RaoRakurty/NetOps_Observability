// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// source_authority_isolation_test.go — configurable source authority (tracker
// 337 N-F6) over HTTP and through Iris's device tool: §3a isolation (a tenant
// reads and writes only its own order, an as_tenant walk is ignored, a body
// tenant is refused, a tenant in the path is a 404, a Global view must choose a
// workspace), the permission gate, whose order applies to which device, and the
// answer text: the winning source is cited and disagreement is stated, even
// when the model does not say so.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/ai"
	"netops/backend/internal/discovery"
	"netops/backend/internal/srcauthority"
	"netops/backend/models"
	"netops/backend/nms"
	"netops/backend/wireless"
)

const srcAuthPath = "/api/ai/source-authority"

const (
	orderManualFirst = `{"order":["manual","controller","discovered","declared"]}`
	orderSNMPFirst   = `{"order":["discovered","controller","declared","manual"]}`
)

// srcAuthFixture: tenants t-a and t-b, both admins, an in-memory order store.
func srcAuthFixture(t *testing.T) (*server, http.Handler, jwtClaims, jwtClaims) {
	t.Helper()
	s, h, a, b := aiEntFixture(t)
	s.srcAuthority = srcauthority.NewMemStore()
	s.srcAuthorityMetrics = &srcauthority.Metrics{}
	a.Sub, b.Sub = "ua-alice", "ub-bob"
	return s, h, a, b
}

func srcAuthCall(t *testing.T, h http.Handler, c jwtClaims, method, path, body string) (int, map[string]any) {
	t.Helper()
	w := serveAs(h, c, method, path, body)
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("%s %s: not JSON (%d): %q", method, path, w.Code, w.Body.String())
	}
	return w.Code, m
}

func srcAuthFirst(m map[string]any) string {
	return m["order"].([]any)[0].(map[string]any)["class"].(string)
}

func TestSourceAuthorityIsolation(t *testing.T) {
	s, h, alice, bob := srcAuthFixture(t)
	ctx := context.Background()

	// Own order only: A's change is invisible to B, and B starts at the default.
	if code, m := srcAuthCall(t, h, alice, http.MethodPut, srcAuthPath, orderManualFirst); code != http.StatusOK || srcAuthFirst(m) != "manual" {
		t.Fatalf("tenant A put: %d %v", code, m)
	}
	if code, m := srcAuthCall(t, h, bob, http.MethodGet, srcAuthPath, ""); code != http.StatusOK || srcAuthFirst(m) != "controller" || m["customized"] != false {
		t.Fatalf("CROSS-TENANT LEAK: tenant B reads %d %v", code, m)
	}

	// The owner is stamped from the token, never from the request.
	if p, ok, err := s.srcAuthority.Get(ctx, "t-a"); err != nil || !ok || p.UpdatedBy != "ua-alice" {
		t.Fatalf("stored for t-a: %+v %v %v", p, ok, err)
	}
	if code, _ := srcAuthCall(t, h, bob, http.MethodPut, srcAuthPath,
		`{"order":["manual","controller","discovered","declared"],"tenant_id":"`+alice.Tenant+`"}`); code != http.StatusBadRequest {
		t.Fatalf("a body tenant must be refused: %d", code)
	}

	// B's write and reset never touch A's row, for B and for an as_tenant walk.
	walker := bob
	walker.ActingTenant = alice.Tenant
	for name, c := range map[string]jwtClaims{"other tenant": bob, "as_tenant walk": walker} {
		q := "?as_tenant=" + alice.Tenant
		if code, m := srcAuthCall(t, h, c, http.MethodGet, srcAuthPath+q, ""); code != http.StatusOK || srcAuthFirst(m) == "manual" {
			t.Fatalf("%s: as_tenant must be ignored on read, got %d %v", name, code, m)
		}
		if code, _ := srcAuthCall(t, h, c, http.MethodPut, srcAuthPath+q, orderSNMPFirst); code != http.StatusOK {
			t.Fatalf("%s: own put: %d", name, code)
		}
		if code, _ := srcAuthCall(t, h, c, http.MethodDelete, srcAuthPath+q, ""); code != http.StatusOK {
			t.Fatalf("%s: own delete: %d", name, code)
		}
		if p, ok, err := s.srcAuthority.Get(ctx, "t-a"); err != nil || !ok || p.Order[0] != srcauthority.ClassManual || p.UpdatedBy != "ua-alice" {
			t.Fatalf("%s reached tenant A's order: %+v %v %v", name, p, ok, err)
		}
		// Naming another tenant in the path reaches nothing — the same 404 for
		// every verb, whether or not that tenant exists.
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			for _, target := range []string{alice.Tenant, "no-such-tenant"} {
				if w := serveAs(h, c, method, srcAuthPath+"/"+target, orderSNMPFirst); w.Code != http.StatusNotFound {
					t.Errorf("%s: %s %s/%s → %d, want 404", name, method, srcAuthPath, target, w.Code)
				}
			}
		}
	}

	// A Global view has no workspace: it reads and writes nothing.
	root := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if code, m := srcAuthCall(t, h, root, method, srcAuthPath, orderSNMPFirst); code != http.StatusBadRequest {
			t.Errorf("Global %s: %d %v, want 400 (choose a workspace)", method, code, m)
		}
	}
	// The platform owner acting in tenant A works on tenant A's own row.
	acting := root
	acting.ActingTenant = alice.Tenant
	if code, m := srcAuthCall(t, h, acting, http.MethodGet, srcAuthPath, ""); code != http.StatusOK || srcAuthFirst(m) != "manual" {
		t.Fatalf("platform owner acting in t-a: %d %v", code, m)
	}
}

func TestSourceAuthorityPermissionGate(t *testing.T) {
	_, h, alice, _ := srcAuthFixture(t)
	viewer := alice
	viewer.Role = "viewer"
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		if w := serveAs(h, viewer, method, srcAuthPath, orderManualFirst); w.Code != http.StatusForbidden {
			t.Errorf("a viewer %s: %d, want 403", method, w.Code)
		}
	}
	// An auditor reads administration but changes nothing: reading and changing
	// are different gates.
	auditor := alice
	auditor.Role = RoleAuditor
	if w := serveAs(h, auditor, http.MethodGet, srcAuthPath, ""); w.Code != http.StatusOK {
		t.Errorf("an auditor reads the order: %d", w.Code)
	}
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		if w := serveAs(h, auditor, method, srcAuthPath, orderManualFirst); w.Code != http.StatusForbidden {
			t.Errorf("an auditor %s: %d, want 403", method, w.Code)
		}
	}
	// An API key with full admin may read but never change (same rule as the
	// network context).
	bot := alice
	bot.Sub = "apikey:k1"
	if w := serveAs(h, bot, http.MethodGet, srcAuthPath, ""); w.Code != http.StatusOK {
		t.Errorf("an API key reads the order: %d", w.Code)
	}
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		if w := serveAs(h, bot, method, srcAuthPath, orderManualFirst); w.Code != http.StatusForbidden {
			t.Errorf("an API key %s: %d, want 403", method, w.Code)
		}
	}
	if w := serveAs(h, alice, http.MethodPut, srcAuthPath, orderManualFirst); w.Code != http.StatusOK {
		t.Fatalf("a tenant admin may change their own order: %d %s", w.Code, w.Body.String())
	}
}

func TestSourceAuthorityWithoutStore(t *testing.T) {
	s, h, alice, _ := srcAuthFixture(t)
	s.srcAuthority = nil
	if code, m := srcAuthCall(t, h, alice, http.MethodGet, srcAuthPath, ""); code != http.StatusOK || m["editable"] != false || srcAuthFirst(m) != "controller" {
		t.Fatalf("no store: the platform default, not editable: %d %v", code, m)
	}
	if w := serveAs(h, alice, http.MethodPut, srcAuthPath, orderManualFirst); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no store: changes refused: %d", w.Code)
	}
}

// ── Iris ──────────────────────────────────────────────────────────────────────

type srcAuthSource struct {
	name string
	devs []models.Device
}

func (f srcAuthSource) Name() string            { return f.name }
func (f srcAuthSource) Interval() time.Duration { return time.Hour }
func (f srcAuthSource) Poll(context.Context) ([]models.Device, error) {
	return f.devs, nil
}

var _ discovery.DiscoverySource = srcAuthSource{}

// srcAuthSeed: one device of tenant A reported by the controller, by SNMP and
// by hand with three different versions, and a same-named device of tenant B
// with a version of its own.
func srcAuthSeed(t *testing.T, s *server) {
	t.Helper()
	ctx := context.Background()
	s.discovery.PollOnceForTest(ctx, srcAuthSource{name: nms.ControllerSourceName, devs: []models.Device{{
		ID: "ctl-vmanage-aaaa", Name: "edge-1", Address: "10.255.255.20", Vendor: "Cisco", Model: "vedge-cloud",
		OSVersion: "20.6.1", OSVersionSource: "api:vmanage", TenantID: "t-a",
	}}})
	s.discovery.PollOnceForTest(ctx, srcAuthSource{name: "snmp", devs: []models.Device{
		{ID: "edge-1-aaaa", Name: "edge-1", Address: "192.168.222.104", Vendor: "cisco", OSVersion: "20.6.2", OSVersionSource: "snmp", TenantID: "t-a"},
		{ID: "edge-1-bbbb", Name: "edge-1", Address: "192.168.222.104", Vendor: "juniper", OSVersion: "66.6", OSVersionSource: "snmp", TenantID: "t-b"},
	}})
	if err := s.discovery.Upsert(models.Device{ID: "edge-1-hand", Name: "edge-1", OSVersion: "9.9.9", TenantID: "t-a"}); err != nil {
		t.Fatal(err)
	}
}

func srcAuthHealth(t *testing.T, s *server, c jwtClaims) ai.ToolResult {
	t.Helper()
	d := aiDataSource{srv: s, ctx: context.Background(), claims: c}
	tr, err := d.moduleDeviceHealth(s.aiPrincipal(c), "edge-1")
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func srcAuthItem(tr ai.ToolResult, suffix string) (ai.EvidenceItem, bool) {
	for _, it := range tr.Items {
		if strings.HasSuffix(it.CitationID, suffix) {
			return it, true
		}
	}
	return ai.EvidenceItem{}, false
}

func TestIrisCitesTheWinningSourceAndTheDisagreement(t *testing.T) {
	s, h, alice, bob := srcAuthFixture(t)
	srcAuthSeed(t, s)

	tr := srcAuthHealth(t, s, alice)
	inv := tr.Items[0]
	if !strings.Contains(inv.Text, "software version 20.6.1 (from the controller (vmanage))") {
		t.Fatalf("the default order must pick the controller and cite it: %s", inv.Text)
	}
	if !strings.Contains(inv.Text, "vendor Cisco (from the controller)") {
		t.Fatalf("the vendor must carry its source: %s", inv.Text)
	}
	note, ok := srcAuthItem(tr, ":sources")
	if !ok {
		t.Fatalf("a disagreement must produce its own citable item: %+v", tr.Items)
	}
	for _, want := range []string{
		"Sources disagree on the software version", "platform default source order",
		"the device itself (SNMP) reports 20.6.2", "a manual entry reports 9.9.9",
	} {
		if !strings.Contains(note.Text, want) {
			t.Errorf("the note lacks %q: %s", want, note.Text)
		}
	}
	if strings.Contains(note.Text, "vendor") {
		t.Errorf("Cisco and cisco agree; the vendor must not be reported as a disagreement: %s", note.Text)
	}
	for _, it := range tr.Items {
		if strings.Contains(it.Text, "66.6") || strings.Contains(it.Text, "juniper") {
			t.Fatalf("CROSS-TENANT LEAK: tenant B's value reached tenant A's answer: %s", it.Text)
		}
	}

	// Tenant B: its own device, one source, nothing to disagree about.
	trB := srcAuthHealth(t, s, bob)
	if _, ok := srcAuthItem(trB, ":sources"); ok || !strings.Contains(trB.Items[0].Text, "66.6") || strings.Contains(trB.Items[0].Text, "20.6") {
		t.Fatalf("tenant B's answer: %+v", trB.Items)
	}

	// Tenant A's admin reorders: A's answer changes, B's does not.
	if w := serveAs(h, alice, http.MethodPut, srcAuthPath, orderManualFirst); w.Code != http.StatusOK {
		t.Fatalf("put: %d", w.Code)
	}
	tr = srcAuthHealth(t, s, alice)
	if !strings.Contains(tr.Items[0].Text, "software version 9.9.9 (from a manual entry)") {
		t.Fatalf("the tenant's own order must decide: %s", tr.Items[0].Text)
	}
	note, _ = srcAuthItem(tr, ":sources")
	if !strings.Contains(note.Text, "this workspace's source order") || !strings.Contains(note.Text, "the controller (vmanage) reports 20.6.1") {
		t.Fatalf("the note must name the workspace's order and the overruled controller: %s", note.Text)
	}
	if got := srcAuthHealth(t, s, bob).Items[0].Text; !strings.Contains(got, "66.6") {
		t.Fatalf("tenant A's order changed tenant B's answer: %s", got)
	}
}

type srcAuthFailStore struct{ srcauthority.Store }

func (srcAuthFailStore) Get(context.Context, string) (srcauthority.Policy, bool, error) {
	return srcauthority.Policy{}, false, errors.New("db down")
}

func TestIrisSaysSoWhenTheOrderCannotBeRead(t *testing.T) {
	s, _, alice, _ := srcAuthFixture(t)
	srcAuthSeed(t, s)
	s.srcAuthority = srcAuthFailStore{}
	tr := srcAuthHealth(t, s, alice)
	if !strings.Contains(tr.Items[0].Text, "20.6.1 (from the controller") {
		t.Fatalf("a failed read falls back to the platform default: %s", tr.Items[0].Text)
	}
	said := false
	for _, n := range tr.Notes {
		said = said || strings.Contains(n, "source order could not be read")
	}
	if !said {
		t.Fatalf("the fallback must be said, never silent: %v", tr.Notes)
	}
	var b bytes.Buffer
	if err := s.srcAuthorityMetrics.Write(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `outcome="policy_error"} 1`) || !strings.Contains(b.String(), `outcome="disagreed"} 1`) {
		t.Fatalf("metrics: %s", b.String())
	}
}

func TestWhoseOrderApplies(t *testing.T) {
	owned := models.Device{ID: "d", TenantID: " T-A "}
	platform := models.Device{ID: "p"}
	for _, c := range []struct {
		name   string
		dev    models.Device
		tenant string
		cross  bool
		want   string
	}{
		{"a tenant uses its own", owned, "t-a", false, "t-a"},
		{"a tenant on a platform device still uses its own", platform, "t-a", false, "t-a"},
		{"a tenant never reaches another tenant's order", owned, "t-b", false, "t-b"},
		{"cross-tenant uses the device owner's", owned, TenantGlobal, true, "t-a"},
		{"cross-tenant on a platform device uses Provider's", platform, TenantGlobal, true, TenantGlobal},
	} {
		if got := srcAuthorityTenant(c.dev, c.tenant, c.cross); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// The golden citation case, through the real agent loop and the real tool: a
// model that states the winner and says nothing about the disagreement still
// produces an answer that states it, and the citation survives the verifier.
func TestAgentAnswerAlwaysStatesTheDisagreement(t *testing.T) {
	s, _, alice, _ := srcAuthFixture(t)
	srcAuthSeed(t, s)
	s.aiToolBudget = ai.NewDailyBudget()
	p := s.aiPrincipal(alice)
	reg := ai.Tools(aiDataSource{srv: s, ctx: context.Background(), claims: alice})
	pol := ai.NewPolicyEngine(ai.PolicyConfig{}, func(string) bool { return false })
	specs := ai.Manifest(reg, pol, p)

	for name, answer := range map[string]string{
		"silent about the disagreement": "edge-1 runs 20.6.1 [device:edge-1-aaaa].",
		"names the losing value":        "edge-1 may run 20.6.2.",
	} {
		round := 0
		call := func(_ context.Context, _ string, _ []ai.AgentTurn, _ []ai.ToolSpec) (string, []ai.ToolCall, error) {
			round++
			if round == 1 {
				return "", []ai.ToolCall{{ID: "c1", Name: "get_device_health", Args: json.RawMessage(`{"device":"edge-1"}`)}}, nil
			}
			return answer, nil, nil
		}
		res, err := s.runAgentLoop(context.Background(), alice, p, reg, pol, specs, "sys",
			[]copilotMessage{{Role: "user", Content: "what version is edge-1 running?"}}, nil, call)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Text, "Sources disagree on the software version") {
			t.Fatalf("%s: the answer hides the disagreement: %q", name, res.Text)
		}
		cited := false
		for _, st := range res.Statements {
			for _, c := range st.Citations {
				cited = cited || strings.HasSuffix(c, ":sources")
			}
		}
		if !cited {
			t.Fatalf("%s: the appended statement must keep its citation: %+v", name, res.Statements)
		}
	}
}

// The names srcauthority classifies must be the names the discovery sources
// actually use: a rename would otherwise silently make a source unranked.
func TestSourceNamesMatchTheDiscoverySources(t *testing.T) {
	for _, c := range []struct {
		real string
		want srcauthority.Class
	}{
		{nms.ControllerSourceName, srcauthority.ClassController},
		{wireless.SourceName, srcauthority.ClassController},
		{(&discovery.SNMPSource{}).Name(), srcauthority.ClassDiscovered},
		{(&discovery.NetboxSource{}).Name(), srcauthority.ClassDeclared},
		{(&discovery.StaticSource{}).Name(), srcauthority.ClassManual},
	} {
		if got := srcauthority.ClassOfRecord(c.real); got != c.want {
			t.Errorf("source %q classifies as %s, want %s", c.real, got, c.want)
		}
	}
	// Upsert stamps "manual" (discovery.go); the inventory read proves it.
	s, _, _, _ := srcAuthFixture(t)
	if err := s.discovery.Upsert(models.Device{ID: "hand", Name: "h", TenantID: "t-a"}); err != nil {
		t.Fatal(err)
	}
	recs := s.discovery.Constituents("hand")
	if len(recs) != 1 || srcauthority.ClassOfRecord(recs[0].Source) != srcauthority.ClassManual {
		t.Fatalf("an operator's record must classify as manual: %+v", recs)
	}
}

// Storage-layer proof (migration 0065): FORCE-RLS confines every statement to
// the tenant and the database refuses an order that is not a permutation, even
// when the application is bypassed.
func TestSourceAuthorityRLSIsolationPG(t *testing.T) {
	if os.Getenv("DATABASE_URL_TEST") == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ps, _ := orgContextPG(t)
	st := srcauthority.NewPGStore(ps.DB())
	ctx := context.Background()
	rev := []srcauthority.Class{srcauthority.ClassManual, srcauthority.ClassDeclared, srcauthority.ClassDiscovered, srcauthority.ClassController}

	if _, ok, err := st.Get(ctx, "acme"); err != nil || ok {
		t.Fatalf("empty: %v %v", ok, err)
	}
	if _, err := st.Put(ctx, "acme", "alice", rev); err != nil {
		t.Fatal(err)
	}
	p, ok, err := st.Get(ctx, "acme")
	if err != nil || !ok || p.Order[0] != srcauthority.ClassManual || p.UpdatedBy != "alice" || p.UpdatedAt.IsZero() {
		t.Fatalf("round trip: %+v %v %v", p, ok, err)
	}
	if _, err := st.Put(ctx, "acme", "bob", srcauthority.DefaultOrder()); err != nil {
		t.Fatal(err)
	}
	if p, _, _ = st.Get(ctx, "acme"); p.Order[0] != srcauthority.ClassController || p.UpdatedBy != "bob" {
		t.Fatalf("upsert: %+v", p)
	}
	if _, err := st.Put(ctx, "acme", "alice", rev); err != nil {
		t.Fatal(err)
	}

	// The store: another tenant reads nothing and its delete touches nothing.
	if _, ok, err := st.Get(ctx, "globex"); err != nil || ok {
		t.Fatalf("CROSS-TENANT LEAK through the store: %v %v", ok, err)
	}
	if err := st.Delete(ctx, "globex"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.Get(ctx, "acme"); !ok {
		t.Fatal("globex's delete removed acme's order")
	}

	// RLS itself: a statement with NO tenant filter, run as globex.
	raw := func(tenant, sql string, args ...any) (int64, error) {
		var n int64
		err := ps.DB().WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, sql, args...)
			n = tag.RowsAffected()
			return err
		})
		return n, err
	}
	if n, err := raw("globex", `UPDATE iris_source_authority SET updated_by = 'mallory'`); err != nil || n != 0 {
		t.Fatalf("RLS let globex update acme's row: n=%d err=%v", n, err)
	}
	if n, err := raw("globex", `DELETE FROM iris_source_authority`); err != nil || n != 0 {
		t.Fatalf("RLS let globex delete acme's row: n=%d err=%v", n, err)
	}
	if _, err := raw("globex", `INSERT INTO iris_source_authority (tenant_id, source_order, updated_by)
	    VALUES ('acme2', ARRAY['controller','discovered','declared','manual'], 'mallory')`); orgCtxPGCode(err) != "42501" {
		t.Fatalf("a row forged for another tenant must be refused by RLS: %v", err)
	}

	// The CHECK: anything but a permutation of the four classes.
	for name, order := range map[string]string{
		"short":     `ARRAY['controller','discovered','declared']`,
		"duplicate": `ARRAY['controller','controller','declared','manual']`,
		"unknown":   `ARRAY['controller','discovered','declared','model_inference']`,
		"long":      `ARRAY['controller','discovered','declared','manual','manual']`,
	} {
		if _, err := raw("globex", `INSERT INTO iris_source_authority (tenant_id, source_order, updated_by) VALUES ('globex', `+order+`, 'm')`); orgCtxPGCode(err) != "23514" {
			t.Errorf("%s order must be refused by the CHECK (23514): %v", name, err)
		}
	}

	// Reset.
	if err := st.Delete(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.Get(ctx, "acme"); ok {
		t.Fatal("delete did not reset")
	}
}
