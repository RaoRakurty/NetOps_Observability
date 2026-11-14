// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_changes_before_incidents_test.go — tracker 337 N-S3: "Show me what
// changed 30 minutes before every SD-WAN incident this week", end to end on the
// deterministic path (no model), plus the §3a contract of the causal-chain seam
// the planner reads to keep correlated and causal apart.
//
//   - the slice: question → grammar → validator → planner → summary, in the
//     caller's scope only; another tenant's incidents and changes never appear,
//     with or without ?as_tenant= / an acting tenant;
//   - the chain seam (nlqScope.ChangeChain): a foreign or unknown incident is
//     ErrNotFound, the read carries the caller's tenant_scope, a malformed id is
//     refused before any read;
//   - the planner's ledger-type → engine-kind map names only real ledger types
//     and real engine change kinds.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/dem/experience"
	"netops/backend/internal/nlquery/plan"
)

const s3Question = "Show me what changed 30 minutes before every SD-WAN incident in the last 7 days"

func s3Ask(t *testing.T, s *server, c jwtClaims, path string) ai.DataAnswer {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, nil)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	nlq := s.aiNLQuery(r, c)
	if nlq == nil {
		t.Fatal("the data arm is not wired for this caller")
	}
	d, err := nlq(context.Background(), ai.Principal{Tenant: c.Tenant}, s3Question, ai.DataOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestS3SliceAnswersOnTheDeterministicPathInTheCallersScope(t *testing.T) {
	s, a, b := corpusWorld(t)

	d := s3Ask(t, s, a, "/api/ai/ask")
	if d.Status != ai.DataAnswered {
		t.Fatalf("tenant A: status %q, text %q", d.Status, d.Text)
	}
	payload := string(d.Payload)
	if !strings.Contains(payload, `"chg-1"`) || !strings.Contains(payload, corpusIncidentA) {
		t.Fatalf("tenant A must see its own change near its own incident: %s", payload)
	}
	for _, foreign := range []string{`"chg-9"`, corpusIncidentB, "Mallory"} {
		if strings.Contains(payload, foreign) || strings.Contains(d.Text, foreign) {
			t.Fatalf("LEAK: tenant B's %s reached tenant A: %s", foreign, payload)
		}
	}
	// chg-2 (50 h old) and chg-3 (another site, 3 h old) are not within 30 min
	// of the incident.
	if strings.Contains(payload, `"chg-2"`) || strings.Contains(payload, `"chg-3"`) {
		t.Fatalf("only the changes inside each incident's window: %s", payload)
	}
	for _, want := range []string{
		"1 change was found before 1 incident.",
		"min before onset",
		"not established",
	} {
		if !strings.Contains(d.Text, want) {
			t.Errorf("answer missing %q:\n%s", want, d.Text)
		}
	}
	// The fixture's analysis names no change step, so nothing is chain-kind.
	if strings.Contains(payload, `"chain_kind"`) {
		t.Fatalf("no chain step in the fixture, so no row may be chain_kind: %s", payload)
	}
	var out struct {
		Result struct {
			Rows []map[string]any `json:"rows"`
		} `json:"result"`
	}
	if err := json.Unmarshal(d.Payload, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Result.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(out.Result.Rows))
	}
	row := out.Result.Rows[0]
	if row["relation"] != plan.RelationTemporal || row["relation_class"] != "DERIVED" || row["incident_id"] != corpusIncidentA {
		t.Fatalf("row = %+v", row)
	}
	if m, _ := row["minutes_before_incident"].(float64); m < 9 || m > 11 {
		t.Fatalf("chg-1 is 10 minutes before onset, got %v", row["minutes_before_incident"])
	}

	// Tenant B sees only its own — and walking in with ?as_tenant= or an acting
	// tenant changes nothing for a non-owner.
	for _, tc := range []struct {
		name string
		c    jwtClaims
		path string
	}{
		{"plain", b, "/api/ai/ask"},
		{"as_tenant", b, "/api/ai/ask?as_tenant=" + a.Tenant},
		{"acting", func() jwtClaims { x := b; x.ActingTenant = a.Tenant; return x }(), "/api/ai/ask"},
	} {
		d := s3Ask(t, s, tc.c, tc.path)
		p := string(d.Payload)
		if !strings.Contains(p, `"chg-9"`) || strings.Contains(p, `"chg-1"`) || strings.Contains(p, corpusIncidentA) {
			t.Fatalf("%s: tenant B must see only its own change and incident: %s", tc.name, p)
		}
	}
}

// chainCH answers corr_current reads by correlation id, and only inside the
// incident owner's tenant_scope — the row policy the real store enforces.
func chainCH(t *testing.T, owner map[string]string) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var scopes []string
	start := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		sql := string(body) + r.URL.Query().Get("query")
		scope := r.URL.Query().Get("tenant_scope")
		mu.Lock()
		scopes = append(scopes, scope)
		mu.Unlock()
		for id, tenant := range owner {
			if strings.Contains(sql, "correlation_id = '"+id+"'") && strings.Contains(sql, "corr_current") && scope == tenant {
				_, _ = fmt.Fprintf(w, `{"data":[{"correlation_id":%q,"state":"open","verdict_tier":"suspected","seam_type":"SDWAN","top_hypothesis":"sig.wan.loss","top_confidence":0.7,"affected":"{}","start_iso":%q}]}`, id, start)
				return
			}
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), scopes...) }
}

func TestNLQScopeChangeChainNeverCrossesTenants(t *testing.T) {
	const incA = "aaaaaaaa-1111-4222-8333-444444444444"
	const incB = "bbbbbbbb-1111-4222-8333-444444444444"
	ch, scopes := chainCH(t, map[string]string{incA: "t-a", incB: "t-b"})
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	s, a, b := nlqFixture(t)
	ctx := context.Background()

	// Own incident: never ErrNotFound (the analysis may or may not be readable
	// from this fixture — either way it is the caller's own incident).
	ha := s.nlqScopeFor(newAITestRequest(t, a), a)
	if _, err := ha.ChangeChain(ctx, incA); errors.Is(err, plan.ErrNotFound) {
		t.Fatalf("tenant A's own incident must resolve: %v", err)
	}
	// Foreign incident: ErrNotFound, exactly like an unknown one.
	for _, id := range []string{incB, "cccccccc-1111-4222-8333-444444444444"} {
		if _, err := ha.ChangeChain(ctx, id); !errors.Is(err, plan.ErrNotFound) {
			t.Fatalf("ChangeChain(%s) for tenant A = %v, want ErrNotFound", id, err)
		}
	}
	// ?as_tenant= on the request and an acting tenant are ignored for a non-owner.
	bActing := b
	bActing.ActingTenant = a.Tenant
	r := httptest.NewRequest(http.MethodPost, "/api/ai/ask?as_tenant="+a.Tenant, nil)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, bActing))
	hb := s.nlqScopeFor(r, bActing)
	if _, err := hb.ChangeChain(ctx, incA); !errors.Is(err, plan.ErrNotFound) {
		t.Fatalf("tenant B reached tenant A's incident chain via as_tenant: %v", err)
	}
	for _, sc := range scopes() {
		if sc != "t-a" && sc != "t-b" {
			t.Fatalf("a chain read ran outside a tenant scope: %q (all: %v)", sc, scopes())
		}
	}
	// A malformed id is refused before any read.
	before := len(scopes())
	if _, err := ha.ChangeChain(ctx, "x' OR 1=1 --"); !errors.Is(err, plan.ErrNotFound) {
		t.Fatalf("malformed id: %v", err)
	}
	if len(scopes()) != before {
		t.Fatal("a malformed id must never reach the store")
	}
}

// The planner keeps its own copy of which ledger types can be which engine
// change kinds (plan/chain.go). Both sides of it are pinned here.
func TestPlanEngineKindsAreRealLedgerTypesAndEngineKinds(t *testing.T) {
	m := plan.EngineKindsForType()
	if len(m) == 0 {
		t.Fatal("empty map")
	}
	for typ, kinds := range m {
		if !experience.ValidChangeType(typ) {
			t.Errorf("%s is not a change-ledger type", typ)
		}
		for _, k := range kinds {
			if !ai.IsEngineChangeKind(k) {
				t.Errorf("%s → %s: not an engine change kind", typ, k)
			}
		}
	}
	if _, ok := m[experience.ChangeInfrastructure]; ok {
		t.Error("a change made through Correlix itself is no engine change kind")
	}
}
