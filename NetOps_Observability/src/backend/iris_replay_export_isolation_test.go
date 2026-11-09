// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_replay_export_isolation_test.go — GET /api/ai/replay/export/{id} (tracker
// 337 N-H2, CLAUDE.md §3a).
//
// Pinned: a caller exports only their own tenant's correlation; another tenant's
// id and an unknown id are the same 404 with the same body; an as_tenant walk
// into another org is ignored; nothing that looks like a secret and nothing of
// another tenant's reaches the export; the export is field data, held out, and
// loads in the replay runner; a ledgered tool step is compared with its re-read,
// and a difference is named as live data that moved.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/aidecision"
	"netops/backend/internal/evalsplit"
	"netops/backend/internal/irisreplay"
	"netops/backend/internal/rbac"
)

const (
	replayIDA       = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
	replayIDB       = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
	replayIDUnknown = "cccccccc-3333-4333-8333-cccccccccccc"
	// Planted in tenant A's own evidence: must be masked on the way out.
	replaySecret = "hunter2-tenant-a-password"
	// Tenant B's own title: must never reach an export of tenant A's.
	replayForeign = "TENANT-B-PRIVATE-TITLE"
)

// replayFixture serves a hostile ClickHouse: it answers every query with the row
// the SQL names, whatever scope the query carries, so what a caller gets back is
// the application's doing.
func replayFixture(t *testing.T) (*server, jwtClaims, jwtClaims) {
	t.Helper()
	s, a, b := ledgerFixture(t)
	rowFor := func(id, tenant, topHypothesis, hypTitle string) string {
		hyp, err := json.Marshal(map[string]any{"ranking": map[string]any{"hypotheses": []map[string]any{
			{"id": "sig-" + tenant, "title": hypTitle, "confidence": 0.7, "satisfied": []string{"password=" + replaySecret}},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		quoted, err := json.Marshal(string(hyp))
		if err != nil {
			t.Fatal(err)
		}
		return `{"correlation_id":"` + id + `","tenant_id":"` + tenant + `","top_hypothesis":"` + topHypothesis + `","top_confidence":0.7,` +
			`"verdict_tier":"suspected","evidence_missing":"[]","affected":"[]","hypotheses":` + string(quoted) + `,` +
			`"signal_count":3,"node_count":2,"engine_version":"3.2.0+cfg.abc","catalog_version":"cat-7"}`
	}
	rowA := rowFor(replayIDA, a.Tenant, "sig.wan.flap", "WAN flap on edge-a")
	rowB := rowFor(replayIDB, b.Tenant, "sig.ent.isp", replayForeign)
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read query: %v", err)
		}
		switch sql := string(body); {
		case strings.Contains(sql, replayIDA):
			_, _ = w.Write([]byte(`{"data":[` + rowA + `]}`)) // a failed write surfaces as a failed read
		case strings.Contains(sql, replayIDB):
			_, _ = w.Write([]byte(`{"data":[` + rowB + `]}`)) // a failed write surfaces as a failed read
		default:
			_, _ = w.Write([]byte(`{"data":[]}`)) // a failed write surfaces as a failed read
		}
	}))
	t.Cleanup(ch.Close)
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	return s, a, b
}

func replayExport(t *testing.T, s *server, c jwtClaims, id, query string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/ai/replay/export/"+id+query, nil)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	s.handleAIReplayExport(w, r)
	return w
}

func exportedCase(t *testing.T, w *httptest.ResponseRecorder) ai.ReplayCase {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("export: %d %s", w.Code, w.Body.String())
	}
	cases, err := ai.ParseReplayCases("export", w.Body.Bytes())
	if err != nil {
		t.Fatalf("the export must load in the strict loader: %v\n%s", err, w.Body.String())
	}
	if len(cases) != 1 {
		t.Fatalf("%d cases", len(cases))
	}
	return cases[0]
}

func TestReplayExportOwnOnly(t *testing.T) {
	s, a, b := replayFixture(t)

	// Own correlation: the whole frozen case, stamped from the token.
	w := replayExport(t, s, a, replayIDA, "")
	c := exportedCase(t, w)
	if c.Principal.Tenant != a.Tenant || c.UI["correlation_id"] != replayIDA || c.Path != ai.ReplayPathAsk {
		t.Fatalf("case: %+v", c)
	}
	if _, foreign := c.Tenants[b.Tenant]; foreign || len(c.Tenants) != 1 {
		t.Fatalf("one tenant's partition only: %v", c.Tenants)
	}
	if c.EngineVersion == "" || !strings.HasPrefix(c.EngineVersion, "3.2.0") || c.CatalogVersion != "cat-7" {
		t.Fatalf("the engine's pins must travel: %q %q", c.EngineVersion, c.CatalogVersion)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	body := w.Body.String()
	for _, leak := range []string{replaySecret, replayForeign, b.Tenant, replayIDB} {
		if strings.Contains(body, leak) {
			t.Errorf("LEAK: %q in the export:\n%s", leak, body)
		}
	}

	// The other direction, to be sure the fixture is symmetric.
	if other := exportedCase(t, replayExport(t, s, b, replayIDB, "")); other.Principal.Tenant != b.Tenant {
		t.Fatalf("t-b's own export: %+v", other.Principal)
	}
}

// Another tenant's id and an unknown id are indistinguishable.
func TestReplayExportCrossTenantIs404IdenticalToUnknown(t *testing.T) {
	s, a, _ := replayFixture(t)
	foreign := replayExport(t, s, a, replayIDB, "")
	unknown := replayExport(t, s, a, replayIDUnknown, "")
	if foreign.Code != http.StatusNotFound || unknown.Code != http.StatusNotFound {
		t.Fatalf("CROSS-TENANT: foreign %d, unknown %d, want 404 both", foreign.Code, unknown.Code)
	}
	if foreign.Body.String() != unknown.Body.String() {
		t.Fatalf("the two 404s must have the same body:\n%q\n%q", foreign.Body.String(), unknown.Body.String())
	}
	if strings.Contains(foreign.Body.String(), replayForeign) {
		t.Fatalf("LEAK in a 404: %s", foreign.Body.String())
	}
	for _, bad := range []string{"", "x", "../../etc/passwd", replayIDA + "/x", "aaaaaaaa"} {
		if w := replayExport(t, s, a, bad, ""); w.Code != http.StatusNotFound || w.Body.String() != unknown.Body.String() {
			t.Errorf("malformed id %q: %d %s", bad, w.Code, w.Body.String())
		}
	}
}

// as_tenant into another org is ignored for a non-cross caller.
func TestReplayExportAsTenantIsIgnored(t *testing.T) {
	s, a, b := replayFixture(t)
	walker := b
	walker.ActingTenant = a.Tenant
	if w := replayExport(t, s, walker, replayIDA, "?as_tenant="+a.Tenant); w.Code != http.StatusNotFound {
		t.Fatalf("CROSS-TENANT: as_tenant walked into t-a: %d %s", w.Code, w.Body.String())
	}
	own := exportedCase(t, replayExport(t, s, walker, replayIDB, "?as_tenant="+a.Tenant))
	if own.Principal.Tenant != b.Tenant {
		t.Fatalf("the owner comes from the token: %q", own.Principal.Tenant)
	}
	// The real door too: withActingTenant ignores a tenant the caller cannot reach.
	r := httptest.NewRequest(http.MethodGet, "/api/ai/replay/export/"+replayIDA+"?as_tenant="+a.Tenant, nil)
	if got := s.withActingTenant(r, b); got.Tenant != b.Tenant {
		t.Fatalf("withActingTenant moved a non-owner: %q", got.Tenant)
	}
}

func TestReplayExportPermissions(t *testing.T) {
	s, a, _ := replayFixture(t)
	op := a
	op.Role = "operator"
	if w := replayExport(t, s, op, replayIDA, ""); w.Code != http.StatusForbidden {
		t.Fatalf("no administration:read: %d", w.Code)
	}
	// A custom role that reads the admin area but not incidents: refused too.
	if _, err := s.roles.Upsert(rbac.Role{ID: "admin-reader", Name: "Admin Reader", Permissions: map[string]int{"administration": LevelRead}}); err != nil {
		t.Fatal(err)
	}
	reader := a
	reader.Role = "admin-reader"
	if w := replayExport(t, s, reader, replayIDA, ""); w.Code != http.StatusForbidden {
		t.Fatalf("administration:read without incident read: %d %s", w.Code, w.Body.String())
	}
	r := httptest.NewRequest(http.MethodPost, "/api/ai/replay/export/"+replayIDA, nil)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, a))
	w := httptest.NewRecorder()
	s.handleAIReplayExport(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodGet, "/api/ai/replay/export/"+replayIDA, nil)
	w = httptest.NewRecorder()
	s.handleAIReplayExport(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", w.Code)
	}
	// The platform owner reads any tenant's, and the case belongs to that tenant.
	owner := jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal, Sub: "root"}
	c := exportedCase(t, replayExport(t, s, owner, replayIDB, ""))
	if c.Principal.Tenant != "t-b" {
		t.Fatalf("a platform export is the incident's own tenant's case: %q", c.Principal.Tenant)
	}
}

// Both layers: a read that lost its scope still refuses a foreign row.
func TestReplaySnapshotIsStrict(t *testing.T) {
	s, a, _ := replayFixture(t)
	d := aiDataSource{srv: s, ctx: context.Background(), scope: a.Tenant, claims: a}
	snap, err := d.replaySnapshot(context.Background(), replayIDA)
	if err != nil || snap.TenantID != a.Tenant || snap.EngineVersion == "" || snap.Hypotheses == "" {
		t.Fatalf("own: %+v %v", snap, err)
	}
	if _, err := d.replaySnapshot(context.Background(), replayIDB); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("CROSS-TENANT: the hostile store's foreign row must be refused: %v", err)
	}
	if _, err := d.replaySnapshot(context.Background(), "x' OR 1=1"); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("a malformed id must not reach the store: %v", err)
	}
}

// The export is field data, held out, and replays offline.
func TestReplayExportIsFieldDataAndReplays(t *testing.T) {
	s, a, _ := replayFixture(t)
	c := exportedCase(t, replayExport(t, s, a, replayIDA, ""))
	if c.Source != string(evalsplit.SourceField) || c.Split() != evalsplit.HeldOut {
		t.Fatalf("source %q, split %s", c.Source, c.Split())
	}
	if c.Category != ai.ReplayCategoryField || !c.ProviderDown || c.Capture == nil || c.Capture.CapturedAt == "" {
		t.Fatalf("case: %+v", c)
	}
	if !strings.Contains(c.Description, "re-read at capture") {
		t.Fatalf("the case must say what it is: %q", c.Description)
	}
	rep, err := irisreplay.Run(context.Background(), []ai.ReplayCase{c}, irisreplay.Options{EngineSemver: "3.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	cr := rep.Cases[0]
	if cr.Result != irisreplay.ResultPass {
		t.Fatalf("the export must replay: %s %v", cr.Result, cr.Failures)
	}
	if cr.Split != string(evalsplit.HeldOut) {
		t.Fatalf("split %s", cr.Split)
	}
	if cr.Pins[0].Status != irisreplay.PinMismatch {
		t.Fatalf("a pin that differs is reported: %+v", cr.Pins)
	}
	if rep.Aggregate.Results[irisreplay.ResultPass] != 1 {
		t.Fatalf("%+v", rep.Aggregate)
	}
}

// The ledger holds hashes: a ledgered step is compared with its re-read.
func TestReplayExportComparesTheLedger(t *testing.T) {
	s, a, b := replayFixture(t)
	const decision = "dddddddd-4444-4444-8444-dddddddddddd"
	entries := []aidecision.Entry{
		{ID: "eeeeeeee-5555-4555-8555-000000000001", DecisionID: decision, Seq: 0, EventType: aidecision.QuestionReceived,
			Principal: a.Sub, Surface: aidecision.SurfaceAsk, IncidentRef: replayIDA, ArgsSHA256: aidecision.SHA256Hex([]byte("q"))},
		{ID: "eeeeeeee-5555-4555-8555-000000000002", DecisionID: decision, Seq: 1, EventType: aidecision.ToolExecuted, Tool: "get_problem",
			Principal: a.Sub, Surface: aidecision.SurfaceAsk, ArgsSHA256: ai.HashToolArgs(ai.ToolArgs{"problem_id": replayIDA}), ResultSHA256: strings.Repeat("0", 64), Outcome: "ok"},
		{ID: "eeeeeeee-5555-4555-8555-000000000003", DecisionID: decision, Seq: 2, EventType: aidecision.ToolExecuted, Tool: "search_logs",
			Principal: a.Sub, Surface: aidecision.SurfaceAsk, ArgsSHA256: strings.Repeat("a", 64), ResultSHA256: strings.Repeat("0", 64), Outcome: "ok"},
		{ID: "eeeeeeee-5555-4555-8555-000000000004", DecisionID: decision, Seq: 3, EventType: aidecision.ToolExecuted, Tool: "get_device_state",
			Principal: a.Sub, Surface: aidecision.SurfaceAsk, ArgsSHA256: ai.HashToolArgs(ai.ToolArgs{"problem_id": replayIDA}), ResultSHA256: strings.Repeat("0", 64), Outcome: "ok"},
		{ID: "eeeeeeee-5555-4555-8555-000000000005", DecisionID: decision, Seq: 4, EventType: aidecision.AnswerReturned,
			Principal: a.Sub, Surface: aidecision.SurfaceAsk, ModelProvider: "anthropic", ModelName: "of-record", ModelTier: "strong"},
	}
	if err := s.aiDecisions.Append(context.Background(), a.Tenant, entries); err != nil {
		t.Fatal(err)
	}
	c := exportedCase(t, replayExport(t, s, a, replayIDA, ""))
	if c.Capture.DecisionID != decision {
		t.Fatalf("decision %q: %+v", c.Capture.DecisionID, c.Capture)
	}
	want := map[string]string{"get_problem": irisreplay.CaptureMoved, "search_logs": irisreplay.CaptureArgsUnknown, "get_device_state": irisreplay.CaptureNotReRead}
	for _, chk := range c.Capture.ToolChecks {
		if want[chk.Tool] != chk.Status {
			t.Errorf("%s: %s, want %s", chk.Tool, chk.Status, want[chk.Tool])
		}
		delete(want, chk.Tool)
	}
	if len(want) != 0 {
		t.Fatalf("not compared: %v", want)
	}
	if c.Model == nil || c.Model.Name != "of-record" {
		t.Fatalf("model of record: %+v", c.Model)
	}
	rep, err := irisreplay.Run(context.Background(), []ai.ReplayCase{c}, irisreplay.Options{})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rep.Cases[0].Provenance, " | ")
	for _, wantLine := range []string{"live data moved since the decision: get_problem", "re-read at capture"} {
		if !strings.Contains(joined, wantLine) {
			t.Errorf("the report must say %q: %s", wantLine, joined)
		}
	}
	if strings.Contains(joined, "as seen ") && !strings.Contains(joined, "not as seen") {
		t.Errorf("a re-read is never 'as seen': %s", joined)
	}

	// Another tenant's ledger is not consulted: t-b sees its own incident with no
	// decision, whatever t-a's ledger holds.
	other := exportedCase(t, replayExport(t, s, b, replayIDB, ""))
	if other.Capture.DecisionID != "" {
		t.Fatalf("CROSS-TENANT: t-b's capture found decision %q", other.Capture.DecisionID)
	}
}
