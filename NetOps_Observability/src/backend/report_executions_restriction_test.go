// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// report_executions_restriction_test.go — the CLAUDE.md §3a rule-5 isolation
// test for the operator-visibility restriction (Tenant.OperatorRestricted) on
// the report RUN / EXECUTION / ARTIFACT surfaces (tracker 304).
//
// This is the most serious disclosure the restriction programme found, and the
// reason is the artifact. An execution row carries the rendered SUMMARY of one
// report fire ("3 active alert(s) · 2 critical/error"), which is bad enough on
// the Global runs map — but GET /api/reports/executions/{id}/artifact STREAMS
// the stored document itself. That document was rendered under the owning
// tenant's OWN scope, so it is not a summary of that tenant's data, it IS that
// tenant's data: device names, management addresses, link health, findings.
//
// WHY THE FIX IS IN THE STORE. reports.ExecutionStore.List applies its LIMIT
// inside the store. A filter at the handler would drop the hidden rows AFTER the
// bound had already been spent on them, so the page comes back short — and the
// missing slots are themselves the disclosure — while runsFromExecutions' fixed
// 200-row window would let a restricted tenant's runs push a VISIBLE tenant's
// latest run off the operator's screen. So the resolved scope (reports.ExecScope)
// is threaded INTO the store and the filter and the bound are one pass.
//
// WHY THE XLSX IS UNZIPPED HERE. A sheet inside an .xlsx is DEFLATE-compressed
// inside a zip: searching the streamed response bytes for a leaked device name
// finds nothing whether or not the leak is real, so a test that greps the raw
// body passes on a live leak. Every artifact assertion below therefore goes
// through rxArtifactText, which unzips a workbook before searching it.

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/reports"
)

// The values that must not reach the platform operator once tenant B asks not to
// be readable. rxBDevice is named INSIDE the rendered artifact; rxBSummary is
// the run detail the Global runs map prints beside the report's name.
const (
	rxADevice  = "rx-globex-edge"
	rxBDevice  = "rx-acme-edge"
	rxBAddr    = "10.77.0.2"
	rxBSummary = "3 active alert(s) · 2 critical/error"
	rxASummary = "1 active alert(s) · 0 critical/error"
	rxPSummary = "platform stack summary"
	rxPDevice  = "rx-stack-jump"
)

// ── an in-memory ExecutionStore that honours the scope it is handed ──────────
//
// The in-memory twin of PGExecStore: same contract, same ordering, same
// "a row the scope may not see is ABSENT" answer. It exists so this test can
// drive the real router and the real handlers without Postgres; the SQL twin is
// proved against a live database in report_executions_pg_test.go
// (TestPgExecStoreHonoursTheOperatorVisibilityRestriction).
type memExecStore struct {
	reports.ExecutionStore // embedded nil: any other method call panics loudly
	recs                   []reports.ExecutionRecord
}

func (m *memExecStore) List(_ context.Context, sc reports.ExecScope, q reports.ExecQuery) ([]reports.ExecutionRecord, error) {
	out := []reports.ExecutionRecord{}
	for _, r := range m.recs {
		if q.Kind != "" && r.Kind != q.Kind {
			continue
		}
		if q.ScheduleID != "" && r.ScheduleID != q.ScheduleID {
			continue
		}
		if !sc.Sees(r) {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func (m *memExecStore) Get(_ context.Context, sc reports.ExecScope, id string) (reports.ExecutionRecord, []reports.ExecEvent, bool, error) {
	for _, r := range m.recs {
		if r.ID != id {
			continue
		}
		if !sc.Sees(r) {
			return reports.ExecutionRecord{}, nil, false, nil
		}
		return r, []reports.ExecEvent{{Phase: reports.PhaseCompleted, At: r.CompletedAt}}, true, nil
	}
	return reports.ExecutionRecord{}, nil, false, nil
}

// memArtifactStore serves the stored, fully-rendered documents by key.
type memArtifactStore struct {
	reports.ArtifactStore
	byKey map[string]reports.Artifact
}

func (m *memArtifactStore) Load(_ context.Context, ref reports.ArtifactRef) (reports.Artifact, error) {
	a, ok := m.byKey[ref.Key]
	if !ok {
		return reports.Artifact{}, errNoSuchArtifact
	}
	return a, nil
}

var errNoSuchArtifact = errStr("artifact not stored")

type errStr string

func (e errStr) Error() string { return string(e) }

// ── the fixture ──────────────────────────────────────────────────────────────

type rxFixture struct {
	t    *testing.T
	srv  *httptest.Server
	s    *server
	adm  string
	a, b *orgFixture
	// the three executions: tenant A's, tenant B's, and a platform-owned one.
	aExec, bExec, pExec string
	aSched, bSched      string
}

// rxArtifactText renders a response body as SEARCHABLE text. An .xlsx is a zip
// whose sheet is DEFLATE-compressed, so the bytes of a leak do not appear in the
// response at all — the workbook has to be opened. Anything else is returned
// as-is.
func rxArtifactText(t *testing.T, body []byte) string {
	t.Helper()
	if !bytes.HasPrefix(body, []byte("PK\x03\x04")) {
		return string(body)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("the xlsx artifact is not a readable zip: %v", err)
	}
	var out strings.Builder
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s inside the workbook: %v", f.Name, err)
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close() // read already succeeded or failed; the error below reports it
		if err != nil {
			t.Fatalf("read %s inside the workbook: %v", f.Name, err)
		}
		out.WriteString(f.Name)
		out.WriteByte('\n')
		out.Write(b)
		out.WriteByte('\n')
	}
	return out.String()
}

// rxViewModel is the gathered data one report fire prints — a device table
// naming the device and where it is reachable.
func rxViewModel(name, tenant, device, addr, summary string) reports.ViewModel {
	return reports.ViewModel{
		ReportID: name, ReportName: name, Kind: "device_inventory", TenantID: tenant,
		GeneratedAt: time.Date(2026, 9, 12, 6, 0, 0, 0, time.UTC), Summary: summary,
		Sections: []reports.Section{{
			Title:  "Devices",
			Header: []string{"Device", "Address", "Status"},
			Rows:   [][]string{{device, addr, "reachable"}},
		}},
	}
}

func newRxFixture(t *testing.T) *rxFixture {
	t.Helper()
	srv, s := newTestServerState(t)
	adm := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", adm, map[string]any{"name": "RxOrg " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", adm, map[string]any{"name": "RxTenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "rx-user-" + name
		st, b = do(t, srv, "POST", "/api/users", adm, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	// One saved report object per tenant plus a platform-owned one, so the runs
	// map has a name to key on and the platform's own row can be shown to
	// survive every filter.
	body := json.RawMessage(`{"kind":"device_inventory","enabled":true}`)
	aObj, err := s.saved.Create("report", "Globex Inventory", "admin", a.tenantID, body)
	if err != nil {
		t.Fatalf("saved report A: %v", err)
	}
	bObj, err := s.saved.Create("report", "Acme Inventory", "admin", b.tenantID, body)
	if err != nil {
		t.Fatalf("saved report B: %v", err)
	}
	pObj, err := s.saved.Create("report", "Platform Inventory", "admin", "", body)
	if err != nil {
		t.Fatalf("saved report platform: %v", err)
	}

	// The stored, fully-rendered documents. Tenant B gets BOTH an html and a
	// real xlsx workbook, because the two leak differently: the html leak is
	// visible in the response bytes and the xlsx leak is not.
	xl := reports.NewXLSXRenderer()
	html, err := reports.NewHTMLRenderer()
	if err != nil {
		t.Fatalf("html renderer: %v", err)
	}
	arts := map[string]reports.Artifact{}
	mustRender := func(key string, r reports.Renderer, vm reports.ViewModel) reports.Artifact {
		art, err := r.Render(context.Background(), vm)
		if err != nil {
			t.Fatalf("render %s: %v", key, err)
		}
		arts[key] = art
		return art
	}
	mustRender("art-a-html", html, rxViewModel("Globex Inventory", a.tenantID, rxADevice, "10.88.0.2", rxASummary))
	mustRender("art-b-html", html, rxViewModel("Acme Inventory", b.tenantID, rxBDevice, rxBAddr, rxBSummary))
	mustRender("art-b-xlsx", xl, rxViewModel("Acme Inventory", b.tenantID, rxBDevice, rxBAddr, rxBSummary))
	mustRender("art-p-html", html, rxViewModel("Platform Inventory", "", rxPDevice, "10.99.0.2", rxPSummary))

	fire := time.Date(2026, 9, 12, 6, 0, 0, 0, time.UTC)
	rec := func(id, tenant, sched string, refs []reports.ArtifactRef) reports.ExecutionRecord {
		return reports.ExecutionRecord{
			ID: id, Kind: "report", TenantID: tenant, ScheduleID: sched, JobID: id + "-job",
			FireTime: fire, StartedAt: fire, CompletedAt: fire.Add(time.Minute),
			Status: reports.StatusCompleted, Artifacts: refs,
		}
	}
	ref := func(key, format, ct, summary string) reports.ArtifactRef {
		return reports.ArtifactRef{Format: format, ContentType: ct, Key: key, Summary: summary,
			SizeBytes: len(arts[key].Bytes)}
	}
	execs := &memExecStore{recs: []reports.ExecutionRecord{
		rec("exec-a", a.tenantID, aObj.ID, []reports.ArtifactRef{ref("art-a-html", "html", "text/html", rxASummary)}),
		rec("exec-b", b.tenantID, bObj.ID, []reports.ArtifactRef{
			ref("art-b-html", "html", "text/html", rxBSummary),
			ref("art-b-xlsx", "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", rxBSummary),
		}),
		rec("exec-p", "", pObj.ID, []reports.ArtifactRef{ref("art-p-html", "html", "text/html", rxPSummary)}),
	}}
	s.reportPipeline = &reportPipeline{srv: s, execs: execs, artifacts: &memArtifactStore{byKey: arts}}

	return &rxFixture{t: t, srv: srv, s: s, adm: adm, a: a, b: b,
		aExec: "exec-a", bExec: "exec-b", pExec: "exec-p", aSched: aObj.ID, bSched: bObj.ID}
}

func (f *rxFixture) restrictB() {
	f.t.Helper()
	if _, err := f.s.tenants.SetOperatorRestricted(f.b.tenantID, true); err != nil {
		f.t.Fatalf("restrict tenant B: %v", err)
	}
}

func withAsTenant(path, asTenant string) string {
	if asTenant == "" {
		return path
	}
	if strings.Contains(path, "?") {
		return path + "&as_tenant=" + asTenant
	}
	return path + "?as_tenant=" + asTenant
}

// executions lists GET /api/reports/executions and returns the decoded rows plus
// the raw body (so an assertion can grep bytes, not only typed fields).
func (f *rxFixture) executions(token, asTenant string) ([]reports.ExecutionRecord, string) {
	f.t.Helper()
	path := withAsTenant("/api/reports/executions", asTenant)
	st, body := do(f.t, f.srv, "GET", path, token, nil)
	if st != http.StatusOK {
		f.t.Fatalf("GET %s = %d: %s", path, st, body)
	}
	var out []reports.ExecutionRecord
	if err := json.Unmarshal(body, &out); err != nil {
		f.t.Fatalf("decode executions: %v (%s)", err, body)
	}
	return out, string(body)
}

// runs reads GET /api/reports/runs — the map whose values carry run.Detail, the
// rendered summary of that tenant's report.
func (f *rxFixture) runs(token, asTenant string) (map[string]reportRun, string) {
	f.t.Helper()
	path := withAsTenant("/api/reports/runs", asTenant)
	st, body := do(f.t, f.srv, "GET", path, token, nil)
	if st != http.StatusOK {
		f.t.Fatalf("GET %s = %d: %s", path, st, body)
	}
	var out map[string]reportRun
	if err := json.Unmarshal(body, &out); err != nil {
		f.t.Fatalf("decode runs: %v (%s)", err, body)
	}
	return out, string(body)
}

// artifact streams GET /api/reports/executions/{id}/artifact and returns the
// status and the bytes ACTUALLY WRITTEN to the wire.
func (f *rxFixture) artifact(token, id, format, asTenant string) (int, []byte) {
	f.t.Helper()
	path := "/api/reports/executions/" + id + "/artifact"
	if format != "" {
		path += "?format=" + format
	}
	return do(f.t, f.srv, "GET", withAsTenant(path, asTenant), token, nil)
}

// runNow drives POST /api/reports/run — the "Send now" trigger. Its synchronous
// (file-backend) branch answers with the run it just produced, Detail and all.
func (f *rxFixture) runNow(token, id, asTenant string) (int, []byte) {
	f.t.Helper()
	return do(f.t, f.srv, "POST", withAsTenant("/api/reports/run", asTenant), token, map[string]any{"id": id})
}

func (f *rxFixture) execByID(token, id, asTenant string) (int, []byte) {
	f.t.Helper()
	return do(f.t, f.srv, "GET", withAsTenant("/api/reports/executions/"+id, asTenant), token, nil)
}

// TestReportExecutionsHonourTheOperatorVisibilityRestriction — both halves, the
// list, the runs map and the STREAMED ARTIFACT BYTES, with the restricted
// tenant's own view captured before the switch and compared after.
func TestReportExecutionsHonourTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRxFixture(t)

	// ── baseline: without it every assertion below could pass on a route that
	//    serves nothing at all. ──
	base, baseRaw := f.executions(f.adm, "")
	if len(base) != 3 {
		t.Fatalf("baseline: the owner should read 3 executions, got %d: %s", len(base), baseRaw)
	}
	if !strings.Contains(baseRaw, rxBSummary) {
		t.Fatalf("baseline: the owner's execution list does not carry tenant B's run summary:\n%s", baseRaw)
	}
	baseRuns, baseRunsRaw := f.runs(f.adm, "")
	if got := baseRuns[f.bSched].Detail; got != rxBSummary {
		t.Fatalf("baseline: the owner's runs map should carry tenant B's detail %q, got %q (%s)", rxBSummary, got, baseRunsRaw)
	}
	// The artifact — the whole point of the row. Both formats, and the xlsx is
	// UNZIPPED, because a DEFLATEd sheet hides the leak from a byte search.
	for _, format := range []string{"html", "xlsx"} {
		st, body := f.artifact(f.adm, f.bExec, format, "")
		if st != http.StatusOK {
			t.Fatalf("baseline: owner GET tenant B's %s artifact = %d: %s", format, st, body)
		}
		text := rxArtifactText(t, body)
		if !strings.Contains(text, rxBDevice) || !strings.Contains(text, rxBAddr) {
			t.Fatalf("baseline: tenant B's %s artifact does not name %s/%s — the fixture proves nothing:\n%s",
				format, rxBDevice, rxBAddr, text)
		}
	}
	// Tenant B's OWN view, captured BEFORE the switch.
	bBefore, bBeforeRaw := f.executions(f.b.token, "")
	if len(bBefore) != 1 || bBefore[0].ID != f.bExec {
		t.Fatalf("baseline: tenant B should read its own single execution, got %s", bBeforeRaw)
	}
	bRunsBefore, _ := f.runs(f.b.token, "")
	stBefore, bArtBefore := f.artifact(f.b.token, f.bExec, "xlsx", "")
	if stBefore != http.StatusOK {
		t.Fatalf("baseline: tenant B cannot download its own artifact: %d", stBefore)
	}

	f.restrictB()

	// ── half 1: the operator's GLOBAL view drops tenant B. ──
	global, globalRaw := f.executions(f.adm, "")
	for _, leak := range []string{f.bExec, rxBSummary, f.b.tenantID} {
		if strings.Contains(globalRaw, leak) {
			t.Errorf("RESTRICTION LEAK: the owner's Global execution list carries tenant B's %q:\n%s", leak, globalRaw)
		}
	}
	if len(global) != 2 {
		t.Errorf("the owner's Global execution list returned %d rows, want 2 (tenant A's and the platform's)", len(global))
	}
	seen := map[string]bool{}
	for _, r := range global {
		seen[r.ID] = true
	}
	if !seen[f.aExec] || !seen[f.pExec] {
		t.Errorf("restricting tenant B also removed tenant A's execution or the PLATFORM's own: %v", seen)
	}

	globalRuns, globalRunsRaw := f.runs(f.adm, "")
	if _, ok := globalRuns[f.bSched]; ok {
		t.Errorf("RESTRICTION LEAK: the owner's Global runs map still carries tenant B's report %q with detail %q:\n%s",
			f.bSched, globalRuns[f.bSched].Detail, globalRunsRaw)
	}
	if strings.Contains(globalRunsRaw, rxBSummary) {
		t.Errorf("RESTRICTION LEAK: the owner's Global runs map still prints tenant B's rendered summary %q:\n%s", rxBSummary, globalRunsRaw)
	}
	if _, ok := globalRuns[f.aSched]; !ok {
		t.Errorf("restricting tenant B removed tenant A's run from the owner's Global map: %s", globalRunsRaw)
	}

	// ── the artifact: the stored, fully-rendered document. 404, never 403 — a
	//    403 confirms the execution id exists. ──
	for _, format := range []string{"", "html", "xlsx"} {
		for _, asTenant := range []string{"", f.b.tenantID} {
			st, body := f.artifact(f.adm, f.bExec, format, asTenant)
			if st != http.StatusNotFound {
				text := rxArtifactText(t, body)
				t.Errorf("ARTIFACT LEAK: owner GET tenant B's artifact (format=%q as_tenant=%q) = %d, want 404.\n"+
					"  The response is the tenant's own rendered report:\n%s", format, asTenant, st, text)
				continue
			}
			if text := rxArtifactText(t, body); strings.Contains(text, rxBDevice) || strings.Contains(text, rxBAddr) {
				t.Errorf("the 404 body itself names tenant B's device/address:\n%s", text)
			}
		}
	}
	// The by-id row is equally absent (it carries the artifact key and summary).
	for _, asTenant := range []string{"", f.b.tenantID} {
		if st, body := f.execByID(f.adm, f.bExec, asTenant); st != http.StatusNotFound {
			t.Errorf("owner GET tenant B's execution by id (as_tenant=%q) = %d, want 404: %s", asTenant, st, body)
		}
	}

	// "Send now" on a restricted tenant's report is refused the same way. The
	// async branch answers "queued", but the file-backend branch below answers
	// with the run it produced — Detail and all — so both are gated.
	for _, asTenant := range []string{"", f.b.tenantID} {
		if st, body := f.runNow(f.adm, f.bSched, asTenant); st != http.StatusNotFound {
			t.Errorf("owner POST /api/reports/run on tenant B's report (as_tenant=%q) = %d, want 404: %s", asTenant, st, body)
		}
	}

	// ── half 2: ?as_tenant into the restricted tenant reads nothing. Not even
	//    the platform's own execution — a scope that may read none of a tenant
	//    is not served the rest of the platform under that tenant's name. ──
	into, intoRaw := f.executions(f.adm, f.b.tenantID)
	if len(into) != 0 {
		t.Errorf("RESTRICTION LEAK: owner→tenantB executions returned %d rows: %s", len(into), intoRaw)
	}
	if intoRuns, raw := f.runs(f.adm, f.b.tenantID); len(intoRuns) != 0 {
		t.Errorf("RESTRICTION LEAK: owner→tenantB runs map returned %d entries: %s", len(intoRuns), raw)
	}

	// ── the owner scoped into the UNRESTRICTED tenant is unmoved, artifact and
	//    all. ──
	intoA, intoARaw := f.executions(f.adm, f.a.tenantID)
	if len(intoA) != 1 || intoA[0].ID != f.aExec {
		t.Errorf("restricting tenant B moved the owner→tenantA execution list: %s", intoARaw)
	}
	if st, body := f.artifact(f.adm, f.aExec, "html", ""); st != http.StatusOK || !strings.Contains(string(body), rxADevice) {
		t.Errorf("restricting tenant B broke the owner's read of tenant A's artifact: %d %s", st, body)
	}
	// And the PLATFORM's own artifact survives every filter.
	if st, body := f.artifact(f.adm, f.pExec, "html", ""); st != http.StatusOK || !strings.Contains(string(body), rxPDevice) {
		t.Errorf("the restriction swallowed the platform's OWN artifact: %d %s", st, body)
	}

	// ── half 3: the restricted tenant's OWN view is unchanged. The switch hides
	//    a tenant from the platform, never from itself. ──
	bAfter, bAfterRaw := f.executions(f.b.token, "")
	if len(bAfter) != len(bBefore) || bAfter[0].ID != f.bExec {
		t.Errorf("the restriction changed tenant B's OWN execution list: %s before, %s after", bBeforeRaw, bAfterRaw)
	}
	bRunsAfter, bRunsAfterRaw := f.runs(f.b.token, "")
	if len(bRunsAfter) != len(bRunsBefore) || bRunsAfter[f.bSched].Detail != rxBSummary {
		t.Errorf("the restriction changed tenant B's OWN runs map: %d entries before, now %s", len(bRunsBefore), bRunsAfterRaw)
	}
	stAfter, bArtAfter := f.artifact(f.b.token, f.bExec, "xlsx", "")
	if stAfter != http.StatusOK || !bytes.Equal(bArtBefore, bArtAfter) {
		t.Errorf("the restriction took tenant B's OWN report away from it: %d, %d bytes before / %d after",
			stAfter, len(bArtBefore), len(bArtAfter))
	}
	if text := rxArtifactText(t, bArtAfter); !strings.Contains(text, rxBDevice) {
		t.Errorf("tenant B's own workbook lost its own device:\n%s", text)
	}
	// Tenant A is unmoved on its own surface too, and still cannot see B.
	aOwn, aOwnRaw := f.executions(f.a.token, "")
	if len(aOwn) != 1 || aOwn[0].ID != f.aExec || strings.Contains(aOwnRaw, rxBDevice) {
		t.Errorf("tenant A's own execution list is wrong or names tenant B: %s", aOwnRaw)
	}
	if st, _ := f.artifact(f.a.token, f.bExec, "html", ""); st != http.StatusNotFound {
		t.Errorf("CROSS-TENANT LEAK: tenant A reading tenant B's artifact = %d, want 404", st)
	}
}

// TestReportRunsFileBackendHonoursTheOperatorVisibilityRestriction covers the
// OTHER backend. /api/reports/runs has two implementations — the execution
// history under Postgres, and the scheduler's in-memory map under the default
// file backend — and run.Detail is the same rendered summary in both.
func TestReportRunsFileBackendHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRxFixture(t)
	// File backend: no async pipeline, the scheduler's own map instead.
	f.s.reportPipeline = nil
	f.s.reports = &reportScheduler{
		srv: f.s, saved: f.s.saved, discovery: f.s.discovery, alerts: alerts.NewEngine("", nil),
		runs: map[string]reportRun{
			f.aSched:   {Status: "ok", Detail: rxASummary, LastRun: time.Date(2026, 9, 12, 6, 0, 0, 0, time.UTC)},
			f.bSched:   {Status: "ok", Detail: rxBSummary, LastRun: time.Date(2026, 9, 12, 6, 0, 0, 0, time.UTC)},
			"orphaned": {Status: "error", Detail: "the report was deleted"},
		},
	}
	// The seam the synchronous branch renders through, wired the way the live
	// scheduler wires it — without it "Send now" cannot be exercised at all and
	// the 404s below would prove nothing.
	f.s.reports.ds = f.s.reports.dataSource()

	base, baseRaw := f.runs(f.adm, "")
	if base[f.bSched].Detail != rxBSummary {
		t.Fatalf("baseline: the file backend's runs map should carry tenant B's detail, got %s", baseRaw)
	}
	bBefore, _ := f.runs(f.b.token, "")
	if len(bBefore) != 1 || bBefore[f.bSched].Detail != rxBSummary {
		t.Fatalf("baseline: tenant B should read its own run: %+v", bBefore)
	}

	f.restrictB()

	global, globalRaw := f.runs(f.adm, "")
	if _, ok := global[f.bSched]; ok {
		t.Errorf("RESTRICTION LEAK: the file backend's Global runs map still carries tenant B's report with detail %q:\n%s",
			global[f.bSched].Detail, globalRaw)
	}
	if strings.Contains(globalRaw, rxBSummary) {
		t.Errorf("RESTRICTION LEAK: the file backend's Global runs map still prints %q:\n%s", rxBSummary, globalRaw)
	}
	if _, ok := global[f.aSched]; !ok {
		t.Errorf("restricting tenant B removed tenant A's run: %s", globalRaw)
	}
	if _, ok := global["orphaned"]; !ok {
		t.Errorf("the restriction swallowed the platform-owned orphan run, which no tenant owns: %s", globalRaw)
	}
	if into, raw := f.runs(f.adm, f.b.tenantID); len(into) != 0 {
		t.Errorf("RESTRICTION LEAK: owner→tenantB file-backend runs returned %d entries: %s", len(into), raw)
	}
	// "Send now" answers with the run it just produced on this branch — the same
	// Detail the list stopped serving — so it is refused, 404 not 403.
	for _, asTenant := range []string{"", f.b.tenantID} {
		if st, body := f.runNow(f.adm, f.bSched, asTenant); st != http.StatusNotFound {
			t.Errorf("RESTRICTION LEAK: owner \"Send now\" on tenant B's report (as_tenant=%q) = %d, want 404: %s",
				asTenant, st, body)
		}
	}
	// Tenant A's report is still triggerable by the owner.
	if st, body := f.runNow(f.adm, f.aSched, ""); st != http.StatusOK && st != http.StatusAccepted {
		t.Errorf("restricting tenant B broke the owner's Send-now on tenant A's report: %d %s", st, body)
	}
	// The restricted tenant's own view is untouched, and still excludes the
	// platform's orphan (it never saw it).
	bAfter, bAfterRaw := f.runs(f.b.token, "")
	if len(bAfter) != len(bBefore) || bAfter[f.bSched].Detail != rxBSummary {
		t.Errorf("the restriction changed tenant B's OWN file-backend runs map: %s", bAfterRaw)
	}
}
