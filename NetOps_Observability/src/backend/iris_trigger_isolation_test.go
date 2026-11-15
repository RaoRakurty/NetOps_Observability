// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_trigger_isolation_test.go — triggered Iris investigations (tracker 337
// N-I2, CLAUDE.md §3a).
//
// Pinned:
//   - the routes are tenant-scoped: own-only list, another tenant's trigger id
//     is 404 on every verb, ?as_tenant= is ignored, the platform owner's
//     all-tenants view is refused (choose a workspace), a tenant in the body is
//     refused, and changes need administration:admin;
//   - a triggered run acts as a SYSTEM principal bound to exactly the
//     trigger's tenant with the read-only role (never cross-tenant, never the
//     platform owner, no infrastructure:write → no active probes);
//   - the workspace switch off → nothing runs and nothing is recorded;
//   - no reachable model → a recorded "skipped: model unavailable";
//   - one incident starts at most one run per trigger; the daily run cap and
//     the token allowance hold;
//   - an admitted run's trace is held in the trigger's tenant only, and its
//     result is attached to the incident in that tenant.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/aientitlement"
	"netops/backend/internal/irisinvest"
	"netops/backend/internal/iristrigger"
)

func trigFixture(t *testing.T) (*server, jwtClaims, jwtClaims) {
	t.Helper()
	s, a, b := invFixture(t) // ai.investigate on for every tenant, no provider key
	s.irisTriggers = iristrigger.NewMemStore()
	s.irisTriggerJobs = make(chan irisTriggerJob, irisTriggerQueue)
	if !s.aiEntitled(irisTriggerClaims(a.Tenant), aientitlement.Investigate) {
		t.Fatal("fixture: AI investigations must be entitled for the trigger's tenant")
	}
	return s, a, b
}

func trigCall(t *testing.T, s *server, c jwtClaims, method, path, body string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	s.handleAIInvestigationTriggers(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out) // error bodies are asserted by status
	return w.Code, out
}

const trigBody = `{"name":"Critical BGP","kind":"incident","filter":{"min_severity":"error","signature":"bgp"}}`

func createTrigger(t *testing.T, s *server, c jwtClaims) string {
	t.Helper()
	code, out := trigCall(t, s, c, http.MethodPost, "/api/ai/investigation-triggers", trigBody)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	id, _ := out["id"].(string)
	if !iristrigger.ValidID(id) {
		t.Fatalf("created trigger has no id: %v", out)
	}
	return id
}

func TestIrisTriggerRoutesAreTenantScoped(t *testing.T) {
	s, a, b := trigFixture(t)
	id := createTrigger(t, s, a)

	code, out := trigCall(t, s, a, http.MethodGet, "/api/ai/investigation-triggers", "")
	if trigs, _ := out["triggers"].([]any); code != http.StatusOK || len(trigs) != 1 {
		t.Fatalf("owner list: %d %v", code, out)
	}
	if settings, _ := out["settings"].(map[string]any); settings["enabled"] != false {
		t.Fatalf("the workspace switch must start off: %v", settings)
	}
	code, out = trigCall(t, s, b, http.MethodGet, "/api/ai/investigation-triggers?as_tenant="+a.Tenant, "")
	if trigs, _ := out["triggers"].([]any); code != http.StatusOK || len(trigs) != 0 {
		t.Fatalf("another tenant (with as_tenant) listed: %d %v", code, out)
	}
	for _, m := range []struct{ method, body string }{
		{http.MethodPut, `{"enabled":false}`},
		{http.MethodDelete, ""},
	} {
		if code, _ := trigCall(t, s, b, m.method, "/api/ai/investigation-triggers/"+id, m.body); code != http.StatusNotFound {
			t.Fatalf("%s of another tenant's trigger: %d, want 404", m.method, code)
		}
	}
	if tr, err := s.irisTriggers.Get(context.Background(), a.Tenant, id); err != nil || !tr.Enabled {
		t.Fatalf("another tenant changed the trigger: %+v %v", tr, err)
	}
	// A tenant in the body is refused, not used.
	smuggled := `{"name":"x","kind":"schedule","schedule":{"every_minutes":30},"tenant":"` + a.Tenant + `"}`
	if code, _ := trigCall(t, s, b, http.MethodPost, "/api/ai/investigation-triggers", smuggled); code != http.StatusBadRequest {
		t.Fatalf("a body tenant was accepted: %d", code)
	}
	// The platform owner's all-tenants view must choose a workspace.
	owner := jwtClaims{Sub: "root", Role: "admin"}
	if code, _ := trigCall(t, s, owner, http.MethodGet, "/api/ai/investigation-triggers", ""); code != http.StatusBadRequest {
		t.Fatalf("the all-tenants view read triggers: %d", code)
	}
	// A malformed id is 404, not a crash or a 400 that tells ids apart.
	if code, _ := trigCall(t, s, a, http.MethodPut, "/api/ai/investigation-triggers/not-an-id", `{"enabled":true}`); code != http.StatusNotFound {
		t.Fatalf("malformed id: %d", code)
	}
}

func TestIrisTriggerChangesNeedAdmin(t *testing.T) {
	s, a, _ := trigFixture(t)
	viewer := jwtClaims{Sub: "viewer-a", Role: RoleReadOnly, Tenant: a.Tenant}
	if code, _ := trigCall(t, s, viewer, http.MethodPost, "/api/ai/investigation-triggers", trigBody); code != http.StatusForbidden {
		t.Fatalf("a read-only user created a trigger: %d", code)
	}
	if code, _ := trigCall(t, s, viewer, http.MethodPut, "/api/ai/investigation-triggers/settings",
		`{"enabled":true,"max_runs_per_day":5,"max_tokens_per_day":5000}`); code != http.StatusForbidden {
		t.Fatalf("a read-only user turned the workspace switch on: %d", code)
	}
	if code, out := trigCall(t, s, a, http.MethodPut, "/api/ai/investigation-triggers/settings",
		`{"enabled":true,"max_runs_per_day":0,"max_tokens_per_day":5000}`); code != http.StatusBadRequest {
		t.Fatalf("zero runs a day accepted: %d %v", code, out)
	}
}

func TestIrisTriggerSystemPrincipalIsReadOnlyAndBoundToOneTenant(t *testing.T) {
	s, a, _ := trigFixture(t)
	c := irisTriggerClaims(a.Tenant)
	if tenant, cross := principalTenant(c); tenant != a.Tenant || cross {
		t.Fatalf("system principal scope = %q cross=%v", tenant, cross)
	}
	if isPlatformOwner(c) {
		t.Fatal("the system principal is the platform owner")
	}
	if s.roles.Allows(c.Role, "infrastructure", LevelWrite) {
		t.Fatal("the system principal can write infrastructure — active probes would be reachable")
	}
	if !s.roles.Allows(c.Role, "infrastructure", LevelRead) {
		t.Fatal("the system principal cannot read infrastructure — every run would be empty")
	}
	for _, bad := range []string{"", "global", "*", "__all__"} {
		if _, ok := irisTriggerTenant(bad); ok {
			t.Fatalf("tenant %q accepted for an unattended run", bad)
		}
	}
	if _, err := s.irisTriggerRun(context.Background(), iristrigger.Trigger{ID: "x", TenantID: "global"}, nil, time.Now()); err == nil {
		t.Fatal("a platform-realm trigger ran")
	}
}

func enableTriggers(t *testing.T, s *server, tenant string, runs, tokens int) {
	t.Helper()
	if err := s.irisTriggers.PutSettings(context.Background(), tenant,
		iristrigger.Settings{Enabled: true, MaxRunsPerDay: runs, MaxTokensPerDay: tokens}); err != nil {
		t.Fatal(err)
	}
}

func storedTrigger(t *testing.T, s *server, tenant string) iristrigger.Trigger {
	t.Helper()
	tr, err := s.irisTriggers.Create(context.Background(), tenant, "u", iristrigger.Trigger{
		Name: "Critical BGP", Kind: iristrigger.KindIncident, Enabled: true,
		Filter: iristrigger.Filter{MinSeverity: "error"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func runsOf(t *testing.T, s *server, tenant string) []iristrigger.Run {
	t.Helper()
	runs, err := s.irisTriggers.Runs(context.Background(), tenant, 50)
	if err != nil {
		t.Fatal(err)
	}
	return runs
}

func TestIrisTriggerSwitchOffRunsAndRecordsNothing(t *testing.T) {
	s, a, _ := trigFixture(t)
	s.irisTriggerModelCheck = func(context.Context, jwtClaims) bool { return true }
	tr := storedTrigger(t, s, a.Tenant)
	ev := &iristrigger.IncidentEvent{IncidentID: "inc-1", Severity: "critical", Title: "BGP down"}
	run, err := s.irisTriggerRun(context.Background(), tr, ev, time.Now())
	if err != nil || run.Status != "" || len(runsOf(t, s, a.Tenant)) != 0 {
		t.Fatalf("switch off: run=%+v err=%v runs=%v", run, err, runsOf(t, s, a.Tenant))
	}
	// AI investigations off for the workspace → the same: state, not history.
	enableTriggers(t, s, a.Tenant, 5, 50_000)
	t.Setenv("AI_TOOLS_ALL_TENANTS", "false")
	t.Setenv("FEATURE_AI_TOOLS", "false")
	setAIModelsForTest(t, s, true, false)
	if run, err := s.irisTriggerRun(context.Background(), tr, ev, time.Now()); err != nil || run.Status != "" {
		t.Fatalf("not entitled: run=%+v err=%v", run, err)
	}
	if n := len(runsOf(t, s, a.Tenant)); n != 0 {
		t.Fatalf("a run was recorded without AI investigations: %d", n)
	}
}

func TestIrisTriggerModelUnavailableIsRecordedNotRetried(t *testing.T) {
	s, a, _ := trigFixture(t)
	s.irisTriggerModelCheck = func(context.Context, jwtClaims) bool { return false }
	enableTriggers(t, s, a.Tenant, 5, 50_000)
	tr := storedTrigger(t, s, a.Tenant)
	ev := &iristrigger.IncidentEvent{IncidentID: "inc-1", Severity: "critical", Title: "BGP down"}
	run, err := s.irisTriggerRun(context.Background(), tr, ev, time.Now())
	if err != nil || run.Status != iristrigger.RunSkipped || run.Reason != iristrigger.SkipModelUnavailable {
		t.Fatalf("run=%+v err=%v", run, err)
	}
	if !strings.Contains(run.Summary, "no AI model could be reached") {
		t.Fatalf("the skip must say why: %q", run.Summary)
	}
	// The same incident does not try again behind the operator's back.
	if again, err := s.irisTriggerRun(context.Background(), tr, ev, time.Now()); err != nil || again.Status != "" {
		t.Fatalf("a skipped incident was retried: %+v %v", again, err)
	}
}

func TestIrisTriggerRunActsInItsTenantAndDedupes(t *testing.T) {
	s, a, b := trigFixture(t)
	s.aiInvestigations = irisinvest.NewMemStore()
	s.irisTriggerModelCheck = func(context.Context, jwtClaims) bool { return true }
	enableTriggers(t, s, a.Tenant, 2, 50_000)
	tr := storedTrigger(t, s, a.Tenant)
	ctx := context.Background()
	ev := &iristrigger.IncidentEvent{IncidentID: "inc-1", Severity: "critical", Title: "BGP down", DeviceID: "edge-b-only"}

	run, err := s.irisTriggerRun(ctx, tr, ev, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != iristrigger.RunDone || run.InvestigationID == "" {
		t.Fatalf("admitted run: %+v", run)
	}
	if _, err := s.aiInvestigations.Get(ctx, a.Tenant, false, run.InvestigationID); err != nil {
		t.Fatalf("the trace is not held in the trigger's tenant: %v", err)
	}
	if _, err := s.aiInvestigations.Get(ctx, b.Tenant, false, run.InvestigationID); !errors.Is(err, irisinvest.ErrNotFound) {
		t.Fatalf("another tenant read the triggered trace: %v", err)
	}
	if tr2, _ := s.aiInvestigations.Get(ctx, a.Tenant, false, run.InvestigationID); tr2.Target.DeviceID != "" {
		t.Fatalf("a device outside the tenant's inventory was bound: %+v", tr2.Target)
	}
	if n := len(runsOf(t, s, b.Tenant)); n != 0 {
		t.Fatalf("a run landed in another tenant: %d", n)
	}
	// One run per incident per trigger.
	if again, err := s.irisTriggerRun(ctx, tr, ev, time.Now()); err != nil || again.Status != "" {
		t.Fatalf("the same incident ran twice: %+v %v", again, err)
	}
	// The daily run cap (2): the second incident runs, the third is skipped and says so.
	ev2, ev3 := *ev, *ev
	ev2.IncidentID, ev3.IncidentID = "inc-2", "inc-3"
	if r, err := s.irisTriggerRun(ctx, tr, &ev2, time.Now()); err != nil || r.Status != iristrigger.RunDone {
		t.Fatalf("second incident: %+v %v", r, err)
	}
	r3, err := s.irisTriggerRun(ctx, tr, &ev3, time.Now())
	if err != nil || r3.Status != iristrigger.RunSkipped || r3.Reason != iristrigger.SkipRunCap {
		t.Fatalf("the daily cap did not hold: %+v %v", r3, err)
	}
}

func TestIrisTriggerTokenAllowanceHolds(t *testing.T) {
	s, a, _ := trigFixture(t)
	s.irisTriggerModelCheck = func(context.Context, jwtClaims) bool { return true }
	enableTriggers(t, s, a.Tenant, 50, 1000)
	tr := storedTrigger(t, s, a.Tenant)
	ctx := context.Background()
	// A run that already spent the day's allowance.
	prior, err := s.irisTriggers.Admit(ctx, a.Tenant, iristrigger.Run{TriggerID: tr.ID, DedupeKey: "incident:old"}, 50, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.irisTriggers.Finish(ctx, a.Tenant, prior.ID, iristrigger.RunDone, "concluded", "", 1000, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	run, err := s.irisTriggerRun(ctx, tr, &iristrigger.IncidentEvent{IncidentID: "inc-9", Severity: "critical"}, time.Now())
	if err != nil || run.Status != iristrigger.RunSkipped || run.Reason != iristrigger.SkipTokenCap {
		t.Fatalf("the token allowance did not hold: %+v %v", run, err)
	}
}

func TestIrisTriggersOnIncidentQueuesMatchesOnly(t *testing.T) {
	s, a, b := trigFixture(t)
	enableTriggers(t, s, a.Tenant, 5, 50_000)
	tr := storedTrigger(t, s, a.Tenant) // min severity: error
	// B has a trigger that would match, but B's switch is off.
	_ = storedTrigger(t, s, b.Tenant)
	s.irisTriggersOnIncident(Incident{ID: "inc-low", TenantID: a.Tenant, Severity: "warning", Title: "BGP flap"}, "")
	s.irisTriggersOnIncident(Incident{ID: "inc-b", TenantID: b.Tenant, Severity: "critical", Title: "BGP down"}, "")
	s.irisTriggersOnIncident(Incident{ID: "inc-plat", TenantID: "", Severity: "critical", Title: "BGP down"}, "")
	if n := len(s.irisTriggerJobs); n != 0 {
		t.Fatalf("queued %d runs for incidents that must not match", n)
	}
	s.irisTriggersOnIncident(Incident{ID: "inc-hit", TenantID: a.Tenant, Severity: "critical", Title: "BGP down"}, "")
	if n := len(s.irisTriggerJobs); n != 1 {
		t.Fatalf("queued %d runs, want 1", n)
	}
	j := <-s.irisTriggerJobs
	if j.trigger.ID != tr.ID || j.trigger.TenantID != a.Tenant || j.event == nil || j.event.IncidentID != "inc-hit" {
		t.Fatalf("queued job: %+v", j)
	}
}
