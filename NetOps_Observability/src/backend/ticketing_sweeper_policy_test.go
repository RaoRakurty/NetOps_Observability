package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/ticketing"
)

// Shuttled back from the adapter test move: sweeper policy-state resolution,
// worker isolation and itsm-store assertions are integrator code. Fixtures
// duplicated (test files cannot be imported across packages).
// fakePD is a minimal Events API v2 endpoint recording every enqueue.
type fakePD struct {
	mu       sync.Mutex
	srv      *httptest.Server
	events   []map[string]any // decoded request bodies
	status   int              // response code override (0 = 202)
	retryHdr string
}

func newFakePD() *fakePD {
	f := &fakePD{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/enqueue" {
			w.WriteHeader(404)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.events = append(f.events, body)
		f.mu.Unlock()
		if f.retryHdr != "" {
			w.Header().Set("Retry-After", f.retryHdr)
		}
		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}
		w.WriteHeader(202)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "success", "dedup_key": asString(body["dedup_key"])})
	}))
	return f
}

func (f *fakePD) cfg(tenant string) ticketing.SystemConfig {
	return ticketing.SystemConfig{System: "pagerduty", TenantID: tenant,
		InstanceURL: f.srv.URL, AuthType: "routing_key", APIToken: "RK-" + tenant}
}

func (f *fakePD) adapter() *ticketing.PagerDutyAdapter {
	return ticketing.NewPagerDutyAdapterWithClient(f.srv.Client())
}

func (f *fakePD) all() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]map[string]any, len(f.events))
	copy(out, f.events)
	return out
}

func pdPayload(corr string) ticketing.Payload {
	return ticketing.Payload{CorrObjectID: corr, ExternalSystem: "pagerduty",
		Title: "Confirmed local link fault on edge1", Verdict: "confirmed",
		Confidence: 0.91, Summary: "two planes agree", Urgency: 1,
		RCAURL: "https://correlix.example/app/correlations/" + corr}
}

// Dual-system resolution: SN + PD policies both enabled resolve independently
// (no HELD), per-system conflict still fails closed, PD is opt-in.
func TestResolvePolicyState_PerSystem(t *testing.T) {
	ctx := context.Background()
	store := ticketing.NewMemStore()
	sw := &ticketSweeper{store: store}

	sn := ticketing.IncidentPolicy{ID: "sn1", TenantID: "t_a", Name: "sn", Enabled: true,
		ExternalSystem: "servicenow", MinVerdict: "suspected"}
	pd := ticketing.IncidentPolicy{ID: "pd1", TenantID: "t_a", Name: "pd", Enabled: true,
		ExternalSystem: "pagerduty", MinVerdict: "confirmed"}
	if err := store.PutPolicy(ctx, sn); err != nil {
		t.Fatalf("put sn: %v", err)
	}
	if err := store.PutPolicy(ctx, pd); err != nil {
		t.Fatalf("put pd (dual-enable must be legal): %v", err)
	}

	if res := sw.resolvePolicyState(ctx, "t_a", "servicenow"); res.state != policyStateActive || res.policy.ID != "sn1" {
		t.Fatalf("sn resolution: %+v", res)
	}
	if res := sw.resolvePolicyState(ctx, "t_a", "pagerduty"); res.state != policyStateActive || res.policy.ID != "pd1" {
		t.Fatalf("pd resolution: %+v", res)
	}
	// second enabled PD policy → conflict at the store
	pd2 := pd
	pd2.ID = "pd2"
	if err := store.PutPolicy(ctx, pd2); !errors.Is(err, ticketing.ErrPolicyConflict) {
		t.Fatalf("second enabled pd policy: err=%v, want conflict", err)
	}
	// no PD policy → opt-in default is OFF (never a default-on pager)
	if res := sw.resolvePolicyState(ctx, "t_b", "pagerduty"); res.state != policyStateOptedOut || res.policy.Enabled {
		t.Fatalf("pd must be opt-in, got %+v", res)
	}
	// SN keeps its default-on MVP fallback
	if res := sw.resolvePolicyState(ctx, "t_b", "servicenow"); res.state != policyStateDefault || !res.policy.Enabled {
		t.Fatalf("sn default lost: %+v", res)
	}
}

// Two-tenant isolation through the WORKER: tenant A's delivery uses A's
// routing key + A-scoped dedup key; B likewise; a tenant-mismatched
// connection is quarantined without any external call.
func TestPDWorker_TenantIsolation(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	fA, fB := newFakePD(), newFakePD()
	defer fA.srv.Close()
	defer fB.srv.Close()
	store := ticketing.NewMemStore()
	ctx := context.Background()

	resolve := func(_ context.Context, tenant, system string) (ticketing.SystemConfig, bool, error) {
		if system != "pagerduty" {
			return ticketing.SystemConfig{}, false, nil
		}
		switch tenant {
		case "t_a":
			return fA.cfg("t_a"), true, nil
		case "t_b":
			return fB.cfg("t_b"), true, nil
		}
		return ticketing.SystemConfig{}, false, nil
	}
	w := ticketing.NewWorker(store, resolve, func(msg string, fields map[string]any) { logWarn("ticketing", msg, fields) }, func(msg string, fields map[string]any) { logError("ticketing", msg, fields) })
	w.RegisterAdapter("pagerduty", fA.adapter()) // same transport works for both fakes (URL comes from cfg)

	corrA := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	corrB := corrA // SAME local id in both tenants — keys must still differ
	if err := ticketing.EnqueueCreate(ctx, store, "t_a", "pagerduty", pdPayload(corrA)); err != nil {
		t.Fatal(err)
	}
	if err := ticketing.EnqueueCreate(ctx, store, "t_b", "pagerduty", pdPayload(corrB)); err != nil {
		t.Fatal(err)
	}
	if n, err := w.Tick(ctx, time.Now().UTC()); err != nil || n != 2 {
		t.Fatalf("runOnce: n=%d err=%v", n, err)
	}

	evA, evB := fA.all(), fB.all()
	if len(evA) != 1 || len(evB) != 1 {
		t.Fatalf("deliveries A=%d B=%d, want 1 each", len(evA), len(evB))
	}
	if asString(evA[0]["routing_key"]) != "RK-t_a" || asString(evB[0]["routing_key"]) != "RK-t_b" {
		t.Fatalf("routing keys crossed tenants: A=%v B=%v", evA[0]["routing_key"], evB[0]["routing_key"])
	}
	keyA, keyB := asString(evA[0]["dedup_key"]), asString(evB[0]["dedup_key"])
	if keyA == keyB {
		t.Fatalf("same local incident id produced identical dedup keys across tenants: %q", keyA)
	}
	if !strings.Contains(keyA, ":t_a:") || !strings.Contains(keyB, ":t_b:") {
		t.Fatalf("dedup keys missing tenant identity: %q / %q", keyA, keyB)
	}

	// tenant-mismatch quarantine: resolver stamps the WRONG tenant
	evil := func(_ context.Context, _ string, _ string) (ticketing.SystemConfig, bool, error) {
		return fB.cfg("t_b"), true, nil // claims B's connection for A's delivery
	}
	w2 := ticketing.NewWorker(store, evil, func(msg string, fields map[string]any) { logWarn("ticketing", msg, fields) }, func(msg string, fields map[string]any) { logError("ticketing", msg, fields) })
	w2.RegisterAdapter("pagerduty", fA.adapter())
	if err := ticketing.EnqueueCreate(ctx, store, "t_a", "pagerduty",
		pdPayload("cccccccc-cccc-4ccc-8ccc-cccccccccccc")); err != nil {
		t.Fatal(err)
	}
	before := len(fB.all())
	if _, err := w2.Tick(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if len(fB.all()) != before {
		t.Fatal("SECURITY: mismatched-tenant delivery reached the external provider")
	}
	items, _, _ := store.ListOutbox(ctx, "t_a", false, ticketing.MaxPage, 0)
	found := false
	for _, it := range items {
		if it.CorrObjectID == "cccccccc-cccc-4ccc-8ccc-cccccccccccc" {
			found = true
			if it.Status != "dead_letter" || !strings.Contains(it.LastError, "SECURITY") {
				t.Fatalf("mismatch not quarantined: %+v", it)
			}
		}
	}
	if !found {
		t.Fatal("quarantined item not found in tenant outbox")
	}
}

// Policy gates: undetermined/low-severity RCA objects never page when the PD
// policy requires confirmed (spec: alert-storm + gate regressions).
func TestPDPolicy_GatesBlockPaging(t *testing.T) {
	pol := ticketing.IncidentPolicy{ID: "pd1", TenantID: "t_a", Enabled: true,
		ExternalSystem: "pagerduty", MinVerdict: "confirmed"}
	und := ticketing.CorrFacts{Verdict: "undetermined", PeakSeverity: "critical", HasAffectedEntity: true}
	if d := ticketing.EvalDecision(und, pol, nil, time.Now()); d.Create {
		t.Fatal("undetermined must not page")
	}
	susp := ticketing.CorrFacts{Verdict: "suspected", PeakSeverity: "critical", HasAffectedEntity: true}
	if d := ticketing.EvalDecision(susp, pol, nil, time.Now()); d.Create {
		t.Fatal("suspected must not page under confirmed-only policy")
	}
	disabled := pol
	disabled.Enabled = false
	conf := ticketing.CorrFacts{Verdict: "confirmed", PeakSeverity: "critical", HasAffectedEntity: true}
	if d := ticketing.EvalDecision(conf, disabled, nil, time.Now()); d.Create {
		t.Fatal("disabled policy must not page")
	}
}

// ── #103-E Slack RCA destination ─────────────────────────────────────────────

type fakeSlackHook struct {
	mu     sync.Mutex
	srv    *httptest.Server
	bodies []map[string]any
	status int
}

func newFakeSlackHook() *fakeSlackHook {
	f := &fakeSlackHook{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		f.bodies = append(f.bodies, b)
		f.mu.Unlock()
		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	return f
}

func (f *fakeSlackHook) cfg(tenant string) ticketing.SystemConfig {
	return ticketing.SystemConfig{System: "slack", TenantID: tenant,
		InstanceURL: ticketing.SlackHooksOrigin, AuthType: "webhook", APIToken: f.srv.URL + "/WH-" + tenant}
}

// The secret webhook must never be persisted onto the ticket link: the link's
// InstanceURL comes from cfg.InstanceURL, which for Slack is the bare origin.
func TestSlackLink_NeverStoresWebhookSecret(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newFakeSlackHook()
	defer f.srv.Close()
	store := ticketing.NewMemStore()
	ctx := context.Background()
	resolve := func(_ context.Context, tenant, system string) (ticketing.SystemConfig, bool, error) {
		if system != "slack" {
			return ticketing.SystemConfig{}, false, nil
		}
		return f.cfg(tenant), true, nil
	}
	w := ticketing.NewWorker(store, resolve, func(msg string, fields map[string]any) { logWarn("ticketing", msg, fields) }, func(msg string, fields map[string]any) { logError("ticketing", msg, fields) })
	w.RegisterAdapter("slack", ticketing.NewSlackAdapterWithClient(f.srv.Client()))
	if err := ticketing.EnqueueCreate(ctx, store, "t_a", "slack",
		pdPayload("44444444-4444-4444-8444-444444444444")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Tick(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	link, found, err := store.GetLink(ctx, "t_a", false, "44444444-4444-4444-8444-444444444444", "slack")
	if err != nil || !found {
		t.Fatalf("link missing: %v", err)
	}
	if strings.Contains(link.InstanceURL, "WH-") || strings.Contains(link.InstanceURL, f.srv.URL) {
		t.Fatalf("SECURITY: webhook secret persisted on link: %q", link.InstanceURL)
	}
	if link.InstanceURL != ticketing.SlackHooksOrigin {
		t.Fatalf("link instance url = %q, want bare origin", link.InstanceURL)
	}
}

// Triple-enable: SN + PD + Slack policies all active per system, no HELD.
func TestResolvePolicyState_TripleSystem(t *testing.T) {
	ctx := context.Background()
	store := ticketing.NewMemStore()
	sw := &ticketSweeper{store: store}
	for i, sys := range []string{"servicenow", "pagerduty", "slack"} {
		p := ticketing.IncidentPolicy{ID: sys[:2] + "1", TenantID: "t_tri", Name: sys, Enabled: true,
			ExternalSystem: sys, MinVerdict: "confirmed"}
		if err := store.PutPolicy(ctx, p); err != nil {
			t.Fatalf("put %d %s: %v", i, sys, err)
		}
	}
	for _, sys := range []string{"servicenow", "pagerduty", "slack"} {
		if res := sw.resolvePolicyState(ctx, "t_tri", sys); res.state != policyStateActive {
			t.Fatalf("%s not active under triple-enable: %+v", sys, res)
		}
	}
}

// ── Global-tenant (single-org customer) parity (#103, owner requirement) ────
// A deployment that doesn't use tenants runs everything as the global tenant:
// its connections live under the "" config key, its correlation objects carry
// tenant_id "" (canonicalized to "global"), and EVERY destination must
// resolve exactly as it does for a real tenant. Pins the itsmKey collapse for
// servicenow, pagerduty, and slack + global policy resolution end to end.
func TestGlobalTenant_AllDestinationsResolve(t *testing.T) {
	store := ticketing.NewITSMConfigStoreForTest(map[string]itsmConfig{
		"": { // platform-owner / single-org config key
			ServiceNow: serviceNowConfig{Enabled: true, InstanceURL: "https://dev.example.service-now.com", User: "u", Password: "p"},
			PagerDuty:  pagerDutyRCAConfig{Enabled: true, RoutingKey: "RK-global"},
			Slack:      slackRCAConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/services/T/G/x"},
			Jira:       jiraConfig{Enabled: true, BaseURL: "https://global.atlassian.net", Email: "noc@example.com", APIToken: "tok", ProjectKey: "NOC"},
		},
	})
	// The sweeper hands us the CANONICAL tenant ("global"), never "".
	canon := canonicalCorrTenant("")
	if canon != TenantGlobal {
		t.Fatalf("canonicalCorrTenant(\"\") = %q, want %q", canon, TenantGlobal)
	}
	for _, sys := range []string{"servicenow", "pagerduty", "slack", "jira"} {
		cfg, ok := store.SystemConfigFor(canon, sys)
		if !ok {
			t.Fatalf("global tenant cannot resolve %s connection — single-org deployments broken", sys)
		}
		// Worker tenant assertion must hold for the canonical/global pair.
		if canonicalCorrTenant(cfg.TenantID) != canon {
			t.Fatalf("%s: cfg tenant %q fails the worker assertion vs %q", sys, cfg.TenantID, canon)
		}
	}
	// Policies stored under the canonical global tenant resolve per system.
	ctx := context.Background()
	tstore := ticketing.NewMemStore()
	sw := &ticketSweeper{store: tstore}
	if err := tstore.PutPolicy(ctx, ticketing.IncidentPolicy{ID: "gpd", TenantID: canon, Name: "g-pd",
		Enabled: true, ExternalSystem: "pagerduty", MinVerdict: "confirmed"}); err != nil {
		t.Fatal(err)
	}
	if res := sw.resolvePolicyState(ctx, canon, "pagerduty"); res.state != policyStateActive || res.policy.ID != "gpd" {
		t.Fatalf("global pagerduty policy not resolving: %+v", res)
	}
	// Dedup identity for the global tenant is stable and tenant-qualified.
	if k := ticketing.PagerDutyDedupKey(canon, "55555555-5555-4555-8555-555555555555"); !strings.Contains(k, ":global:") {
		t.Fatalf("global dedup key missing canonical tenant: %q", k)
	}
}

// ── #103 UX-2: human display id in notification payloads ────────────────────
// Operators reported raw hex identifiers in notifications. Every operator-facing
// string leads with the friendly Correlix Problem ID (P-XXXXXX — the same handle
// the RCA Inspector and ServiceNow tickets use); the correlation UUID stays
// canonical in dedup keys / custom details.
