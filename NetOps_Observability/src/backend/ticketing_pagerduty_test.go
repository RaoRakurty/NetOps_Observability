package main

// ticketing_pagerduty_test.go — #103 PagerDuty RCA-lane tests: lifecycle dedup
// identity, retry classification, dual-system policy resolution, two-tenant
// isolation (distinct routing-key markers), storm identity, and the worker's
// tenant-mismatch quarantine. Uses a local fake Events API server — the real
// PagerDuty API is never contacted.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/ticketing"
	"strings"
	"sync"
	"testing"
	"time"
)

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

func (f *fakePD) cfg(tenant string) ticketSystemConfig {
	return ticketSystemConfig{System: "pagerduty", TenantID: tenant,
		InstanceURL: f.srv.URL, AuthType: "routing_key", APIToken: "RK-" + tenant}
}

func (f *fakePD) adapter() *pagerDutyTicketAdapter {
	return &pagerDutyTicketAdapter{httpClient: f.srv.Client()}
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

// Lifecycle: create/update x3/resolve share ONE dedup identity (storm-proof).
func TestPDTicketAdapter_LifecycleSingleDedupIdentity(t *testing.T) {
	f := newFakePD()
	defer f.srv.Close()
	a := f.adapter()
	cfg := f.cfg("t_a")
	ctx := context.Background()

	ref, err := a.CreateIncident(ctx, cfg, pdPayload("11111111-1111-4111-8111-111111111111"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	wantKey := "correlix:t_a:11111111-1111-4111-8111-111111111111:pagerduty"
	if ref.SysID != wantKey {
		t.Fatalf("dedup key = %q, want %q", ref.SysID, wantKey)
	}
	for i := 0; i < 3; i++ { // repeated updates (severity/impact changes)
		if err := a.UpdateIncident(ctx, cfg, ref, pdPayload("11111111-1111-4111-8111-111111111111")); err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
	}
	if err := a.ResolveIncident(ctx, cfg, ref, "cleared"); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	evs := f.all()
	if len(evs) != 5 {
		t.Fatalf("events = %d, want 5", len(evs))
	}
	keys := map[string]bool{}
	actions := []string{}
	for _, e := range evs {
		keys[asString(e["dedup_key"])] = true
		actions = append(actions, asString(e["event_action"]))
	}
	if len(keys) != 1 || !keys[wantKey] {
		t.Fatalf("expected ONE dedup identity %q, got %v", wantKey, keys)
	}
	if actions[0] != "trigger" || actions[len(actions)-1] != "resolve" {
		t.Fatalf("lifecycle actions wrong: %v", actions)
	}
	// payload sanity: source=correlix, severity mapped from urgency 1
	pl, _ := evs[0]["payload"].(map[string]any)
	if asString(pl["source"]) != "correlix" || asString(pl["severity"]) != "critical" {
		t.Fatalf("payload source/severity wrong: %v", pl)
	}
}

// Retry classification: 429→rateLimited(Retry-After), 400/401→permanent, 5xx→transient.
func TestPDTicketAdapter_RetryClassification(t *testing.T) {
	f := newFakePD()
	defer f.srv.Close()
	a := f.adapter()
	ctx := context.Background()

	f.status, f.retryHdr = 429, "7"
	_, err := a.CreateIncident(ctx, f.cfg("t_a"), pdPayload("22222222-2222-4222-8222-222222222222"))
	var rl rateLimitedError
	if !errors.As(err, &rl) || rl.After != 7*time.Second {
		t.Fatalf("429 → %v, want rateLimitedError{7s}", err)
	}

	for _, code := range []int{400, 401, 403} {
		f.status, f.retryHdr = code, ""
		_, err = a.CreateIncident(ctx, f.cfg("t_a"), pdPayload("22222222-2222-4222-8222-222222222222"))
		var perm permanentDeliveryError
		if !errors.As(err, &perm) {
			t.Fatalf("%d → %v, want permanentDeliveryError", code, err)
		}
		if strings.Contains(err.Error(), "RK-t_a") {
			t.Fatalf("error leaks routing key: %v", err)
		}
	}

	f.status = 503
	_, err = a.CreateIncident(ctx, f.cfg("t_a"), pdPayload("22222222-2222-4222-8222-222222222222"))
	var perm permanentDeliveryError
	if err == nil || errors.As(err, &perm) {
		t.Fatalf("503 must be transient, got %v", err)
	}

	// missing routing key = permanent (never retried into the void)
	bad := f.cfg("t_a")
	bad.APIToken = ""
	_, err = a.CreateIncident(ctx, bad, pdPayload("22222222-2222-4222-8222-222222222222"))
	if !errors.As(err, &perm) {
		t.Fatalf("missing key → %v, want permanent", err)
	}
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

	resolve := func(_ context.Context, tenant, system string) (ticketSystemConfig, bool, error) {
		if system != "pagerduty" {
			return ticketSystemConfig{}, false, nil
		}
		switch tenant {
		case "t_a":
			return fA.cfg("t_a"), true, nil
		case "t_b":
			return fB.cfg("t_b"), true, nil
		}
		return ticketSystemConfig{}, false, nil
	}
	w := newTicketWorker(store, resolve)
	w.adapters["pagerduty"] = fA.adapter() // same transport works for both fakes (URL comes from cfg)

	corrA := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	corrB := corrA // SAME local id in both tenants — keys must still differ
	if err := enqueueTicketCreate(ctx, store, "t_a", "pagerduty", pdPayload(corrA)); err != nil {
		t.Fatal(err)
	}
	if err := enqueueTicketCreate(ctx, store, "t_b", "pagerduty", pdPayload(corrB)); err != nil {
		t.Fatal(err)
	}
	if n, err := w.tick(ctx, time.Now().UTC()); err != nil || n != 2 {
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
	evil := func(_ context.Context, _ string, _ string) (ticketSystemConfig, bool, error) {
		return fB.cfg("t_b"), true, nil // claims B's connection for A's delivery
	}
	w2 := newTicketWorker(store, evil)
	w2.adapters["pagerduty"] = fA.adapter()
	if err := enqueueTicketCreate(ctx, store, "t_a", "pagerduty",
		pdPayload("cccccccc-cccc-4ccc-8ccc-cccccccccccc")); err != nil {
		t.Fatal(err)
	}
	before := len(fB.all())
	if _, err := w2.tick(ctx, time.Now().UTC()); err != nil {
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

func (f *fakeSlackHook) cfg(tenant string) ticketSystemConfig {
	return ticketSystemConfig{System: "slack", TenantID: tenant,
		InstanceURL: slackHooksOrigin, AuthType: "webhook", APIToken: f.srv.URL + "/WH-" + tenant}
}

func TestSlackTicketAdapter_LifecycleAndSecrets(t *testing.T) {
	f := newFakeSlackHook()
	defer f.srv.Close()
	a := &slackTicketAdapter{httpClient: f.srv.Client()}
	ctx := context.Background()
	cfg := f.cfg("t_a")

	ref, err := a.CreateIncident(ctx, cfg, pdPayload("33333333-3333-4333-8333-333333333333"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ref.SysID == "" || strings.Contains(ref.SysID, f.srv.URL) {
		t.Fatalf("ref must be the dedupe identity, never the webhook: %q", ref.SysID)
	}
	if err := a.UpdateIncident(ctx, cfg, ref, pdPayload("33333333-3333-4333-8333-333333333333")); err != nil {
		t.Fatal(err)
	}
	if err := a.ResolveIncident(ctx, cfg, ref, ""); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	n := len(f.bodies)
	first := f.bodies[0]
	last := f.bodies[n-1]
	f.mu.Unlock()
	if n != 3 {
		t.Fatalf("posts = %d, want 3 (opened/updated/resolved)", n)
	}
	if !strings.Contains(asString(first["text"]), "Opened") {
		t.Fatalf("first message not an open: %v", first["text"])
	}
	if !strings.Contains(asString(last["text"]), "Resolved") {
		t.Fatalf("last message not a resolve: %v", last["text"])
	}

	// error classification + secret-free errors
	f.status = 404 // Slack's no_service
	_, err = a.CreateIncident(ctx, cfg, pdPayload("33333333-3333-4333-8333-333333333333"))
	var perm permanentDeliveryError
	if !errors.As(err, &perm) || strings.Contains(err.Error(), f.srv.URL) {
		t.Fatalf("404 → %v (must be permanent, secret-free)", err)
	}
}

// The secret webhook must never be persisted onto the ticket link: the link's
// InstanceURL comes from cfg.InstanceURL, which for Slack is the bare origin.
func TestSlackLink_NeverStoresWebhookSecret(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newFakeSlackHook()
	defer f.srv.Close()
	store := ticketing.NewMemStore()
	ctx := context.Background()
	resolve := func(_ context.Context, tenant, system string) (ticketSystemConfig, bool, error) {
		if system != "slack" {
			return ticketSystemConfig{}, false, nil
		}
		return f.cfg(tenant), true, nil
	}
	w := newTicketWorker(store, resolve)
	w.adapters["slack"] = &slackTicketAdapter{httpClient: f.srv.Client()}
	if err := enqueueTicketCreate(ctx, store, "t_a", "slack",
		pdPayload("44444444-4444-4444-8444-444444444444")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.tick(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	link, found, err := store.GetLink(ctx, "t_a", false, "44444444-4444-4444-8444-444444444444", "slack")
	if err != nil || !found {
		t.Fatalf("link missing: %v", err)
	}
	if strings.Contains(link.InstanceURL, "WH-") || strings.Contains(link.InstanceURL, f.srv.URL) {
		t.Fatalf("SECURITY: webhook secret persisted on link: %q", link.InstanceURL)
	}
	if link.InstanceURL != slackHooksOrigin {
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
	store := &itsmConfigStore{
		cfgs: map[string]itsmConfig{
			"": { // platform-owner / single-org config key
				ServiceNow: serviceNowConfig{Enabled: true, InstanceURL: "https://dev.example.service-now.com", User: "u", Password: "p"},
				PagerDuty:  pagerDutyRCAConfig{Enabled: true, RoutingKey: "RK-global"},
				Slack:      slackRCAConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/services/T/G/x"},
				Jira:       jiraConfig{Enabled: true, BaseURL: "https://global.atlassian.net", Email: "noc@example.com", APIToken: "tok", ProjectKey: "NOC"},
			},
		},
		live: map[string]*itsmLive{},
	}
	// The sweeper hands us the CANONICAL tenant ("global"), never "".
	canon := canonicalCorrTenant("")
	if canon != TenantGlobal {
		t.Fatalf("canonicalCorrTenant(\"\") = %q, want %q", canon, TenantGlobal)
	}
	for _, sys := range []string{"servicenow", "pagerduty", "slack", "jira"} {
		cfg, ok := store.ticketSystemConfig(canon, sys)
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
	if k := pdTicketDedupKey(canon, "55555555-5555-4555-8555-555555555555"); !strings.Contains(k, ":global:") {
		t.Fatalf("global dedup key missing canonical tenant: %q", k)
	}
}

// ── #103 UX-2: human display id in notification payloads ────────────────────
// Operators reported raw hex identifiers in notifications. Every operator-facing
// string leads with the friendly Correlix Problem ID (P-XXXXXX — the same handle
// the RCA Inspector and ServiceNow tickets use); the correlation UUID stays
// canonical in dedup keys / custom details.
func TestNotificationPayloads_CarryDisplayID(t *testing.T) {
	ctx := context.Background()
	const corr = "5564d1ab-1111-4111-8111-999999999999"
	const pid = "P-5564D1"

	// PagerDuty: summary leads with the id; custom_details carry both handles.
	f := newFakePD()
	defer f.srv.Close()
	ref, err := f.adapter().CreateIncident(ctx, f.cfg("t_a"), pdPayload(corr))
	if err != nil {
		t.Fatalf("pd create: %v", err)
	}
	ev := f.all()[0]
	pl, _ := ev["payload"].(map[string]any)
	if !strings.HasPrefix(asString(pl["summary"]), "["+pid+"] ") {
		t.Fatalf("pd summary missing display id: %q", pl["summary"])
	}
	det, _ := pl["custom_details"].(map[string]any)
	if asString(det["problem_id"]) != pid || asString(det["correlation_id"]) != corr {
		t.Fatalf("pd custom_details handles wrong: %v", det)
	}
	if !strings.Contains(asString(ev["dedup_key"]), corr) {
		t.Fatalf("dedup key must keep the canonical UUID: %v", ev["dedup_key"])
	}
	_ = ref

	// Slack: title + footer carry the id; the resolve message names the incident
	// by the id, never the raw dedupe-hash ref.
	fs := newFakeSlackHook()
	defer fs.srv.Close()
	a := &slackTicketAdapter{httpClient: fs.srv.Client()}
	sref, err := a.CreateIncident(ctx, fs.cfg("t_a"), pdPayload(corr))
	if err != nil {
		t.Fatalf("slack create: %v", err)
	}
	if err := a.ResolveIncident(ctx, fs.cfg("t_a"), sref, ""); err != nil {
		t.Fatalf("slack resolve: %v", err)
	}
	fs.mu.Lock()
	opened, resolved := fs.bodies[0], fs.bodies[len(fs.bodies)-1]
	fs.mu.Unlock()
	if !strings.Contains(asString(opened["text"]), "["+pid+"]") {
		t.Fatalf("slack open title missing display id: %q", opened["text"])
	}
	atts, _ := opened["attachments"].([]any)
	att, _ := atts[0].(map[string]any)
	if asString(att["footer"]) != "Correlix RCA · "+pid {
		t.Fatalf("slack footer = %q, want display id (no raw UUID)", att["footer"])
	}
	rtxt := asString(resolved["text"])
	if !strings.Contains(rtxt, pid) || strings.Contains(rtxt, sref.Number) {
		t.Fatalf("slack resolve must name %s, never the raw ref %q: %q", pid, sref.Number, rtxt)
	}
}
