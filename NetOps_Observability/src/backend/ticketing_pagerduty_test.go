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

func pdPayload(corr string) ticketPayload {
	return ticketPayload{CorrObjectID: corr, ExternalSystem: "pagerduty",
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
	store := newMemTicketingStore()
	sw := &ticketSweeper{store: store}

	sn := incidentPolicy{ID: "sn1", TenantID: "t_a", Name: "sn", Enabled: true,
		ExternalSystem: "servicenow", MinVerdict: "suspected"}
	pd := incidentPolicy{ID: "pd1", TenantID: "t_a", Name: "pd", Enabled: true,
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
	if err := store.PutPolicy(ctx, pd2); !errors.Is(err, errPolicyConflict) {
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
	store := newMemTicketingStore()
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
	items, _ := store.ListOutbox(ctx, "t_a", false)
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
	pol := incidentPolicy{ID: "pd1", TenantID: "t_a", Enabled: true,
		ExternalSystem: "pagerduty", MinVerdict: "confirmed"}
	und := corrTicketFacts{Verdict: "undetermined", PeakSeverity: "critical", HasAffectedEntity: true}
	if d := evalTicketDecision(und, pol, nil, time.Now()); d.Create {
		t.Fatal("undetermined must not page")
	}
	susp := corrTicketFacts{Verdict: "suspected", PeakSeverity: "critical", HasAffectedEntity: true}
	if d := evalTicketDecision(susp, pol, nil, time.Now()); d.Create {
		t.Fatal("suspected must not page under confirmed-only policy")
	}
	disabled := pol
	disabled.Enabled = false
	conf := corrTicketFacts{Verdict: "confirmed", PeakSeverity: "critical", HasAffectedEntity: true}
	if d := evalTicketDecision(conf, disabled, nil, time.Now()); d.Create {
		t.Fatal("disabled policy must not page")
	}
}
