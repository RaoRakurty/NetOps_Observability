// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// adapter_teams_test.go — Microsoft Teams as a tenant problem destination: the
// lifecycle cards, the outbox error classes, the write-only webhook, and the
// per-tenant config (resolve, merge, redaction, validation).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type fakeTeamsHook struct {
	mu     sync.Mutex
	srv    *httptest.Server
	bodies []string
	paths  []string
	status int
	retry  string
}

func newFakeTeamsHook(t *testing.T) *fakeTeamsHook {
	f := &fakeTeamsHook{status: http.StatusAccepted}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.bodies = append(f.bodies, string(b))
		f.paths = append(f.paths, r.URL.Path)
		st, ra := f.status, f.retry
		f.mu.Unlock()
		if ra != "" {
			w.Header().Set("Retry-After", ra)
		}
		w.WriteHeader(st)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTeamsHook) cfg(tenant string) SystemConfig {
	return SystemConfig{System: "teams", TenantID: tenant, InstanceURL: TeamsOrigin, AuthType: "webhook",
		APIToken: f.srv.URL + "/workflows/WH-" + tenant + "/invoke?sig=SIG-" + tenant}
}

func (f *fakeTeamsHook) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bodies[len(f.bodies)-1]
}

func TestTeamsTicketAdapter_Lifecycle(t *testing.T) {
	f := newFakeTeamsHook(t)
	a := NewTeamsAdapterWithClient(f.srv.Client())
	if a.Name() != "teams" {
		t.Fatalf("name %q", a.Name())
	}
	cfg := f.cfg("acme")
	p := Payload{CorrObjectID: "3e0400aa-0000-4000-8000-000000000001", Title: "Confirmed BGP session failure on edge-1",
		Verdict: "confirmed", Confidence: 0.91, Summary: "peer 10.0.0.2 down", RecommendedAction: "check the WAN link",
		AffectedScope: "site HQ", RCAURL: "https://correlix.example/#/investigate/rca/x"}

	ref, err := a.CreateIncident(context.Background(), cfg, p)
	if err != nil {
		t.Fatal(err)
	}
	if ref.SysID != DedupeKey("acme", p.CorrObjectID, "teams") || ref.Number == "" || ref.URL != "" {
		t.Fatalf("ref = %+v", ref)
	}
	body := f.last()
	for _, want := range []string{`"AdaptiveCard"`, "Opened: [P-", "Confirmed BGP session failure", "check the WAN link", "site HQ", "91%", p.RCAURL} {
		if !strings.Contains(body, want) {
			t.Fatalf("opened card missing %q: %s", want, body)
		}
	}
	if err := a.UpdateIncident(context.Background(), cfg, ref, p); err != nil || !strings.Contains(f.last(), "Updated: [P-") {
		t.Fatalf("update: %v %s", err, f.last())
	}
	if err := a.AddWorkNote(context.Background(), cfg, ref, "   "); err != nil {
		t.Fatal(err)
	}
	if err := a.AddWorkNote(context.Background(), cfg, ref, "engineer on site"); err != nil || !strings.Contains(f.last(), "engineer on site") {
		t.Fatalf("note: %v %s", err, f.last())
	}
	if err := a.ResolveIncident(context.Background(), cfg, ref, ""); err != nil {
		t.Fatal(err)
	}
	if last := f.last(); !strings.Contains(last, "Resolved — problem P-") || strings.Contains(last, ref.SysID) {
		t.Fatalf("resolve must name the Problem ID, never the dedupe key: %s", last)
	}
	f.mu.Lock()
	n := len(f.bodies)
	f.mu.Unlock()
	if n != 4 { // blank note posts nothing
		t.Fatalf("posts = %d, want 4", n)
	}
	if _, found, err := a.LookupByCorrelationID(context.Background(), cfg, p.CorrObjectID); found || err != nil {
		t.Fatal("a webhook cannot be queried; the link store is the identity")
	}
}

func TestTeamsTicketAdapter_ErrorClassesNeverCarryTheWebhook(t *testing.T) {
	f := newFakeTeamsHook(t)
	a := NewTeamsAdapterWithClient(f.srv.Client())
	cfg := f.cfg("acme")
	p := Payload{CorrObjectID: "c1", Title: "t", Verdict: "suspected"}
	secretParts := []string{"WH-acme", "SIG-acme", cfg.APIToken}
	clean := func(err error) {
		t.Helper()
		for _, s := range secretParts {
			if strings.Contains(err.Error(), s) {
				t.Fatalf("error leaked the webhook (%q): %v", s, err)
			}
		}
	}

	f.status, f.retry = http.StatusTooManyRequests, "17"
	_, err := a.CreateIncident(context.Background(), cfg, p)
	var rl RateLimitedError
	if !errors.As(err, &rl) || rl.After.Seconds() != 17 {
		t.Fatalf("429 must be RateLimited(17s): %v", err)
	}
	f.retry = ""
	if _, err = a.CreateIncident(context.Background(), cfg, p); !errors.As(err, &rl) || rl.After.Seconds() != 30 {
		t.Fatalf("429 without Retry-After backs off 30s: %v", err)
	}

	f.status = http.StatusNotFound // workflow deleted / webhook revoked
	_, err = a.CreateIncident(context.Background(), cfg, p)
	var perm PermanentDeliveryError
	if !errors.As(err, &perm) {
		t.Fatalf("4xx must be permanent: %v", err)
	}
	clean(err)

	f.status = http.StatusBadGateway
	_, err = a.CreateIncident(context.Background(), cfg, p)
	if err == nil || errors.As(err, &perm) || errors.As(err, &rl) {
		t.Fatalf("5xx must be transient: %v", err)
	}
	clean(err)

	f.srv.Close()
	_, err = a.CreateIncident(context.Background(), cfg, p)
	if err == nil || errors.As(err, &perm) {
		t.Fatalf("a refused connection must be transient: %v", err)
	}
	clean(err)

	plain := cfg
	plain.APIToken = "http://hooks.example/WH-acme"
	if _, err = a.CreateIncident(context.Background(), plain, p); !errors.As(err, &perm) {
		t.Fatalf("an http webhook is permanently refused: %v", err)
	}
	clean(err)
	if err := a.ValidateConfig(SystemConfig{}); err == nil {
		t.Fatal("an empty webhook is invalid")
	}
}

func TestTeamsRCAConfig_PerTenantResolveMergeAndRedaction(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true") // no DNS in the save-time URL pre-check
	st := newTestITSMStore(t)
	const hookA = "https://contoso.webhook.office.com/webhookb2/A/IncomingWebhook/SECRET-A"
	const hookB = "https://prod-1.westus.logic.azure.com:443/workflows/B/triggers/manual/paths/invoke?sig=SECRET-B"

	if !(TeamsRCAConfig{}).WatchAlertsOn() || (TeamsRCAConfig{WatchAlerts: boolPtr(false)}).WatchAlertsOn() {
		t.Fatal("Teams watch alerts default ON and an explicit opt-out sticks")
	}
	if err := st.SetTeamsRCA("acme", TeamsRCAConfig{Enabled: true}); err == nil {
		t.Fatal("enabling without a webhook must be refused")
	}
	if err := st.SetTeamsRCA("acme", TeamsRCAConfig{Enabled: true, WebhookURL: "http://contoso.webhook.office.com/x"}); err == nil {
		t.Fatal("an http webhook must be refused")
	}
	if err := st.SetTeamsRCA("acme", TeamsRCAConfig{Enabled: true, WebhookURL: hookA, WatchAlerts: boolPtr(false)}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetTeamsRCA("globex", TeamsRCAConfig{Enabled: true, WebhookURL: hookB}); err != nil {
		t.Fatal(err)
	}
	// A blank URL and an omitted choice keep what is stored (write-only).
	if err := st.SetTeamsRCA("acme", TeamsRCAConfig{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// The combined ITSM save without a teams block never disables Teams.
	if err := st.Set("acme", ITSMConfig{}); err != nil {
		t.Fatal(err)
	}

	for tenant, hook := range map[string]string{"acme": hookA, "globex": hookB} {
		sc, ok := st.SystemConfigFor(tenant, "teams")
		if !ok || sc.APIToken != hook || sc.TenantID != tenant || sc.InstanceURL != TeamsOrigin || sc.System != "teams" {
			t.Fatalf("%s resolves %+v ok=%v", tenant, sc, ok)
		}
	}
	if _, ok := st.SystemConfigFor("initech", "teams"); ok {
		t.Fatal("a tenant with no Teams lane resolves nothing — never another tenant's")
	}
	cfg, _ := st.ConfigFor("acme")
	if cfg.Teams.WatchAlertsOn() {
		t.Fatal("the omitted choice flipped acme's opt-out")
	}

	pub, _ := json.Marshal(st.Public("acme"))
	if strings.Contains(string(pub), "SECRET-A") || strings.Contains(string(pub), "SECRET-B") || strings.Contains(string(pub), "webhook.office.com") {
		t.Fatalf("Public leaked a webhook: %s", pub)
	}
	var raw struct {
		Teams map[string]any `json:"teams"`
	}
	if err := json.Unmarshal(pub, &raw); err != nil {
		t.Fatal(err)
	}
	tm := raw.Teams
	if tm["enabled"] != true || tm["has_webhook"] != true || tm["configured"] != true || tm["watch_alerts"] != false {
		t.Fatalf("acme's teams view = %v", tm)
	}

	if err := st.SetTeamsRCA("acme", TeamsRCAConfig{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.SystemConfigFor("acme", "teams"); ok {
		t.Fatal("a disabled lane resolves nothing")
	}
	if _, ok := st.SystemConfigFor("globex", "teams"); !ok {
		t.Fatal("acme's disable reached globex")
	}
}

func TestTeamsIsAPolicyDestination(t *testing.T) {
	found := false
	for _, s := range TicketSystems {
		found = found || s == "teams"
	}
	if !found {
		t.Fatal("teams is not in TicketSystems")
	}
	p := IncidentPolicy{ExternalSystem: "teams", MinVerdict: "suspected", DefaultImpact: 2, DefaultUrgency: 2}
	if err := ValidateIncidentPolicy(p); err != nil && strings.Contains(err.Error(), "external_system") {
		t.Fatalf("a Teams policy must validate: %v", err)
	}
	w := NewWorker(nil, nil, nil, nil)
	if _, ok := w.adapters["teams"]; !ok {
		t.Fatal("the worker has no Teams adapter")
	}
}
