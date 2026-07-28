package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/ticketing"
)

// Shuttled back from the adapter test move: these exercise the WORKER and the
// itsm config store — integrator code; only the wire adapters moved. Fixtures
// duplicated (test files cannot be imported across packages).
// fakeJira is a minimal REST v2 endpoint recording every call.
type fakeJira struct {
	mu          sync.Mutex
	srv         *httptest.Server
	creates     []map[string]any // POST /issue bodies
	updates     []map[string]any // PUT /issue/{id} bodies
	comments    []map[string]any // POST /issue/{id}/comment bodies
	transitions []map[string]any // POST /issue/{id}/transitions bodies
	auths       []string         // Authorization headers seen
	status      int              // response code override (0 = normal)
	retryHdr    string
	statusDone  bool     // GET issue status reports done
	transNames  []string // available transitions (default Done)
	searchKey   string   // non-empty: search finds this issue key
}

func newFakeJira() *fakeJira {
	f := &fakeJira{transNames: []string{"In Progress", "Done"}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		status, retryHdr := f.status, f.retryHdr
		f.mu.Unlock()
		if retryHdr != "" {
			w.Header().Set("Retry-After", retryHdr)
		}
		if status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"errorMessages":["injected failure"]}`))
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		p := r.URL.Path
		switch {
		case p == "/rest/api/2/issue" && r.Method == http.MethodPost:
			f.mu.Lock()
			f.creates = append(f.creates, body)
			n := len(f.creates)
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "1000" + string(rune('0'+n)), "key": "NOC-" + string(rune('0'+n))})
		case strings.HasSuffix(p, "/comment") && r.Method == http.MethodPost:
			f.mu.Lock()
			f.comments = append(f.comments, body)
			f.mu.Unlock()
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{}`))
		case strings.HasSuffix(p, "/transitions") && r.Method == http.MethodGet:
			var ts []map[string]string
			f.mu.Lock()
			for i, n := range f.transNames {
				ts = append(ts, map[string]string{"id": string(rune('1' + i)), "name": n})
			}
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"transitions": ts})
		case strings.HasSuffix(p, "/transitions") && r.Method == http.MethodPost:
			f.mu.Lock()
			f.transitions = append(f.transitions, body)
			f.mu.Unlock()
			w.WriteHeader(204)
		case strings.HasPrefix(p, "/rest/api/2/issue/") && r.Method == http.MethodGet:
			cat := "indeterminate"
			f.mu.Lock()
			if f.statusDone {
				cat = "done"
			}
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"fields": map[string]any{"status": map[string]any{"statusCategory": map[string]any{"key": cat}}},
			})
		case strings.HasPrefix(p, "/rest/api/2/issue/") && r.Method == http.MethodPut:
			f.mu.Lock()
			f.updates = append(f.updates, body)
			f.mu.Unlock()
			w.WriteHeader(204)
		case p == "/rest/api/2/search":
			f.mu.Lock()
			key := f.searchKey
			f.mu.Unlock()
			issues := []map[string]any{}
			if key != "" {
				issues = append(issues, map[string]any{"id": "99999", "key": key})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"issues": issues})
		case p == "/rest/api/2/myself":
			_, _ = w.Write([]byte(`{"accountId":"x"}`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"errorMessages":["no route"]}`))
		}
	}))
	return f
}

func (f *fakeJira) cfg(tenant string) ticketing.SystemConfig {
	return ticketing.SystemConfig{System: "jira", TenantID: tenant,
		InstanceURL: f.srv.URL, AuthType: "basic",
		User: "noc@" + tenant + ".example", APIToken: "TOK-" + tenant,
		ProjectKey: "NOC", IssueType: ""}
}

func (f *fakeJira) adapter() *ticketing.JiraAdapter {
	return ticketing.NewJiraAdapterWithClient(f.srv.Client())
}

// Crash-recovery: a create whose link store was lost adopts the existing issue
// via the dedupe-label search — never a second issue.
func TestJiraWorker_CreateAdoptsExistingIssue(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newFakeJira()
	defer f.srv.Close()
	f.searchKey = "NOC-42"
	store := ticketing.NewMemStore()
	ctx := context.Background()
	resolve := func(_ context.Context, tenant, system string) (ticketing.SystemConfig, bool, error) {
		if system != "jira" {
			return ticketing.SystemConfig{}, false, nil
		}
		return f.cfg(tenant), true, nil
	}
	w := newTicketWorker(store, resolve)
	w.adapters["jira"] = f.adapter()

	const corr = "66666666-6666-4666-8666-666666666666"
	if err := enqueueTicketCreate(ctx, store, "t_a", "jira", jiraPayload(corr)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.tick(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if len(f.creates) != 0 {
		t.Fatalf("adopted create still POSTed a new issue (%d)", len(f.creates))
	}
	link, found, err := store.GetLink(ctx, "t_a", false, corr, "jira")
	if err != nil || !found {
		t.Fatalf("link missing after adopt: %v", err)
	}
	if link.TicketNumber != "NOC-42" {
		t.Fatalf("adopted wrong issue: %+v", link)
	}
}

// Retry classification: 429→rateLimited(Retry-After), 400/401/403→permanent
// (secret-free), 5xx→transient; enabled-but-incomplete config never resolves.
// Config resolution: the RCA lane resolves Jira only when enabled AND complete
// (base URL + project key); the resolved config carries the connection whole.
func TestJiraTicketSystemConfig_Resolution(t *testing.T) {
	full := jiraConfig{Enabled: true, BaseURL: "https://acme.atlassian.net", Email: "noc@acme.example",
		APIToken: "tok", ProjectKey: "NOC", IssueType: "Incident", ResolveTransition: "Done"}
	store := &itsmConfigStore{
		cfgs: map[string]itsmConfig{
			"t_a": {Jira: full},
			"t_b": {Jira: jiraConfig{Enabled: true, BaseURL: "https://b.atlassian.net"}},   // no project key
			"t_c": {Jira: jiraConfig{BaseURL: "https://c.atlassian.net", ProjectKey: "X"}}, // disabled
		},
		live: map[string]*itsmLive{},
	}
	cfg, ok := store.systemConfig("t_a", "jira")
	if !ok {
		t.Fatal("complete enabled jira config must resolve")
	}
	if cfg.System != "jira" || cfg.InstanceURL != full.BaseURL || cfg.User != full.Email ||
		cfg.APIToken != full.APIToken || cfg.ProjectKey != "NOC" || cfg.IssueType != "Incident" ||
		cfg.ResolveTransition != "Done" || cfg.TenantID != "t_a" {
		t.Fatalf("resolved config incomplete: %+v", cfg)
	}
	if _, ok := store.systemConfig("t_b", "jira"); ok {
		t.Fatal("jira without a project key must not resolve (would 400 every create)")
	}
	if _, ok := store.systemConfig("t_c", "jira"); ok {
		t.Fatal("disabled jira must not resolve")
	}
}

// Two-tenant isolation through the WORKER: each tenant's issue lands on its
// own Jira with its own credentials; a tenant-mismatched connection is
// quarantined without any external call.
func TestJiraWorker_TenantIsolation(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	fA, fB := newFakeJira(), newFakeJira()
	defer fA.srv.Close()
	defer fB.srv.Close()
	store := ticketing.NewMemStore()
	ctx := context.Background()

	resolve := func(_ context.Context, tenant, system string) (ticketing.SystemConfig, bool, error) {
		if system != "jira" {
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
	w := newTicketWorker(store, resolve)
	w.adapters["jira"] = fA.adapter() // transport shared; target URL comes from cfg

	const corr = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" // SAME local id in both tenants
	if err := enqueueTicketCreate(ctx, store, "t_a", "jira", jiraPayload(corr)); err != nil {
		t.Fatal(err)
	}
	if err := enqueueTicketCreate(ctx, store, "t_b", "jira", jiraPayload(corr)); err != nil {
		t.Fatal(err)
	}
	if n, err := w.tick(ctx, time.Now().UTC()); err != nil || n != 2 {
		t.Fatalf("tick: n=%d err=%v", n, err)
	}
	if len(fA.creates) != 1 || len(fB.creates) != 1 {
		t.Fatalf("creates A=%d B=%d, want 1 each", len(fA.creates), len(fB.creates))
	}
	// Credentials never cross: each server saw only its own tenant's basic auth.
	for _, auth := range fA.auths {
		if auth != "" && auth == fB.auths[0] {
			t.Fatal("SECURITY: tenant credentials crossed Jira instances")
		}
	}

	// Tenant-mismatch quarantine: resolver stamps the WRONG tenant.
	evil := func(_ context.Context, _ string, _ string) (ticketing.SystemConfig, bool, error) {
		return fB.cfg("t_b"), true, nil
	}
	w2 := newTicketWorker(store, evil)
	w2.adapters["jira"] = fA.adapter()
	if err := enqueueTicketCreate(ctx, store, "t_a", "jira",
		jiraPayload("cccccccc-cccc-4ccc-8ccc-cccccccccccc")); err != nil {
		t.Fatal(err)
	}
	before := len(fB.creates)
	if _, err := w2.tick(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if len(fB.creates) != before {
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

// Quad-enable: SN + PD + Slack + Jira policies all active per system; Jira is
// strictly opt-in (no policy → no delivery).
func TestResolvePolicyState_QuadSystemAndJiraOptIn(t *testing.T) {
	ctx := context.Background()
	store := ticketing.NewMemStore()
	sw := &ticketSweeper{store: store}
	for _, sys := range ticketSystems {
		p := ticketing.IncidentPolicy{ID: "q-" + sys, TenantID: "t_quad", Name: sys, Enabled: true,
			ExternalSystem: sys, MinVerdict: "confirmed"}
		if err := store.PutPolicy(ctx, p); err != nil {
			t.Fatalf("put %s: %v", sys, err)
		}
	}
	for _, sys := range ticketSystems {
		if res := sw.resolvePolicyState(ctx, "t_quad", sys); res.state != policyStateActive {
			t.Fatalf("%s not active under quad-enable: %+v", sys, res)
		}
	}
	// No Jira policy → opt-in default is OFF (never a default-on ticket stream).
	if res := sw.resolvePolicyState(ctx, "t_other", "jira"); res.state != policyStateOptedOut || res.policy.Enabled {
		t.Fatalf("jira must be opt-in, got %+v", res)
	}
	// The policy validator accepts jira as a first-class destination.
	if err := validateIncidentPolicy(ticketing.IncidentPolicy{ExternalSystem: "jira", MinVerdict: "confirmed"}); err != nil {
		t.Fatalf("validateIncidentPolicy(jira): %v", err)
	}
}

func jiraPayload(corr string) ticketing.Payload {
	p := pdPayload(corr)
	p.ExternalSystem = "jira"
	return p
}
