package ticketing

// ticketing_jira_test.go — #103 Jira RCA-lane tests: lifecycle (create/update/
// comment/resolve-transition), idempotent resolve, crash-recovery lookup by
// dedupe label, retry classification, quad-system policy resolution (Jira is
// strictly opt-in), two-tenant isolation + quarantine through the worker, and
// the display-id payload contract. Uses a local fake Jira REST v2 server —
// the real Atlassian API is never contacted.

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

func (f *fakeJira) cfg(tenant string) SystemConfig {
	return SystemConfig{System: "jira", TenantID: tenant,
		InstanceURL: f.srv.URL, AuthType: "basic",
		User: "noc@" + tenant + ".example", APIToken: "TOK-" + tenant,
		ProjectKey: "NOC", IssueType: ""}
}

func (f *fakeJira) adapter() *JiraAdapter {
	return &JiraAdapter{httpClient: f.srv.Client()}
}

func jiraPayload(corr string) Payload {
	p := pdPayload(corr)
	p.ExternalSystem = "jira"
	return p
}

// Lifecycle: create carries project/type/labels + display id; updates refresh
// summary/description but never labels or workflow fields; resolve walks the
// transition and attaches the note.
func TestJiraTicketAdapter_Lifecycle(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newFakeJira()
	defer f.srv.Close()
	a := f.adapter()
	cfg := f.cfg("t_a")
	ctx := context.Background()
	const corr = "5564d1ab-1111-4111-8111-999999999999"
	const pid = "P-5564D1"

	ref, err := a.CreateIncident(ctx, cfg, jiraPayload(corr))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ref.Number != "NOC-1" || ref.SysID != "10001" {
		t.Fatalf("ref = %+v, want key NOC-1 / id 10001", ref)
	}
	if ref.URL != f.srv.URL+"/browse/NOC-1" {
		t.Fatalf("browse url = %q", ref.URL)
	}
	fields, _ := f.creates[0]["fields"].(map[string]any)
	if proj, _ := fields["project"].(map[string]any); asString(proj["key"]) != "NOC" {
		t.Fatalf("project = %v", fields["project"])
	}
	if it, _ := fields["issuetype"].(map[string]any); asString(it["name"]) != "Task" {
		t.Fatalf("default issue type = %v, want Task", fields["issuetype"])
	}
	if !strings.HasPrefix(asString(fields["summary"]), "["+pid+"] ") {
		t.Fatalf("summary missing display id: %q", fields["summary"])
	}
	if !strings.Contains(asString(fields["description"]), "Correlix Problem: "+pid) {
		t.Fatalf("description missing problem id: %q", fields["description"])
	}
	labels, _ := fields["labels"].([]any)
	var hasDedup bool
	for _, l := range labels {
		if asString(l) == "correlix-id-"+corr {
			hasDedup = true
		}
	}
	if !hasDedup {
		t.Fatalf("create labels missing dedupe identity: %v", labels)
	}

	if err := a.UpdateIncident(ctx, cfg, ref, jiraPayload(corr)); err != nil {
		t.Fatalf("update: %v", err)
	}
	uf, _ := f.updates[0]["fields"].(map[string]any)
	for _, forbidden := range []string{"labels", "project", "issuetype"} {
		if _, ok := uf[forbidden]; ok {
			t.Fatalf("update must never touch %s (dedupe label/workflow safety): %v", forbidden, uf)
		}
	}
	if uf["summary"] == nil || uf["description"] == nil {
		t.Fatalf("update must refresh summary+description: %v", uf)
	}

	if err := a.AddWorkNote(ctx, cfg, ref, "operator note"); err != nil {
		t.Fatalf("note: %v", err)
	}
	if len(f.comments) != 1 || asString(f.comments[0]["body"]) != "operator note" {
		t.Fatalf("comment not delivered: %v", f.comments)
	}

	if err := a.ResolveIncident(ctx, cfg, ref, "cleared in Correlix"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(f.transitions) != 1 {
		t.Fatalf("transitions posted = %d, want 1", len(f.transitions))
	}
	tr, _ := f.transitions[0]["transition"].(map[string]any)
	if asString(tr["id"]) != "2" { // "Done" is the second available transition
		t.Fatalf("picked transition %v, want the resolve-like one (id 2)", tr)
	}
	if b, _ := json.Marshal(f.transitions[0]); !strings.Contains(string(b), "cleared in Correlix") {
		t.Fatalf("resolve note not attached: %s", b)
	}
}

// Resolve semantics: a pinned transition (name or id) wins; an already-done
// issue no-ops; a workflow with no resolve-like transition dead-letters with
// an actionable message.
func TestJiraTicketAdapter_ResolveSemantics(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newFakeJira()
	defer f.srv.Close()
	ctx := context.Background()
	ref := Ref{Number: "NOC-7", SysID: "10007"}

	// Pinned by name (case-insensitive) — "In Progress" is transition id 1.
	cfg := f.cfg("t_a")
	cfg.ResolveTransition = "in progress"
	if err := f.adapter().ResolveIncident(ctx, cfg, ref, ""); err != nil {
		t.Fatalf("pinned resolve: %v", err)
	}
	tr, _ := f.transitions[0]["transition"].(map[string]any)
	if asString(tr["id"]) != "1" {
		t.Fatalf("pinned transition ignored: %v", tr)
	}

	// Already done → success no-op (idempotent replay), no transition POST.
	f.mu.Lock()
	f.statusDone = true
	before := len(f.transitions)
	f.mu.Unlock()
	if err := f.adapter().ResolveIncident(ctx, f.cfg("t_a"), ref, ""); err != nil {
		t.Fatalf("resolve on done issue must no-op: %v", err)
	}
	if len(f.transitions) != before {
		t.Fatal("resolve on done issue still posted a transition")
	}

	// No resolve-like transition and none pinned → permanent, actionable.
	f.mu.Lock()
	f.statusDone = false
	f.transNames = []string{"Start Review"}
	f.mu.Unlock()
	err := f.adapter().ResolveIncident(ctx, f.cfg("t_a"), ref, "")
	var perm PermanentDeliveryError
	if !errors.As(err, &perm) || !strings.Contains(err.Error(), "resolve transition") {
		t.Fatalf("missing transition → %v, want actionable permanent error", err)
	}
}

func TestJiraTicketAdapter_RetryClassification(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newFakeJira()
	defer f.srv.Close()
	a := f.adapter()
	ctx := context.Background()
	const corr = "22222222-2222-4222-8222-222222222222"

	f.status, f.retryHdr = 429, "9"
	_, err := a.CreateIncident(ctx, f.cfg("t_a"), jiraPayload(corr))
	var rl RateLimitedError
	if !errors.As(err, &rl) || rl.After != 9*time.Second {
		t.Fatalf("429 → %v, want RateLimitedError{9s}", err)
	}

	for _, code := range []int{400, 401, 403} {
		f.status, f.retryHdr = code, ""
		_, err = a.CreateIncident(ctx, f.cfg("t_a"), jiraPayload(corr))
		var perm PermanentDeliveryError
		if !errors.As(err, &perm) {
			t.Fatalf("%d → %v, want PermanentDeliveryError", code, err)
		}
		if strings.Contains(err.Error(), "TOK-t_a") {
			t.Fatalf("error leaks API token: %v", err)
		}
	}

	f.status = 503
	_, err = a.CreateIncident(ctx, f.cfg("t_a"), jiraPayload(corr))
	var perm PermanentDeliveryError
	if err == nil || errors.As(err, &perm) {
		t.Fatalf("503 must be transient, got %v", err)
	}
}
