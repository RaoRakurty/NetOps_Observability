package main

// ticketing_jira.go — Jira as a tenant-scoped RCA incident-policy destination
// (#103). The ITSM work-tracking lane for Jira shops: one Jira issue per
// correlated RCA object, driven by the same per-tenant policies, outbox, and
// worker as ServiceNow/PagerDuty/Slack — never by raw alerts. Strictly OPT-IN
// (no policy → no delivery). The legacy raw-alert Jira connector
// (notify/jira.go, FEATURE_LEGACY_ALERT_ITSM) stays dormant and separate.
//
// Wire contract: Jira REST API v2 (plain-text description; served by both
// Jira Cloud and Server/DC), HTTP Basic with the tenant's Atlassian account
// email + API token. The tenant's connection comes from its own ITSM config
// (base URL, project key, issue type, resolve transition — itsm_config.go).
//
// Identity: the immutable numeric issue id is the canonical ref (SysID);
// the issue KEY (e.g. NOC-123) is the operator-visible Number and can change
// if the issue moves projects. Crash-after-create recovery uses a JQL lookup
// on the dedupe label "correlix-id-<corr-uuid>" stamped at create, so a lost
// link store never files a second issue (same recovery contract as
// ServiceNow's correlation_id lookup).
//
// Lifecycle mapping:
//   create  -> POST /rest/api/2/issue        (labels carry the dedupe id)
//   update  -> PUT  /rest/api/2/issue/{id}   (summary/description refresh)
//   add_work_note -> POST .../comment
//   resolve -> workflow transition: honor the configured resolve transition
//     (id or name), else the first done/resolve/close/complete-like one; an
//     issue already in the "done" status category no-ops (idempotent).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"netops/backend/internal/noclabel"
	"strconv"
	"strings"
	"time"

	"netops/backend/safehttp"
)

const jiraMaxRespBytes = 1 << 20

// jiraTicketAdapter implements ticketAdapter against the Jira REST v2 API.
// httpClient is injectable so tests drive it against an httptest fake.
type jiraTicketAdapter struct {
	httpClient *http.Client
}

func newJiraTicketAdapter() *jiraTicketAdapter {
	return &jiraTicketAdapter{httpClient: safehttp.Client(20 * time.Second)}
}

func (a *jiraTicketAdapter) Name() string { return "jira" }

func (a *jiraTicketAdapter) client() *http.Client {
	if a.httpClient != nil {
		return a.httpClient
	}
	return safehttp.Client(20 * time.Second)
}

func (a *jiraTicketAdapter) ValidateConfig(cfg ticketSystemConfig) error {
	u, err := jiraBaseURL(cfg.InstanceURL)
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.ProjectKey) == "" {
		return fmt.Errorf("jira: project key is required")
	}
	if cfg.User == "" || cfg.APIToken == "" {
		return fmt.Errorf("jira: basic auth requires account email and API token")
	}
	return safehttp.ValidateURL(u.Hostname())
}

// HealthCheck proves auth + reachability with a cheap, bounded read.
func (a *jiraTicketAdapter) HealthCheck(ctx context.Context, cfg ticketSystemConfig) error {
	_, _, err := a.do(ctx, cfg, http.MethodGet, "/rest/api/2/myself", nil)
	return err
}

// jiraDedupeLabel is the label stamped on every Correlix issue that carries the
// RCA object identity for the crash-recovery JQL lookup. Labels reject spaces,
// so the id is sanitized to the label alphabet (UUIDs pass through unchanged).
func jiraDedupeLabel(corrID string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(corrID) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return "correlix-id-" + truncate(b.String(), 200)
}

func (a *jiraTicketAdapter) CreateIncident(ctx context.Context, cfg ticketSystemConfig, p ticketPayload) (ticketRef, error) {
	body := map[string]any{"fields": jiraIssueFields(cfg, p, true)}
	raw, _, err := a.do(ctx, cfg, http.MethodPost, "/rest/api/2/issue", body)
	if err != nil {
		return ticketRef{}, err
	}
	var resp struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return ticketRef{}, fmt.Errorf("jira: decode create: %w", err)
	}
	if resp.Key == "" {
		return ticketRef{}, fmt.Errorf("jira: create returned no issue key")
	}
	return ticketRef{
		Number: resp.Key,
		SysID:  orDefault(resp.ID, resp.Key),
		URL:    jiraBrowseURL(cfg.InstanceURL, resp.Key),
	}, nil
}

func (a *jiraTicketAdapter) UpdateIncident(ctx context.Context, cfg ticketSystemConfig, ref ticketRef, p ticketPayload) error {
	if ref.SysID == "" {
		return fmt.Errorf("jira: update requires an issue id")
	}
	// Refresh summary/description only — never labels (the dedupe label must
	// survive every update) and never workflow state.
	fields := jiraIssueFields(cfg, p, false)
	delete(fields, "project")
	delete(fields, "issuetype")
	_, _, err := a.do(ctx, cfg, http.MethodPut,
		"/rest/api/2/issue/"+url.PathEscape(ref.SysID), map[string]any{"fields": fields})
	return err
}

func (a *jiraTicketAdapter) AddWorkNote(ctx context.Context, cfg ticketSystemConfig, ref ticketRef, note string) error {
	if ref.SysID == "" {
		return fmt.Errorf("jira: comment requires an issue id")
	}
	if strings.TrimSpace(note) == "" {
		return nil
	}
	_, _, err := a.do(ctx, cfg, http.MethodPost,
		"/rest/api/2/issue/"+url.PathEscape(ref.SysID)+"/comment",
		map[string]any{"body": truncate(note, 4000)})
	return err
}

// ResolveIncident transitions the issue into a done state. Jira models resolve
// as a workflow transition whose id is project-specific, so it is resolved at
// close time: the configured resolve transition (id or name) wins, else the
// first transition whose name reads as done/resolve/close/complete. An issue
// already in the "done" status category is a success no-op, so worker retries
// and sweeper replays stay idempotent.
func (a *jiraTicketAdapter) ResolveIncident(ctx context.Context, cfg ticketSystemConfig, ref ticketRef, note string) error {
	if ref.SysID == "" {
		return fmt.Errorf("jira: resolve requires an issue id")
	}
	done, err := a.issueDone(ctx, cfg, ref.SysID)
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	tid, err := a.resolveTransitionID(ctx, cfg, ref.SysID)
	if err != nil {
		return err
	}
	if tid == "" {
		// No resolve-like transition from the current state and none pinned —
		// retrying cannot help; the operator must pin resolve_transition.
		return permanentDeliveryError{fmt.Errorf("jira: no resolve transition available (pin one in the Jira connection settings)")}
	}
	body := map[string]any{"transition": map[string]string{"id": tid}}
	if strings.TrimSpace(note) != "" {
		body["update"] = map[string]any{
			"comment": []map[string]any{{"add": map[string]string{"body": truncate(note, 4000)}}},
		}
	}
	_, _, err = a.do(ctx, cfg, http.MethodPost,
		"/rest/api/2/issue/"+url.PathEscape(ref.SysID)+"/transitions", body)
	return err
}

// LookupByCorrelationID recovers an existing issue by the dedupe label — the
// path that keeps a crash-after-create from ever filing a second issue.
func (a *jiraTicketAdapter) LookupByCorrelationID(ctx context.Context, cfg ticketSystemConfig, corrID string) (ticketRef, bool, error) {
	// The label is produced by jiraDedupeLabel's closed alphabet, so the quoted
	// JQL term cannot break out of its quotes.
	jql := `labels = "` + jiraDedupeLabel(corrID) + `" ORDER BY created ASC`
	q := "/rest/api/2/search?maxResults=1&fields=key&jql=" + url.QueryEscape(jql)
	raw, status, err := a.do(ctx, cfg, http.MethodGet, q, nil)
	if err != nil {
		// A Jira instance can refuse label JQL (permissions/config); treat a
		// clean 400 as "not found" rather than wedging creates permanently —
		// the outbox idempotency key still bounds duplicates.
		if status == http.StatusBadRequest {
			return ticketRef{}, false, nil
		}
		return ticketRef{}, false, err
	}
	var resp struct {
		Issues []struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"issues"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return ticketRef{}, false, fmt.Errorf("jira: decode search: %w", err)
	}
	if len(resp.Issues) == 0 || resp.Issues[0].Key == "" {
		return ticketRef{}, false, nil
	}
	return ticketRef{
		Number: resp.Issues[0].Key,
		SysID:  orDefault(resp.Issues[0].ID, resp.Issues[0].Key),
		URL:    jiraBrowseURL(cfg.InstanceURL, resp.Issues[0].Key),
	}, true, nil
}

// FetchIncident: the inbound state sync speaks ServiceNow's lifecycle model;
// mapping Jira workflow categories onto it is future work (documented in #103).
func (a *jiraTicketAdapter) FetchIncident(_ context.Context, _ ticketSystemConfig, _ ticketRef) (snowIncident, bool, error) {
	return snowIncident{}, false, nil
}

// issueDone reports whether the issue's status category is "done".
func (a *jiraTicketAdapter) issueDone(ctx context.Context, cfg ticketSystemConfig, id string) (bool, error) {
	raw, status, err := a.do(ctx, cfg, http.MethodGet,
		"/rest/api/2/issue/"+url.PathEscape(id)+"?fields=status", nil)
	if err != nil {
		if status == http.StatusNotFound {
			// Issue deleted downstream — nothing left to resolve.
			return true, nil
		}
		return false, err
	}
	var resp struct {
		Fields struct {
			Status struct {
				StatusCategory struct {
					Key string `json:"key"`
				} `json:"statusCategory"`
			} `json:"status"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, fmt.Errorf("jira: decode status: %w", err)
	}
	return resp.Fields.Status.StatusCategory.Key == "done", nil
}

// resolveTransitionID picks the transition used to close the issue: the
// configured hint (by id or name) wins outright, else the first resolve-like name.
func (a *jiraTicketAdapter) resolveTransitionID(ctx context.Context, cfg ticketSystemConfig, id string) (string, error) {
	raw, _, err := a.do(ctx, cfg, http.MethodGet,
		"/rest/api/2/issue/"+url.PathEscape(id)+"/transitions", nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"transitions"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", fmt.Errorf("jira: decode transitions: %w", err)
	}
	if hint := strings.TrimSpace(cfg.ResolveTransition); hint != "" {
		for _, t := range resp.Transitions {
			if t.ID == hint || strings.EqualFold(t.Name, hint) {
				return t.ID, nil
			}
		}
	}
	for _, t := range resp.Transitions {
		n := strings.ToLower(t.Name)
		for _, kw := range []string{"done", "resolve", "close", "complete"} {
			if strings.Contains(n, kw) {
				return t.ID, nil
			}
		}
	}
	return "", nil
}

// jiraIssueFields maps the RCA payload onto Jira issue fields. The friendly
// Correlix Problem ID (P-XXXXXX) leads the summary — one handle across every
// destination and the RCA Inspector (#103 UX-2); the UUID stays canonical in
// the dedupe label. Priority is deliberately NOT set: priority schemes are
// per-instance and an unknown name fails the whole create with a 400.
func jiraIssueFields(cfg ticketSystemConfig, p ticketPayload, withLabels bool) map[string]any {
	pid := noclabel.ProblemDisplayID(p.CorrObjectID)
	summary := orDefault(p.Title, "Correlix RCA incident")
	if pid != "" {
		summary = "[" + pid + "] " + summary
	}
	f := map[string]any{
		"project":     map[string]string{"key": cfg.ProjectKey},
		"summary":     truncate(summary, 240),
		"description": snowDescription(p), // provider-agnostic plain-text RCA body
		"issuetype":   map[string]string{"name": orDefault(cfg.IssueType, "Task")},
	}
	if withLabels {
		f["labels"] = []string{"correlix", "rca", "verdict-" + orDefault(p.Verdict, "unknown"), jiraDedupeLabel(p.CorrObjectID)}
	}
	return f
}

// ── HTTP plumbing ────────────────────────────────────────────────────────────

// do performs one bounded, SSRF-guarded, authenticated REST request. Errors
// never contain the API token; failure classes map to the worker's typed
// retry semantics (429 honors Retry-After; auth/payload rejections are
// permanent; everything else retries with backoff).
func (a *jiraTicketAdapter) do(ctx context.Context, cfg ticketSystemConfig, method, path string, body map[string]any) ([]byte, int, error) {
	base, err := jiraBaseURL(cfg.InstanceURL)
	if err != nil {
		return nil, 0, permanentDeliveryError{err}
	}
	if err := safehttp.ValidateURL(base.Hostname()); err != nil {
		return nil, 0, permanentDeliveryError{err}
	}
	reqURL, err := url.Parse(strings.TrimRight(base.String(), "/") + path)
	if err != nil {
		return nil, 0, permanentDeliveryError{fmt.Errorf("jira: bad request url")}
	}
	// Defense in depth: the composed URL must stay on the configured host.
	if !strings.EqualFold(reqURL.Hostname(), base.Hostname()) {
		return nil, 0, permanentDeliveryError{fmt.Errorf("jira: request host %q escaped configured base URL", reqURL.Hostname())}
	}

	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, permanentDeliveryError{fmt.Errorf("jira: encode body: %w", err)}
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), rdr)
	if err != nil {
		return nil, 0, fmt.Errorf("jira: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBasicAuth(cfg.User, cfg.APIToken)

	resp, err := a.client().Do(req)
	if err != nil {
		// net/url errors can embed the URL but never the auth header/secret.
		return nil, 0, fmt.Errorf("jira: %s %s: request failed", method, redactPath(path))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, jiraMaxRespBytes))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return raw, resp.StatusCode, nil
	}
	err = fmt.Errorf("jira: %s %s returned %d: %s", method, redactPath(path), resp.StatusCode, jiraError(raw))
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		delay := 30 * time.Second
		if ra, perr := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); perr == nil && ra > 0 && ra <= 3600 {
			delay = time.Duration(ra) * time.Second
		}
		return raw, resp.StatusCode, rateLimitedError{After: delay}
	case http.StatusBadRequest:
		// Payload rejected — retrying identical bytes cannot succeed.
		return raw, resp.StatusCode, permanentDeliveryError{err}
	case http.StatusUnauthorized, http.StatusForbidden:
		// Credentials revoked/insufficient — retry won't fix it.
		return raw, resp.StatusCode, permanentDeliveryError{err}
	default:
		return raw, resp.StatusCode, err // transient: worker backoff (incl. 404 races)
	}
}

func jiraBaseURL(raw string) (*url.URL, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return nil, fmt.Errorf("jira: base URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("jira: base URL is not a URL")
	}
	if u.Host == "" {
		// Parsed, but carries no host (e.g. "jira.example.com" with no scheme) —
		// a different operator mistake from an unparseable string, and the
		// message now says which one it is.
		return nil, fmt.Errorf("jira: base URL has no host (include the scheme, e.g. https://…)")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("jira: base URL must be http(s)")
	}
	return u, nil
}

func jiraBrowseURL(baseURL, key string) string {
	if key == "" {
		return ""
	}
	return strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/browse/" + url.PathEscape(key)
}

// jiraError extracts Jira's {errorMessages:[], errors:{}} without leaking a
// huge (or secret-bearing) body into logs/audit rows.
func jiraError(raw []byte) string {
	var e struct {
		ErrorMessages []string          `json:"errorMessages"`
		Errors        map[string]string `json:"errors"`
	}
	if json.Unmarshal(raw, &e) == nil {
		parts := append([]string{}, e.ErrorMessages...)
		for k, v := range e.Errors {
			parts = append(parts, k+": "+v)
		}
		if len(parts) > 0 {
			return truncate(strings.Join(parts, "; "), 240)
		}
	}
	return truncate(strings.TrimSpace(string(raw)), 240)
}

var _ ticketAdapter = (*jiraTicketAdapter)(nil)
