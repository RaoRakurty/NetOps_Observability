// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

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

// ticketing_servicenow.go — the RCA-object ServiceNow adapter (#78 P2). Unlike
// notify.ServiceNow (one incident per ALERT fingerprint), this adapter speaks
// the Payload built from ONE RCA correlation object and uses ServiceNow's
// native correlation_id as the dedupe anchor (= corr_object_id). The worker
// (ticketing_worker.go) drives it; ticketing never blocks correlation.
//
// Zero-trust outbound (CLAUDE.md §3/§8): the HTTP client is SSRF-guarded
// (safehttp), every request URL is checked to belong to the configured instance
// host, secrets travel only in the Authorization header and are NEVER logged or
// echoed in errors, and the request/response bodies are bounded.

// Adapter is the provider-agnostic ticketing port (§5 interfaces for
// external deps). ServiceNow is the first impl; Jira/PagerDuty reuse the same
// outbox + worker against this interface.
type Adapter interface {
	Name() string
	ValidateConfig(cfg SystemConfig) error
	HealthCheck(ctx context.Context, cfg SystemConfig) error
	CreateIncident(ctx context.Context, cfg SystemConfig, p Payload) (Ref, error)
	UpdateIncident(ctx context.Context, cfg SystemConfig, ref Ref, p Payload) error
	AddWorkNote(ctx context.Context, cfg SystemConfig, ref Ref, note string) error
	ResolveIncident(ctx context.Context, cfg SystemConfig, ref Ref, note string) error
	LookupByCorrelationID(ctx context.Context, cfg SystemConfig, corrID string) (Ref, bool, error)
	// FetchIncident reads an incident's current state + lifecycle timestamps back
	// from the provider (the inbound state sync, #84). found=false when the record
	// no longer exists. Read-only.
	FetchIncident(ctx context.Context, cfg SystemConfig, ref Ref) (RemoteIncident, bool, error)
}

// RemoteIncident is the subset of incident fields the inbound state sync reads to map
// a ticket's ServiceNow progress onto the RCA incident timeline. Times are UTC
// (zero when unset). State is the numeric ServiceNow incident state.
type RemoteIncident struct {
	Number     string
	SysID      string
	State      int       // 1 New · 2 In Progress · 3 On Hold · 6 Resolved · 7 Closed
	OpenedAt   time.Time // standard field
	WorkStart  time.Time // standard field (work began)
	ResolvedAt time.Time // standard field
	ClosedAt   time.Time // standard field
	UpdatedAt  time.Time // sys_updated_on
	// Optional Correlix custom fields — let a customer drive the Correlix-specific
	// phases precisely; absent ⇒ that phase stays honestly incomplete.
	AcknowledgedAt      time.Time
	MitigationStartedAt time.Time
	MitigatedAt         time.Time
	RecoveredAt         time.Time
}

// ServiceNow incident state codes (default set).
const (
	SnowStateInProgress = 2
	SnowStateResolved   = 6
	SnowStateClosed     = 7
)

// SystemConfig is the connection for one external system. Secrets
// (Password/APIToken) are write-only and never serialized back out.
type SystemConfig struct {
	System          string `json:"system"` // servicenow | pagerduty | slack | jira
	TenantID        string `json:"-"`      // stamped by the resolver; identity for the worker's tenant assertion + PD dedup key
	InstanceURL     string `json:"instance_url"`
	AuthType        string `json:"auth_type"` // basic | token
	User            string `json:"user"`
	Password        string `json:"-"`
	APIToken        string `json:"-"`
	AssignmentGroup string `json:"assignment_group"`
	// Jira-only (non-secret): target project, issue type, and the workflow
	// transition (id or name) used to resolve an issue.
	ProjectKey        string `json:"project_key,omitempty"`
	IssueType         string `json:"issue_type,omitempty"`
	ResolveTransition string `json:"resolve_transition,omitempty"`
}

// Ref identifies a created external ticket.
type Ref struct {
	Number string `json:"number"`
	SysID  string `json:"sys_id"`
	URL    string `json:"url"`
}

const snowMaxRespBytes = 1 << 20 // 1 MiB cap on a Table API response

// ServiceNowAdapter implements Adapter against the ServiceNow Table API.
// httpClient is injectable so tests drive it against an httptest mock.
// asString mirrors the integrator's tolerant string extraction (duplicated per
// the no-shared-utils rule).
func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

type ServiceNowAdapter struct {
	httpClient *http.Client
}

// NewServiceNowAdapterWithClient injects the HTTP client (integrator tests).
func NewServiceNowAdapterWithClient(c *http.Client) *ServiceNowAdapter {
	return &ServiceNowAdapter{httpClient: c}
}

func NewServiceNowAdapter() *ServiceNowAdapter {
	return &ServiceNowAdapter{httpClient: safehttp.Client(20 * time.Second)}
}

func (a *ServiceNowAdapter) Name() string { return "servicenow" }

func (a *ServiceNowAdapter) client() *http.Client {
	if a.httpClient != nil {
		return a.httpClient
	}
	return safehttp.Client(20 * time.Second)
}

// ValidateConfig checks the connection is well-formed and the instance host is a
// public, resolvable target (SSRF). Pure-ish (one DNS resolve, no ServiceNow call).
func (a *ServiceNowAdapter) ValidateConfig(cfg SystemConfig) error {
	u, err := parseInstanceURL(cfg.InstanceURL)
	if err != nil {
		return err
	}
	switch strings.ToLower(orDefault(cfg.AuthType, "basic")) {
	case "basic":
		if cfg.User == "" || cfg.Password == "" {
			return fmt.Errorf("servicenow: basic auth requires user and password")
		}
	case "token":
		if cfg.APIToken == "" {
			return fmt.Errorf("servicenow: token auth requires an API token")
		}
	default:
		return fmt.Errorf("servicenow: unsupported auth_type %q", cfg.AuthType)
	}
	return safehttp.ValidateURL(u.Hostname())
}

// HealthCheck does a cheap, bounded GET that proves auth + reachability.
func (a *ServiceNowAdapter) HealthCheck(ctx context.Context, cfg SystemConfig) error {
	_, _, err := a.do(ctx, cfg, http.MethodGet, "/api/now/table/incident?sysparm_limit=1&sysparm_fields=sys_id", nil)
	return err
}

func (a *ServiceNowAdapter) CreateIncident(ctx context.Context, cfg SystemConfig, p Payload) (Ref, error) {
	body := snowIncidentFields(cfg, p)
	body["work_notes"] = snowWorkNote("Correlix opened this incident from RCA correlation object "+p.CorrObjectID, p)
	// sysparm_input_display_value=true: reference fields (assignment_group,
	// category) arrive as display NAMES, not sys_ids — without this ServiceNow
	// silently drops them and the incident lands unassigned/uncategorized.
	raw, _, err := a.do(ctx, cfg, http.MethodPost, "/api/now/table/incident?sysparm_input_display_value=true", body)
	if err != nil {
		return Ref{}, err
	}
	return a.parseRef(cfg, raw)
}

func (a *ServiceNowAdapter) UpdateIncident(ctx context.Context, cfg SystemConfig, ref Ref, p Payload) error {
	if ref.SysID == "" {
		return fmt.Errorf("servicenow: update requires sys_id")
	}
	body := snowIncidentFields(cfg, p)
	body["work_notes"] = snowWorkNote("RCA verdict updated", p)
	_, _, err := a.do(ctx, cfg, http.MethodPatch,
		"/api/now/table/incident/"+url.PathEscape(ref.SysID)+"?sysparm_input_display_value=true", body)
	return err
}

func (a *ServiceNowAdapter) AddWorkNote(ctx context.Context, cfg SystemConfig, ref Ref, note string) error {
	if ref.SysID == "" {
		return fmt.Errorf("servicenow: work note requires sys_id")
	}
	_, _, err := a.do(ctx, cfg, http.MethodPatch, "/api/now/table/incident/"+url.PathEscape(ref.SysID),
		map[string]any{"work_notes": note})
	return err
}

func (a *ServiceNowAdapter) ResolveIncident(ctx context.Context, cfg SystemConfig, ref Ref, note string) error {
	if ref.SysID == "" {
		return fmt.Errorf("servicenow: resolve requires sys_id")
	}
	// state 6 = Resolved; close_code is required by most ServiceNow instances.
	_, _, err := a.do(ctx, cfg, http.MethodPatch, "/api/now/table/incident/"+url.PathEscape(ref.SysID),
		map[string]any{"state": "6", "close_code": "Resolved by caller", "close_notes": note, "work_notes": note})
	return err
}

// LookupByCorrelationID finds an existing incident by ServiceNow's native
// correlation_id (= corr_object_id). This is the recovery path when a create
// succeeded but our link store didn't persist — we never create a second ticket.
func (a *ServiceNowAdapter) LookupByCorrelationID(ctx context.Context, cfg SystemConfig, corrID string) (Ref, bool, error) {
	q := "/api/now/table/incident?sysparm_limit=1&sysparm_fields=number,sys_id&sysparm_query=correlation_id=" +
		url.QueryEscape(corrID)
	raw, _, err := a.do(ctx, cfg, http.MethodGet, q, nil)
	if err != nil {
		return Ref{}, false, err
	}
	var resp struct {
		Result []struct {
			Number string `json:"number"`
			SysID  string `json:"sys_id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Ref{}, false, fmt.Errorf("servicenow: decode lookup: %w", err)
	}
	if len(resp.Result) == 0 || resp.Result[0].SysID == "" {
		return Ref{}, false, nil
	}
	return Ref{Number: resp.Result[0].Number, SysID: resp.Result[0].SysID,
		URL: incidentURL(cfg.InstanceURL, resp.Result[0].SysID)}, true, nil
}

// FetchIncident reads one incident's state + lifecycle timestamps back from the
// Table API (the inbound state sync). found=false on a 404 (record gone). The
// composed query stays on the configured instance host (do() enforces it).
func (a *ServiceNowAdapter) FetchIncident(ctx context.Context, cfg SystemConfig, ref Ref) (RemoteIncident, bool, error) {
	if ref.SysID == "" {
		return RemoteIncident{}, false, fmt.Errorf("servicenow: fetch requires sys_id")
	}
	fields := "number,sys_id,state,opened_at,work_start,resolved_at,closed_at,sys_updated_on," +
		"u_correlix_acknowledged_at,u_correlix_mitigation_started_at,u_correlix_mitigated_at,u_correlix_recovered_at"
	path := "/api/now/table/incident/" + url.PathEscape(ref.SysID) +
		"?sysparm_display_value=false&sysparm_fields=" + url.QueryEscape(fields)
	raw, status, err := a.do(ctx, cfg, http.MethodGet, path, nil)
	if err != nil {
		if status == http.StatusNotFound {
			return RemoteIncident{}, false, nil
		}
		return RemoteIncident{}, false, err
	}
	var resp struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return RemoteIncident{}, false, fmt.Errorf("servicenow: decode incident: %w", err)
	}
	r := resp.Result
	if len(r) == 0 {
		return RemoteIncident{}, false, nil
	}
	inc := RemoteIncident{
		Number:              asString(r["number"]),
		SysID:               orDefault(asString(r["sys_id"]), ref.SysID),
		State:               snowStateCode(r["state"]),
		OpenedAt:            parseSnowTime(r["opened_at"]),
		WorkStart:           parseSnowTime(r["work_start"]),
		ResolvedAt:          parseSnowTime(r["resolved_at"]),
		ClosedAt:            parseSnowTime(r["closed_at"]),
		UpdatedAt:           parseSnowTime(r["sys_updated_on"]),
		AcknowledgedAt:      parseSnowTime(r["u_correlix_acknowledged_at"]),
		MitigationStartedAt: parseSnowTime(r["u_correlix_mitigation_started_at"]),
		MitigatedAt:         parseSnowTime(r["u_correlix_mitigated_at"]),
		RecoveredAt:         parseSnowTime(r["u_correlix_recovered_at"]),
	}
	return inc, true, nil
}

// snowStateCode coerces the Table API state (a string with sysparm_display_value=
// false, but tolerate a number) to its numeric code; 0 when absent/unparseable.
func snowStateCode(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n
		}
	}
	return 0
}

// parseSnowTime parses a ServiceNow timestamp ("2006-01-02 15:04:05", UTC) or an
// RFC3339 string; returns the zero time for empty/unparseable input.
func parseSnowTime(v any) time.Time {
	s := strings.TrimSpace(asString(v))
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.ParseInLocation("2006-01-02 15:04:05", s, time.UTC); err == nil {
		return ts.UTC()
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

// ── HTTP plumbing ────────────────────────────────────────────────────────────

// do performs one bounded, SSRF-guarded, authenticated Table API request. It
// returns the response body (capped) and status. Errors never contain secrets.
func (a *ServiceNowAdapter) do(ctx context.Context, cfg SystemConfig, method, path string, body map[string]any) ([]byte, int, error) {
	base, err := parseInstanceURL(cfg.InstanceURL)
	if err != nil {
		return nil, 0, err
	}
	if err := safehttp.ValidateURL(base.Hostname()); err != nil {
		return nil, 0, err
	}
	full := strings.TrimRight(base.String(), "/") + path
	reqURL, err := url.Parse(full)
	if err != nil {
		return nil, 0, fmt.Errorf("servicenow: bad request url")
	}
	// Defense in depth: the composed URL must stay on the configured instance host.
	if !strings.EqualFold(reqURL.Hostname(), base.Hostname()) {
		return nil, 0, fmt.Errorf("servicenow: request host %q escaped configured instance", reqURL.Hostname())
	}

	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("servicenow: encode body: %w", err)
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), rdr)
	if err != nil {
		return nil, 0, fmt.Errorf("servicenow: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	switch strings.ToLower(orDefault(cfg.AuthType, "basic")) {
	case "token":
		req.Header.Set("Authorization", "Bearer "+cfg.APIToken)
	default:
		req.SetBasicAuth(cfg.User, cfg.Password)
	}

	resp, err := a.client().Do(req)
	if err != nil {
		// net/url errors can embed the URL but never the auth header/secret.
		return nil, 0, fmt.Errorf("servicenow: %s %s: request failed", method, path)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, snowMaxRespBytes)) // best-effort: diagnostic snippet; a read error just leaves it empty
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return raw, resp.StatusCode, fmt.Errorf("servicenow: %s %s returned %d: %s",
			method, redactPath(path), resp.StatusCode, snowError(raw))
	}
	return raw, resp.StatusCode, nil
}

func (a *ServiceNowAdapter) parseRef(cfg SystemConfig, raw []byte) (Ref, error) {
	var resp struct {
		Result struct {
			Number string `json:"number"`
			SysID  string `json:"sys_id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Ref{}, fmt.Errorf("servicenow: decode create: %w", err)
	}
	if resp.Result.SysID == "" {
		return Ref{}, fmt.Errorf("servicenow: create returned no sys_id")
	}
	return Ref{Number: resp.Result.Number, SysID: resp.Result.SysID,
		URL: incidentURL(cfg.InstanceURL, resp.Result.SysID)}, nil
}

// ── field mapping ────────────────────────────────────────────────────────────

// snowIncidentFields maps the RCA payload onto ServiceNow incident fields,
// including the native correlation_id dedupe key and the u_correlix_* custom
// fields the design specifies. Never carries raw-alert text.
func snowIncidentFields(cfg SystemConfig, p Payload) map[string]any {
	group := p.AssignmentGroup
	if group == "" {
		group = cfg.AssignmentGroup
	}
	// Stamp the friendly Correlix Problem ID (P-XXXXXX) into the short description
	// and a custom field so NOC + ServiceNow share ONE handle (the UUID stays the
	// dedupe anchor in correlation_id / u_correlix_object_id).
	pid := noclabel.ProblemDisplayID(p.CorrObjectID)
	f := map[string]any{
		"short_description": Truncate("["+pid+"] "+p.Title, 160),
		"description":       snowDescription(p),
		// Every Correlix RCA ticket is a network fault — without this ServiceNow
		// files the incident under its default category (Inquiry/Help), which
		// misroutes it away from network queues (operator report 2026-07-11).
		"category":              "network",
		"correlation_id":        p.CorrObjectID,
		"correlation_display":   "Correlix RCA",
		"u_correlix_problem_id": pid,
		"u_correlix_object_id":  p.CorrObjectID,
		"u_correlix_verdict":    p.Verdict,
		"u_correlix_confidence": strconv.FormatFloat(p.Confidence, 'f', 2, 64),
		"u_correlix_signature":  p.Signature,
		"u_correlix_owner":      p.Owner,
		"u_correlix_affected":   p.AffectedScope,
		"u_correlix_rca_url":    p.RCAURL,
	}
	if p.Impact > 0 {
		f["impact"] = strconv.Itoa(p.Impact)
	}
	if p.Urgency > 0 {
		f["urgency"] = strconv.Itoa(p.Urgency)
	}
	if group != "" {
		f["assignment_group"] = group
	}
	return f
}

// snowDescription is the human-readable RCA body (the diagnosis, not raw alerts).
func snowDescription(p Payload) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Correlix Problem: %s\n\n", noclabel.ProblemDisplayID(p.CorrObjectID))
	fmt.Fprintf(&b, "%s\n\n", p.Summary)
	fmt.Fprintf(&b, "Verdict: %s (confidence %.0f%%)\n", p.Verdict, p.Confidence*100)
	if p.AffectedScope != "" {
		fmt.Fprintf(&b, "Affected: %s\n", p.AffectedScope)
	}
	if len(p.ImpactedApps) > 0 {
		fmt.Fprintf(&b, "Impacted applications: %s\n", strings.Join(p.ImpactedApps, ", "))
	}
	if len(p.EvidenceUsed) > 0 {
		fmt.Fprintf(&b, "\nEvidence used:\n- %s\n", strings.Join(p.EvidenceUsed, "\n- "))
	}
	if len(p.MissingEvidence) > 0 {
		fmt.Fprintf(&b, "\nMissing evidence:\n- %s\n", strings.Join(p.MissingEvidence, "\n- "))
	}
	if p.RecommendedAction != "" {
		fmt.Fprintf(&b, "\nRecommended action: %s\n", p.RecommendedAction)
	}
	if p.RCAURL != "" {
		fmt.Fprintf(&b, "\nFull RCA: %s\n", p.RCAURL)
	}
	return b.String()
}

func snowWorkNote(headline string, p Payload) string {
	if p.RCAURL == "" {
		return headline
	}
	return headline + " — " + p.RCAURL
}

// ── helpers ──────────────────────────────────────────────────────────────────

func parseInstanceURL(raw string) (*url.URL, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return nil, fmt.Errorf("servicenow: instance_url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("servicenow: instance_url is not a URL")
	}
	if u.Host == "" {
		// Parsed, but carries no host (e.g. "dev123.service-now.com" with no
		// scheme) — a different mistake from an unparseable string.
		return nil, fmt.Errorf("servicenow: instance_url has no host (include the scheme, e.g. https://…)")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("servicenow: instance_url must be http(s)")
	}
	return u, nil
}

func incidentURL(instanceURL, sysID string) string {
	return strings.TrimRight(strings.TrimSpace(instanceURL), "/") + "/nav_to.do?uri=incident.do?sys_id=" + url.QueryEscape(sysID)
}

// snowError extracts ServiceNow's {error:{message}} without leaking a huge body.
func snowError(raw []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error.Message != "" {
		return Truncate(e.Error.Message, 240)
	}
	return Truncate(strings.TrimSpace(string(raw)), 240)
}

// redactPath drops the query string from a logged path (correlation ids/filters
// are not secret, but keep error strings tight and free of injected values).
func redactPath(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}

// Truncate bounds provider/display strings (shared with the worker's
// last-error field).
func Truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

var _ Adapter = (*ServiceNowAdapter)(nil)
