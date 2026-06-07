package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/models"
	"netops/backend/safehttp"
)

// Jira is an ITSM connector that AUTO-TICKETS alerts bi-directionally, mirroring
// the ServiceNow connector (notify/servicenow.go) so the two behave identically
// from the alert engine's point of view:
//
//   - an alert at/above the configured severity threshold opens a Jira issue via
//     the REST v2 API (deduped by fingerprint so a flapping alert never spawns
//     duplicates);
//   - when that alert clears, the SAME issue is transitioned to a resolved/done
//     state, closing the loop without a human touching it.
//
// Open-ticket state is persisted to disk (WithStateFile) so dedup and auto-close
// survive an API restart. Auth is HTTP Basic with an Atlassian account email +
// API token (Jira Cloud's standard machine credential). Configure via
// FEATURE_JIRA_NOTIFICATIONS=true + JIRA_BASE_URL + JIRA_EMAIL + JIRA_API_TOKEN +
// JIRA_PROJECT_KEY (+ optional JIRA_ISSUE_TYPE, JIRA_MIN_SEVERITY,
// JIRA_RESOLVE_TRANSITION). See docs/ITSM_INTEGRATION.md.
type Jira struct {
	baseURL       string // e.g. https://yourorg.atlassian.net
	email         string
	apiToken      string
	projectKey    string
	issueType     string
	client        *http.Client
	threshold     int    // minimum severity rank that cuts a ticket
	thresholdName string // human label for the threshold
	// resolveHint optionally pins the transition used to resolve an issue (its
	// name or numeric id). Empty → auto-detect a done/resolve-like transition.
	resolveHint string
	statePath   string

	mu   sync.Mutex
	open map[string]*JiraTicket // fingerprint -> ticket
}

// ResolveExternal transitions a Jira issue to Done/Resolved by its KEY (the drift
// reconciler's outbound re-push). Idempotent — already-resolved issues no-op via
// the transition lookup.
func (j *Jira) ResolveExternal(key string) error {
	if j.baseURL == "" || key == "" {
		return errors.New("jira not configured")
	}
	return j.resolveIssue(key)
}

// PollState fetches an issue's current status name + a version (the `updated`
// timestamp in epoch millis, since Jira has no monotonic change counter) by its
// key, for the drift reconciler. found=false when the issue is gone. Read-only.
func (j *Jira) PollState(key string) (state string, version int64, found bool, err error) {
	if j.baseURL == "" || key == "" {
		return "", 0, false, nil
	}
	u := strings.TrimRight(j.baseURL, "/") + "/rest/api/2/issue/" + url.PathEscape(key) + "?fields=status,updated"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", 0, false, err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(j.email, j.apiToken)
	resp, err := j.client.Do(req)
	if err != nil {
		return "", 0, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", 0, false, nil
	}
	if resp.StatusCode >= 300 {
		return "", 0, false, fmt.Errorf("jira poll returned %d", resp.StatusCode)
	}
	var out struct {
		Fields struct {
			Status  struct{ Name string } `json:"status"`
			Updated string                `json:"updated"`
		} `json:"fields"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, false, err
	}
	if t, e := time.Parse("2006-01-02T15:04:05.999-0700", out.Fields.Updated); e == nil {
		version = t.UnixMilli()
	}
	return out.Fields.Status.Name, version, true, nil
}

// JiraTicket links a NetOps alert fingerprint to its Jira issue.
type JiraTicket struct {
	Fingerprint string    `json:"fingerprint"`
	Key         string    `json:"key"` // e.g. NETOPS-1234
	IssueID     string    `json:"issue_id"`
	Severity    string    `json:"severity"`
	Device      string    `json:"device,omitempty"`
	Summary     string    `json:"summary,omitempty"`
	OpenedAt    time.Time `json:"opened_at"`
	State       string    `json:"state"` // pending | open
}

func NewJira(baseURL, email, apiToken, projectKey string) *Jira {
	return &Jira{
		baseURL:       strings.TrimRight(baseURL, "/"),
		email:         email,
		apiToken:      apiToken,
		projectKey:    strings.TrimSpace(projectKey),
		issueType:     "Task",
		client:        safehttp.Client(15 * time.Second),
		threshold:     severityRank("critical"),
		thresholdName: "critical",
		open:          make(map[string]*JiraTicket),
	}
}

// WithThreshold sets the minimum severity that cuts a ticket (default critical).
func (j *Jira) WithThreshold(sev string) *Jira {
	sev = strings.ToLower(strings.TrimSpace(sev))
	if sev == "" {
		return j
	}
	j.threshold = severityRank(sev)
	j.thresholdName = sev
	return j
}

// WithIssueType overrides the Jira issue type opened for alerts (default Task).
func (j *Jira) WithIssueType(t string) *Jira {
	if t = strings.TrimSpace(t); t != "" {
		j.issueType = t
	}
	return j
}

// WithResolveTransition pins the transition used to close an issue (name or id).
func (j *Jira) WithResolveTransition(t string) *Jira {
	j.resolveHint = strings.TrimSpace(t)
	return j
}

// WithStateFile makes open tickets durable across restarts.
func (j *Jira) WithStateFile(path string) *Jira {
	if path == "" {
		return j
	}
	j.statePath = path
	j.loadState()
	return j
}

func (j *Jira) Name() string { return "jira" }

// Configured reports whether the connector has the minimum config to operate.
func (j *Jira) Configured() bool {
	return j != nil && j.baseURL != "" && j.projectKey != ""
}

// ThresholdName is the minimum severity that cuts a ticket.
func (j *Jira) ThresholdName() string { return j.thresholdName }

// ProjectKey is the Jira project alerts open issues in (for the status UI).
func (j *Jira) ProjectKey() string { return j.projectKey }

// Tickets returns the currently-open issues (newest first) for the status UI.
func (j *Jira) Tickets() []JiraTicket {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]JiraTicket, 0, len(j.open))
	for _, t := range j.open {
		if t.State == "open" {
			out = append(out, *t)
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].OpenedAt.After(out[k].OpenedAt) })
	return out
}

func (j *Jira) meets(sev string) bool { return severityRank(sev) >= j.threshold }

func (j *Jira) Send(a models.Alert) error {
	// Resolution events for a tracked ticket are handled even if the alert's
	// severity is below threshold at clear time; otherwise only threshold-
	// meeting alerts are relevant.
	if a.ResolvedAt != nil {
		return j.resolve(fingerprint(a))
	}
	if !j.meets(a.Severity) {
		return nil
	}
	if !j.Configured() {
		return errors.New("jira base url / project key not configured")
	}
	fp := fingerprint(a)

	// Dedup: reserve the slot before the network call so concurrent dispatches
	// don't race into two issues.
	j.mu.Lock()
	if _, exists := j.open[fp]; exists {
		j.mu.Unlock()
		return nil
	}
	j.open[fp] = &JiraTicket{Fingerprint: fp, State: "pending"}
	j.mu.Unlock()

	key, id, err := j.createIssue(a)
	if err != nil {
		j.mu.Lock()
		delete(j.open, fp)
		j.mu.Unlock()
		return err
	}
	j.mu.Lock()
	j.open[fp] = &JiraTicket{
		Fingerprint: fp, Key: key, IssueID: id, Severity: a.Severity,
		Device: a.DeviceID, Summary: a.Summary, OpenedAt: time.Now().UTC(), State: "open",
	}
	j.saveLocked()
	j.mu.Unlock()
	return nil
}

// resolve auto-closes the issue bound to fp (if any) and forgets it. The local
// forget is unconditional so a genuine re-fire can open a fresh ticket even if
// Jira is briefly unreachable.
func (j *Jira) resolve(fp string) error {
	j.mu.Lock()
	t, ok := j.open[fp]
	if ok {
		delete(j.open, fp)
		j.saveLocked()
	}
	j.mu.Unlock()
	if !ok || t.Key == "" || !j.Configured() {
		return nil
	}
	return j.resolveIssue(t.Key)
}

// createIssue POSTs to the REST v2 API and returns (key, id). The v2 endpoint
// accepts a plain-text description (v3 requires the verbose ADF document body);
// Jira Cloud serves both.
// CreateForIncident projects a platform Incident to a new Jira issue and returns
// (issue key, url). Used by the incident sync worker (outward projection only).
func (j *Jira) CreateForIncident(title, description, severity string) (string, string, error) {
	key, _, err := j.createIssue(models.Alert{
		Rule: title, Severity: severity, Summary: title, Description: description,
	})
	if err != nil {
		return "", "", err
	}
	url := ""
	if j.baseURL != "" && key != "" {
		url = strings.TrimRight(j.baseURL, "/") + "/browse/" + key
	}
	return key, url, nil
}

func (j *Jira) createIssue(a models.Alert) (string, string, error) {
	fields := map[string]any{
		"project":     map[string]string{"key": j.projectKey},
		"summary":     fmt.Sprintf("[%s] %s", strings.ToUpper(a.Severity), a.Summary),
		"description": incidentBody(a),
		"issuetype":   map[string]string{"name": j.issueType},
		"labels":      []string{"netops", "auto-ticket", "sev-" + strings.ToLower(a.Severity)},
	}
	payload := map[string]any{"fields": fields}
	buf, _ := json.Marshal(payload)

	url := j.baseURL + "/rest/api/2/issue"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(j.email, j.apiToken)

	resp, err := j.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("jira create returned %d", resp.StatusCode)
	}
	var out struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", err
	}
	return out.Key, out.ID, nil
}

// resolveIssue transitions an issue into a done/resolved state. Jira models
// "resolve" as a workflow transition whose id is project-specific, so we resolve
// the transition id at close time: honor JIRA_RESOLVE_TRANSITION when set (by id
// or name), else pick the first transition whose name looks resolve-like.
func (j *Jira) resolveIssue(key string) error {
	tid, err := j.resolveTransitionID(key)
	if err != nil {
		return err
	}
	if tid == "" {
		return fmt.Errorf("jira: no resolve transition available for %s", key)
	}
	payload := map[string]any{
		"transition": map[string]string{"id": tid},
		"update": map[string]any{
			"comment": []map[string]any{
				{"add": map[string]string{"body": "Auto-resolved by NetOps/Opsis: the underlying alert cleared."}},
			},
		},
	}
	buf, _ := json.Marshal(payload)
	url := j.baseURL + "/rest/api/2/issue/" + key + "/transitions"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(j.email, j.apiToken)
	resp, err := j.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("jira transition returned %d", resp.StatusCode)
	}
	return nil
}

// resolveTransitionID GETs the issue's available transitions and chooses the one
// to use for resolution.
func (j *Jira) resolveTransitionID(key string) (string, error) {
	url := j.baseURL + "/rest/api/2/issue/" + key + "/transitions"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(j.email, j.apiToken)
	resp, err := j.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("jira transitions returned %d", resp.StatusCode)
	}
	var out struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"transitions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	// Operator pinned an explicit transition (by id or name) — honor it exactly.
	if j.resolveHint != "" {
		for _, t := range out.Transitions {
			if t.ID == j.resolveHint || strings.EqualFold(t.Name, j.resolveHint) {
				return t.ID, nil
			}
		}
	}
	// Otherwise pick the first transition whose name reads as resolve/done/close.
	for _, t := range out.Transitions {
		if isResolveLike(t.Name) {
			return t.ID, nil
		}
	}
	return "", nil
}

func isResolveLike(name string) bool {
	n := strings.ToLower(name)
	for _, kw := range []string{"done", "resolve", "close", "complete"} {
		if strings.Contains(n, kw) {
			return true
		}
	}
	return false
}

// ---- state persistence -----------------------------------------------------

func (j *Jira) saveLocked() {
	if j.statePath == "" {
		return
	}
	list := make([]JiraTicket, 0, len(j.open))
	for _, t := range j.open {
		if t.State == "open" {
			list = append(list, *t)
		}
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(j.statePath), 0o755); err != nil {
		return
	}
	tmp := j.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, j.statePath)
	}
}

func (j *Jira) loadState() {
	b, err := os.ReadFile(j.statePath)
	if err != nil {
		return
	}
	var list []JiraTicket
	if err := json.Unmarshal(b, &list); err != nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range list {
		t := list[i]
		j.open[t.Fingerprint] = &t
	}
}
