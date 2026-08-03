package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"netops/backend/models"
	"netops/backend/safehttp"
)

// ServiceNow is an ITSM connector that AUTO-TICKETS alerts bi-directionally:
//
//   - an alert at/above the configured severity threshold opens an incident via
//     the ServiceNow Table API (deduped by fingerprint so a flapping alert never
//     spawns duplicates);
//   - when that alert clears, the SAME incident is auto-resolved (state →
//     Resolved with close notes), closing the loop without a human touching it.
//
// Open-ticket state is persisted to disk (WithStateFile) so dedup and auto-close
// survive an API restart. Auth is HTTP Basic against the Table API; swap for
// OAuth by replacing the SetBasicAuth calls. Configure via
// FEATURE_SERVICENOW_NOTIFICATIONS=true + SERVICENOW_INSTANCE_URL +
// SERVICENOW_USER + SERVICENOW_PASSWORD (+ optional SERVICENOW_MIN_SEVERITY,
// SERVICENOW_ASSIGNMENT_GROUP). See docs/ITSM_INTEGRATION.md.
type ServiceNow struct {
	instanceURL     string // e.g. https://dev12345.service-now.com
	user            string
	password        string
	client          *http.Client
	assignmentGroup string

	// shared dedup/threshold/state-persistence core (ticket_state.go)
	ticketCore[ServiceNowTicket]
}

// ServiceNowTicket links a NetOps alert fingerprint to its ServiceNow incident.
type ServiceNowTicket struct {
	Fingerprint string    `json:"fingerprint"`
	Number      string    `json:"number"`
	SysID       string    `json:"sys_id"`
	Severity    string    `json:"severity"`
	Device      string    `json:"device,omitempty"`
	Summary     string    `json:"summary,omitempty"`
	OpenedAt    time.Time `json:"opened_at"`
	State       string    `json:"state"` // pending | open
}

// PollState fetches an incident's current state + version (sys_mod_count) by its
// number, for the drift reconciler. Returns found=false when the incident no
// longer exists. Read-only; uses the same Basic auth as the create path.
func (s *ServiceNow) PollState(number string) (state string, version int64, found bool, err error) {
	if s.instanceURL == "" || number == "" {
		return "", 0, false, nil
	}
	u := strings.TrimRight(s.instanceURL, "/") +
		"/api/now/table/incident?sysparm_limit=1&sysparm_fields=number,state,sys_mod_count&sysparm_query=number=" +
		url.QueryEscape(number)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", 0, false, err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(s.user, s.password)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", 0, false, fmt.Errorf("servicenow poll returned %d", resp.StatusCode)
	}
	// ServiceNow's Table API returns every field as a string.
	var out struct {
		Result []struct {
			State       string `json:"state"`
			SysModCount string `json:"sys_mod_count"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, false, err
	}
	if len(out.Result) == 0 {
		return "", 0, false, nil
	}
	v, _ := strconv.ParseInt(out.Result[0].SysModCount, 10, 64)
	return out.Result[0].State, v, true, nil
}

// ResolveExternal resolves a ServiceNow incident by its NUMBER (the drift
// reconciler's outbound re-push when NMS is terminal but the ticket is still
// open). Resolves the sys_id first, then PATCHes to Resolved. Idempotent — a
// PATCH to an already-resolved incident is a no-op.
func (s *ServiceNow) ResolveExternal(number string) error {
	if s.instanceURL == "" || number == "" {
		return errors.New("servicenow not configured")
	}
	u := strings.TrimRight(s.instanceURL, "/") +
		"/api/now/table/incident?sysparm_limit=1&sysparm_fields=sys_id&sysparm_query=number=" + url.QueryEscape(number)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(s.user, s.password)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("servicenow lookup returned %d", resp.StatusCode)
	}
	var out struct {
		Result []struct {
			SysID string `json:"sys_id"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if len(out.Result) == 0 || out.Result[0].SysID == "" {
		return errors.New("servicenow: ticket not found")
	}
	return s.resolveIncident(out.Result[0].SysID)
}

func NewServiceNow(instanceURL, user, password string) *ServiceNow {
	return &ServiceNow{
		instanceURL: strings.TrimRight(instanceURL, "/"),
		user:        user,
		password:    password,
		client:      safehttp.Client(15 * time.Second),
		ticketCore: newTicketCore[ServiceNowTicket](
			func(t *ServiceNowTicket) string { return t.Fingerprint },
			func(t *ServiceNowTicket) bool { return t.State == "open" },
			func(t *ServiceNowTicket) time.Time { return t.OpenedAt },
		),
	}
}

// WithThreshold sets the minimum severity that cuts a ticket (default critical).
func (s *ServiceNow) WithThreshold(sev string) *ServiceNow {
	s.setThreshold(sev)
	return s
}

// WithStateFile makes open tickets durable across restarts.
func (s *ServiceNow) WithStateFile(path string) *ServiceNow {
	s.setStateFile(path)
	return s
}

func (s *ServiceNow) WithAssignmentGroup(g string) *ServiceNow {
	s.assignmentGroup = strings.TrimSpace(g)
	return s
}

func (s *ServiceNow) Name() string { return "servicenow" }

// Configured reports whether the connector has an instance URL.
func (s *ServiceNow) Configured() bool { return s != nil && s.instanceURL != "" }

// Tickets returns the currently-open incidents (newest first) for the status UI.
func (s *ServiceNow) Tickets() []ServiceNowTicket { return s.tickets() }

// severityRank orders the product's severity ladder so a threshold can be
// "this and worse". Unknown severities sort low (won't ticket).
func severityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 5
	case "error":
		return 4
	case "warning":
		return 3
	case "notice":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func fingerprint(a models.Alert) string {
	if a.ID != "" {
		return a.ID
	}
	return a.Rule + "|" + a.DeviceID
}

func (s *ServiceNow) Send(a models.Alert) error {
	// Resolution events for a tracked ticket are handled even if the alert's
	// severity is below threshold at clear time; otherwise only threshold-
	// meeting alerts are relevant.
	if a.ResolvedAt != nil {
		return s.resolve(fingerprint(a))
	}
	if !s.meets(a.Severity) {
		return nil
	}
	if s.instanceURL == "" {
		return errors.New("servicenow instance url not configured")
	}
	fp := fingerprint(a)

	// Dedup: reserve the slot before the network call so concurrent dispatches
	// don't race into two incidents.
	s.mu.Lock()
	if _, exists := s.open[fp]; exists {
		s.mu.Unlock()
		return nil
	}
	s.open[fp] = &ServiceNowTicket{Fingerprint: fp, State: "pending"}
	s.mu.Unlock()

	num, sysID, err := s.createIncident(a)
	if err != nil {
		s.mu.Lock()
		delete(s.open, fp)
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	s.open[fp] = &ServiceNowTicket{
		Fingerprint: fp, Number: num, SysID: sysID, Severity: a.Severity,
		Device: a.DeviceID, Summary: a.Summary, OpenedAt: time.Now().UTC(), State: "open",
	}
	s.noteStateWrite(s.saveLocked())
	s.mu.Unlock()
	return nil
}

// resolve auto-closes the incident bound to fp (if any) and forgets it. The
// local forget is unconditional so a genuine re-fire can open a fresh ticket
// even if ServiceNow is briefly unreachable.
func (s *ServiceNow) resolve(fp string) error {
	s.mu.Lock()
	t, ok := s.open[fp]
	if ok {
		delete(s.open, fp)
		s.noteStateWrite(s.saveLocked())
	}
	s.mu.Unlock()
	if !ok || t.SysID == "" || s.instanceURL == "" {
		return nil
	}
	return s.resolveIncident(t.SysID)
}

// createIncident POSTs to the Table API and returns (number, sys_id).
// CreateForIncident projects a platform Incident to a new ServiceNow incident and
// returns (ticket number, url). Used by the incident sync worker; the platform
// Incident stays the source of truth (this is an outward projection only).
func (s *ServiceNow) CreateForIncident(title, description, severity, deviceID string) (string, string, error) {
	num, sysID, err := s.createIncident(models.Alert{
		Rule: title, Severity: severity, Summary: title, Description: description, DeviceID: deviceID,
	})
	if err != nil {
		return "", "", err
	}
	url := ""
	if s.instanceURL != "" && sysID != "" {
		url = strings.TrimRight(s.instanceURL, "/") + "/nav_to.do?uri=incident.do?sys_id=" + sysID
	}
	return num, url, nil
}

func (s *ServiceNow) createIncident(a models.Alert) (string, string, error) {
	impact, urgency := severityToImpactUrgency(a.Severity)
	payload := map[string]string{
		"short_description": fmt.Sprintf("[%s] %s", strings.ToUpper(a.Severity), a.Summary),
		"description":       incidentBody(a),
		"impact":            impact,
		"urgency":           urgency,
		"category":          "network",
		"caller_id":         s.user,
	}
	if a.DeviceID != "" {
		payload["cmdb_ci"] = a.DeviceID // best-effort CI match by name/id
	}
	if s.assignmentGroup != "" {
		payload["assignment_group"] = s.assignmentGroup
	}
	buf, _ := json.Marshal(payload)

	url := s.instanceURL + "/api/now/table/incident"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(s.user, s.password)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("servicenow returned %d", resp.StatusCode)
	}
	var out struct {
		Result struct {
			Number string `json:"number"`
			SysID  string `json:"sys_id"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", err
	}
	num := out.Result.Number
	if num == "" {
		num = out.Result.SysID
	}
	return num, out.Result.SysID, nil
}

// resolveIncident PATCHes an incident to the Resolved state with close notes.
func (s *ServiceNow) resolveIncident(sysID string) error {
	payload := map[string]string{
		"state":       "6", // Resolved
		"close_code":  "Resolved by caller",
		"close_notes": "Auto-resolved by Correlix: the underlying alert cleared.",
		"work_notes":  "Alert cleared; incident auto-resolved by Correlix.",
	}
	buf, _ := json.Marshal(payload)
	url := s.instanceURL + "/api/now/table/incident/" + sysID
	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(s.user, s.password)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("servicenow resolve returned %d", resp.StatusCode)
	}
	return nil
}

// severityToImpactUrgency maps the NetOps ladder onto ServiceNow's 1(high)..3(low).
func severityToImpactUrgency(sev string) (impact, urgency string) {
	switch severityRank(sev) {
	case 5: // critical
		return "1", "1"
	case 4: // error
		return "2", "1"
	case 3: // warning
		return "2", "2"
	default:
		return "3", "3"
	}
}

// State persistence (dedup map, F-62/F-78 write-failure accounting) lives in
// the shared ticketCore — see ticket_state.go.

func incidentBody(a models.Alert) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Alert: %s\nSeverity: %s\n", a.Rule, a.Severity)
	if a.DeviceID != "" {
		fmt.Fprintf(&b, "Device: %s\n", a.DeviceID)
	}
	if a.Summary != "" {
		fmt.Fprintf(&b, "Summary: %s\n", a.Summary)
	}
	if a.Description != "" {
		fmt.Fprintf(&b, "\n%s\n", a.Description)
	}
	if !a.FiredAt.IsZero() {
		fmt.Fprintf(&b, "\nFired at: %s\n", a.FiredAt.Format(time.RFC3339))
	}
	fmt.Fprint(&b, "\nOpened automatically by Correlix.")
	return b.String()
}
