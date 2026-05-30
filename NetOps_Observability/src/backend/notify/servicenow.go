package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"netops/backend/models"
)

// ServiceNow opens an ITSM incident (ticket) when a CRITICAL alert fires.
//
// It is a notify.Channel like the others, but self-filters to critical severity
// so only real, page-worthy alerts cut a ticket. A small in-memory dedup set
// keyed by alert fingerprint (rule+device) prevents a flapping alert from
// spawning duplicate incidents within the process lifetime; cleared when the
// alert resolves (Dispatch is called again with ResolvedAt set — see engine).
//
// Auth is HTTP Basic against the ServiceNow Table API; swap for OAuth by
// replacing setAuth. Configure via FEATURE_SERVICENOW_NOTIFICATIONS=true +
// SERVICENOW_INSTANCE_URL + SERVICENOW_USER + SERVICENOW_PASSWORD.
type ServiceNow struct {
	instanceURL string // e.g. https://dev12345.service-now.com
	user        string
	password    string
	client      *http.Client

	mu   sync.Mutex
	open map[string]string // fingerprint -> incident number/sys_id
}

func NewServiceNow(instanceURL, user, password string) *ServiceNow {
	return &ServiceNow{
		instanceURL: strings.TrimRight(instanceURL, "/"),
		user:        user,
		password:    password,
		client:      &http.Client{Timeout: 15 * time.Second},
		open:        make(map[string]string),
	}
}

func (s *ServiceNow) Name() string { return "servicenow" }

// isCritical reports whether an alert is severe enough to warrant a ticket.
func isCritical(sev string) bool {
	return strings.EqualFold(strings.TrimSpace(sev), "critical")
}

func fingerprint(a models.Alert) string {
	if a.ID != "" {
		return a.ID
	}
	return a.Rule + "|" + a.DeviceID
}

func (s *ServiceNow) Send(a models.Alert) error {
	// Only critical alerts cut a ticket.
	if !isCritical(a.Severity) {
		return nil
	}
	if s.instanceURL == "" {
		return errors.New("servicenow instance url not configured")
	}
	fp := fingerprint(a)

	// Resolution event: close-out is a follow-up; for now just forget the
	// fingerprint so a genuine re-fire can open a fresh ticket.
	if a.ResolvedAt != nil {
		s.mu.Lock()
		delete(s.open, fp)
		s.mu.Unlock()
		return nil
	}

	// Dedup: skip if this alert already has an open ticket this process.
	s.mu.Lock()
	if _, exists := s.open[fp]; exists {
		s.mu.Unlock()
		return nil
	}
	// Reserve the slot before the network call so concurrent dispatches don't race.
	s.open[fp] = "pending"
	s.mu.Unlock()

	num, err := s.createIncident(a)
	if err != nil {
		// Roll back the reservation so a later retry can succeed.
		s.mu.Lock()
		delete(s.open, fp)
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	s.open[fp] = num
	s.mu.Unlock()
	return nil
}

// createIncident POSTs to the ServiceNow Table API and returns the incident
// number on success.
func (s *ServiceNow) createIncident(a models.Alert) (string, error) {
	// Critical → impact/urgency 1 (= priority 1 / Critical in ServiceNow).
	payload := map[string]string{
		"short_description": fmt.Sprintf("[%s] %s", strings.ToUpper(a.Severity), a.Summary),
		"description":       incidentBody(a),
		"impact":            "1",
		"urgency":           "1",
		"category":          "network",
		"caller_id":         s.user,
	}
	if a.DeviceID != "" {
		payload["cmdb_ci"] = a.DeviceID // best-effort CI match by name/id
	}
	buf, _ := json.Marshal(payload)

	url := s.instanceURL + "/api/now/table/incident"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(s.user, s.password)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("servicenow returned %d", resp.StatusCode)
	}
	var out struct {
		Result struct {
			Number string `json:"number"`
			SysID  string `json:"sys_id"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	num := out.Result.Number
	if num == "" {
		num = out.Result.SysID
	}
	return num, nil
}

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
	fmt.Fprint(&b, "\nOpened automatically by NetOps/Netra.")
	return b.String()
}
