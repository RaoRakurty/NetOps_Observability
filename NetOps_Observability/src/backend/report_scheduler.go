package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/alerts"
	"netops/backend/models"
	"netops/backend/notify"
)

// handleReportRuns: GET /api/reports/runs — run-state map keyed by report id,
// so the Reports UI can show last/next delivery and status alongside each
// saved report object (listed via /api/saved?type=report).
func (s *server) handleReportRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.reports.Runs())
}

// handleReportRunNow: POST /api/reports/run {"id":"..."} — deliver a report
// immediately and reschedule its next automatic run. Powers "Send now".
func (s *server) handleReportRunNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.ID) == "" {
		writeError(w, http.StatusBadRequest, errors.New("id required"))
		return
	}
	run, err := s.reports.RunNow(strings.TrimSpace(req.ID))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// Report scheduler — the server-side half of Phase 5.
//
// A report is a SavedObject of type "report" whose opaque body the frontend
// owns; the scheduler only reads the few fields it needs (reportSpec). On a
// cadence it renders a point-in-time summary from in-memory state (active
// alerts, device inventory, stack health) and delivers it through the same
// notify.Dispatcher the alert engine uses — so reports reach Slack/email/
// PagerDuty with zero new transport code.
//
// Run-state (last/next fire, status) is kept OUT of the saved object so the
// frontend stays the sole owner of the body. It is file-backed alongside the
// saved store (data/report_runs.json) so cadence survives restarts.

// reportSpec is the slice of a report's JSON body the scheduler reads. The
// frontend may carry additional fields freely; unknown keys are ignored.
type reportSpec struct {
	Kind            string `json:"kind"`             // alerts_summary | device_inventory | health_summary
	IntervalMinutes int    `json:"interval_minutes"` // cadence; <=0 disables scheduling
	Severity        string `json:"severity"`         // severity stamped on the delivered message
	Enabled         bool   `json:"enabled"`
	Description     string `json:"description"`
}

// reportRun records the scheduler's per-report state.
type reportRun struct {
	LastRun time.Time `json:"last_run,omitempty"`
	NextRun time.Time `json:"next_run,omitempty"`
	Status  string    `json:"status,omitempty"` // ok | error | skipped
	Detail  string    `json:"detail,omitempty"`
}

type reportScheduler struct {
	saved     *savedStore
	notifier  *notify.Dispatcher
	discovery *DiscoveryAggregator
	alerts    *alerts.Engine
	startedAt time.Time

	mu   sync.Mutex
	runs map[string]reportRun
	path string
}

func newReportScheduler(s *server, path string) *reportScheduler {
	if path == "" {
		path = "/data/report_runs.json"
	}
	rs := &reportScheduler{
		saved:     s.saved,
		notifier:  s.notifier,
		discovery: s.discovery,
		alerts:    s.alerts,
		startedAt: s.startedAt,
		runs:      make(map[string]reportRun),
		path:      path,
	}
	rs.load()
	return rs
}

// Start ticks the scheduler once a minute until ctx is cancelled.
func (rs *reportScheduler) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		rs.tick() // evaluate once on boot so newly-due reports don't wait a minute
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				rs.tick()
			}
		}
	}()
}

// tick fires every report whose NextRun has arrived.
func (rs *reportScheduler) tick() {
	now := time.Now().UTC()
	for _, o := range rs.saved.List("report") {
		spec, err := parseReportSpec(o.Body)
		if err != nil || !spec.Enabled || spec.IntervalMinutes <= 0 {
			continue
		}
		rs.mu.Lock()
		run, seen := rs.runs[o.ID]
		if !seen || run.NextRun.IsZero() {
			// First sight: schedule the first delivery one interval out
			// rather than firing immediately on every restart.
			run.NextRun = now.Add(time.Duration(spec.IntervalMinutes) * time.Minute)
			rs.runs[o.ID] = run
			rs.flushLocked()
			rs.mu.Unlock()
			continue
		}
		due := !run.NextRun.After(now)
		rs.mu.Unlock()
		if due {
			rs.deliver(o, spec, now)
		}
	}
	rs.gc()
}

// RunNow delivers a report immediately, ignoring its schedule, and reschedules
// the next automatic delivery from now. Powers the UI's "Send now".
func (rs *reportScheduler) RunNow(id string) (reportRun, error) {
	o, ok := rs.saved.Get(id)
	if !ok || o.Type != "report" {
		return reportRun{}, errors.New("report not found")
	}
	spec, err := parseReportSpec(o.Body)
	if err != nil {
		return reportRun{}, fmt.Errorf("invalid report body: %w", err)
	}
	rs.deliver(o, spec, time.Now().UTC())
	return rs.Run(id), nil
}

// deliver renders and dispatches a report, then records the outcome.
func (rs *reportScheduler) deliver(o SavedObject, spec reportSpec, now time.Time) {
	msg := rs.render(o, spec, now)
	rs.notifier.Dispatch(msg)
	log.Printf("report %q (%s) delivered", o.Name, o.ID)

	rs.mu.Lock()
	defer rs.mu.Unlock()
	run := rs.runs[o.ID]
	run.LastRun = now
	if spec.IntervalMinutes > 0 {
		run.NextRun = now.Add(time.Duration(spec.IntervalMinutes) * time.Minute)
	}
	run.Status = "ok"
	run.Detail = msg.Summary
	rs.runs[o.ID] = run
	rs.flushLocked()
}

// render builds the models.Alert carrying the report content. Reusing the
// alert shape lets every existing notify channel format it unchanged.
func (rs *reportScheduler) render(o SavedObject, spec reportSpec, now time.Time) models.Alert {
	sev := strings.ToLower(strings.TrimSpace(spec.Severity))
	if sev == "" {
		sev = "info"
	}
	var summary, body string
	switch spec.Kind {
	case "device_inventory":
		summary, body = rs.renderDevices()
	case "health_summary":
		summary, body = rs.renderHealth(now)
	default: // alerts_summary
		summary, body = rs.renderAlerts()
	}
	header := "Report: " + o.Name
	if spec.Description != "" {
		body = spec.Description + "\n\n" + body
	}
	return models.Alert{
		ID:          "report-" + o.ID,
		Rule:        "report",
		Severity:    sev,
		Summary:     header + " — " + summary,
		Description: body,
		Labels:      map[string]string{"report_id": o.ID, "kind": firstNonEmpty(spec.Kind, "alerts_summary")},
		FiredAt:     now,
	}
}

func (rs *reportScheduler) renderAlerts() (string, string) {
	active := rs.alerts.Active()
	bySev := map[string]int{}
	for _, a := range active {
		bySev[strings.ToLower(a.Severity)]++
	}
	summary := fmt.Sprintf("%d active alert(s)", len(active))
	var b strings.Builder
	if len(active) == 0 {
		b.WriteString("No active alerts. ✅\n")
	} else {
		for _, sev := range []string{"critical", "error", "warning", "notice", "info"} {
			if n := bySev[sev]; n > 0 {
				fmt.Fprintf(&b, "%s: %d\n", sev, n)
			}
		}
		b.WriteString("\nMost recent:\n")
		// Newest first, cap the list so notifications stay readable.
		sort.Slice(active, func(i, j int) bool { return active[i].FiredAt.After(active[j].FiredAt) })
		for i, a := range active {
			if i >= 10 {
				fmt.Fprintf(&b, "…and %d more\n", len(active)-10)
				break
			}
			fmt.Fprintf(&b, "• [%s] %s\n", a.Severity, a.Summary)
		}
	}
	return summary, b.String()
}

func (rs *reportScheduler) renderDevices() (string, string) {
	devs := rs.discovery.Devices()
	summary := fmt.Sprintf("%d device(s) discovered", len(devs))
	var b strings.Builder
	for i, d := range devs {
		m := toMap(d)
		if i >= 25 {
			fmt.Fprintf(&b, "…and %d more\n", len(devs)-25)
			break
		}
		name := firstNonEmpty(str(m["name"]), str(m["id"]))
		fmt.Fprintf(&b, "• %s  %s\n", name, str(m["address"]))
	}
	if len(devs) == 0 {
		b.WriteString("No devices discovered.\n")
	}
	return summary, b.String()
}

func (rs *reportScheduler) renderHealth(now time.Time) (string, string) {
	uptime := now.Sub(rs.startedAt).Round(time.Second)
	devs := len(rs.discovery.Devices())
	active := len(rs.alerts.Active())
	summary := fmt.Sprintf("uptime %s · %d devices · %d active alerts", uptime, devs, active)
	b := fmt.Sprintf("API uptime: %s\nDevices discovered: %d\nActive alerts: %d\n", uptime, devs, active)
	return summary, b
}

// Run returns the recorded run-state for a report (zero value if none yet).
func (rs *reportScheduler) Run(id string) reportRun {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.runs[id]
}

// Runs returns a copy of all recorded run-states keyed by report id.
func (rs *reportScheduler) Runs() map[string]reportRun {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := make(map[string]reportRun, len(rs.runs))
	for k, v := range rs.runs {
		out[k] = v
	}
	return out
}

// gc drops run-state for reports that no longer exist.
func (rs *reportScheduler) gc() {
	live := map[string]bool{}
	for _, o := range rs.saved.List("report") {
		live[o.ID] = true
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	changed := false
	for id := range rs.runs {
		if !live[id] {
			delete(rs.runs, id)
			changed = true
		}
	}
	if changed {
		rs.flushLocked()
	}
}

func parseReportSpec(body json.RawMessage) (reportSpec, error) {
	var spec reportSpec
	if len(body) == 0 {
		return spec, errors.New("empty body")
	}
	err := json.Unmarshal(body, &spec)
	return spec, err
}

func (rs *reportScheduler) load() {
	b, err := os.ReadFile(rs.path)
	if err != nil {
		return // no prior state is fine
	}
	var m map[string]reportRun
	if err := json.Unmarshal(b, &m); err == nil && m != nil {
		rs.runs = m
	}
}

// flushLocked persists run-state; callers must hold rs.mu.
func (rs *reportScheduler) flushLocked() {
	if err := os.MkdirAll(filepath.Dir(rs.path), 0o755); err != nil {
		log.Printf("report runs mkdir: %v", err)
		return
	}
	b, err := json.MarshalIndent(rs.runs, "", "  ")
	if err != nil {
		return
	}
	tmp := rs.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("report runs write: %v", err)
		return
	}
	if err := os.Rename(tmp, rs.path); err != nil {
		log.Printf("report runs rename: %v", err)
	}
}
