package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netops/backend/alerts"
	"netops/backend/models"
	"netops/backend/notify"
	"netops/backend/reports"
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
	// Under the async backend, derive last/next/status from the execution history
	// (scoped to the caller's tenant); the file backend uses the in-memory map.
	if s.reportPipeline != nil {
		claims, ok := s.requirePerm(w, r, "reports", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		writeJSON(w, http.StatusOK, s.reportPipeline.runsFromExecutions(r.Context(), tenant, cross))
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
	if _, ok := s.requirePerm(w, r, "reports", LevelWrite); !ok {
		return
	}
	var req struct {
		ID       string   `json:"id"`
		Channels []string `json:"channels,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.ID) == "" {
		writeError(w, http.StatusBadRequest, errors.New("id required"))
		return
	}
	id := strings.TrimSpace(req.ID)

	// Async path (Postgres): enqueue a job and return immediately — no blocking
	// render/SMTP in the request. The worker pool delivers and records the
	// execution; the client polls /api/reports/executions/{id} for progress.
	if s.reportPipeline != nil {
		o, ok := s.saved.Get(id)
		if !ok || o.Type != "report" {
			writeError(w, http.StatusNotFound, errors.New("report not found"))
			return
		}
		execID, err := s.reportPipeline.EnqueueNow(r.Context(), o)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{
			"execution_id": execID,
			"status":       "queued",
			// "run" keeps the legacy shape so the existing UI still updates.
			"run": reportRun{Status: "queued", Detail: "queued for async delivery"},
		})
		return
	}

	// Synchronous fallback (file backend).
	run, err := s.reports.RunNow(id, req.Channels)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// handleReportChannels: GET /api/reports/channels — the notify channels actually
// configured, so the "Send now" UI offers only real delivery destinations.
func (s *server) handleReportChannels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.notifier.Names())
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
	// Kind selects the renderer. Operational: alerts_summary | device_inventory |
	// health_summary. Executive (added for the exec reporting backlog, modelled
	// on Datadog/Zabbix scheduled reports): wan_utilization | security_threats |
	// device_utilization | latency_jitter_sla.
	Kind            string `json:"kind"`
	IntervalMinutes int    `json:"interval_minutes"` // cadence; <=0 disables scheduling
	Severity        string `json:"severity"`         // severity stamped on the delivered message
	Enabled         bool   `json:"enabled"`
	Description     string `json:"description"`
	// Channels optionally restricts delivery to named notify channels (email,
	// slack, pagerduty, sns, twilio…). Empty => all configured channels. Used by
	// scheduled runs and as the default for "Send now".
	Channels []string `json:"channels,omitempty"`
	// ContactPoints lists reusable contact-point ids (contactpoints.go) this
	// report is delivered to — the modern recipient model. Email-type points are
	// resolved to addresses and emailed directly (in the report's tenant scope);
	// independent of Channels (which still drives slack/pagerduty/etc.).
	ContactPoints []string `json:"contact_points,omitempty"`
	// DeliveryMode selects how contact-point delivery carries the report:
	// "body" (default) emails the rendered report; "link" emails a secure link
	// (Phase 3). Unknown/empty => body.
	DeliveryMode string `json:"delivery_mode,omitempty"`
	// Schedule is the calendar+timezone recurrence used by the async pipeline
	// (PG backend). When set and valid it supersedes IntervalMinutes; when absent
	// the pipeline falls back to IntervalMinutes (rolling cadence) for back-compat.
	Schedule *reports.Recurrence `json:"schedule,omitempty"`
	// Formats lists the output formats to render (html, xlsx, pdf). Empty => html.
	// HTML is always produced (the email body); extras are stored + attached.
	Formats []string `json:"formats,omitempty"`
}

const (
	deliverBody = "body"
	deliverLink = "link"
)

// reportRun records the scheduler's per-report state.
type reportRun struct {
	LastRun time.Time `json:"last_run,omitempty"`
	NextRun time.Time `json:"next_run,omitempty"`
	Status  string    `json:"status,omitempty"` // ok | error | skipped
	Detail  string    `json:"detail,omitempty"`
}

type reportScheduler struct {
	srv       *server // for lazily-constructed deps (notifyCfg, contactPoints)
	saved     savedRepo
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
		srv:       s,
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
	for _, o := range rs.saved.List("report", "", true) {
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
// the next automatic delivery from now. Powers the UI's "Send now". channels
// optionally restricts delivery to specific notify channels for this one send
// (nil/empty => the report's configured channels, falling back to all).
func (rs *reportScheduler) RunNow(id string, channels []string) (reportRun, error) {
	o, ok := rs.saved.Get(id)
	if !ok || o.Type != "report" {
		return reportRun{}, errors.New("report not found")
	}
	spec, err := parseReportSpec(o.Body)
	if err != nil {
		return reportRun{}, fmt.Errorf("invalid report body: %w", err)
	}
	if len(channels) > 0 {
		spec.Channels = channels // one-off override for this manual send
	}
	rs.deliver(o, spec, time.Now().UTC())
	return rs.Run(id), nil
}

// deliver renders and dispatches a report, then records the outcome. Delivery
// honours spec.Channels (empty => all configured channels).
func (rs *reportScheduler) deliver(o SavedObject, spec reportSpec, now time.Time) {
	msg := rs.render(o, spec, now)
	sent := rs.notifier.DispatchTo(msg, spec.Channels)

	// Contact-point delivery (the modern recipient model). Resolve the report's
	// email-type contact points in the report's own tenant scope, then email the
	// report to those addresses directly via the configured SMTP transport —
	// independent of the named-channel routing above.
	cpRecipients, cpNote := rs.deliverToContactPoints(msg, o, spec)
	log.Printf("report %q (%s) delivered to %d channel(s), %d contact-point recipient(s)",
		o.Name, o.ID, sent, cpRecipients)

	rs.mu.Lock()
	defer rs.mu.Unlock()
	run := rs.runs[o.ID]
	run.LastRun = now
	if spec.IntervalMinutes > 0 {
		run.NextRun = now.Add(time.Duration(spec.IntervalMinutes) * time.Minute)
	}
	run.Status = "ok"
	detail := fmt.Sprintf("%s — sent to %d channel(s)", msg.Summary, sent)
	if len(spec.Channels) > 0 {
		detail += ": " + strings.Join(spec.Channels, ", ")
	}
	if cpNote != "" {
		detail += "; " + cpNote
	}
	run.Detail = detail
	rs.runs[o.ID] = run
	rs.flushLocked()
}

// deliverToContactPoints resolves the report's email contact points (tenant-
// scoped) and emails the report to them. Returns the recipient count and a short
// status note for the run detail. No-op (0, "") when the report has no contact
// points. "link" delivery is Phase 3 — until then it is recorded as pending and
// the report body is NOT emailed (so tenant data isn't leaked while the secure
// link is unbuilt).
func (rs *reportScheduler) deliverToContactPoints(msg models.Alert, o SavedObject, spec reportSpec) (int, string) {
	if len(spec.ContactPoints) == 0 || rs.srv == nil || rs.srv.contactPoints == nil || rs.srv.notifyCfg == nil {
		return 0, ""
	}
	t := normTenant(o.TenantID)
	cross := t == "" || t == TenantGlobal
	recipients := rs.srv.contactPoints.resolveEmailRecipients(spec.ContactPoints, t, cross)
	if len(recipients) == 0 {
		return 0, "contact points resolved to no email recipients"
	}
	if strings.EqualFold(spec.DeliveryMode, deliverLink) {
		// Phase 3 builds the signed report-view link; until then do not email the
		// report body in link mode.
		return 0, fmt.Sprintf("secure-link delivery to %d recipient(s) pending (phase 3)", len(recipients))
	}
	sender, ok := rs.srv.notifyCfg.emailSenderTo(recipients)
	if !ok {
		return 0, "SMTP not configured — contact-point email skipped"
	}
	if err := sender.Send(msg); err != nil {
		log.Printf("report %q contact-point email: %v", o.Name, err)
		return 0, fmt.Sprintf("contact-point email failed: %v", err)
	}
	return len(recipients), fmt.Sprintf("emailed to %d contact-point recipient(s)", len(recipients))
}

// render builds the models.Alert carrying the report content. Reusing the
// alert shape lets every existing notify channel format it unchanged.
func (rs *reportScheduler) render(o SavedObject, spec reportSpec, now time.Time) models.Alert {
	sev := strings.ToLower(strings.TrimSpace(spec.Severity))
	if sev == "" {
		sev = "info"
	}
	// Per-tenant reports: a report owned by a tenant reflects only that tenant's
	// devices/alerts; a global/unassigned report is platform-wide.
	tenant := o.TenantID
	var summary, body string
	switch spec.Kind {
	case "device_inventory":
		summary, body = rs.renderDevices(tenant)
	case "health_summary":
		summary, body = rs.renderHealth(now, tenant)
	case "wan_utilization":
		summary, body = rs.renderWANUtilization()
	case "security_threats":
		summary, body = rs.renderSecurityThreats()
	case "device_utilization":
		summary, body = rs.renderDeviceUtilization()
	case "latency_jitter_sla":
		summary, body = rs.renderLatencyJitterSLA()
	default: // alerts_summary
		summary, body = rs.renderAlerts(tenant)
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

// buildViewModel is the "Build Dataset" stage: it gathers a report's data once
// into a render-neutral, structured reports.ViewModel that every renderer (HTML,
// Excel, PDF) consumes. Tabular kinds populate Section.Header+Rows (real tables,
// so Excel exports cells, not a text blob); narrative kinds fall back to a Note.
func (rs *reportScheduler) buildViewModel(o SavedObject, spec reportSpec, now time.Time) reports.ViewModel {
	sev := strings.ToLower(strings.TrimSpace(spec.Severity))
	if sev == "" {
		sev = "info"
	}
	tenant := o.TenantID
	var summary string
	var sections []reports.Section
	switch spec.Kind {
	case "device_inventory":
		summary, sections = rs.datasetDevices(tenant)
	case "health_summary":
		summary, sections = rs.datasetHealth(now, tenant)
	case "wan_utilization":
		summary, sections = rs.datasetWAN()
	case "security_threats":
		summary, sections = rs.datasetSecurity()
	case "device_utilization":
		summary, sections = rs.datasetDeviceUtil()
	case "latency_jitter_sla":
		summary, sections = rs.datasetLatency()
	default:
		summary, sections = rs.datasetAlerts(tenant)
	}
	return reports.ViewModel{
		ReportID:    o.ID,
		ReportName:  o.Name,
		Kind:        firstNonEmpty(spec.Kind, "alerts_summary"),
		TenantID:    tenant,
		GeneratedAt: now,
		Severity:    sev,
		Description: spec.Description,
		Summary:     summary,
		Sections:    sections,
	}
}

// alertFromViewModel renders the structured ViewModel down to the models.Alert
// shape the notify channels (slack/pagerduty/...) consume, so named-channel
// delivery keeps working from the same dataset.
func alertFromViewModel(vm reports.ViewModel, now time.Time) models.Alert {
	var b strings.Builder
	if vm.Description != "" {
		b.WriteString(vm.Description + "\n\n")
	}
	for _, s := range vm.Sections {
		b.WriteString(s.Title + "\n")
		if s.Note != "" {
			b.WriteString(s.Note + "\n")
		}
		for _, row := range s.Rows {
			b.WriteString("  " + strings.Join(row, "  ") + "\n")
		}
		b.WriteString("\n")
	}
	return models.Alert{
		ID:          "report-" + vm.ReportID,
		Rule:        "report",
		Severity:    firstNonEmpty(vm.Severity, "info"),
		Summary:     "Report: " + vm.ReportName + " — " + vm.Summary,
		Description: strings.TrimSpace(b.String()),
		Labels:      map[string]string{"report_id": vm.ReportID, "kind": vm.Kind},
		FiredAt:     now,
	}
}

func (rs *reportScheduler) datasetAlerts(tenant string) (string, []reports.Section) {
	active := rs.tenantAlerts(tenant)
	bySev := map[string]int{}
	for _, a := range active {
		bySev[strings.ToLower(a.Severity)]++
	}
	summary := fmt.Sprintf("%d active alert(s)", len(active))
	if len(active) == 0 {
		return summary, []reports.Section{{Title: "Active alerts", Note: "No active alerts."}}
	}
	var sevRows [][]string
	for _, s := range []string{"critical", "error", "warning", "notice", "info"} {
		if n := bySev[s]; n > 0 {
			sevRows = append(sevRows, []string{s, strconv.Itoa(n)})
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i].FiredAt.After(active[j].FiredAt) })
	var recent [][]string
	for i, a := range active {
		if i >= 25 {
			break
		}
		recent = append(recent, []string{a.Severity, a.Summary})
	}
	return summary, []reports.Section{
		{Title: "By severity", Header: []string{"Severity", "Count"}, Rows: sevRows},
		{Title: "Most recent", Header: []string{"Severity", "Alert"}, Rows: recent},
	}
}

func (rs *reportScheduler) datasetDevices(tenant string) (string, []reports.Section) {
	devs := rs.tenantDevices(tenant)
	summary := fmt.Sprintf("%d device(s) discovered", len(devs))
	if len(devs) == 0 {
		return summary, []reports.Section{{Title: "Devices", Note: "No devices discovered."}}
	}
	var rows [][]string
	for _, d := range devs {
		m := toMap(d)
		name := firstNonEmpty(str(m["name"]), str(m["id"]))
		rows = append(rows, []string{name, str(m["address"]), str(m["vendor"])})
	}
	return summary, []reports.Section{{Title: "Devices", Header: []string{"Name", "Address", "Vendor"}, Rows: rows}}
}

func (rs *reportScheduler) datasetHealth(now time.Time, tenant string) (string, []reports.Section) {
	uptime := now.Sub(rs.startedAt).Round(time.Second)
	devs := len(rs.tenantDevices(tenant))
	active := len(rs.tenantAlerts(tenant))
	rows := [][]string{
		{"API uptime", uptime.String()},
		{"Devices discovered", strconv.Itoa(devs)},
		{"Active alerts", strconv.Itoa(active)},
	}
	return fmt.Sprintf("uptime %s · %d devices · %d active alerts", uptime, devs, active),
		[]reports.Section{{Title: "Stack health", Header: []string{"Metric", "Value"}, Rows: rows}}
}

func (rs *reportScheduler) datasetWAN() (string, []reports.Section) {
	rows := chQuery(`
SELECT local_device, remote_device, type, status,
       round(loss_pct,2), round(qoe,2)
  FROM netops.tunnels
 ORDER BY ts DESC
 LIMIT 1 BY id
 FORMAT TSV`)
	if len(rows) == 0 {
		return "no WAN/overlay links reporting", []reports.Section{{Title: "WAN / overlay links", Note: "No tunnel/overlay telemetry yet."}}
	}
	up := 0
	var data [][]string
	for _, r := range rows {
		c := strings.Split(r, "\t")
		if len(c) < 6 {
			continue
		}
		if c[3] == "up" {
			up++
		}
		data = append(data, []string{c[0] + "↔" + c[1], c[2], c[3], c[4] + "%", c[5]})
	}
	return fmt.Sprintf("%d WAN/overlay link(s), %d up", len(rows), up),
		[]reports.Section{{Title: "WAN / overlay links", Header: []string{"Link", "Type", "Status", "Loss", "QoE"}, Rows: data}}
}

func (rs *reportScheduler) datasetSecurity() (string, []reports.Section) {
	sev := chQuery(`
SELECT severity, count()
  FROM netops.findings
 WHERE ts >= now() - INTERVAL 24 HOUR
 GROUP BY severity
 ORDER BY count() DESC
 FORMAT TSV`)
	recent := chQuery(`
SELECT severity, device, summary
  FROM netops.findings
 WHERE ts >= now() - INTERVAL 24 HOUR
 ORDER BY ts DESC
 LIMIT 10
 FORMAT TSV`)
	var secs []reports.Section
	total := 0
	if len(sev) == 0 {
		secs = append(secs, reports.Section{Title: "Findings (24h)", Note: "No findings in the last 24h."})
	} else {
		var sevRows [][]string
		for _, r := range sev {
			c := strings.Split(r, "\t")
			if len(c) == 2 {
				sevRows = append(sevRows, []string{c[0], c[1]})
				total += atoiSafe(c[1])
			}
		}
		secs = append(secs, reports.Section{Title: "By severity (24h)", Header: []string{"Severity", "Count"}, Rows: sevRows})
	}
	if len(recent) > 0 {
		var rows [][]string
		for _, r := range recent {
			c := strings.Split(r, "\t")
			if len(c) >= 3 {
				rows = append(rows, []string{c[0], c[1], c[2]})
			}
		}
		secs = append(secs, reports.Section{Title: "Recent findings", Header: []string{"Severity", "Device", "Summary"}, Rows: rows})
	}
	crit := 0
	for _, a := range rs.alerts.Active() {
		if strings.EqualFold(a.Severity, "critical") {
			crit++
		}
	}
	secs = append(secs, reports.Section{Title: "Critical active alerts", Note: strconv.Itoa(crit)})
	return fmt.Sprintf("%d finding(s)/24h · %d critical alert(s)", total, crit), secs
}

func (rs *reportScheduler) datasetDeviceUtil() (string, []reports.Section) {
	cpu := vmTopk(`topk(10, device_cpu_percent)`, "%")
	mem := vmTopk(`topk(10, device_mem_percent)`, "%")
	if len(cpu) == 0 && len(mem) == 0 {
		return "no device utilisation metrics", []reports.Section{{Title: "Device utilisation", Note: "No CPU/memory metrics reporting yet."}}
	}
	var secs []reports.Section
	if len(cpu) > 0 {
		secs = append(secs, reports.Section{Title: "Top CPU", Note: strings.Join(cpu, "\n")})
	}
	if len(mem) > 0 {
		secs = append(secs, reports.Section{Title: "Top memory", Note: strings.Join(mem, "\n")})
	}
	return fmt.Sprintf("%d device(s) by CPU, %d by memory", len(cpu), len(mem)), secs
}

func (rs *reportScheduler) datasetLatency() (string, []reports.Section) {
	summary, body := rs.renderLatencyJitterSLA()
	return summary, []reports.Section{{Title: "Latency, jitter & SLA", Note: body}}
}

// tenantDevices returns the devices a report for the given tenant should cover:
// a global/unassigned report sees the whole fleet, a tenant report only its own.
func (rs *reportScheduler) tenantDevices(tenant string) []models.Device {
	all := rs.discovery.Devices()
	t := strings.ToLower(strings.TrimSpace(tenant))
	if t == "" || t == TenantGlobal {
		return all
	}
	out := make([]models.Device, 0, len(all))
	for _, d := range all {
		if canSeeDevice(d, t, false) {
			out = append(out, d)
		}
	}
	return out
}

// tenantAlerts returns the active alerts visible to the report's tenant (alerts
// on its devices, plus device-less stack alerts).
func (rs *reportScheduler) tenantAlerts(tenant string) []models.Alert {
	active := rs.alerts.Active()
	t := strings.ToLower(strings.TrimSpace(tenant))
	if t == "" || t == TenantGlobal {
		return active
	}
	ids := map[string]bool{}
	for _, d := range rs.tenantDevices(t) {
		ids[d.ID] = true
	}
	out := make([]models.Alert, 0, len(active))
	for _, a := range active {
		if a.DeviceID == "" || ids[a.DeviceID] {
			out = append(out, a)
		}
	}
	return out
}

func (rs *reportScheduler) renderAlerts(tenant string) (string, string) {
	active := rs.tenantAlerts(tenant)
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

func (rs *reportScheduler) renderDevices(tenant string) (string, string) {
	devs := rs.tenantDevices(tenant)
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

func (rs *reportScheduler) renderHealth(now time.Time, tenant string) (string, string) {
	uptime := now.Sub(rs.startedAt).Round(time.Second)
	devs := len(rs.tenantDevices(tenant))
	active := len(rs.tenantAlerts(tenant))
	summary := fmt.Sprintf("uptime %s · %d devices · %d active alerts", uptime, devs, active)
	b := fmt.Sprintf("API uptime: %s\nDevices discovered: %d\nActive alerts: %d\n", uptime, devs, active)
	return summary, b
}

// ---- Executive reports -----------------------------------------------------
//
// These read point-in-time analytics the stack already collects: tunnel/overlay
// telemetry and findings from ClickHouse (netops.tunnels, netops.findings) and
// device resource metrics from VictoriaMetrics. Each renderer degrades to a
// clear "no data" line if its backend is empty/unreachable, so a report never
// fails — it reports the gap, mirroring how Datadog/Zabbix scheduled summaries
// behave.

// renderWANUtilization summarises per-WAN/overlay link load + health from the
// tunnels telemetry (status, loss, qoe) — the closest the stack has to circuit
// utilisation until per-circuit bandwidth counters land.
func (rs *reportScheduler) renderWANUtilization() (string, string) {
	rows := chQuery(`
SELECT local_device, remote_device, type, status,
       round(loss_pct,2), round(qoe,2)
  FROM netops.tunnels
 ORDER BY ts DESC
 LIMIT 1 BY id
 FORMAT TSV`)
	if len(rows) == 0 {
		return "no WAN/overlay links reporting", "No tunnel/overlay telemetry yet.\n"
	}
	up := 0
	var b strings.Builder
	for i, r := range rows {
		c := strings.Split(r, "\t")
		if len(c) < 6 {
			continue
		}
		if c[3] == "up" {
			up++
		}
		if i < 25 {
			fmt.Fprintf(&b, "• %s↔%s [%s] %s — loss %s%%, QoE %s\n",
				c[0], c[1], c[2], c[3], c[4], c[5])
		}
	}
	if len(rows) > 25 {
		fmt.Fprintf(&b, "…and %d more\n", len(rows)-25)
	}
	summary := fmt.Sprintf("%d WAN/overlay link(s), %d up", len(rows), up)
	return summary, b.String()
}

// renderSecurityThreats rolls up correlation findings (severity breakdown +
// recent items) and critical active alerts — the executive "are we under
// threat" view.
func (rs *reportScheduler) renderSecurityThreats() (string, string) {
	sev := chQuery(`
SELECT severity, count()
  FROM netops.findings
 WHERE ts >= now() - INTERVAL 24 HOUR
 GROUP BY severity
 ORDER BY count() DESC
 FORMAT TSV`)
	recent := chQuery(`
SELECT severity, device, summary
  FROM netops.findings
 WHERE ts >= now() - INTERVAL 24 HOUR
 ORDER BY ts DESC
 LIMIT 10
 FORMAT TSV`)
	var b strings.Builder
	total := 0
	if len(sev) == 0 {
		b.WriteString("No findings in the last 24h.\n")
	} else {
		b.WriteString("By severity (24h):\n")
		for _, r := range sev {
			c := strings.Split(r, "\t")
			if len(c) == 2 {
				fmt.Fprintf(&b, "  %s: %s\n", c[0], c[1])
				total += atoiSafe(c[1])
			}
		}
	}
	if len(recent) > 0 {
		b.WriteString("\nRecent:\n")
		for _, r := range recent {
			c := strings.Split(r, "\t")
			if len(c) >= 3 {
				fmt.Fprintf(&b, "• [%s] %s — %s\n", c[0], c[1], c[2])
			}
		}
	}
	crit := 0
	for _, a := range rs.alerts.Active() {
		if strings.EqualFold(a.Severity, "critical") {
			crit++
		}
	}
	fmt.Fprintf(&b, "\nCritical active alerts: %d\n", crit)
	return fmt.Sprintf("%d finding(s)/24h · %d critical alert(s)", total, crit), b.String()
}

// renderDeviceUtilization lists the busiest devices by CPU and memory from the
// metrics VictoriaMetrics already stores (SNMP + gNMI collectors).
func (rs *reportScheduler) renderDeviceUtilization() (string, string) {
	cpu := vmTopk(`topk(10, device_cpu_percent)`, "%")
	mem := vmTopk(`topk(10, device_mem_percent)`, "%")
	if len(cpu) == 0 && len(mem) == 0 {
		return "no device utilisation metrics", "No CPU/memory metrics reporting yet.\n"
	}
	var b strings.Builder
	if len(cpu) > 0 {
		b.WriteString("Top CPU:\n")
		for _, l := range cpu {
			b.WriteString("  " + l + "\n")
		}
	}
	if len(mem) > 0 {
		b.WriteString("\nTop memory:\n")
		for _, l := range mem {
			b.WriteString("  " + l + "\n")
		}
	}
	return fmt.Sprintf("%d device(s) by CPU, %d by memory", len(cpu), len(mem)), b.String()
}

// renderLatencyJitterSLA reports per-link latency/jitter/loss and a simple SLA
// (% of links currently up) from the tunnels telemetry.
func (rs *reportScheduler) renderLatencyJitterSLA() (string, string) {
	rows := chQuery(`
SELECT local_device, remote_device, status,
       round(latency_ms,2), round(jitter_ms,2), round(loss_pct,2)
  FROM netops.tunnels
 ORDER BY ts DESC
 LIMIT 1 BY id
 FORMAT TSV`)
	if len(rows) == 0 {
		return "no latency/SLA telemetry", "No tunnel latency/jitter telemetry yet.\n"
	}
	up := 0
	var b strings.Builder
	for i, r := range rows {
		c := strings.Split(r, "\t")
		if len(c) < 6 {
			continue
		}
		if c[2] == "up" {
			up++
		}
		if i < 25 {
			fmt.Fprintf(&b, "• %s↔%s [%s] latency %sms, jitter %sms, loss %s%%\n",
				c[0], c[1], c[2], c[3], c[4], c[5])
		}
	}
	sla := 100.0
	if len(rows) > 0 {
		sla = float64(up) / float64(len(rows)) * 100
	}
	summary := fmt.Sprintf("%d link(s), %d up, SLA %.2f%%", len(rows), up, sla)
	fmt.Fprintf(&b, "\nAvailability SLA: %.2f%% (%d/%d up)\n", sla, up, len(rows))
	return summary, b.String()
}

// chQuery runs a read-only query against ClickHouse over HTTP and returns the
// non-empty result lines. Best-effort: any error yields nil so the caller emits
// a clean "no data" report rather than failing.
func chQuery(sql string) []string {
	base := envOr("CLICKHOUSE_URL", "http://clickhouse:8123")
	u, err := url.Parse(base)
	if err != nil {
		return nil
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), strings.NewReader(sql))
	if err != nil {
		return nil
	}
	req.SetBasicAuth(envOr("CLICKHOUSE_USER", "netops"), os.Getenv("CLICKHOUSE_PASSWORD"))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	b, _ := io.ReadAll(resp.Body)
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

// vmTopk runs an instant PromQL query against VictoriaMetrics and formats each
// returned series as "<device> <value><unit>". Best-effort (nil on error).
func vmTopk(query, unit string) []string {
	base := envOr("VICTORIA_URL", envOr("METRICS_URL", "http://victoria:8428"))
	endpoint := strings.TrimRight(base, "/") + "/api/v1/query?query=" + url.QueryEscape(query)
	resp, err := (&http.Client{Timeout: 6 * time.Second}).Get(endpoint)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var out struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  [2]any            `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return nil
	}
	var lines []string
	for _, r := range out.Data.Result {
		name := firstNonEmpty(r.Metric["device"], r.Metric["instance"], r.Metric["host"], "device")
		val := ""
		if s, ok := r.Value[1].(string); ok {
			val = s
		}
		lines = append(lines, fmt.Sprintf("%s %s%s", name, val, unit))
	}
	return lines
}

func atoiSafe(s string) int {
	n := 0
	for _, ch := range strings.TrimSpace(s) {
		if ch < '0' || ch > '9' {
			return n
		}
		n = n*10 + int(ch-'0')
	}
	return n
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
	for _, o := range rs.saved.List("report", "", true) {
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
