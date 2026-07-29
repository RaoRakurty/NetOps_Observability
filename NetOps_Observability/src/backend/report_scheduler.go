package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"netops/backend/internal/discovery"
	"netops/backend/internal/saved"
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
	claims, ok := s.requirePerm(w, r, "reports", LevelWrite)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
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
		// Tenant isolation (SR-002): the saved store Get is unscoped, and EnqueueNow
		// runs the job — and delivers to its channels — under the report's OWN tenant.
		// Without this ownership check a tenant holding reports:write could trigger
		// another tenant's report and have it exfiltrated to that tenant's channels
		// (or, with link-delivery, obtain the capability URL). 404 (not 403) so the
		// id's existence in another tenant isn't revealed.
		if !ok || o.Type != "report" || !canSeeSaved(o, tenant, cross) {
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

	// Synchronous fallback (file backend). Same tenant-ownership gate as the async
	// path (SR-002) before running/delivering the report.
	if o, ok := s.saved.Get(id); !ok || o.Type != "report" || !canSeeSaved(o, tenant, cross) {
		writeError(w, http.StatusNotFound, errors.New("report not found"))
		return
	}
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
// A report is a saved.Object of type "report" whose opaque body the frontend
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
	// on Zabbix scheduled reports): wan_utilization | security_threats |
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
	saved     saved.Repo
	notifier  *notify.Dispatcher
	discovery *discovery.DiscoveryAggregator
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
			if err := rs.flushLocked(); err != nil {
				logError("reports", "run history persist failed", map[string]any{"err": err.Error()})
			}
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
func (rs *reportScheduler) deliver(o saved.Object, spec reportSpec, now time.Time) {
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
	if err := rs.flushLocked(); err != nil {
		logError("reports", "run history persist failed", map[string]any{"err": err.Error()})
	}
}

// deliverToContactPoints resolves the report's email contact points (tenant-
// scoped) and emails the report to them. Returns the recipient count and a short
// status note for the run detail. No-op (0, "") when the report has no contact
// points.
//
// "link" delivery (signed report-view URL) is served by the ASYNC pipeline
// (`reportDelivery.Deliver`, Postgres backend) — that path stores an execution +
// artifact and emails a `reportViewLink` to it. This legacy synchronous
// file-backend scheduler has no execution/artifact store to anchor a token to,
// so it cannot mint a secure link; rather than email the report body (and leak
// tenant data in what the operator asked to be link-only), it records that link
// mode needs the async pipeline. Switch STORE_BACKEND=postgres to use it.
func (rs *reportScheduler) deliverToContactPoints(msg models.Alert, o saved.Object, spec reportSpec) (int, string) {
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
		// Secure-link delivery requires the async (Postgres) report pipeline,
		// which stores the artifact the link serves. Don't email the body here.
		return 0, fmt.Sprintf("secure-link delivery to %d recipient(s) needs the async report pipeline (STORE_BACKEND=postgres)", len(recipients))
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
func (rs *reportScheduler) render(o saved.Object, spec reportSpec, now time.Time) models.Alert {
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
		summary, body = rs.renderWANUtilization(tenant)
	case "security_threats":
		summary, body = rs.renderSecurityThreats(tenant)
	case "device_utilization":
		summary, body = rs.renderDeviceUtilization(tenant)
	case "latency_jitter_sla":
		summary, body = rs.renderLatencyJitterSLA(tenant)
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
func (rs *reportScheduler) buildViewModel(o saved.Object, spec reportSpec, now time.Time) reports.ViewModel {
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
		summary, sections = rs.datasetWAN(tenant)
	case "security_threats":
		summary, sections = rs.datasetSecurity(tenant)
	case "device_utilization":
		summary, sections = rs.datasetDeviceUtil(tenant)
	case "latency_jitter_sla":
		summary, sections = rs.datasetLatency(tenant)
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
	byRule := map[string]int{}
	for _, a := range active {
		bySev[strings.ToLower(a.Severity)]++
		byRule[firstNonEmpty(a.Rule, "—")]++
	}
	crit := bySev["critical"] + bySev["error"]
	warn := bySev["warning"]
	summary := fmt.Sprintf("%d active alert(s) · %d critical/error · %d warning", len(active), crit, warn)
	if len(active) == 0 {
		return "0 active alerts — all clear", []reports.Section{{Title: "Active alerts", Note: "No active alerts. The fleet is operating within thresholds."}}
	}
	var sevRows [][]string
	for _, s := range []string{"critical", "error", "warning", "notice", "info"} {
		if n := bySev[s]; n > 0 {
			sevRows = append(sevRows, []string{titleCase(s), strconv.Itoa(n), pctStr(n, len(active))})
		}
	}
	// Top firing rules — what's noisiest, an at-a-glance triage signal.
	ruleRows := topCounts(byRule, 5)
	sort.Slice(active, func(i, j int) bool { return active[i].FiredAt.After(active[j].FiredAt) })
	var recent [][]string
	for i, a := range active {
		if i >= 25 {
			break
		}
		recent = append(recent, []string{titleCase(a.Severity), firstNonEmpty(a.DeviceID, "—"), a.Summary, agoStr(a.FiredAt, time.Now())})
	}
	secs := []reports.Section{
		{Title: "By severity", Header: []string{"Severity", "Count", "Share"}, Rows: sevRows},
	}
	if len(ruleRows) > 0 {
		secs = append(secs, reports.Section{Title: "Top firing rules", Header: []string{"Rule", "Alerts"}, Rows: ruleRows})
	}
	secs = append(secs, reports.Section{Title: "Most recent", Header: []string{"Severity", "Device", "Alert", "Age"}, Rows: recent})
	return summary, secs
}

func (rs *reportScheduler) datasetDevices(tenant string) (string, []reports.Section) {
	devs := rs.tenantDevices(tenant)
	if len(devs) == 0 {
		return "0 devices — discovery hasn't returned anything", []reports.Section{{Title: "Devices", Note: "No devices discovered."}}
	}
	up, degraded, down, health := rs.fleetHealth(devs, time.Now())
	byVendor := map[string]int{}
	byType := map[string]int{}
	for _, d := range devs {
		byVendor[firstNonEmpty(titleCase(strings.ToLower(d.Vendor)), "Unknown")]++
		byType[firstNonEmpty(titleCase(d.Type), "Generic")]++
	}
	// Inventory table — name, address, classification, live health and freshness.
	var rows [][]string
	sort.Slice(devs, func(i, j int) bool {
		return firstNonEmpty(devs[i].Name, devs[i].ID) < firstNonEmpty(devs[j].Name, devs[j].ID)
	})
	now := time.Now()
	for _, d := range devs {
		name := firstNonEmpty(d.Name, d.ID)
		rows = append(rows, []string{
			name, d.Address,
			firstNonEmpty(titleCase(strings.ToLower(d.Vendor)), "—"),
			firstNonEmpty(titleCase(d.Type), "—"),
			health[d.ID],
			lastSeenStr(d.LastSeen, now),
		})
	}
	summary := fmt.Sprintf("%d device(s) · %d up · %d degraded · %d down", len(devs), up, degraded, down)
	secs := []reports.Section{
		{Title: "Fleet status", Header: []string{"Status", "Devices", "Share"}, Rows: [][]string{
			{"Up", strconv.Itoa(up), pctStr(up, len(devs))},
			{"Degraded", strconv.Itoa(degraded), pctStr(degraded, len(devs))},
			{"Down", strconv.Itoa(down), pctStr(down, len(devs))},
		}},
		{Title: "By manufacturer", Header: []string{"Manufacturer", "Devices"}, Rows: topCounts(byVendor, 12)},
		{Title: "By type", Header: []string{"Type", "Devices"}, Rows: topCounts(byType, 12)},
		{Title: "Inventory", Header: []string{"Name", "Address", "Manufacturer", "Type", "Status", "Last seen"}, Rows: rows},
	}
	return summary, secs
}

func (rs *reportScheduler) datasetHealth(now time.Time, tenant string) (string, []reports.Section) {
	uptime := now.Sub(rs.startedAt).Round(time.Second)
	devs := rs.tenantDevices(tenant)
	alerts := rs.tenantAlerts(tenant)
	up, degraded, down, _ := rs.fleetHealth(devs, now)
	bySev := map[string]int{}
	for _, a := range alerts {
		bySev[strings.ToLower(a.Severity)]++
	}
	crit := bySev["critical"] + bySev["error"]
	warn := bySev["warning"]
	// Availability = share of the fleet with a healthy heartbeat right now.
	avail := 100.0
	if len(devs) > 0 {
		avail = float64(up) / float64(len(devs)) * 100
	}
	// Executive at-a-glance — the numbers leadership reads first.
	exec := [][]string{
		{"Fleet availability", fmt.Sprintf("%.1f%%", avail)},
		{"Devices monitored", strconv.Itoa(len(devs))},
		{"Up / Degraded / Down", fmt.Sprintf("%d / %d / %d", up, degraded, down)},
		{"Active alerts", strconv.Itoa(len(alerts))},
		{"Critical / Warning", fmt.Sprintf("%d / %d", crit, warn)},
		{"Platform uptime", uptime.String()},
	}
	secs := []reports.Section{
		{Title: "Executive summary", Header: []string{"Metric", "Value"}, Rows: exec},
		{Title: "Fleet status", Header: []string{"Status", "Devices", "Share"}, Rows: [][]string{
			{"Up", strconv.Itoa(up), pctStr(up, max1(len(devs)))},
			{"Degraded", strconv.Itoa(degraded), pctStr(degraded, max1(len(devs)))},
			{"Down", strconv.Itoa(down), pctStr(down, max1(len(devs)))},
		}},
	}
	if len(alerts) > 0 {
		var sevRows [][]string
		for _, s := range []string{"critical", "error", "warning", "notice", "info"} {
			if n := bySev[s]; n > 0 {
				sevRows = append(sevRows, []string{titleCase(s), strconv.Itoa(n)})
			}
		}
		secs = append(secs, reports.Section{Title: "Active alerts by severity", Header: []string{"Severity", "Count"}, Rows: sevRows})
	}
	return fmt.Sprintf("%.1f%% availability · %d devices · %d active alerts (%d critical)", avail, len(devs), len(alerts), crit), secs
}

func (rs *reportScheduler) datasetWAN(tenant string) (string, []reports.Section) {
	keys, platform := rs.reportDeviceKeys(tenant)
	var rows []string
	if platform || len(keys) > 0 {
		rows = chQuery(`
SELECT local_device, remote_device, type, status,
       round(latency_ms,1), round(jitter_ms,1), round(loss_pct,2), round(qoe,1)
  FROM netops.tunnels
` + tunnelReportCond(platform, keys) + ` ORDER BY ts DESC
 LIMIT 1 BY id
 FORMAT TSV`)
	}
	if len(rows) == 0 {
		return "no WAN/overlay links reporting", []reports.Section{{Title: "WAN / overlay links", Note: "No tunnel/overlay telemetry yet."}}
	}
	up, degraded := 0, 0
	var qoeSum float64
	var data [][]string
	for _, r := range rows {
		c := strings.Split(r, "\t")
		if len(c) < 8 {
			continue
		}
		if c[3] == "up" {
			up++
		} else {
			degraded++
		}
		qoeSum += parseFloatSafe(c[7])
		data = append(data, []string{c[0] + " ↔ " + c[1], c[2], titleCase(c[3]), c[4] + " ms", c[5] + " ms", c[6] + "%", c[7]})
	}
	avgQoE := 0.0
	if len(data) > 0 {
		avgQoE = qoeSum / float64(len(data))
	}
	summary := fmt.Sprintf("%d link(s) · %d up · %d degraded · avg QoE %.1f", len(rows), up, degraded, avgQoE)
	return summary, []reports.Section{
		{Title: "Overview", Header: []string{"Metric", "Value"}, Rows: [][]string{
			{"Links monitored", strconv.Itoa(len(rows))},
			{"Up / Degraded", fmt.Sprintf("%d / %d", up, degraded)},
			{"Average QoE", fmt.Sprintf("%.1f", avgQoE)},
		}},
		{Title: "WAN / overlay links", Header: []string{"Link", "Type", "Status", "Latency", "Jitter", "Loss", "QoE"}, Rows: data},
	}
}

func (rs *reportScheduler) datasetSecurity(tenant string) (string, []reports.Section) {
	keys, platform := rs.reportDeviceKeys(tenant)
	var sev, recent []string
	if platform || len(keys) > 0 {
		cond := findingsReportCond(platform, keys)
		sev = chQuery(`
SELECT severity, count()
  FROM netops.findings
 WHERE ts >= now() - INTERVAL 24 HOUR` + cond + `
 GROUP BY severity
 ORDER BY count() DESC
 FORMAT TSV`)
		recent = chQuery(`
SELECT severity, device, summary
  FROM netops.findings
 WHERE ts >= now() - INTERVAL 24 HOUR` + cond + `
 ORDER BY ts DESC
 LIMIT 10
 FORMAT TSV`)
	}
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
	// Top affected devices (24h) — where to look first.
	var byDev []string
	if platform || len(keys) > 0 {
		byDev = chQuery(`
SELECT device, count()
  FROM netops.findings
 WHERE ts >= now() - INTERVAL 24 HOUR AND device != ''` + findingsReportCond(platform, keys) + `
 GROUP BY device
 ORDER BY count() DESC
 LIMIT 10
 FORMAT TSV`)
	}
	if len(byDev) > 0 {
		var rows [][]string
		for _, r := range byDev {
			c := strings.Split(r, "\t")
			if len(c) == 2 {
				rows = append(rows, []string{c[0], c[1]})
			}
		}
		secs = append(secs, reports.Section{Title: "Top affected devices (24h)", Header: []string{"Device", "Findings"}, Rows: rows})
	}
	if len(recent) > 0 {
		var rows [][]string
		for _, r := range recent {
			c := strings.Split(r, "\t")
			if len(c) >= 3 {
				rows = append(rows, []string{titleCase(c[0]), c[1], c[2]})
			}
		}
		secs = append(secs, reports.Section{Title: "Recent findings", Header: []string{"Severity", "Device", "Summary"}, Rows: rows})
	}
	crit := 0
	for _, a := range rs.tenantAlerts(tenant) {
		if strings.EqualFold(a.Severity, "critical") {
			crit++
		}
	}
	secs = append(secs, reports.Section{Title: "Critical active alerts", Header: []string{"Metric", "Value"}, Rows: [][]string{{"Critical active alerts", strconv.Itoa(crit)}}})
	return fmt.Sprintf("%d finding(s)/24h · %d critical alert(s)", total, crit), secs
}

func (rs *reportScheduler) datasetDeviceUtil(tenant string) (string, []reports.Section) {
	// Join CPU + memory per device into one ranked table (was two text blobs).
	keys, platform := rs.reportDeviceKeys(tenant)
	var cpu, mem map[string]float64
	if platform || len(keys) > 0 {
		cpu = vmQueryMap(`device_cpu_percent`)
		mem = vmQueryMap(`device_mem_percent`)
		if !platform {
			cpu, mem = filterDeviceMap(cpu, keys), filterDeviceMap(mem, keys)
		}
	}
	if len(cpu) == 0 && len(mem) == 0 {
		return "no device utilisation metrics", []reports.Section{{Title: "Device utilisation", Note: "No CPU/memory metrics reporting yet."}}
	}
	seen := map[string]bool{}
	var devs []string
	for d := range cpu {
		if !seen[d] {
			seen[d] = true
			devs = append(devs, d)
		}
	}
	for d := range mem {
		if !seen[d] {
			seen[d] = true
			devs = append(devs, d)
		}
	}
	// Rank by the busier of the two dimensions so the hottest devices lead.
	peak := func(d string) float64 {
		if c, m := cpu[d], mem[d]; c > m {
			return c
		} else {
			return m
		}
	}
	sort.Slice(devs, func(i, j int) bool { return peak(devs[i]) > peak(devs[j]) })
	var rows [][]string
	var cpuSum, memSum float64
	hot := 0
	for _, d := range devs {
		cpuSum += cpu[d]
		memSum += mem[d]
		if peak(d) >= 80 {
			hot++
		}
		rows = append(rows, []string{d, fmt.Sprintf("%.0f%%", cpu[d]), fmt.Sprintf("%.0f%%", mem[d])})
		if len(rows) >= 15 {
			break
		}
	}
	n := maxf(float64(len(devs)), 1)
	summary := fmt.Sprintf("%d device(s) · avg CPU %.0f%% · avg mem %.0f%% · %d over 80%%", len(devs), cpuSum/n, memSum/n, hot)
	return summary, []reports.Section{
		{Title: "Overview", Header: []string{"Metric", "Value"}, Rows: [][]string{
			{"Devices reporting", strconv.Itoa(len(devs))},
			{"Average CPU", fmt.Sprintf("%.0f%%", cpuSum/n)},
			{"Average memory", fmt.Sprintf("%.0f%%", memSum/n)},
			{"Devices over 80%", strconv.Itoa(hot)},
		}},
		{Title: "Top devices by utilisation", Header: []string{"Device", "CPU", "Memory"}, Rows: rows},
	}
}

func (rs *reportScheduler) datasetLatency(tenant string) (string, []reports.Section) {
	// Per-link latency/jitter/loss as a real table + an availability SLA (was a
	// single text blob).
	keys, platform := rs.reportDeviceKeys(tenant)
	var rows []string
	if platform || len(keys) > 0 {
		rows = chQuery(`
SELECT local_device, remote_device, status,
       round(latency_ms,1), round(jitter_ms,1), round(loss_pct,2)
  FROM netops.tunnels
` + tunnelReportCond(platform, keys) + ` ORDER BY ts DESC
 LIMIT 1 BY id
 FORMAT TSV`)
	}
	if len(rows) == 0 {
		return "no latency/SLA telemetry", []reports.Section{{Title: "Latency, jitter & SLA", Note: "No tunnel latency/jitter telemetry yet."}}
	}
	up := 0
	var data [][]string
	var latSum float64
	for _, r := range rows {
		c := strings.Split(r, "\t")
		if len(c) < 6 {
			continue
		}
		if c[2] == "up" {
			up++
		}
		latSum += parseFloatSafe(c[3])
		data = append(data, []string{c[0] + " ↔ " + c[1], titleCase(c[2]), c[3] + " ms", c[4] + " ms", c[5] + "%"})
	}
	sla := 100.0
	if len(rows) > 0 {
		sla = float64(up) / float64(len(rows)) * 100
	}
	avgLat := 0.0
	if len(data) > 0 {
		avgLat = latSum / float64(len(data))
	}
	summary := fmt.Sprintf("%d link(s) · %d up · SLA %.2f%% · avg latency %.1f ms", len(rows), up, sla, avgLat)
	return summary, []reports.Section{
		{Title: "SLA overview", Header: []string{"Metric", "Value"}, Rows: [][]string{
			{"Availability SLA", fmt.Sprintf("%.2f%%", sla)},
			{"Links up", fmt.Sprintf("%d / %d", up, len(rows))},
			{"Average latency", fmt.Sprintf("%.1f ms", avgLat)},
		}},
		{Title: "Per-link latency, jitter & loss", Header: []string{"Link", "Status", "Latency", "Jitter", "Loss"}, Rows: data},
	}
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

// reportDeviceKeys returns the device ids/names a tenant-owned report may
// reference (the visibleDeviceKeys key set, derived from the report's owner
// instead of request claims). platform=true means the report is global or
// unassigned and stays platform-wide — the contract renderDevices/renderAlerts
// already follow. Default-closed: a scoped tenant with no visible devices gets
// an empty key set, and renderers must emit their "no data" note without
// querying rather than fall back to unscoped telemetry.
func (rs *reportScheduler) reportDeviceKeys(tenant string) (keys []string, platform bool) {
	t := strings.ToLower(strings.TrimSpace(tenant))
	if t == "" || t == TenantGlobal {
		return nil, true
	}
	seen := map[string]bool{}
	for _, d := range rs.tenantDevices(t) {
		for _, k := range []string{d.ID, d.Name} {
			if k != "" && !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	return keys, false
}

// tunnelReportCond narrows netops.tunnels rows to tunnels terminating on one of
// the report tenant's devices (either endpoint) — the same contract as
// /api/tunnels. The tunnels row policy is hybrid (untagged rows shared), so
// this app-layer clause is what keeps a tenant report from describing other
// tenants' links. Injection-safe via sqlInList (inventory values, escaped
// regardless).
func tunnelReportCond(platform bool, keys []string) string {
	if platform {
		return ""
	}
	in := sqlInList(keys)
	return ` WHERE (local_device IN (` + in + `) OR remote_device IN (` + in + `))
`
}

// findingsReportCond is the findings sibling, keyed on the device name column.
// Scoped reports exclude device-less platform findings (default-closed).
func findingsReportCond(platform bool, keys []string) string {
	if platform {
		return ""
	}
	return " AND device IN (" + sqlInList(keys) + ")"
}

// filterDeviceMap keeps only the metric entries whose device label matches one
// of the tenant's device keys. Pure.
func filterDeviceMap(m map[string]float64, keys []string) map[string]float64 {
	allow := make(map[string]bool, len(keys))
	for _, k := range keys {
		allow[k] = true
	}
	out := make(map[string]float64, len(m))
	for k, v := range m {
		if allow[k] {
			out[k] = v
		}
	}
	return out
}

// topDeviceLines renders the top-n devices of a metric map as "name value<unit>"
// lines, highest first (ties broken by name for determinism). Pure.
func topDeviceLines(m map[string]float64, n int, unit string) []string {
	devs := make([]string, 0, len(m))
	for d := range m {
		devs = append(devs, d)
	}
	sort.Slice(devs, func(i, j int) bool {
		if m[devs[i]] != m[devs[j]] {
			return m[devs[i]] > m[devs[j]]
		}
		return devs[i] < devs[j]
	})
	if len(devs) > n {
		devs = devs[:n]
	}
	lines := make([]string, 0, len(devs))
	for _, d := range devs {
		lines = append(lines, fmt.Sprintf("%s %.0f%s", d, m[d], unit))
	}
	return lines
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
// fails — it reports the gap, mirroring how Zabbix scheduled summaries
// behave.

// renderWANUtilization summarises per-WAN/overlay link load + health from the
// tunnels telemetry (status, loss, qoe) — the closest the stack has to circuit
// utilisation until per-circuit bandwidth counters land.
func (rs *reportScheduler) renderWANUtilization(tenant string) (string, string) {
	keys, platform := rs.reportDeviceKeys(tenant)
	var rows []string
	if platform || len(keys) > 0 {
		rows = chQuery(`
SELECT local_device, remote_device, type, status,
       round(loss_pct,2), round(qoe,2)
  FROM netops.tunnels
` + tunnelReportCond(platform, keys) + ` ORDER BY ts DESC
 LIMIT 1 BY id
 FORMAT TSV`)
	}
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
func (rs *reportScheduler) renderSecurityThreats(tenant string) (string, string) {
	keys, platform := rs.reportDeviceKeys(tenant)
	var sev, recent []string
	if platform || len(keys) > 0 {
		cond := findingsReportCond(platform, keys)
		sev = chQuery(`
SELECT severity, count()
  FROM netops.findings
 WHERE ts >= now() - INTERVAL 24 HOUR` + cond + `
 GROUP BY severity
 ORDER BY count() DESC
 FORMAT TSV`)
		recent = chQuery(`
SELECT severity, device, summary
  FROM netops.findings
 WHERE ts >= now() - INTERVAL 24 HOUR` + cond + `
 ORDER BY ts DESC
 LIMIT 10
 FORMAT TSV`)
	}
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
	for _, a := range rs.tenantAlerts(tenant) {
		if strings.EqualFold(a.Severity, "critical") {
			crit++
		}
	}
	fmt.Fprintf(&b, "\nCritical active alerts: %d\n", crit)
	return fmt.Sprintf("%d finding(s)/24h · %d critical alert(s)", total, crit), b.String()
}

// renderDeviceUtilization lists the busiest devices by CPU and memory from the
// metrics VictoriaMetrics already stores (SNMP + gNMI collectors), ranked
// in-app so a tenant-owned report's top-N is computed over ITS devices only
// (a server-side topk would rank platform-wide and then filter).
func (rs *reportScheduler) renderDeviceUtilization(tenant string) (string, string) {
	keys, platform := rs.reportDeviceKeys(tenant)
	var cpuMap, memMap map[string]float64
	if platform || len(keys) > 0 {
		cpuMap = vmQueryMap(`device_cpu_percent`)
		memMap = vmQueryMap(`device_mem_percent`)
		if !platform {
			cpuMap, memMap = filterDeviceMap(cpuMap, keys), filterDeviceMap(memMap, keys)
		}
	}
	cpu := topDeviceLines(cpuMap, 10, "%")
	mem := topDeviceLines(memMap, 10, "%")
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
func (rs *reportScheduler) renderLatencyJitterSLA(tenant string) (string, string) {
	keys, platform := rs.reportDeviceKeys(tenant)
	var rows []string
	if platform || len(keys) > 0 {
		rows = chQuery(`
SELECT local_device, remote_device, status,
       round(latency_ms,2), round(jitter_ms,2), round(loss_pct,2)
  FROM netops.tunnels
` + tunnelReportCond(platform, keys) + ` ORDER BY ts DESC
 LIMIT 1 BY id
 FORMAT TSV`)
	}
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

// ── Report dataset helpers (UI-9 enrichment) ───────────────────────────────────

// titleCase upper-cases the first letter of a token for display ("warning" →
// "Warning", "cloud-gw" → "Cloud-gw"); empty stays empty.
func titleCase(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// pctStr renders n/total as a one-decimal percentage string ("42.0%").
func pctStr(n, total int) string {
	if total <= 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", float64(n)/float64(total)*100)
}

// max1 returns at least 1 (avoids divide-by-zero on share/avg columns).
func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// parseFloatSafe parses a float, returning 0 on any error (telemetry strings).
func parseFloatSafe(s string) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0
	}
	return f
}

// topCounts turns a label→count map into the top-N rows, count-descending then
// label-ascending for stable output.
func topCounts(m map[string]int, n int) [][]string {
	type kv struct {
		k string
		v int
	}
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v != pairs[j].v {
			return pairs[i].v > pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	var rows [][]string
	for i, p := range pairs {
		if i >= n {
			break
		}
		rows = append(rows, []string{p.k, strconv.Itoa(p.v)})
	}
	return rows
}

// agoStr renders a compact relative age ("3m ago", "2h ago").
func agoStr(t, now time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// lastSeenStr renders a device's heartbeat freshness, or "never" if unseen.
func lastSeenStr(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return agoStr(t, now)
}

// fleetHealth classifies each device into up/degraded/down by the same rules as
// the Devices UI: fresh heartbeat (<5m) = up; alerting or stale (<15m) =
// degraded; older or never-seen = down. Returns the counts and a per-device map.
func (rs *reportScheduler) fleetHealth(devs []models.Device, now time.Time) (up, degraded, down int, perDevice map[string]string) {
	alerted := map[string]bool{}
	for _, a := range rs.alerts.Active() {
		s := strings.ToLower(a.Severity)
		if (s == "warning" || s == "critical" || s == "error") && a.DeviceID != "" {
			alerted[a.DeviceID] = true
		}
	}
	perDevice = make(map[string]string, len(devs))
	for _, d := range devs {
		age := now.Sub(d.LastSeen)
		switch {
		case d.LastSeen.IsZero() || age > 15*time.Minute:
			perDevice[d.ID] = "Down"
			down++
		case alerted[d.ID] || age > 5*time.Minute:
			perDevice[d.ID] = "Degraded"
			degraded++
		default:
			perDevice[d.ID] = "Up"
			up++
		}
	}
	return
}

// vmQueryMap runs an instant PromQL query and returns device→value, keyed by the
// friendly device label so several metrics can be joined per device.
func vmQueryMap(query string) map[string]float64 {
	base := envOr("VICTORIA_URL", envOr("METRICS_URL", "http://victoria:8428"))
	endpoint := strings.TrimRight(base, "/") + "/api/v1/query?query=" + url.QueryEscape(query)
	resp, err := backendHTTPClient(6 * time.Second).Get(endpoint)
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
	m := make(map[string]float64, len(out.Data.Result))
	for _, r := range out.Data.Result {
		name := firstNonEmpty(r.Metric["device"], r.Metric["instance"], r.Metric["host"], "device")
		if s, ok := r.Value[1].(string); ok {
			if f, err := strconv.ParseFloat(s, 64); err == nil {
				m[name] = f
			}
		}
	}
	return m
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
		if err := rs.flushLocked(); err != nil {
			logError("reports", "run history persist failed", map[string]any{"err": err.Error()})
		}
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
// flushLocked persists the run history, returning any failure (F-78 class:
// found by the widened TestNoVoidPersistFuncs guard, not by the audit).
func (rs *reportScheduler) flushLocked() error {
	if err := os.MkdirAll(filepath.Dir(rs.path), 0o755); err != nil {
		log.Printf("report runs mkdir: %v", err)
		return err
	}
	b, err := json.MarshalIndent(rs.runs, "", "  ")
	if err != nil {
		log.Printf("report runs marshal: %v", err)
		return err
	}
	tmp := rs.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("report runs write: %v", err)
		return err
	}
	if err := os.Rename(tmp, rs.path); err != nil {
		log.Printf("report runs rename: %v", err)
		return err
	}
	return nil
}
