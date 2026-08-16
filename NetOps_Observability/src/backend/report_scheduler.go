package backend

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
	// Both backends require the same permission and scope by the caller's
	// tenant (H7): run details carry report names/summaries/channel names, so
	// an unscoped map is a cross-tenant leak on the file backend.
	claims, ok := s.requirePerm(w, r, "reports", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	// Under the async backend, derive last/next/status from the execution history
	// (scoped to the caller's tenant); the file backend uses the in-memory map.
	if s.reportPipeline != nil {
		writeJSON(w, http.StatusOK, s.reportPipeline.runsFromExecutions(r.Context(), tenant, cross))
		return
	}
	// File backend: keep only runs whose owning saved report the caller may
	// see (mirrors the PG branch). A run for a deleted report has no owner to
	// authorize against, so a scoped caller doesn't get it either
	// (default-closed; gc reaps those entries anyway).
	runs := s.reports.Runs()
	if !cross {
		for id := range runs {
			if o, ok := s.saved.Get(id); !ok || !canSeeSaved(o, tenant, cross) {
				delete(runs, id)
			}
		}
	}
	writeJSON(w, http.StatusOK, runs)
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
	// Named notify channels are PLATFORM-GLOBAL resources (M15): a tenant
	// principal must not be able to point a run at an arbitrary operator
	// channel (Slack/PagerDuty/... it doesn't own). Only the cross-tenant
	// platform owner may bind them; default-closed, matching §3a.3.
	if len(req.Channels) > 0 && !cross {
		writeError(w, http.StatusForbidden, errors.New("named notify channels are platform-global; contact points are the tenant delivery model"))
		return
	}

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
	// The channel names enumerate the operator's notification integrations,
	// which are PLATFORM-GLOBAL resources (§3a.3): a tenant admin must not be
	// able to enumerate operator channel names. Gate as the notify_config.go
	// siblings do and as RunNow's channel-binding cross gate does — platform
	// admin only, default-closed (M15; was under-gated at reports:read).
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
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
	// slack, pagerduty, sns, twilio…). Empty => contact points only (M15 —
	// never a broadcast to all channels), and only platform-owned reports may
	// name channels at all (they are platform-global resources). Used by
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

	// ds is the reports.DataSource seam the extracted dataset/renderer
	// builders read through (Phase-2 W2.1) — tenant scoping lives in the
	// closures below, not in the reports package.
	ds reports.DataSource
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
	rs.ds = rs.dataSource()
	rs.load()
	return rs
}

// dataSource wires the reports.DataSource seam over this scheduler's
// tenant-scoped reads. Split from the constructor so test fixtures that build
// the scheduler as a struct literal can wire it too (a zero DataSource panics
// on first use — better here than a nil-tolerant seam that hides miswiring).
func (rs *reportScheduler) dataSource() reports.DataSource {
	return reports.DataSource{
		Devices:    rs.tenantDevices,
		Alerts:     rs.tenantAlerts,
		DeviceKeys: rs.reportDeviceKeys,
		CHQuery:    chQuery,
		VMMap:      vmQueryMap,
		StartedAt:  rs.startedAt,
	}
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
// optionally overrides the report's configured notify channels for this one
// send (nil/empty => the report's configured channels; an empty result means
// contact points only — deliver never falls back to broadcasting, see M15).
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

// deliver renders and dispatches a report, then records the outcome.
//
// Named-channel semantics (M15, aligned with the async pipeline's Phase-1
// contract in report_delivery.go): an EMPTY spec.Channels means "contact
// points only" — it must NOT fan out to every configured channel (DispatchTo's
// nil fallback), which broadcast a tenant's report to each platform channel.
// And because notify channels are platform-global resources, only a
// platform-owned (global/unassigned) report may name them at all; a
// tenant-owned report's channel list is skipped, default-closed.
func (rs *reportScheduler) deliver(o saved.Object, spec reportSpec, now time.Time) {
	msg := rs.render(o, spec, now)
	t := normTenant(o.TenantID)
	platformOwned := t == "" || t == TenantGlobal
	sent := 0
	var chNote string
	switch {
	case len(spec.Channels) == 0:
		// contact points only — never broadcast
	case !platformOwned:
		chNote = "named channels skipped (platform-owned reports only)"
	default:
		sent = rs.notifier.DispatchTo(msg, spec.Channels)
	}

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
	if sent > 0 {
		detail += ": " + strings.Join(spec.Channels, ", ")
	}
	if chNote != "" {
		detail += "; " + chNote
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
	recipients := rs.srv.contactPoints.ResolveEmailRecipients(spec.ContactPoints, t, cross)
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
		summary, body = rs.ds.RenderDevices(tenant)
	case "health_summary":
		summary, body = rs.ds.RenderHealth(now, tenant)
	case "wan_utilization":
		summary, body = rs.ds.RenderWANUtilization(tenant)
	case "security_threats":
		summary, body = rs.ds.RenderSecurityThreats(tenant)
	case "device_utilization":
		summary, body = rs.ds.RenderDeviceUtilization(tenant)
	case "latency_jitter_sla":
		summary, body = rs.ds.RenderLatencyJitterSLA(tenant)
	default: // alerts_summary
		summary, body = rs.ds.RenderAlerts(tenant)
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
		summary, sections = rs.ds.DatasetDevices(tenant)
	case "health_summary":
		summary, sections = rs.ds.DatasetHealth(now, tenant)
	case "wan_utilization":
		summary, sections = rs.ds.DatasetWAN(tenant)
	case "security_threats":
		summary, sections = rs.ds.DatasetSecurity(tenant)
	case "device_utilization":
		summary, sections = rs.ds.DatasetDeviceUtil(tenant)
	case "latency_jitter_sla":
		summary, sections = rs.ds.DatasetLatency(tenant)
	default:
		summary, sections = rs.ds.DatasetAlerts(tenant)
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
