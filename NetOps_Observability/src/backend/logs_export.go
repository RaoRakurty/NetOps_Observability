package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netops/backend/reports"

	"netops/backend/internal/oslog"

	"netops/backend/internal/logexport"
)

// jobTypeExport is the shared report-substrate job type for log exports.
const jobTypeExport = "export"

// logs_export.go — Explore→Logs export (Phase 1).
//
// Two modes over the SAME tenant-scoped OpenSearch query the Logs search uses:
//
//	Mode A (sync, selected rows): the browser already holds the rows; it POSTs
//	   them to /api/logs/export/rows and the server renders one file (Excel reuses
//	   the OOXML renderer; csv/json/ndjson share the encoders here). No queue.
//	Mode B (entire result set): GET /api/logs/export. Small sets stream straight
//	   back; large sets run on the SHARED report execution substrate (job_type=
//	   export) — paging OpenSearch with search_after under row/byte/runtime caps,
//	   storing an artifact, and handing back a signed, expiring download link.
//
// All paths are tenant-scoped (the requester's visible-device set, frozen into the
// job for async so it reproduces exactly what they could see) and audited by the
// request middleware. No browser ever talks to OpenSearch directly.

func (s *server) handleLogsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	q := r.URL.Query()
	format := logexport.NormalizeFormat(q.Get("format"))
	if format == "" {
		writeError(w, http.StatusBadRequest, errors.New("format must be csv, json, ndjson, or xlsx"))
		return
	}
	tenant, cross := principalTenant(claims)
	if !s.exportLimiter.AllowN(tenant, envInt("EXPORT_RATE_PER_MIN", 10)) {
		writeError(w, http.StatusTooManyRequests, errors.New("export rate limit exceeded for this tenant — try again shortly"))
		return
	}
	start, end := exportTimeRange(q.Get("from"), q.Get("to"))
	if cap := exportMaxTimeRange(); cap > 0 && end.Sub(start) > cap {
		writeError(w, http.StatusBadRequest, fmt.Errorf("export window %s exceeds the maximum of %s — narrow the time range", end.Sub(start).Round(time.Minute), cap))
		return
	}
	spec := s.exportSpecFor(claims, q.Get("query"), q.Get("from"), q.Get("to"), q.Get("signal"), format)

	// App logs are platform-owner-only — the SAME boundary as the interactive search
	// (logs.go). The export path previously relied solely on osTenantFilter excluding
	// untagged applogs docs by device; per the zero-leak bar, gate explicitly AND
	// guard the resolved index pattern (defense-in-depth, fail-closed) so a tenant can
	// never export the platform's internal logs.
	if sig := strings.ToLower(strings.TrimSpace(q.Get("signal"))); (sig == "applogs" || sig == "app") && !isPlatformOwner(claims) {
		writeError(w, http.StatusForbidden, fmt.Errorf("app logs are restricted to the platform owner"))
		return
	}
	if !oslog.AppLogPatternAllowed(oslog.TenantIndexPattern(spec.Signal, spec.Tenant, spec.Cross), isPlatformOwner(claims)) {
		writeError(w, http.StatusForbidden, fmt.Errorf("app logs are restricted to the platform owner"))
		return
	}

	// Decide sync vs async by the matched count (cheap _count), unless forced.
	mode := strings.ToLower(q.Get("mode"))
	count, _ := countLogs(r.Context(), spec, start, end) // best-effort: count failure → 0 → sync-path fallback
	syncMax := envInt("EXPORT_SYNC_MAX_ROWS", 5000)
	wantAsync := mode == "async" || (mode != "sync" && count > syncMax)

	if wantAsync {
		if s.reportPipeline == nil {
			writeError(w, http.StatusConflict, fmt.Errorf("result set is large (%d rows) and async export requires the Postgres backend; narrow the query for a direct download", count))
			return
		}
		execID, err := s.reportPipeline.EnqueueExport(r.Context(), tenant, spec)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.auditExport(r, claims, tenant, cross, "async", spec, count, execID)
		logInfo("logs.export", "export enqueued", map[string]any{"execution_id": execID, "tenant_id": tenant, "signal": spec.Signal, "format": format, "matched": count})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		out := map[string]any{"execution_id": execID, "status": "queued", "matched": count}
		// Sample honesty: a flows export contains the 1:50 OS sample, not the
		// flow stream — the disclosure travels with the queued-export receipt.
		if isFlowsSignal(spec.Signal) {
			out["sampling"] = flowsSamplingMeta()
		}
		_ = json.NewEncoder(w).Encode(out) // best-effort: a failed encode/write means the client is gone
		return
	}

	// Sync: bounded fetch → encode → stream.
	data, err := logexport.FetchBounded(r.Context(), openSearch, spec, start, end, envInt("MAX_EXPORT_ROWS", 500_000), envInt("MAX_EXPORT_BYTES", 256*1024*1024))
	if err != nil {
		if errors.Is(err, logexport.ErrTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, err)
			return
		}
		writeError(w, http.StatusBadGateway, err)
		return
	}
	art, err := logexport.Encode(r.Context(), format, logexport.Columns, data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.auditExport(r, claims, tenant, cross, "sync", spec, len(data.Rows), "")
	logInfo("logs.export", "export delivered (sync)", map[string]any{"tenant_id": tenant, "signal": spec.Signal, "format": format, "rows": len(data.Rows), "bytes": len(art.Bytes)})
	// Sample honesty: the downloaded file holds the 1:50 OS flow sample. The
	// artifact bytes stay untouched (a note row would corrupt csv/xlsx), so
	// the disclosure rides a response header (ASCII note) — and the UI states
	// it alongside the download (Logs.tsx).
	if isFlowsSignal(spec.Signal) {
		w.Header().Set("X-Sampling-Note", flowsSamplingMeta()["note"].(string))
	}
	writeDownload(w, art, "logs-export")
}

// auditExport records a sensitive export action into the immutable audit trail
// with the query/size/execution-id detail the hardening spec requires.
func (s *server) auditExport(r *http.Request, claims jwtClaims, tenant string, cross bool, mode string, spec logexport.Spec, count int, execID string) {
	if s.audit == nil {
		return
	}
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross,
		Method: "EXPORT", Path: "/api/logs/export", Status: http.StatusOK, Decision: "allow",
		Remote: auditClientIP(r),
		Detail: map[string]any{
			"signal": spec.Signal, "format": spec.Format, "query": spec.Query,
			"mode": mode, "matched": count, "execution_id": execID,
		},
	})
}

// ---- Mode A: POST /api/logs/export/rows (selected/loaded rows) --------------

type exportRowsReq struct {
	Format   string     `json:"format"`
	Columns  []string   `json:"columns,omitempty"`
	Rows     [][]string `json:"rows"`
	Filename string     `json:"filename,omitempty"`
}

func (s *server) handleLogsExportRows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	tenant, cross := principalTenant(claims)
	if !s.exportLimiter.AllowN(tenant, envInt("EXPORT_RATE_PER_MIN", 10)) {
		writeError(w, http.StatusTooManyRequests, errors.New("export rate limit exceeded for this tenant — try again shortly"))
		return
	}
	var req exportRowsReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	format := logexport.NormalizeFormat(req.Format)
	if format == "" {
		writeError(w, http.StatusBadRequest, errors.New("format must be csv, json, ndjson, or xlsx"))
		return
	}
	cols := req.Columns
	if len(cols) == 0 {
		cols = logexport.Columns
	}
	if len(req.Rows) > envInt("MAX_EXPORT_ROWS", 500_000) {
		writeError(w, http.StatusRequestEntityTooLarge, logexport.ErrTooLarge)
		return
	}
	art, err := logexport.Encode(r.Context(), format, cols, logexport.Data{Rows: req.Rows})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	name := req.Filename
	if name == "" {
		name = "logs-export"
	}
	s.auditExport(r, claims, tenant, cross, "rows", logexport.Spec{Format: format}, len(req.Rows), "")
	writeDownload(w, art, name)
}

// ---- async status + signed download ----------------------------------------

// handleExportStatus polls one export execution (tenant-scoped) and, when done,
// returns a signed, expiring download link.
func (s *server) handleExportStatus(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	if s.reportPipeline == nil {
		writeError(w, http.StatusConflict, errors.New("exports require the Postgres backend"))
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/exports/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, errors.New("export id required"))
		return
	}
	tenant, cross := principalTenant(claims)
	rec, _, found, err := s.reportPipeline.execs.Get(r.Context(), tenant, cross, id)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if !found || rec.Kind != jobTypeExport {
		writeError(w, http.StatusNotFound, errors.New("export not found"))
		return
	}
	out := map[string]any{"id": rec.ID, "status": string(rec.Status)}
	if rec.Error != "" {
		out["error"] = rec.Error
	}
	if rec.Status == reports.StatusCompleted {
		if a := rec.PrimaryArtifact(); a != nil {
			out["format"] = a.Format
			out["size_bytes"] = a.SizeBytes
			out["download_url"] = exportViewLink(rec.ID, rec.TenantID, a.Format)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out) // best-effort: a failed encode/write means the client is gone
}

// exportViewLink builds the public, signed, short-lived, tenant-bound download URL
// for an export artifact (the token IS the authorization).
func exportViewLink(execID, tenant, format string) string {
	base := strings.TrimRight(envOr("REPORT_PUBLIC_BASE_URL", ""), "/")
	u := base + "/api/exports/view/" + signExportLink(execID, tenant)
	if format != "" {
		u += "?format=" + format
	}
	return u
}

// handleExportView serves a stored export artifact to anyone holding a valid
// signed link — no session required (mirrors handleReportView).
func (s *server) handleExportView(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.reportPipeline == nil {
		writeError(w, http.StatusConflict, errors.New("exports require the Postgres backend"))
		return
	}
	// PIPE-HIGH-2: prefer the X-Link-Token header (never logged, never in a
	// proxy's access log or the browser's history); the path form stays for the
	// plain browser download and is masked at both log boundaries. See
	// report_links.go.
	token := linkTokenFromRequest(r, "/api/exports/view/")
	execID, linkTenant, err := verifyExportLink(token)
	if err != nil {
		writeError(w, http.StatusForbidden, errors.New("invalid or expired export link"))
		return
	}
	rec, _, found, err := s.reportPipeline.execs.Get(r.Context(), "", true, execID)
	if err != nil || !found || rec.Kind != jobTypeExport {
		writeError(w, http.StatusNotFound, errors.New("export not found"))
		return
	}
	// Defense-in-depth: the token's tenant must match the artifact's owner, so a
	// leaked/forwarded token can never be replayed against another tenant's data.
	if normTenant(rec.TenantID) != normTenant(linkTenant) {
		writeError(w, http.StatusForbidden, errors.New("export link tenant mismatch"))
		return
	}
	ref := rec.PrimaryArtifact()
	if f := logexport.NormalizeFormat(r.URL.Query().Get("format")); f != "" {
		if a := rec.ArtifactByFormat(f); a != nil {
			ref = a
		}
	}
	if ref == nil {
		writeError(w, http.StatusNotFound, errors.New("no artifact for this export"))
		return
	}
	art, err := s.reportPipeline.artifacts.Load(r.Context(), *ref)
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("artifact unavailable"))
		return
	}
	// Audit the download (link-bearer; tenant from the signed token).
	if s.audit != nil {
		s.audit.Record(AuditEvent{
			Tenant: normTenant(linkTenant), Method: "EXPORT_DOWNLOAD", Path: "/api/exports/view",
			Status: http.StatusOK, Decision: "allow", Remote: auditClientIP(r),
			Detail: map[string]any{"execution_id": execID, "format": ref.Format},
		})
	}
	writeDownload(w, art, "logs-export")
}

// writeDownload streams an artifact as a file attachment.
func writeDownload(w http.ResponseWriter, art reports.Artifact, basename string) {
	_, ext := logexport.ContentType(art.Format)
	w.Header().Set("Content-Type", art.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", basename+"."+ext))
	w.Header().Set("Content-Length", strconv.Itoa(len(art.Bytes)))
	// A forwarded link must not leak the (capability-bearing) URL via Referer.
	w.Header().Set("Referrer-Policy", "no-referrer")
	_, _ = w.Write(art.Bytes) // best-effort: status committed; a failed write means the client is gone
}

// exportMaxTimeRange bounds how wide an export window may be (anti-exfiltration /
// anti-unbounded-scan). Default 7 days; 0 or negative disables the cap.
func exportMaxTimeRange() time.Duration {
	return envDuration("MAX_EXPORT_TIME_RANGE", 7*24*time.Hour)
}

// ---- helpers shared with the worker ----------------------------------------

// exportSpecFor builds a spec with the caller's tenant-visibility frozen in,
// including the operator-visibility compliance restriction (so an export can never
// exfiltrate a restricted tenant's telemetry, even via the async worker later).
func (s *server) exportSpecFor(claims jwtClaims, query, from, to, signal, format string) logexport.Spec {
	keys, cross := s.visibleDeviceKeys(claims)
	addrs, _ := s.visibleDeviceAddrs(claims)
	tenant, _ := principalTenant(claims)
	exclude, deny := s.operatorTelemetryRestriction(claims, tenant, cross)
	return logexport.Spec{
		Query: query, From: from, To: to, Signal: signal, Format: format,
		Tenant: tenant, Cross: cross, DeviceKeys: keys, DeviceAddrs: addrs,
		ExcludeTenants: exclude, DenyAll: deny,
	}
}

func exportTimeRange(from, to string) (time.Time, time.Time) {
	end := time.Now().UTC()
	start := end.Add(-15 * time.Minute)
	if from != "" {
		if t, err := oslog.ParseTimeFlexible(from); err == nil {
			start = t
		}
	}
	if to != "" {
		if t, err := oslog.ParseTimeFlexible(to); err == nil {
			end = t
		}
	}
	return start, end
}

// countLogs returns the matched document count for an export query (cheap; used
// to choose sync vs async). A failure returns 0 so the caller falls back to sync.
func countLogs(ctx context.Context, spec logexport.Spec, start, end time.Time) (int, error) {
	body := logexport.BuildSearchBody(spec, start, end, 0, nil)
	delete(body, "size")
	delete(body, "sort")
	resp, err := openSearch("POST", "/"+oslog.TenantIndexPattern(spec.Signal, spec.Tenant, spec.Cross)+"/_count", map[string]any{"query": body["query"]})
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var out struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}
	return out.Count, nil
}

// ---- worker handler (Mode B async, on the shared substrate) ----------------

// EnqueueExport places a log-export job on the shared queue and records its
// immutable execution (kind=export), owned by the requester's tenant so the
// status poll is RLS-scoped to them. Returns the execution id to poll.
func (p *reportPipeline) EnqueueExport(ctx context.Context, tenant string, spec logexport.Spec) (string, error) {
	now := time.Now().UTC()
	tenant = normTenant(tenant)
	execID := randHex(8)
	payload, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	// Synthetic schedule_id (the exec id) keeps the UNIQUE(schedule_id, fire_time)
	// idempotency key from colliding with reports; one-off so fire_time = now.
	job := reports.Job{JobType: jobTypeExport, TenantID: tenant, ScheduleID: execID, ExecutionID: execID, FireTime: now, Payload: payload}
	if _, _, err := p.queue.Enqueue(ctx, job, now); err != nil {
		return "", err
	}
	rec := reports.ExecutionRecord{ID: execID, Kind: jobTypeExport, TenantID: tenant, ScheduleID: execID, JobID: execID, FireTime: now, Status: reports.StatusQueued}
	if err := p.execs.Append(ctx, rec); err != nil {
		return "", err
	}
	p.recordPhase(ctx, tenant, execID, reports.PhaseQueued, now, "log export")
	return execID, nil
}

// processExport runs a log-export job: page OpenSearch (bounded) → encode →
// store artifact → complete. ctx is the parent (durable writes); jctx the job
// timeout. The execution is already marked running by process().
func (p *reportPipeline) processExport(ctx, jctx context.Context, _ string, job reports.Job, tenant string, fields map[string]any) {
	startedAt := time.Now().UTC()
	var spec logexport.Spec
	if err := json.Unmarshal(job.Payload, &spec); err != nil {
		p.fail(ctx, jctx, job, tenant, "invalid export spec: "+err.Error(), nil, true, fields)
		p.metExportFailed.Add(1)
		return
	}
	format := logexport.NormalizeFormat(spec.Format)
	if format == "" {
		p.fail(ctx, jctx, job, tenant, "unsupported export format: "+spec.Format, nil, true, fields)
		p.metExportFailed.Add(1)
		return
	}
	start, end := exportTimeRange(spec.From, spec.To)

	p.recordPhase(jctx, tenant, job.ExecutionID, reports.PhaseExporting, time.Now().UTC(), spec.Signal)
	data, err := logexport.FetchBounded(jctx, openSearch, spec, start, end, envInt("MAX_EXPORT_ROWS", 500_000), envInt("MAX_EXPORT_BYTES", 256*1024*1024))
	if err != nil {
		// Size-cap breaches are deterministic → dead-letter, don't retry.
		dead := errors.Is(err, logexport.ErrTooLarge) || p.dead(job)
		p.fail(ctx, jctx, job, tenant, "export query: "+err.Error(), nil, dead, fields)
		p.metExportFailed.Add(1)
		return
	}
	art, err := logexport.Encode(jctx, format, logexport.Columns, data)
	if err != nil {
		p.fail(ctx, jctx, job, tenant, "export encode: "+err.Error(), nil, p.dead(job), fields)
		p.metExportFailed.Add(1)
		return
	}
	ref, err := p.artifacts.Save(ctx, job.ExecutionID+"_"+format, art)
	if err != nil {
		p.fail(ctx, jctx, job, tenant, "export store: "+err.Error(), nil, p.dead(job), fields)
		p.metExportFailed.Add(1)
		return
	}

	done := time.Now().UTC()
	if err := p.execs.Complete(ctx, job.ExecutionID, done, []reports.ArtifactRef{ref}, nil, job.LockedBy); err != nil {
		logError("logs.export", "record completion", merge(fields, errf(err)))
	}
	p.recordPhase(ctx, tenant, job.ExecutionID, reports.PhaseCompleted, done, "")
	if err := p.queue.Complete(ctx, job.ID, job.LockedBy); err != nil {
		logError("logs.export", "finalize job", merge(fields, errf(err)))
	}
	p.metExportDone.Add(1)
	p.metExportRows.Add(int64(len(data.Rows)))
	p.metExportBytes.Add(int64(len(art.Bytes)))
	p.metExportSeconds.Add(int64(done.Sub(startedAt).Seconds()))
	logInfo("logs.export", "export completed", merge(fields, map[string]any{
		"signal": spec.Signal, "format": format, "rows": len(data.Rows), "bytes": len(art.Bytes),
		"seconds": done.Sub(startedAt).Seconds(),
	}))
}
