// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netops/backend/ai"
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
// job for async so it reproduces exactly what they could see), need explore:read
// and are audited here, with who, the query and the row count, never a row. An
// export is a mass disclosure, so its audit is STRICT: if the trail cannot hold
// the record the export does not happen. No browser ever talks to OpenSearch
// directly.

// exportIdentityNote travels with every export (ASCII only, it rides a header):
// device log lines carry usernames, retained for security attribution (D7), and
// what leaves the platform is no longer under its access control or retention.
const exportIdentityNote = "log lines may contain usernames retained for security attribution - handle under your data policy; this file is outside platform access control and retention"

// exportAuditQueryMax bounds the query text stored in one audit record.
const exportAuditQueryMax = 512

// auditQueryText is the search text as the trail may hold it: bounded, with
// anything credential-shaped masked. A person can paste a secret into a search
// box, and the trail is readable by every auditor.
func auditQueryText(q string) string {
	q = ai.RedactSecrets(strings.TrimSpace(q))
	if len(q) > exportAuditQueryMax {
		q = strings.ToValidUTF8(q[:exportAuditQueryMax], "") + " …"
	}
	return q
}

// logHitCounts is the size of one search answer. Both are -1 when the answer
// could not be read as a search response, because an unknown count recorded as
// zero would claim that nothing was disclosed.
type logHitCounts struct {
	Matched int64
	Rows    int
}

type logHitSummary struct {
	Hits struct {
		Total struct {
			Value int64 `json:"value"`
		} `json:"total"`
		Hits []struct{} `json:"hits"`
	} `json:"hits"`
}

func (h logHitSummary) counts() logHitCounts {
	return logHitCounts{Matched: h.Hits.Total.Value, Rows: len(h.Hits.Hits)}
}

// countLogHits reads the counts from a buffered search answer.
func countLogHits(raw []byte) logHitCounts {
	var parsed logHitSummary
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return logHitCounts{Matched: -1, Rows: -1}
	}
	return parsed.counts()
}

// relayLogSearch passes a search answer through byte for byte and reads the
// counts on the way past, so the audit record states what was actually
// delivered without changing the response. A body that is not JSON still reaches
// the caller in full; only its counts are unknown. The error is the relay's.
func relayLogSearch(w io.Writer, body io.Reader) (logHitCounts, error) {
	tee := io.TeeReader(body, w)
	var parsed logHitSummary
	counts := logHitCounts{Matched: -1, Rows: -1}
	if err := json.NewDecoder(tee).Decode(&parsed); err == nil {
		counts = parsed.counts()
	}
	_, err := io.Copy(io.Discard, tee)
	return counts, err
}

// auditLogSearch records one interactive log read: who, the query and how many
// rows went back, never a row. It replaces the bare path-only line withAudit
// wrote for POST and adds the GET form, which was not recorded at all.
func (s *server) auditLogSearch(r *http.Request, claims jwtClaims, req logSearchReq, status int, counts logHitCounts) {
	if s.audit == nil {
		return
	}
	tenant, cross := principalTenant(claims)
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross, SessionID: claims.Sid,
		Method: auditMethodLogRead, Path: "/api/logs/search", Status: status, Decision: auditDecision(status),
		Remote: auditClientIP(r),
		Detail: map[string]any{
			"action": "logs.search", "signal": strings.ToLower(strings.TrimSpace(req.Signal)),
			"query": auditQueryText(req.Query), "from": req.From, "to": req.To, "offset": req.Offset,
			"matched": counts.Matched, "rows": counts.Rows,
		},
	})
}

func (s *server) handleLogsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requirePerm(w, r, logsReadModule, LevelRead)
	if !ok {
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
	// The SAME refusal logsScope applies to the interactive search (review
	// 2026-09-08, H9). This handler builds its own spec instead of resolving
	// logsScope, so the boundary has to be restated here or the export door
	// stays open on data the search door now refuses. See logsScope for the
	// gate-choice reasoning: findings are read at /api/security/findings, which
	// checks infrastructure:read AND the licence feature.
	if oslog.IsSecFindingsSignal(q.Get("signal")) {
		writeError(w, http.StatusForbidden, logsForbiddenErr(q.Get("signal")))
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
		// Audit BEFORE the job exists: the id is chosen here so the record names
		// it, and a trail that cannot hold the record stops the export.
		spec.ExecutionID = randHex(8)
		if err := s.auditExport(r, claims, tenant, cross, "async", spec, count, spec.ExecutionID); err != nil {
			writeError(w, http.StatusServiceUnavailable, errExportAudit)
			return
		}
		execID, err := s.reportPipeline.EnqueueExport(r.Context(), tenant, spec)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		logInfo("logs.export", "export enqueued", map[string]any{"execution_id": execID, "tenant_id": tenant, "signal": spec.Signal, "format": format, "matched": count})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		out := map[string]any{"execution_id": execID, "status": "queued", "matched": count, "notice": exportIdentityNote}
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
	if err := s.auditExport(r, claims, tenant, cross, "sync", spec, len(data.Rows), ""); err != nil {
		writeError(w, http.StatusServiceUnavailable, errExportAudit)
		return
	}
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

// errExportAudit is what a caller sees when the trail refused the export's
// record. The export did not happen, and the reason is theirs to act on.
var errExportAudit = errors.New("the audit trail could not record this export, so it was not performed - try again shortly")

// auditExport records a sensitive export action into the immutable audit trail
// with the query/size/execution-id detail the hardening spec requires, and
// returns the trail's error so the caller can refuse to deliver.
func (s *server) auditExport(r *http.Request, claims jwtClaims, tenant string, cross bool, mode string, spec logexport.Spec, count int, execID string) error {
	if s.audit == nil {
		return nil
	}
	err := s.audit.RecordStrict(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross, SessionID: claims.Sid,
		Method: "EXPORT", Path: "/api/logs/export", Status: http.StatusOK, Decision: "allow",
		Remote: auditClientIP(r),
		Detail: map[string]any{
			"signal": spec.Signal, "format": spec.Format, "query": auditQueryText(spec.Query),
			"mode": mode, "matched": count, "execution_id": execID,
		},
	})
	if err != nil {
		logError("logs.export", "audit refused an export", map[string]any{"tenant_id": tenant, "mode": mode, "err": err.Error()})
	}
	return err
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
	claims, ok := s.requirePerm(w, r, logsReadModule, LevelRead)
	if !ok {
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
	if err := s.auditExport(r, claims, tenant, cross, "rows", logexport.Spec{Format: format}, len(req.Rows), ""); err != nil {
		writeError(w, http.StatusServiceUnavailable, errExportAudit)
		return
	}
	writeDownload(w, art, name)
}

// ---- async status + signed download ----------------------------------------

// handleExportStatus polls one export execution (tenant-scoped) and, when done,
// returns a signed, expiring download link.
func (s *server) handleExportStatus(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, logsReadModule, LevelRead)
	if !ok {
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
	// The caller's RESOLVED scope, not a bare (tenant, cross) pair: this record
	// carries the export's size, status and — once complete — a signed download
	// URL for the stored rows themselves, so a restricted tenant's export must
	// be as absent here as it is in the list. 404, never 403.
	rec, _, found, err := s.reportPipeline.execs.Get(r.Context(), s.execScope(claims), id)
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
	if exportExpired(rec, time.Now().UTC()) {
		out["expired"] = true
	} else if rec.Status == reports.StatusCompleted {
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
	// Platform scope: the signed token IS the authorization here, and it is
	// bound to the owning tenant (checked below). A tenant downloading its own
	// export is never the operator reading across tenants.
	rec, _, found, err := s.reportPipeline.execs.Get(r.Context(), reports.PlatformExecScope(), execID)
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
	if exportExpired(rec, time.Now().UTC()) {
		writeError(w, http.StatusNotFound, errors.New("export expired - run it again"))
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
	// An empty artifact is the retention sweep's tombstone, not an empty file.
	if err != nil || len(art.Bytes) == 0 {
		writeError(w, http.StatusNotFound, errors.New("artifact unavailable"))
		return
	}
	// Audit the download (link-bearer; tenant from the signed token). Who ASKED is
	// on the EXPORT record with the same execution_id.
	if s.audit != nil {
		if err := s.audit.RecordStrict(AuditEvent{
			Tenant: normTenant(linkTenant), Method: "EXPORT_DOWNLOAD", Path: "/api/exports/view",
			Status: http.StatusOK, Decision: "allow", Remote: auditClientIP(r),
			Detail: map[string]any{"execution_id": execID, "format": ref.Format, "summary": ref.Summary, "bytes": ref.SizeBytes},
		}); err != nil {
			logError("logs.export", "audit refused an export download", map[string]any{"execution_id": execID, "err": err.Error()})
			writeError(w, http.StatusServiceUnavailable, errExportAudit)
			return
		}
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
	w.Header().Set("X-Data-Notice", exportIdentityNote)
	_, _ = w.Write(art.Bytes) // best-effort: status committed; a failed write means the client is gone
}

// exportArtifactRetention is how long a queued export's stored file exists. The
// file exists to be downloaded straight away, and it holds log lines with their
// usernames, so it must not outlive its purpose or the log store it came from
// (D7). Default 24 h; the env value takes a Go duration, and a bad one keeps the
// default rather than turning the limit off.
func exportArtifactRetention() time.Duration {
	return envDuration("EXPORT_ARTIFACT_RETENTION", 24*time.Hour)
}

// exportExpired reports whether an export's stored file is past its retention.
// Every read path asks this, so the limit holds to the minute whatever the
// sweep's timing, and whether or not the sweep has run.
func exportExpired(rec reports.ExecutionRecord, now time.Time) bool {
	at := rec.CompletedAt
	if at.IsZero() {
		at = rec.FireTime
	}
	return !at.IsZero() && now.Sub(at) > exportArtifactRetention()
}

// exportSweepEvery is how often stored export files past retention are removed.
const exportSweepEvery = time.Hour

// exportSweepPage bounds one history read of the sweep; exportSweepMaxPages
// bounds one pass. What is left is reached by the next pass.
const (
	exportSweepPage     = 500
	exportSweepMaxPages = 100
)

// sweepExportArtifacts removes the stored files of exports past retention and
// reports how many it removed. It reads the history as the platform because it
// is infrastructure, not a tenant's request, and touches files only: the
// execution row stays as the record that the export happened. A file already
// removed is skipped, so a pass is idempotent and safe on every replica. One
// unreadable file does not stop the rest; the first error is returned.
func (p *reportPipeline) sweepExportArtifacts(ctx context.Context, now time.Time) (int, error) {
	removed := 0
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	before := now.Add(-exportArtifactRetention())
	for page := 0; page < exportSweepMaxPages; page++ {
		list, err := p.execs.List(ctx, reports.PlatformExecScope(), reports.ExecQuery{Kind: jobTypeExport, Before: before, Limit: exportSweepPage})
		if err != nil {
			note(err)
			return removed, firstErr
		}
		for _, rec := range list {
			if !exportExpired(rec, now) {
				continue
			}
			for _, ref := range rec.Artifacts {
				art, err := p.artifacts.Load(ctx, ref)
				if err != nil {
					note(err)
					continue
				}
				if len(art.Bytes) == 0 {
					continue // already removed by an earlier pass
				}
				if err := p.artifacts.Delete(ctx, ref); err != nil {
					note(err)
					continue
				}
				removed++
			}
		}
		if len(list) < exportSweepPage {
			break
		}
		before = list[len(list)-1].FireTime
	}
	return removed, firstErr
}

// runExportArtifactSweep runs the sweep at start and then on a timer until ctx
// ends. A failed pass is logged and retried on the next tick (§10).
func (p *reportPipeline) runExportArtifactSweep(ctx context.Context) {
	t := time.NewTicker(exportSweepEvery)
	defer t.Stop()
	for {
		sweepCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		removed, err := p.sweepExportArtifacts(sweepCtx, time.Now().UTC())
		cancel()
		if err != nil {
			logError("logs.export", "export artifact sweep incomplete", map[string]any{"removed": removed, "err": err.Error()})
		} else if removed > 0 {
			logInfo("logs.export", "export artifacts past retention removed", map[string]any{"removed": removed})
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
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
		ExcludeTenants: exclude, DenyAll: deny, RequestedBy: claims.Sub,
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

// auditExportDone records what a queued export actually collected. The EXPORT
// record written at request time holds the MATCHED count, taken before the result
// set was read; this one holds the rows in the file. The file is complete by now
// and the download is audited on its own, so a blip here is logged by the store
// and does not fail a finished export.
func (p *reportPipeline) auditExportDone(spec logexport.Spec, execID, tenant, format string, rows, size int) {
	if p.srv == nil || p.srv.audit == nil {
		return
	}
	p.srv.audit.Record(AuditEvent{
		Actor: spec.RequestedBy, Tenant: tenant, Cross: spec.Cross,
		Method: "EXPORT_DONE", Path: "/api/logs/export", Status: http.StatusOK, Decision: "allow",
		Detail: map[string]any{
			"signal": spec.Signal, "format": format, "query": auditQueryText(spec.Query),
			"mode": "async", "rows": rows, "bytes": size, "execution_id": execID,
		},
	})
}

// ---- worker handler (Mode B async, on the shared substrate) ----------------

// EnqueueExport places a log-export job on the shared queue and records its
// immutable execution (kind=export), owned by the requester's tenant so the
// status poll is RLS-scoped to them. Returns the execution id to poll.
func (p *reportPipeline) EnqueueExport(ctx context.Context, tenant string, spec logexport.Spec) (string, error) {
	now := time.Now().UTC()
	tenant = normTenant(tenant)
	execID := spec.ExecutionID
	if execID == "" {
		execID = randHex(8)
	}
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
	p.auditExportDone(spec, job.ExecutionID, tenant, format, len(data.Rows), len(art.Bytes))
	p.metExportDone.Add(1)
	p.metExportRows.Add(int64(len(data.Rows)))
	p.metExportBytes.Add(int64(len(art.Bytes)))
	p.metExportSeconds.Add(int64(done.Sub(startedAt).Seconds()))
	logInfo("logs.export", "export completed", merge(fields, map[string]any{
		"signal": spec.Signal, "format": format, "rows": len(data.Rows), "bytes": len(art.Bytes),
		"seconds": done.Sub(startedAt).Seconds(),
	}))
}
