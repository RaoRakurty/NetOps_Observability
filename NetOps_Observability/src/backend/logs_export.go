package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netops/backend/reports"
)

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

const (
	jobTypeReport = "report"
	jobTypeExport = "export"
)

// errExportTooLarge is a deterministic (non-retryable) failure: the matched set
// exceeds the configured caps. The caller surfaces an actionable message.
var errExportTooLarge = errors.New("export exceeds configured size limit")

// logExportSpec is the frozen, self-contained parameter set for one export — the
// job payload for Mode B and the request shape for Mode A's query path.
type logExportSpec struct {
	Query  string `json:"query"`
	From   string `json:"from"` // RFC3339 / unix
	To     string `json:"to"`
	Signal string `json:"signal"`
	Format string `json:"format"` // csv | json | ndjson | xlsx

	// Frozen tenant-visibility snapshot: the async worker reproduces exactly what
	// the requester could see at request time (the device set may change later).
	Tenant      string   `json:"tenant,omitempty"` // #20 Phase 3: caller's tenant for index routing + tenant_id filter
	Cross       bool     `json:"cross"`
	DeviceKeys  []string `json:"device_keys,omitempty"`
	DeviceAddrs []string `json:"device_addrs,omitempty"`
}

// exportColumns is the canonical tabular projection used for csv/xlsx (and for
// json/ndjson when no raw document is available, i.e. Mode A selected rows).
var exportColumns = []string{"time", "source", "level", "message"}

func normalizeExportFormat(f string) string {
	f = strings.ToLower(strings.TrimSpace(f))
	switch f {
	case "csv", "json", "ndjson", "xlsx":
		return f
	case "", "excel", "xls":
		if f == "excel" || f == "xls" {
			return "xlsx"
		}
		return "csv"
	default:
		return ""
	}
}

func exportContentType(format string) (contentType, ext string) {
	switch format {
	case "csv":
		return "text/csv; charset=utf-8", "csv"
	case "json":
		return "application/json", "json"
	case "ndjson":
		return "application/x-ndjson", "ndjson"
	case "xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"
	default:
		return "application/octet-stream", "bin"
	}
}

// ---- query construction + paging -------------------------------------------

// buildExportSearchBody mirrors handleLogsSearch's tenant scoping but sorts
// ascending with an _id tiebreaker so search_after pages deterministically.
func buildExportSearchBody(spec logExportSpec, start, end time.Time, size int, searchAfter []any) map[string]any {
	filters := []any{
		map[string]any{"range": map[string]any{"timestamp": map[string]string{
			"gte": start.Format(time.RFC3339),
			"lte": end.Format(time.RFC3339),
		}}},
	}
	// Tenant isolation (#20 Phase 3) — same index-pattern + tenant_id/device clause
	// as handleLogsSearch, frozen onto the spec. The platform owner (Cross) is
	// unrestricted; the read index pattern (tenantIndexPattern) already excludes
	// other tenants' indices at the storage layer.
	if f := osTenantFilter(spec.Tenant, spec.Cross, spec.DeviceKeys, spec.DeviceAddrs); f != nil {
		filters = append(filters, f)
	}
	body := map[string]any{
		"size": size,
		"sort": []any{
			map[string]any{"timestamp": map[string]string{"order": "asc", "unmapped_type": "date"}},
			map[string]any{"_id": "asc"}, // unique tiebreaker for search_after
		},
		"query": map[string]any{"bool": map[string]any{
			"must": []any{map[string]any{"query_string": map[string]any{
				"query":            queryOrAll(spec.Query),
				"analyze_wildcard": true,
			}}},
			"filter": filters,
		}},
	}
	if len(searchAfter) > 0 {
		body["search_after"] = searchAfter
	}
	return body
}

// osHit is the slice of a _search response we consume.
type osSearchResp struct {
	Hits struct {
		Hits []struct {
			Index  string          `json:"_index"`
			ID     string          `json:"_id"`
			Source json.RawMessage `json:"_source"`
			Sort   []any           `json:"sort"`
		} `json:"hits"`
	} `json:"hits"`
}

// exportData is the accumulated, bounded result of an export query. raw carries
// the verbatim _source per row (lossless json/ndjson); rows carries the canonical
// tabular projection (csv/xlsx). Both are bounded by the caps.
type exportData struct {
	rows  [][]string
	raw   []json.RawMessage
	bytes int
}

// fetchLogsBounded pages the tenant-scoped query with search_after, accumulating
// rows under maxRows/maxBytes. Exceeding either cap is a deterministic failure
// (errExportTooLarge) rather than a silent truncation. Memory is bounded by the
// caps (the honest Phase-1 contract; a streaming sink is a later substrate add).
func fetchLogsBounded(ctx context.Context, spec logExportSpec, start, end time.Time, maxRows, maxBytes int) (exportData, error) {
	const batch = 1000
	index := tenantIndexPattern(spec.Signal, spec.Tenant, spec.Cross)
	var data exportData
	var after []any
	for {
		select {
		case <-ctx.Done():
			return data, ctx.Err()
		default:
		}
		body := buildExportSearchBody(spec, start, end, batch, after)
		resp, err := openSearch("POST", "/"+index+"/_search", body)
		if err != nil {
			return data, err
		}
		var parsed osSearchResp
		decErr := json.NewDecoder(resp.Body).Decode(&parsed)
		_ = resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return data, fmt.Errorf("opensearch search status %d", resp.StatusCode)
		}
		if decErr != nil {
			return data, decErr
		}
		hits := parsed.Hits.Hits
		if len(hits) == 0 {
			break
		}
		for i := range hits {
			h := hits[i]
			data.bytes += len(h.Source)
			data.rows = append(data.rows, flattenLogSource(h.Source, h.Index))
			data.raw = append(data.raw, h.Source)
			if len(data.rows) > maxRows {
				return data, fmt.Errorf("%w: more than %d rows match — narrow the query or time range", errExportTooLarge, maxRows)
			}
			if data.bytes > maxBytes {
				return data, fmt.Errorf("%w: result exceeds %d bytes — narrow the query or time range", errExportTooLarge, maxBytes)
			}
		}
		after = hits[len(hits)-1].Sort
		if len(hits) < batch || len(after) == 0 {
			break
		}
	}
	return data, nil
}

// flattenLogSource projects one log document to the canonical [time, source,
// level, message] row, matching the Logs UI's resolution (flow rows show the
// real source host, not the collector container).
func flattenLogSource(raw json.RawMessage, index string) []string {
	var s map[string]any
	if err := json.Unmarshal(raw, &s); err != nil {
		return []string{"", "", "", string(raw)}
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := s[k]; ok && v != nil {
				if vs := fmt.Sprintf("%v", v); vs != "" {
					return vs
				}
			}
		}
		return ""
	}
	ts := str("@timestamp", "timestamp", "ts", "time", "time_received_ns")
	level := str("level", "severity")
	source := str("src_addr") // flow source host wins over the collector container
	if source == "" {
		source = str("compose_service", "container_name", "hostname", "appname")
	}
	if source == "" {
		source = index
	}
	message := str("message", "msg")
	if message == "" {
		message = string(raw)
	}
	return []string{ts, source, level, message}
}

// ---- encoders --------------------------------------------------------------

// encodeExport renders accumulated data to the requested format. json/ndjson use
// the verbatim documents when present (lossless), else the tabular projection.
func encodeExport(ctx context.Context, format string, cols []string, data exportData) (reports.Artifact, error) {
	contentType, _ := exportContentType(format)
	switch format {
	case "csv":
		var buf bytes.Buffer
		w := csv.NewWriter(&buf)
		_ = w.Write(cols)
		for _, r := range data.rows {
			if err := w.Write(r); err != nil {
				return reports.Artifact{}, err
			}
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return reports.Artifact{}, err
		}
		return reports.Artifact{Format: format, ContentType: contentType, Bytes: buf.Bytes(), Summary: exportSummary(len(data.rows))}, nil

	case "ndjson":
		var buf bytes.Buffer
		if len(data.raw) > 0 {
			for _, raw := range data.raw {
				buf.Write(raw)
				buf.WriteByte('\n')
			}
		} else {
			enc := json.NewEncoder(&buf)
			for _, r := range data.rows {
				if err := enc.Encode(rowObject(cols, r)); err != nil {
					return reports.Artifact{}, err
				}
			}
		}
		return reports.Artifact{Format: format, ContentType: contentType, Bytes: buf.Bytes(), Summary: exportSummary(len(data.rows))}, nil

	case "json":
		var out []byte
		var err error
		if len(data.raw) > 0 {
			var buf bytes.Buffer
			buf.WriteByte('[')
			for i, raw := range data.raw {
				if i > 0 {
					buf.WriteByte(',')
				}
				buf.Write(raw)
			}
			buf.WriteByte(']')
			out = buf.Bytes()
		} else {
			objs := make([]map[string]string, 0, len(data.rows))
			for _, r := range data.rows {
				objs = append(objs, rowObject(cols, r))
			}
			out, err = json.Marshal(objs)
			if err != nil {
				return reports.Artifact{}, err
			}
		}
		return reports.Artifact{Format: format, ContentType: contentType, Bytes: out, Summary: exportSummary(len(data.rows))}, nil

	case "xlsx":
		vm := reports.ViewModel{
			ReportName:  "Log export",
			Kind:        "logs",
			GeneratedAt: time.Now().UTC(),
			Sections:    []reports.Section{{Title: "Logs", Header: cols, Rows: data.rows}},
		}
		return reports.NewXLSXRenderer().Render(ctx, vm)

	default:
		return reports.Artifact{}, fmt.Errorf("unsupported export format %q", format)
	}
}

func rowObject(cols, row []string) map[string]string {
	m := make(map[string]string, len(cols))
	for i, c := range cols {
		if i < len(row) {
			m[c] = row[i]
		}
	}
	return m
}

func exportSummary(n int) string { return fmt.Sprintf("%d log rows", n) }

// ---- Mode B: GET /api/logs/export (entire result set) ----------------------

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
	format := normalizeExportFormat(q.Get("format"))
	if format == "" {
		writeError(w, http.StatusBadRequest, errors.New("format must be csv, json, ndjson, or xlsx"))
		return
	}
	tenant, cross := principalTenant(claims)
	if !s.exportLimiter.allow(tenant) {
		writeError(w, http.StatusTooManyRequests, errors.New("export rate limit exceeded for this tenant — try again shortly"))
		return
	}
	start, end := exportTimeRange(q.Get("from"), q.Get("to"))
	if cap := exportMaxTimeRange(); cap > 0 && end.Sub(start) > cap {
		writeError(w, http.StatusBadRequest, fmt.Errorf("export window %s exceeds the maximum of %s — narrow the time range", end.Sub(start).Round(time.Minute), cap))
		return
	}
	spec := s.exportSpecFor(claims, q.Get("query"), q.Get("from"), q.Get("to"), q.Get("signal"), format)

	// Decide sync vs async by the matched count (cheap _count), unless forced.
	mode := strings.ToLower(q.Get("mode"))
	count, _ := countLogs(r.Context(), spec, start, end)
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
		_ = json.NewEncoder(w).Encode(map[string]any{"execution_id": execID, "status": "queued", "matched": count})
		return
	}

	// Sync: bounded fetch → encode → stream.
	data, err := fetchLogsBounded(r.Context(), spec, start, end, envInt("MAX_EXPORT_ROWS", 500_000), envInt("MAX_EXPORT_BYTES", 256*1024*1024))
	if err != nil {
		if errors.Is(err, errExportTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, err)
			return
		}
		writeError(w, http.StatusBadGateway, err)
		return
	}
	art, err := encodeExport(r.Context(), format, exportColumns, data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.auditExport(r, claims, tenant, cross, "sync", spec, len(data.rows), "")
	logInfo("logs.export", "export delivered (sync)", map[string]any{"tenant_id": tenant, "signal": spec.Signal, "format": format, "rows": len(data.rows), "bytes": len(art.Bytes)})
	writeDownload(w, art, "logs-export")
}

// auditExport records a sensitive export action into the immutable audit trail
// with the query/size/execution-id detail the hardening spec requires.
func (s *server) auditExport(r *http.Request, claims jwtClaims, tenant string, cross bool, mode string, spec logExportSpec, count int, execID string) {
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
	if !s.exportLimiter.allow(tenant) {
		writeError(w, http.StatusTooManyRequests, errors.New("export rate limit exceeded for this tenant — try again shortly"))
		return
	}
	var req exportRowsReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	format := normalizeExportFormat(req.Format)
	if format == "" {
		writeError(w, http.StatusBadRequest, errors.New("format must be csv, json, ndjson, or xlsx"))
		return
	}
	cols := req.Columns
	if len(cols) == 0 {
		cols = exportColumns
	}
	if len(req.Rows) > envInt("MAX_EXPORT_ROWS", 500_000) {
		writeError(w, http.StatusRequestEntityTooLarge, errExportTooLarge)
		return
	}
	art, err := encodeExport(r.Context(), format, cols, exportData{rows: req.Rows})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	name := req.Filename
	if name == "" {
		name = "logs-export"
	}
	s.auditExport(r, claims, tenant, cross, "rows", logExportSpec{Format: format}, len(req.Rows), "")
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
	_ = json.NewEncoder(w).Encode(out)
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
	token := strings.TrimPrefix(r.URL.Path, "/api/exports/view/")
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
	if f := normalizeExportFormat(r.URL.Query().Get("format")); f != "" {
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
	_, ext := exportContentType(art.Format)
	w.Header().Set("Content-Type", art.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", basename+"."+ext))
	w.Header().Set("Content-Length", strconv.Itoa(len(art.Bytes)))
	// A forwarded link must not leak the (capability-bearing) URL via Referer.
	w.Header().Set("Referrer-Policy", "no-referrer")
	_, _ = w.Write(art.Bytes)
}

// exportMaxTimeRange bounds how wide an export window may be (anti-exfiltration /
// anti-unbounded-scan). Default 7 days; 0 or negative disables the cap.
func exportMaxTimeRange() time.Duration {
	return envDuration("MAX_EXPORT_TIME_RANGE", 7*24*time.Hour)
}

// ---- helpers shared with the worker ----------------------------------------

// exportSpecFor builds a spec with the caller's tenant-visibility frozen in.
func (s *server) exportSpecFor(claims jwtClaims, query, from, to, signal, format string) logExportSpec {
	keys, cross := s.visibleDeviceKeys(claims)
	addrs, _ := s.visibleDeviceAddrs(claims)
	tenant, _ := principalTenant(claims)
	return logExportSpec{
		Query: query, From: from, To: to, Signal: signal, Format: format,
		Tenant: tenant, Cross: cross, DeviceKeys: keys, DeviceAddrs: addrs,
	}
}

func exportTimeRange(from, to string) (time.Time, time.Time) {
	end := time.Now().UTC()
	start := end.Add(-15 * time.Minute)
	if from != "" {
		if t, err := parseTimeFlexible(from); err == nil {
			start = t
		}
	}
	if to != "" {
		if t, err := parseTimeFlexible(to); err == nil {
			end = t
		}
	}
	return start, end
}

// countLogs returns the matched document count for an export query (cheap; used
// to choose sync vs async). A failure returns 0 so the caller falls back to sync.
func countLogs(ctx context.Context, spec logExportSpec, start, end time.Time) (int, error) {
	body := buildExportSearchBody(spec, start, end, 0, nil)
	delete(body, "size")
	delete(body, "sort")
	resp, err := openSearch("POST", "/"+tenantIndexPattern(spec.Signal, spec.Tenant, spec.Cross)+"/_count", map[string]any{"query": body["query"]})
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
func (p *reportPipeline) EnqueueExport(ctx context.Context, tenant string, spec logExportSpec) (string, error) {
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
	_ = p.execs.RecordEvent(ctx, tenant, execID, reports.PhaseQueued, now, "log export")
	return execID, nil
}

// processExport runs a log-export job: page OpenSearch (bounded) → encode →
// store artifact → complete. ctx is the parent (durable writes); jctx the job
// timeout. The execution is already marked running by process().
func (p *reportPipeline) processExport(ctx, jctx context.Context, _ string, job reports.Job, tenant string, fields map[string]any) {
	startedAt := time.Now().UTC()
	var spec logExportSpec
	if err := json.Unmarshal(job.Payload, &spec); err != nil {
		p.fail(ctx, jctx, job, tenant, "invalid export spec: "+err.Error(), nil, true, fields)
		p.metExportFailed.Add(1)
		return
	}
	format := normalizeExportFormat(spec.Format)
	if format == "" {
		p.fail(ctx, jctx, job, tenant, "unsupported export format: "+spec.Format, nil, true, fields)
		p.metExportFailed.Add(1)
		return
	}
	start, end := exportTimeRange(spec.From, spec.To)

	_ = p.execs.RecordEvent(jctx, tenant, job.ExecutionID, reports.PhaseExporting, time.Now().UTC(), spec.Signal)
	data, err := fetchLogsBounded(jctx, spec, start, end, envInt("MAX_EXPORT_ROWS", 500_000), envInt("MAX_EXPORT_BYTES", 256*1024*1024))
	if err != nil {
		// Size-cap breaches are deterministic → dead-letter, don't retry.
		dead := errors.Is(err, errExportTooLarge) || p.dead(job)
		p.fail(ctx, jctx, job, tenant, "export query: "+err.Error(), nil, dead, fields)
		p.metExportFailed.Add(1)
		return
	}
	art, err := encodeExport(jctx, format, exportColumns, data)
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
	if err := p.execs.Complete(ctx, job.ExecutionID, done, []reports.ArtifactRef{ref}, nil); err != nil {
		logError("logs.export", "record completion", merge(fields, errf(err)))
	}
	_ = p.execs.RecordEvent(ctx, tenant, job.ExecutionID, reports.PhaseCompleted, done, "")
	if err := p.queue.Complete(ctx, job.ID); err != nil {
		logError("logs.export", "finalize job", merge(fields, errf(err)))
	}
	p.metExportDone.Add(1)
	p.metExportRows.Add(int64(len(data.rows)))
	p.metExportBytes.Add(int64(len(art.Bytes)))
	p.metExportSeconds.Add(int64(done.Sub(startedAt).Seconds()))
	logInfo("logs.export", "export completed", merge(fields, map[string]any{
		"signal": spec.Signal, "format": format, "rows": len(data.rows), "bytes": len(art.Bytes),
		"seconds": done.Sub(startedAt).Seconds(),
	}))
}
