// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"netops/backend/reports"

	"netops/backend/internal/httppage"
)

// report_executions_http.go — read API for the async pipeline's execution
// history. Tenant-scoped via RLS (a scoped principal sees only its own
// executions; the platform owner sees all). Returns 409 on the file backend,
// where durable execution history does not exist (honest, not fabricated).

// execScope resolves WHO is reading the execution history, ONCE per request: the
// ordinary tenant scope PLUS the per-tenant operator-visibility restriction
// (Tenant.OperatorRestricted), both taken from the shared tenantVisibility
// chokepoint rather than re-derived here.
//
// The restriction has to reach the STORE rather than stop at this handler. An
// execution row carries the rendered SUMMARY of one report fire and the key of
// the stored artifact, and the /artifact branch below STREAMS that artifact —
// the complete HTML/XLSX/PDF document, rendered under the owning tenant's own
// scope, so the tenant's whole report, not a summary of it. The list's LIMIT is
// applied inside the store, so a filter here would hand back a short page whose
// missing rows are themselves the disclosure. tenant_id is the right key: an
// execution row names its owning tenant.
func (s *server) execScope(c jwtClaims) reports.ExecScope {
	v := s.tenantVisibilityFor(c)
	return reports.ExecScope{Tenant: v.tenant, Cross: v.cross, Deny: v.deny, Hidden: v.hiddenTenantIDs()}
}

func (s *server) handleReportExecutions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requirePerm(w, r, "reports", LevelRead)
	if !ok {
		return
	}
	if s.reportPipeline == nil {
		writeError(w, http.StatusConflict, errors.New("execution history requires the Postgres backend (STORE_BACKEND=postgres)"))
		return
	}
	// Same bounded-read contract as every other list endpoint (F-57/F-74
	// class): a parameter is applied as written or refused by name. `limit` and
	// `before` used to have their parse errors discarded, so `?limit=abc` and
	// `?before=yesterday` silently became "no filter" behind a 200.
	if err := httppage.RejectUnknownQuery(r, "schedule_id", "before"); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	limit, err := intQuery(r, "limit", 0, 1, 500)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Scope to report executions only — log exports share the table (kind='export').
	q := reports.ExecQuery{Kind: "report", ScheduleID: r.URL.Query().Get("schedule_id"), Limit: limit}
	if b := r.URL.Query().Get("before"); b != "" {
		t, perr := time.Parse(time.RFC3339, b)
		if perr != nil {
			writeError(w, http.StatusBadRequest, errors.New("before must be an RFC3339 timestamp"))
			return
		}
		q.Before = t
	}
	list, err := s.reportPipeline.execs.List(r.Context(), s.execScope(claims), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if list == nil {
		list = []reports.ExecutionRecord{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *server) handleReportExecutionByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requirePerm(w, r, "reports", LevelRead)
	if !ok {
		return
	}
	if s.reportPipeline == nil {
		writeError(w, http.StatusConflict, errors.New("execution history requires the Postgres backend (STORE_BACKEND=postgres)"))
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/reports/executions/")
	id, sub, _ := strings.Cut(rest, "/")
	if id == "" {
		writeError(w, http.StatusBadRequest, errors.New("execution id required"))
		return
	}
	rec, events, found, err := s.reportPipeline.execs.Get(r.Context(), s.execScope(claims), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !found {
		// 404, never 403: a row hidden by tenancy or by the operator-visibility
		// restriction must be indistinguishable from one that does not exist.
		writeError(w, http.StatusNotFound, errors.New("execution not found"))
		return
	}

	// /api/reports/executions/{id}/artifact[?format=html|xlsx|pdf] streams a stored
	// rendered document (defaults to the HTML/primary artifact).
	if sub == "artifact" {
		ref := rec.PrimaryArtifact()
		if f := r.URL.Query().Get("format"); f != "" {
			ref = rec.ArtifactByFormat(f)
		}
		if ref == nil {
			writeError(w, http.StatusNotFound, errors.New("no artifact for this execution/format"))
			return
		}
		art, err := s.reportPipeline.artifacts.Load(r.Context(), *ref)
		if err != nil {
			writeError(w, http.StatusNotFound, errors.New("artifact unavailable"))
			return
		}
		ct := art.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		w.Header().Set("Content-Type", ct)
		if ref.Format != "html" {
			w.Header().Set("Content-Disposition", "attachment; filename=\"report."+ref.Format+"\"")
		}
		_, _ = w.Write(art.Bytes) // best-effort: status committed; a failed write means the client is gone
		return
	}

	writeJSON(w, http.StatusOK, struct {
		reports.ExecutionRecord
		Events []reports.ExecEvent `json:"events"`
	}{rec, events})
}
