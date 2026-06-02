package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netops/backend/reports"
)

// report_executions_http.go — read API for the async pipeline's execution
// history. Tenant-scoped via RLS (a scoped principal sees only its own
// executions; the platform owner sees all). Returns 409 on the file backend,
// where durable execution history does not exist (honest, not fabricated).

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
	tenant, cross := principalTenant(claims)
	q := reports.ExecQuery{ScheduleID: r.URL.Query().Get("schedule_id")}
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			q.Limit = n
		}
	}
	if b := r.URL.Query().Get("before"); b != "" {
		if t, err := time.Parse(time.RFC3339, b); err == nil {
			q.Before = t
		}
	}
	list, err := s.reportPipeline.execs.List(r.Context(), tenant, cross, q)
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
	tenant, cross := principalTenant(claims)
	rest := strings.TrimPrefix(r.URL.Path, "/api/reports/executions/")
	id, sub, _ := strings.Cut(rest, "/")
	if id == "" {
		writeError(w, http.StatusBadRequest, errors.New("execution id required"))
		return
	}
	rec, events, found, err := s.reportPipeline.execs.Get(r.Context(), tenant, cross, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !found {
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
		_, _ = w.Write(art.Bytes)
		return
	}

	writeJSON(w, http.StatusOK, struct {
		reports.ExecutionRecord
		Events []reports.ExecEvent `json:"events"`
	}{rec, events})
}
