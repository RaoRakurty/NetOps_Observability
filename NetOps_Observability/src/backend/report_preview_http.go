package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"netops/backend/reports"
)

// report_preview_http.go — POST /api/reports/preview renders a report's dataset
// to HTML (or ?format=xlsx) on demand, WITHOUT enqueuing a job, writing an
// execution, or delivering anything. It powers the builder's live preview /
// "what will this look like" pane. Works on both backends (it only needs the
// dataset builder + a renderer, not the queue).

var (
	previewOnce sync.Once
	previewHTML reports.Renderer
	previewXLSX reports.Renderer
)

func previewRenderer(format string) reports.Renderer {
	previewOnce.Do(func() {
		previewHTML, _ = reports.NewHTMLRenderer()
		previewXLSX = reports.NewXLSXRenderer()
	})
	if format == "xlsx" {
		return previewXLSX
	}
	return previewHTML
}

func (s *server) handleReportPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requirePerm(w, r, "reports", LevelRead)
	if !ok {
		return
	}
	var req struct {
		Name string          `json:"name"`
		Body json.RawMessage `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Body) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("report body required"))
		return
	}
	spec, err := parseReportSpec(req.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	tenant, _ := principalTenant(claims)
	name := req.Name
	if name == "" {
		name = "Preview"
	}
	// A synthetic, in-scope SavedObject so the dataset is gathered in the caller's
	// tenant view exactly as a scheduled run would be.
	o := SavedObject{ID: "preview", Type: "report", Name: name, TenantID: tenant, Body: req.Body, CreatedAt: time.Now().UTC()}
	vm := s.reports.buildViewModel(o, spec, time.Now().UTC())

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "html"
	}
	rend := previewRenderer(format)
	if rend == nil {
		writeError(w, http.StatusBadRequest, errors.New("unknown preview format"))
		return
	}
	art, err := rend.Render(r.Context(), vm)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", art.ContentType)
	if format != "html" {
		w.Header().Set("Content-Disposition", "attachment; filename=\"preview."+format+"\"")
	}
	_, _ = w.Write(art.Bytes)
}
