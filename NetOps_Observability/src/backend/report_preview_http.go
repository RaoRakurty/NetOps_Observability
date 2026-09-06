// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"errors"
	"net/http"
	"netops/backend/internal/saved"
	"sync"
	"time"

	"netops/backend/reports"
)

// report_preview_http.go — POST /api/reports/preview renders a report's dataset
// to HTML (or ?format=xlsx) on demand, WITHOUT enqueuing a job, writing an
// execution, or delivering anything. It powers the builder's live preview /
// "what will this look like" pane. Works on both backends (it only needs the
// dataset builder + a renderer, not the queue).

var previewRenderers = sync.OnceValues(func() (html, xlsx reports.Renderer) {
	html, _ = reports.NewHTMLRenderer() // embedded templates, validated at boot by the pipeline; cannot fail here
	return html, reports.NewXLSXRenderer()
})

func previewRenderer(format string) reports.Renderer {
	html, xlsx := previewRenderers()
	if format == "xlsx" {
		return xlsx
	}
	return html
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
	// A synthetic, in-scope saved.Object so the dataset is gathered in the caller's
	// tenant view exactly as a scheduled run would be.
	o := saved.Object{ID: "preview", Type: "report", Name: name, TenantID: tenant, Body: req.Body, CreatedAt: time.Now().UTC()}
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
	_, _ = w.Write(art.Bytes) // best-effort: status committed; a failed write means the client is gone
}
