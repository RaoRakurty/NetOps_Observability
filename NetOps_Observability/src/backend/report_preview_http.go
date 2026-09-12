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
	now := time.Now().UTC()
	o := saved.Object{ID: "preview", Type: "report", Name: name, TenantID: tenant, Body: req.Body, CreatedAt: now}

	// Operator-visibility (Tenant.OperatorRestricted) has to be answered HERE,
	// not by the dataset builder, and that is structural rather than an omission.
	//
	// buildViewModel resolves a scheduled run's scope from the REPORT'S OWN
	// tenant, and it is right to: a tenant-owned schedule is that tenant's own
	// view of its own estate, which the restriction never touches — it hides a
	// tenant from the PLATFORM, never from itself. The preview stamps the
	// CALLER's tenant onto its synthetic object, so an operator previewing with
	// ?as_tenant=<restricted> arrives at that builder wearing the tenant's own
	// clothes and is served the tenant's own data. No filter inside the builder
	// can tell the two apart, because by then they are the same object.
	//
	// The caller's scope is the thing that differs, so the caller's scope is
	// what is asked — once, through the shared resolver, before any dataset is
	// gathered. Denied means nothing is READ: alerts, devices, health, WAN,
	// security and utilisation all come from this one builder, so one gate
	// closes the whole route. The answer is the same "serve nothing, 200" the
	// alert, topology and flow surfaces give this scope — never a 403, which
	// would confirm what it refuses.
	//
	// The GLOBAL half needs no gate here: with no as_tenant the synthetic report
	// is platform-owned, and the platform scope already excludes the restricted
	// tenants' alerts, devices and telemetry (report_scheduler.go).
	vm := emptyReportViewModel(o, spec, now)
	if !s.restrictedTelemetry(claims).deny {
		vm = s.reports.buildViewModel(o, spec, now)
	}

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
