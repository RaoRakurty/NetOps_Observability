package main

// rca_report_http.go — GET /api/correlations/{id}/rca-report[?format=json|html|pdf]
//
// The canonical, server-side RCA report (rca_report.go). Same permission gate
// and tenant scope as every other correlation read: dispatched from
// handleCorrelationByID AFTER requirePerm(infrastructure, read); every
// ClickHouse read goes through loadCorrSlice → chTenantScope → CH row policies;
// ticket + policy reads go through the RLS-scoped ticketing store. The PDF is
// rendered by the existing Gotenberg sidecar seam (REPORT_PDF_SIDECAR_URL) with
// a CONTROLLED header/footer — no browser print chrome can appear (§18).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

func (s *server) serveRcaReport(w http.ResponseWriter, r *http.Request, id string) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("authentication required"))
		return
	}
	version := intQuery(r, "version", 0, 0, 1<<30)
	meta, sigRows, evRows, edgeRows, status, err := s.loadCorrSlice(r.Context(), chTenantScope(r), id, version)
	if err != nil {
		writeError(w, status, err)
		return
	}
	trigger := fmt.Sprintf("%v", meta["trigger_signal"])
	// stamps attached/link_status onto sigRows (the same derivation the timeline uses)
	_ = mergeTimelineEvidence(sigRows, evRows, edgeRows, trigger)

	// ticket + policy — RLS-scoped store reads; default policy is labelled as such.
	ticket := s.ticketStatusForObject(r, id)
	tenant, cross := principalTenant(claims)
	pol := defaultIncidentPolicy(tenant)
	configured := false
	if s.ticketing != nil {
		if pols, err := s.ticketing.ListPolicies(r.Context(), tenant, cross); err == nil {
			for _, p := range pols {
				if p.Enabled {
					pol, configured = p, true
					break
				}
			}
		}
	}

	pathBlock := s.rcaPathBlock(r.Context(), r, id, fmt.Sprintf("%v", meta["verdict_tier"]), fmt.Sprintf("%v", meta["top_hypothesis"]))
	rep := buildRcaReport(rcaReportInput{
		ID: id, Meta: meta, Signals: sigRows, Edges: edgeRows,
		Ticket: ticket, Policy: pol, PolicyConfigured: configured,
		Path: pathBlock,
		Now:  time.Now().UTC(),
	})
	rep.Topology = rcaTopologyFromSpine(pathBlock)

	switch strings.ToLower(r.URL.Query().Get("format")) {
	case "", "json":
		writeJSON(w, http.StatusOK, rep)
	case "html":
		html, err := renderRcaReportHTML(rep)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(html)
	case "pdf":
		html, err := renderRcaReportHTML(rep)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		pdf, err := s.rcaReportPDF(r.Context(), rep, html)
		if err != nil {
			// Honest degradation: the caller falls back to the HTML view; we never
			// silently produce a browser-printed artifact from here.
			writeError(w, http.StatusServiceUnavailable,
				fmt.Errorf("pdf renderer unavailable: %w (fetch ?format=html and print, or start the pdf sidecar)", err))
			return
		}
		fname := fmt.Sprintf("%s-%s.pdf", strings.ToLower(strings.ReplaceAll(rep.ReportType, " ", "-")), rep.DisplayID)
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pdf)
	default:
		writeError(w, http.StatusBadRequest, errors.New("format must be json, html or pdf"))
	}
}

// rcaReportPDF converts the report HTML via the Gotenberg sidecar with a
// controlled header/footer (report type · display id · page X of Y · generated
// timestamp · confidentiality marking). Fails closed when the sidecar is not
// configured — the endpoint degrades to the HTML view, never to browser chrome.
func (s *server) rcaReportPDF(ctx context.Context, rep rcaReport, html []byte) ([]byte, error) {
	url := strings.TrimSpace(os.Getenv("REPORT_PDF_SIDECAR_URL"))
	if url == "" {
		return nil, errors.New("REPORT_PDF_SIDECAR_URL not configured")
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	addFile := func(name string, content []byte) error {
		fw, err := mw.CreateFormFile("files", name)
		if err != nil {
			return err
		}
		_, err = fw.Write(content)
		return err
	}
	if err := addFile("index.html", html); err != nil {
		return nil, err
	}
	// Gotenberg header/footer documents: only inline styles; special classes
	// pageNumber/totalPages are substituted by Chromium's print engine.
	head := fmt.Sprintf(`<html><head></head><body><div style="font:9px -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#667085;width:100%%;padding:0 14mm;display:flex;justify-content:space-between"><span>CORRELIX · %s</span><span>%s</span></div></body></html>`,
		htmlEscape(rep.ReportType), htmlEscape(rep.DisplayID))
	foot := fmt.Sprintf(`<html><head></head><body><div style="font:9px -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#667085;width:100%%;padding:0 14mm;display:flex;justify-content:space-between"><span>Generated %s · Confidential</span><span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div></body></html>`,
		htmlEscape(rep.GeneratedAt))
	if err := addFile("header.html", []byte(head)); err != nil {
		return nil, err
	}
	if err := addFile("footer.html", []byte(foot)); err != nil {
		return nil, err
	}
	for k, v := range map[string]string{
		"marginTop": "0.55", "marginBottom": "0.55", "marginLeft": "0.4", "marginRight": "0.4",
		"printBackground": "true", "preferCssPageSize": "false", "paperWidth": "8.27", "paperHeight": "11.7",
	} {
		if err := mw.WriteField(k, v); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pdf sidecar returned %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// rcaTopologyFromSpine projects the §7 spine block onto the report's topology
// view (§15): measured hops only, honest absence otherwise.
func rcaTopologyFromSpine(block any) rcaTopologyView {
	resp, ok := block.(pathSpineResponse)
	if !ok || resp.Spine == nil || !resp.SpineAvailable {
		reason := "No measured path is attached to this case — the topology is omitted, not inferred."
		if ok && resp.Reason != "" {
			reason = resp.Reason
		}
		return rcaTopologyView{Available: false, Reason: reason}
	}
	out := rcaTopologyView{
		Available: true, VantageID: resp.VantageID,
		ObservedAt: resp.ObservedAt, Stale: resp.Stale,
	}
	for _, n := range resp.Spine.Spine {
		out.Hops = append(out.Hops, rcaSpineHopView{
			Index: n.Index, Label: n.Label, Address: n.Address,
			Kind: n.Kind, Boundary: n.Boundary, State: n.State, SeamID: n.SeamID,
			Fault: n.Fault, Provider: n.Provider,
		})
		if n.Fault != "" {
			// The path's own causality statement: where the measurement died.
			out.DropPoint = fmt.Sprintf(
				"The measured path dies after %s (%s boundary) — every later hop went dark. This drop point is consistent with the propagation ladder's origin.",
				orDefault(n.Label, n.Address), strings.ToLower(orDefault(n.Boundary, "unknown")))
		}
	}
	return out
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
