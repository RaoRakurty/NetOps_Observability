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
	"netops/backend/internal/rca"
	"netops/backend/internal/ticketing"
	"os"
	"strings"
	"time"

	"netops/backend/timeintel"
)

// buildRcaReportForID is THE shared report-build path: tenant-scoped slice load
// → timeline-evidence merge → ticket/policy → path block → merge-chain →
// rca.BuildReport → promotion evaluation (#113 point 3). Both the per-case
// endpoint (serveRcaReport) and the RCA-reports library list call it — the
// pipeline exists exactly once. Every ClickHouse read runs under the CALLER's
// chTenantScope (row policies), every store read is RLS/tenant-scoped. On
// failure it returns the HTTP status to answer with (404 for an invisible or
// absent id — never revealing whether it exists elsewhere).
func (s *server) buildRcaReportForID(r *http.Request, claims jwtClaims, id string, version int) (rca.Report, int, error) {
	meta, sigRows, evRows, edgeRows, status, err := s.loadCorrSlice(r.Context(), chTenantScope(r), id, version)
	if err != nil {
		return rca.Report{}, status, err
	}
	trigger := fmt.Sprintf("%v", meta["trigger_signal"])
	// stamps attached/link_status onto sigRows (the same derivation the timeline uses)
	_ = rca.MergeTimelineEvidence(sigRows, evRows, edgeRows, trigger)

	// ticket + policy — RLS-scoped store reads; default policy is labelled as such.
	ticket := s.ticketStatusForObject(r, id)
	tenant, cross := principalTenant(claims)
	pol := ticketing.DefaultIncidentPolicy(tenant)
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
	// Merged/superseded source case: resolve the TERMINAL surviving incident,
	// tenant-scoped and cycle-safe (resolveMergeChain never crosses the owning
	// tenant boundary). The builder derives the merge record from this + meta.
	survivingID := ""
	if _, isMerged := rca.MergeIncidentState(asString(meta["state"])); isMerged {
		if first := asString(meta["merged_into"]); first != "" {
			owner := canonicalCorrTenant(asString(meta["tenant_id"]))
			survivingID, _ = s.resolveMergeChain(r.Context(), chTenantScope(r), owner, id, first)
		}
	}
	// Manual/ITSM lifecycle stamps (tenant-scoped store) feed the detection
	// milestones (postmortem spec §1) — absent events stay absent milestones.
	lc := timeintel.Lifecycle{}
	if !s.manualLifecycle(r, claims, id, lc) {
		lc = nil
	}
	rep := rca.BuildReport(rca.ReportInput{
		ID: id, Meta: meta, Signals: sigRows, Edges: edgeRows,
		Ticket: ticket, Policy: pol, PolicyConfigured: configured,
		Path:                pathBlock,
		Now:                 time.Now().UTC(),
		SurvivingIncidentID: survivingID,
		Lifecycle:           lc,
	})
	rep.Topology = rcaTopologyFromSpine(pathBlock)
	rca.StampTopologyTemporalRole(&rep)

	// #113 point 3 — RCA creation policy. Candidates and RCA documents are
	// different tiers: JSON (the workspace's data) stays fully readable, but the
	// DOCUMENT (html/pdf) renders only for a promoted real outage — auto
	// (confirmed verdict + confirmed user/app impact + duration) or an explicit,
	// audited manual promotion. The refusal names the unmet criteria.
	var manual *rca.PromotionRecord
	if rec, has := s.rcaPromotions.get(canonicalCorrTenant(asString(meta["tenant_id"])), id); has {
		manual = &rec
	}
	rep.Promotion = rca.EvaluatePromotion(&rep, manual)
	// Artifact class depends on promotion — re-stamp now that it is known
	// (postmortem spec: operational/validation/preliminary; interim/final are
	// Phase 3 human lifecycle advances, none recorded yet).
	rca.StampReportMaturity(&rep, "")
	rep.SetOwnerTenant(canonicalCorrTenant(asString(meta["tenant_id"])))
	return rep, http.StatusOK, nil
}

func (s *server) serveRcaReport(w http.ResponseWriter, r *http.Request, id string) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("authentication required"))
		return
	}
	version, errVersion := intQuery(r, "version", 0, 0, 1<<30)
	if errVersion != nil {
		writeError(w, http.StatusBadRequest, errVersion)
		return
	}
	rep, status, err := s.buildRcaReportForID(r, claims, id, version)
	if err != nil {
		writeError(w, status, err)
		return
	}

	format := strings.ToLower(r.URL.Query().Get("format"))
	if (format == "html" || format == "pdf") && !rep.Promotion.Promoted {
		writeError(w, http.StatusForbidden, errors.New(rep.Promotion.Reason))
		return
	}

	// Immutability (postmortem Phase 1): every response embeds the integrity
	// block — analysis snapshot hash, policy + template versions, status-as-of.
	// A rendered DOCUMENT additionally lands in the tenant-scoped revision
	// register with its content hash; an identical regeneration reuses the
	// existing (immutable) revision.
	integ, ierr := rca.ComputeReportIntegrity(rep)
	if ierr != nil {
		writeError(w, http.StatusInternalServerError, ierr)
		return
	}
	rep.Integrity = &integ

	switch format {
	case "", "json":
		writeJSON(w, http.StatusOK, rep)
	case "html":
		html, err := rca.RenderReportHTML(rep)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		integ.ContentHash = rca.HashContent(html)
		s.recordReportRevision(claims, rep.OwnerTenant(), id, rep, integ, "html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(html) // #nosec G705 -- html/template output (auto-escaped) served under a default-src 'none' CSP
	case "pdf":
		html, err := rca.RenderReportHTML(rep)
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
		integ.ContentHash = rca.HashContent(pdf)
		s.recordReportRevision(claims, rep.OwnerTenant(), id, rep, integ, "pdf")
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
func (s *server) rcaReportPDF(ctx context.Context, rep rca.Report, html []byte) ([]byte, error) {
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
	// The running HEADER is intentionally empty: page 1 already carries the
	// document masthead (CORRELIX · report type · display id), and a running
	// header repeating the same words directly above it read as a defect.
	// Every page-level identifier lives in the running FOOTER instead.
	head := `<html><head></head><body><div style="font:9px sans-serif"></div></body></html>`
	foot := fmt.Sprintf(`<html><head></head><body><div style="font:9px -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#667085;width:100%%;padding:0 14mm;display:flex;justify-content:space-between"><span>CORRELIX · %s · %s · Generated %s · Confidential</span><span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div></body></html>`,
		htmlEscape(rep.ReportType), htmlEscape(rep.DisplayID), htmlEscape(rep.GeneratedAt))
	if err := addFile("header.html", []byte(head)); err != nil {
		return nil, err
	}
	if err := addFile("footer.html", []byte(foot)); err != nil {
		return nil, err
	}
	for k, v := range map[string]string{
		"marginTop": "0.45", "marginBottom": "0.55", "marginLeft": "0.4", "marginRight": "0.4",
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
func rcaTopologyFromSpine(block any) rca.TopologyView {
	resp, ok := block.(pathSpineResponse)
	if !ok || resp.Spine == nil || !resp.SpineAvailable {
		reason := "No measured path is attached to this case — the topology is omitted, not inferred."
		if ok && resp.Reason != "" {
			reason = resp.Reason
		}
		return rca.TopologyView{Available: false, Reason: reason}
	}
	out := rca.TopologyView{
		Available: true, VantageID: resp.VantageID,
		ObservedAt: resp.ObservedAt, Stale: resp.Stale,
	}
	for _, n := range resp.Spine.Spine {
		out.Hops = append(out.Hops, rca.SpineHopView{
			Index: n.Index, Label: n.Label, Address: n.Address,
			Kind: n.Kind, Boundary: n.Boundary, State: n.State, SeamID: n.SeamID,
			Fault: n.Fault, Provider: n.Provider,
		})
		switch n.Fault {
		case "broken", "suspected":
			// CAUSAL: the case's verdict blames this path, and this is where it broke.
			// P1.8 wording: the last RESPONDING hop is a fact; the failure/visibility
			// boundary sits AFTER it — a responding hop is never labelled failed.
			out.DropPoint = fmt.Sprintf(
				"The last responding hop was %s (%s boundary); the destination did not respond beyond this point. This case's fault is on the path, so the failure or visibility boundary after this hop is consistent with the propagation ladder's origin. This narrows the affected path; it does not by itself identify the exact failed component.",
				orDefault(n.Label, n.Address), strings.ToLower(orDefault(n.Boundary, "unknown")))
		case "last_response":
			// FACT ONLY: state where the measurement stopped, blame nothing.
			out.DropPoint = fmt.Sprintf(
				"The measurement stops responding after %s (%s boundary) — later hops did not answer. This case's fault is NOT attributed to the network path, so this is stated as a measurement boundary, not as a break.",
				orDefault(n.Label, n.Address), strings.ToLower(orDefault(n.Boundary, "unknown")))
		}
	}
	return out
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
