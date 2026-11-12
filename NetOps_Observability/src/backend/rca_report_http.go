// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

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
	"sort"
	"strings"
	"time"

	"netops/backend/models"
	"netops/backend/timeintel"
	"netops/backend/topology"
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
	return s.buildRcaReport(r, claims, id, version, s.reportNow(), true)
}

// buildRcaReportSummaryForID is the same pipeline WITHOUT the topology read —
// for the RCA library, which evaluates up to rcaLibraryEvalCap candidates per
// request and projects only promotion and display fields. The topology stores
// (collector neighbour tables, the persisted graph) are never read per
// candidate for a list that does not render them.
func (s *server) buildRcaReportSummaryForID(r *http.Request, claims jwtClaims, id string, version int) (rca.Report, int, error) {
	return s.buildRcaReport(r, claims, id, version, s.reportNow(), false)
}

// reportNow is the RCA generation clock: rcaClock when injected (tests), the
// wall clock otherwise — always UTC and TRUNCATED TO THE SECOND, so that
// FmtUTC(now) round-trips losslessly through rca.ParseFmtUTC. The document
// reuse path below parses a prior revision's GeneratedAt back into a build
// clock; a sub-second remainder on the original build would make that rebuild
// drift off the recorded bytes by up to a second and defeat the reproduction.
func (s *server) reportNow() time.Time {
	now := time.Now()
	if s.rcaClock != nil {
		now = s.rcaClock()
	}
	return now.UTC().Truncate(time.Second)
}

// buildRcaReportForIDAt is buildRcaReportForID with an explicit generation
// clock — the deterministic-regeneration path rebuilds an unchanged analysis
// at the PRIOR revision's generation instant so it re-renders byte-identically.
func (s *server) buildRcaReportForIDAt(r *http.Request, claims jwtClaims, id string, version int, now time.Time) (rca.Report, int, error) {
	return s.buildRcaReport(r, claims, id, version, now, true)
}

func (s *server) buildRcaReport(r *http.Request, claims jwtClaims, id string, version int, now time.Time, withTopology bool) (rca.Report, int, error) {
	meta, sigRows, evRows, edgeRows, status, err := s.loadCorrSlice(r.Context(), claimsOf(r), id, version)
	if err != nil {
		return rca.Report{}, status, err
	}
	trigger := fmt.Sprintf("%v", meta["trigger_signal"])
	// stamps attached/link_status onto sigRows (the same derivation the timeline uses)
	_ = rca.MergeTimelineEvidence(sigRows, evRows, edgeRows, trigger) // result unused: the stamp mutates sigRows in place

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
	// RCA v2 §2: the ONE topology model, built before BuildReport from the
	// exact inputs the rca-path-view handler uses — the slice rows as loaded and
	// the UNSTAMPED spine (the builder stamps it against the case window) — so
	// the two endpoints produce the same context. Skipped only for the library.
	var topoCtx rca.TopologyContext
	if withTopology {
		spine := rcaTopologyFromSpine(pathBlock)
		topoCtx = s.rcaTopologyContext(r.Context(), claims, meta, sigRows, edgeRows, &spine, now)
	}
	// Merged/superseded source case: resolve the TERMINAL surviving incident,
	// tenant-scoped and cycle-safe (resolveMergeChain never crosses the owning
	// tenant boundary). The builder derives the merge record from this + meta.
	survivingID := ""
	if _, isMerged := rca.MergeIncidentState(asString(meta["state"])); isMerged {
		if first := asString(meta["merged_into"]); first != "" {
			owner := canonicalCorrTenant(asString(meta["tenant_id"]))
			survivingID, _ = s.resolveMergeChain(r.Context(), s.chTenantScope(r), owner, id, first) // best-effort: on resolve failure the original id stands
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
		Now:                 now,
		SurvivingIncidentID: survivingID,
		Lifecycle:           lc,
	})
	rep.Topology = rcaTopologyFromSpine(pathBlock)
	rep.TopologyContext = topoCtx
	rca.StampTopologyTemporalRole(&rep)

	// #113 point 3 — RCA creation policy. Candidates and RCA documents are
	// different tiers: JSON (the workspace's data) stays fully readable, but the
	// DOCUMENT (html/pdf) renders only for a promoted real outage — auto
	// (confirmed verdict + confirmed user/app impact + duration) or an explicit,
	// audited manual promotion. The refusal names the unmet criteria.
	var manual *rca.PromotionRecord
	if rec, has := s.rcaPromotions.Get(canonicalCorrTenant(asString(meta["tenant_id"])), id); has {
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

	// Deterministic document regeneration: if this exact analysis (snapshot +
	// policy + template) already produced a revision in this format, render
	// with THAT revision's generation stamp — the bytes and their content hash
	// then reproduce the existing revision instead of appending a
	// same-analysis revision on every wall-clock second (the register dedupes
	// by content, and the rendered document embeds its generation timestamp).
	if format == "html" || format == "pdf" {
		if prior, ok := s.rcaRevisions.FindBySnapshot(rep.OwnerTenant(), id, integ, format); ok {
			// Re-stamping GeneratedAt/EscalationAt is NOT sufficient. Freshness
			// strings (agoShort, "9m ago") and still-active elapsed durations are
			// baked into the analysis text at BuildReport time from the build
			// clock. They are normalized OUT of the snapshot hash — so the register
			// still matches — but the rendered BYTES drift as soon as the clock
			// crosses a minute, and every later view would append a junk revision.
			// So REBUILD the whole document at the prior revision's generation
			// instant; only then does an unchanged analysis re-render byte-identically
			// at any later time. Costs one extra slice read on the repeat-view path,
			// which is the price of an immutable document register that holds.
			if at, perr := rca.ParseFmtUTC(prior.Integrity.GeneratedAt); perr == nil {
				if rebuilt, _, rerr := s.buildRcaReportForIDAt(r, claims, id, version, at); rerr == nil {
					if reInteg, rierr := rca.ComputeReportIntegrity(rebuilt); rierr == nil &&
						reInteg.AnalysisSnapshotHash == integ.AnalysisSnapshotHash {
						// Adopt the rebuild only when it is provably the SAME analysis;
						// otherwise a concurrent change would inherit a stale stamp.
						rep, integ = rebuilt, reInteg
					}
				}
			}
			// Belt-and-braces for the fields the rebuild cannot reach (and the
			// fallback when the rebuild above declined): the document must embed
			// the prior revision's stamps or it can never reproduce it.
			if rep.Decision.EscalationAt == rep.GeneratedAt {
				rep.Decision.EscalationAt = prior.Integrity.GeneratedAt
			}
			rep.GeneratedAt = prior.Integrity.GeneratedAt
			integ.GeneratedAt = prior.Integrity.GeneratedAt
			rep.Integrity = &integ
		}
	}

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
		// The register's whole point is that a served document IS registered —
		// a refused/unpersisted row must fail the request, never serve an
		// unregistered immutable document.
		if err := s.recordReportRevision(claims, rep.OwnerTenant(), id, rep, integ, "html"); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("report revision register refused this generation: %w", err))
			return
		}
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
		// A pdf revision's ContentHash attests the DETERMINISTIC HTML source
		// document fed to the converter, NOT the sidecar's output: Gotenberg
		// (Chromium print) embeds a random /ID and CreationDate, so hashing the
		// pdf bytes minted a "new" revision on every download of an unchanged
		// analysis and FindBySnapshot dedupe could never reproduce one. The
		// served PDF stays the sidecar's output; what the revision register
		// certifies is the source document it was converted from.
		integ.ContentHash = rca.HashContent(html)
		if err := s.recordReportRevision(claims, rep.OwnerTenant(), id, rep, integ, "pdf"); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("report revision register refused this generation: %w", err))
			return
		}
		fname := fmt.Sprintf("%s-%s.pdf", strings.ToLower(strings.ReplaceAll(rep.ReportType, " ", "-")), rep.DisplayID)
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pdf) // best-effort: status committed; a failed write means the client is gone
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
	// Mesh transport, never a bare client (2026-08-05 incident class): on TLS
	// deployments this verifies the gotenberg SVID against the mesh CA and
	// presents the api's SVID (gotenberg 8 serves TLS without client-cert
	// verification, so the hop is server-verified TLS, not mTLS — the SVID is
	// presented regardless). Plain client on plaintext installs.
	client := backendHTTPClient(30 * time.Second)
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

// ── RCA v2 §2: the topology context and its source reader ──────────────────

// rcaTopologyReadTimeout bounds one report's whole topology read (§9): the
// neighbour tables, the persisted graph and the overlay snapshot together.
const rcaTopologyReadTimeout = 5 * time.Second

// rcaTopologyMaxLinkRows bounds the link rows one read hands the builder (it
// draws at most rca.TopoCtxMaxNodes nodes; this only stops a pathological
// fabric from growing the response).
const rcaTopologyMaxLinkRows = 512

// rcaTopologyContext is the ONE call both endpoints make (the RCA report and
// the rca-path-view): same inputs, same builder, same output.
func (s *server) rcaTopologyContext(ctx context.Context, claims jwtClaims, meta map[string]any, sigRows, edgeRows []map[string]any, spine *rca.TopologyView, now time.Time) rca.TopologyContext {
	return rca.BuildTopologyContext(ctx, serverTopologySource{s: s, claims: claims}, rca.TopologyContextInput{
		OwnerTenant: canonicalCorrTenant(asString(meta["tenant_id"])),
		Meta:        meta, Signals: sigRows, Edges: edgeRows,
		Verdict: asString(meta["verdict_tier"]), Spine: spine, Now: now,
	})
}

// serverTopologySource is the production rca.TopologySourceReader. Every row
// it returns is scoped twice, with parity to rcaPathSpine:
//
//   - by the OBJECT OWNER's tenant (canonicalCorrTenant(meta.tenant_id)): a
//     platform owner reading tenant A's report never receives tenant B's
//     devices or adjacencies, though B is visible to it elsewhere;
//   - by the CALLER's visibility: the operator scoped into a restricted tenant
//     reads nothing, before any store is touched; a restricted owner tenant is
//     answered like an empty one; a scoped principal reads only its own tenant;
//     and each source applies its own restriction filter (visibleDevicesFor,
//     gatherTopoLinksFor, visibleGraphRecords), so a link naming a restricted
//     tenant's device is dropped even when it hangs off a visible one.
type serverTopologySource struct {
	s      *server
	claims jwtClaims
}

func (src serverTopologySource) ReadTopology(ctx context.Context, q rca.TopologyQuery) (rca.TopologyRead, error) {
	s := src.s
	ctx, cancel := context.WithTimeout(ctx, rcaTopologyReadTimeout)
	defer cancel()
	tenant, cross := principalTenant(src.claims)
	exclude, deny := s.operatorTelemetryRestriction(src.claims, tenant, cross)
	vis := pathVisibility{deny: deny, exclude: exclude}
	owner := canonicalCorrTenant(q.OwnerTenant)
	if vis.deny || vis.hides(owner) || vis.hides(q.OwnerTenant) || (!cross && canonicalCorrTenant(tenant) != owner) {
		// Indistinguishable from an owner with no inventory (the posture
		// reasonNoPathEntity holds for the spine).
		return rca.TopologyRead{}, nil
	}

	// Inventory: the caller's visible devices that the object owner owns. This
	// slice is also the RESOLUTION universe for the neighbour tables, so a
	// neighbour never resolves to another tenant's device (topoLinkMaps).
	var ownerDevs []models.Device
	for _, d := range s.visibleDevicesFor(src.claims) {
		if canonicalCorrTenant(deviceTenant(d)) == owner {
			ownerDevs = append(ownerDevs, d)
		}
	}
	devByID := make(map[string]models.Device, len(ownerDevs))
	for _, d := range ownerDevs {
		devByID[d.ID] = d
	}
	ownedID, byName, byAddr := topoLinkMaps(ownerDevs)
	anchors := map[string]bool{}
	for _, a := range q.Devices {
		switch {
		case ownedID[a] != "" || devByID[a].ID != "":
			anchors[a] = true
		case byName[strings.ToLower(strings.TrimSpace(a))] != "":
			anchors[byName[strings.ToLower(strings.TrimSpace(a))]] = true
		case byAddr[strings.TrimSpace(a)] != "":
			anchors[byAddr[strings.TrimSpace(a)]] = true
		}
	}
	var read rca.TopologyRead
	if len(anchors) == 0 {
		// Nothing of the owner's inventory to anchor on: no neighbour read can
		// place anything, so none is made.
		return read, nil
	}

	graphNodes := map[string]topology.NodeRecord{}
	read.Links = append(read.Links, src.liveLinks(ctx, ownerDevs, anchors, &read)...)
	read.Links = append(read.Links, src.graphLinks(ctx, tenant, cross, owner, anchors, graphNodes, &read)...)
	read.Links = append(read.Links, src.overlayLinks(q.Now, devByID, anchors, &read)...)
	if len(read.Links) > rcaTopologyMaxLinkRows {
		sort.SliceStable(read.Links, func(i, j int) bool { return read.Links[i].ID < read.Links[j].ID })
		read.Links = read.Links[:rcaTopologyMaxLinkRows]
	}

	// Inventory rows: the anchors and every resolved neighbour, nothing else.
	want := map[string]bool{}
	for a := range anchors {
		want[a] = true
	}
	for _, l := range read.Links {
		want[l.A], want[l.B] = true, true
	}
	ids := make([]string, 0, len(want))
	for id := range want {
		if _, ok := devByID[id]; ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		d := devByID[id]
		row := rca.InventoryRow{ID: d.ID, Name: d.Name, Address: d.Address, Source: d.Source,
			LastSeen: d.LastSeen, Stale: d.DiscoveryStale,
			Role: firstNonEmpty(d.Labels["role"], d.Type)}
		if n, ok := graphNodes[d.ID]; ok {
			row.Role = firstNonEmpty(n.DeviceRole, row.Role, n.Role)
			row.FirstSeen = n.FirstSeen
		}
		read.Inventory = append(read.Inventory, row)
	}
	return read, nil
}

// liveLinks reads the LLDP/CDP/BGP-LS neighbour tables through the SAME
// normalizer /api/topology/links uses, with the owner's devices as the
// resolution universe and the caller's restriction applied to both ends.
func (src serverTopologySource) liveLinks(ctx context.Context, ownerDevs []models.Device, anchors map[string]bool, read *rca.TopologyRead) []rca.TopologyLinkRow {
	links, err := src.s.gatherTopoLinksFor(ctx, src.claims, ownerDevs)
	counts := map[string]int{}
	var out []rca.TopologyLinkRow
	for _, l := range links {
		if !anchors[l.Source] && !anchors[l.Target] {
			continue
		}
		protos := rcaTopoProtos(l.SourceProto)
		for _, p := range protos {
			counts[p]++
		}
		out = append(out, rca.TopologyLinkRow{
			ID: topoEdgeID(l), Sources: protos,
			A: l.Source, APort: l.LocalPort, ALabel: l.SourceName,
			B: l.Target, BPort: l.RemotePort, BLabel: l.TargetName, BManaged: l.Resolved,
			Relationship: rcaTopoRelationship(protos), Protocol: l.SourceProto,
			Bidirectional: l.Bidirectional, LastSeen: rcaTopoUnixMilli(l.LastSeen),
		})
	}
	status, detail := rca.TopoReadOK, ""
	if err != nil {
		status, detail = rca.TopoReadUnavailable, "the collector's neighbour tables could not be read"
		logWarn("rca", "topology context: neighbour tables unread — reported as unavailable, not as no adjacency",
			map[string]any{"error": err.Error()})
	}
	for _, k := range []string{rca.TopoSrcLLDP, rca.TopoSrcCDP, rca.TopoSrcBGPLS} {
		read.Reads = append(read.Reads, rca.TopologySourceRead{Kind: k, Status: status, Rows: counts[k], Detail: detail})
	}
	return out
}

// graphLinks reads the persisted reconciled graph at the CALLER's scope (as
// /api/topology/graph does), applies the operator-visibility filter, then keeps
// only the owner tenant's records.
func (src serverTopologySource) graphLinks(ctx context.Context, tenant string, cross bool, owner string, anchors map[string]bool, nodes map[string]topology.NodeRecord, read *rca.TopologyRead) []rca.TopologyLinkRow {
	if src.s.topology == nil {
		read.Reads = append(read.Reads, rca.TopologySourceRead{Kind: rca.TopoSrcGraph, Status: rca.TopoReadNotAvailable, Detail: "the topology graph store is not enabled"})
		return nil
	}
	snap, err := src.s.topology.Snapshot(ctx, tenant, cross)
	if err != nil {
		logWarn("rca", "topology context: persisted graph unread — reported as unavailable", map[string]any{"error": err.Error()})
		read.Reads = append(read.Reads, rca.TopologySourceRead{Kind: rca.TopoSrcGraph, Status: rca.TopoReadUnavailable, Detail: "the persisted topology graph could not be read"})
		return nil
	}
	snap = src.s.visibleGraphRecords(src.claims, snap)
	for _, n := range snap.Nodes {
		if canonicalCorrTenant(n.TenantID) == owner {
			nodes[n.ID] = n
		}
	}
	var out []rca.TopologyLinkRow
	for _, e := range snap.Edges {
		if canonicalCorrTenant(e.TenantID) != owner || (!anchors[e.Source] && !anchors[e.Target]) {
			continue
		}
		protos := rcaTopoProtos(e.Protocol)
		out = append(out, rca.TopologyLinkRow{
			ID: e.ID, Sources: []string{rca.TopoSrcGraph},
			A: e.Source, APort: e.SourcePort, ALabel: nodes[e.Source].Label,
			B: e.Target, BPort: e.TargetPort, BLabel: nodes[e.Target].Label, BManaged: e.Resolved,
			Relationship: rcaTopoRelationship(protos), Protocol: e.Protocol,
			Bidirectional: e.Bidirectional, FirstSeen: e.FirstSeen, LastSeen: e.LastSeen, Stale: e.Stale,
		})
	}
	read.Reads = append(read.Reads, rca.TopologySourceRead{Kind: rca.TopoSrcGraph, Status: rca.TopoReadOK, Rows: len(out)})
	return out
}

// overlayLinks reads the SD-WAN overlay snapshot (tracker 349) the reconciler
// keeps in memory. It already folds the SD-WAN Manager integrations' stored BFD
// sessions in per device (refreshSDWANOverlay, T4b), and each edge says which
// reported it (Tags["sources"]), so the controller source needs no second,
// platform-wide session-store scan per report (ctloverlay.Links is that scan).
// Same rule as attachSDWANOverlay: an overlay edge only when BOTH ends are the
// owner's visible devices; a transport membership only from one.
func (src serverTopologySource) overlayLinks(now time.Time, devs map[string]models.Device, anchors map[string]bool, read *rca.TopologyRead) []rca.TopologyLinkRow {
	snap := src.s.sdwanOverlay.Load()
	if snap == nil {
		for _, k := range []string{rca.TopoSrcSDWANOverlay, rca.TopoSrcController} {
			read.Reads = append(read.Reads, rca.TopologySourceRead{Kind: k, Status: rca.TopoReadNotAvailable, Detail: "no SD-WAN overlay has been inferred on this deployment"})
		}
		return nil
	}
	stale := !now.IsZero() && now.Sub(snap.at) > 5*time.Minute
	labels := map[string]string{}
	for _, n := range snap.res.Nodes {
		labels[n.ID] = n.Label
	}
	counts := map[string]int{}
	var out []rca.TopologyLinkRow
	for _, e := range snap.res.Edges {
		var row rca.TopologyLinkRow
		switch e.Relationship {
		case topology.RelOverlay:
			_, okA := devs[e.Source]
			_, okB := devs[e.Target]
			if !okA || !okB || (!anchors[e.Source] && !anchors[e.Target]) {
				continue
			}
			var srcs []string
			for _, t := range strings.Split(e.Tags["sources"], ",") {
				switch strings.TrimSpace(t) {
				case "controller":
					srcs = append(srcs, rca.TopoSrcController)
				case "snmp":
					srcs = append(srcs, rca.TopoSrcSDWANOverlay)
				}
			}
			if len(srcs) == 0 {
				srcs = []string{rca.TopoSrcSDWANOverlay}
			}
			row = rca.TopologyLinkRow{ID: e.ID, Sources: srcs, A: e.Source, B: e.Target, BManaged: true, Relationship: "overlay"}
		case topology.RelInferred:
			if _, ok := devs[e.Source]; !ok || !anchors[e.Source] {
				continue
			}
			row = rca.TopologyLinkRow{ID: e.ID, Sources: []string{rca.TopoSrcSDWANOverlay}, A: e.Source, B: e.Target, BLabel: labels[e.Target], Relationship: "membership"}
		default:
			continue
		}
		row.Protocol, row.Confidence, row.LastSeen, row.Stale = e.Protocol, e.Confidence, snap.at, stale
		for _, k := range row.Sources {
			counts[k]++
		}
		out = append(out, row)
	}
	for _, k := range []string{rca.TopoSrcSDWANOverlay, rca.TopoSrcController} {
		read.Reads = append(read.Reads, rca.TopologySourceRead{Kind: k, Status: rca.TopoReadOK, Rows: counts[k]})
	}
	return out
}

// rcaTopoProtos splits a "+"-joined protocol list ("lldp+cdp") into source kinds.
func rcaTopoProtos(p string) []string {
	var out []string
	for _, x := range strings.Split(strings.ToLower(p), "+") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		out = []string{rca.TopoSrcLLDP}
	}
	return out
}

func rcaTopoRelationship(protos []string) string {
	for _, p := range protos {
		if p == rca.TopoSrcLLDP || p == rca.TopoSrcCDP {
			return "physical"
		}
	}
	return "routing"
}

func rcaTopoUnixMilli(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
