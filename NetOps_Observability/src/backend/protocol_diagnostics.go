// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// protocol_diagnostics.go — HTTP surface for the operator-initiated routing-
// protocol diagnostics feature (Troubleshooting page, item 7; owner spec
// docs/design/TROUBLESHOOTING_PROTOCOL_DIAGNOSTICS_2026-08-27.md). It wires the
// pure, deterministic internal/protocoldiag library (catalog → collect → analyze
// → redacted TAC export) to three authenticated, tenant-scoped endpoints:
//
//	GET  /api/troubleshoot/protocol-diagnostics/catalog  — the 15-issue matrix
//	     (BGP/OSPF/IS-IS tabs + per-issue command bundle) so the UI can render.
//	POST /api/troubleshoot/protocol-diagnostics/analyze  — run the failure
//	     signatures over operator-pasted `show` output; return the honest verdict
//	     (or "no known signature matched") + a redacted TAC-export blob.
//	POST /api/troubleshoot/protocol-diagnostics/collect  — run an issue's read-
//	     only command bundle against one of the CALLER'S OWN devices via the
//	     injected CommandRunner (nil until the SSH/gNMI transport is wired at
//	     deploy time → a clear 503, never a fabricated result).
//	POST /api/troubleshoot/protocol-diagnostics/export   — assemble the redacted
//	     "Send to TAC" bundle from supplied outputs, with the signature analysis
//	     optionally folded in. Reachable WITHOUT an analysis, so an operator can
//	     share a capture whose failure no signature recognises.
//
// §3a: every surface is per-tenant operator data gated with requirePerm on the
// "infrastructure" module. Collect resolves the subject device through the
// principal-scoped inventory and 404s a cross-tenant id (existence never
// revealed); the Collection's tenant is stamped from the RESOLVED DEVICE, never
// a request body. Analyze is request-scoped (operator-pasted text) — the tenant
// is still derived from the token, and no other tenant's data is reachable.
//
// §3/§8/§15: analyze and export ingest untrusted operator-pasted text — the body
// is bounded (MaxBytesReader + per-field char caps), spec ids are validated
// against the issue's own bundle, and the TAC export runs the library's
// redaction pass so secrets/PII never leave in the shareable blob.
//
// §8 REDACTION AT CAPTURE, not only at export: `show` output from a real device
// carries neighbour passwords, authentication keys, key-strings and SNMP
// communities (a `... | section router bgp` capture reliably does). Collect
// therefore renders the collection through protocoldiag.Redact BEFORE it is
// serialised, so the on-screen output an operator reads — and anything they
// copy out of the browser — is already masked. The raw capture never leaves the
// process. The read is audited with a `sensitive` tag for the same reason the
// config-version read is.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/chschema"
	"netops/backend/internal/deviceident"
	"netops/backend/internal/httppage"
	"netops/backend/internal/incident"
	"netops/backend/internal/osprobe"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/protocoldiag"
	"netops/backend/internal/tac"
	"netops/backend/internal/ticketing"
	"netops/backend/models"
)

// Body/size caps for the untrusted analyze payload (§3/§8/§15 LLM-adjacent
// hygiene: bound the request, then bound each field within it).
const (
	pdAnalyzeMaxBody    = 2 << 20 // 2 MiB total request body (analyze AND export)
	pdAnalyzeMaxOutputs = 64      // at most this many command outputs per request
	pdAnalyzeMaxOutput  = 256 << 10
	pdMaxTargetField    = 256 // per Target field (interface/peer/prefix/vrf)
)

// pdCatalog returns the built diagnostics catalog, falling back to a freshly
// built default when the server was constructed without one (test harnesses that
// build *server directly). The catalog is pure and immutable, so a fresh build is
// always correct.
func (s *server) pdCatalog() *protocoldiag.Catalog {
	if s.protocolCatalog != nil {
		return s.protocolCatalog
	}
	return protocoldiag.DefaultCatalog()
}

// pdAnalyzer mirrors pdCatalog for the signature analyzer.
func (s *server) pdAnalyzer() *protocoldiag.Analyzer {
	if s.protocolAnalyzer != nil {
		return s.protocolAnalyzer
	}
	return protocoldiag.DefaultAnalyzer()
}

// pdRenderedVendor mirrors the library's (unexported) dialect-fallback rule so an
// analyze-built Collection records the SAME rendered dialect a live collection
// would: a recognized vendor renders itself, anything else falls back to the
// primary (Cisco IOS-XE) dialect.
func pdRenderedVendor(v protocoldiag.Vendor) protocoldiag.Vendor {
	switch v {
	case protocoldiag.VendorCiscoIOSXE, protocoldiag.VendorJuniper, protocoldiag.VendorNokia:
		return v
	default:
		return protocoldiag.VendorCiscoIOSXE
	}
}

// pdPlatformString builds the free-form platform string the library derives the
// device dialect from, out of the inventory device's vendor/os/model fields.
func pdPlatformString(d models.Device) string {
	return strings.TrimSpace(strings.Join(strings.Fields(d.Vendor+" "+d.OS+" "+d.Model), " "))
}

// ── wire types ──────────────────────────────────────────────────────────────

type pdCommandView struct {
	SpecID  string `json:"spec_id"`
	Purpose string `json:"purpose"`
	Command string `json:"command"`
}

type pdIssueView struct {
	ID          string `json:"id"`
	Protocol    string `json:"protocol"`
	Title       string `json:"title"`
	Description string `json:"description"`
	// Symptoms is the authored "what you are seeing" list the UI shows so an
	// operator can pick the right issue out of a protocol's five without reading
	// every description.
	Symptoms []string `json:"symptoms"`
	// Vendors is the issue's honest dialect COVERAGE: the vendors every command
	// in its bundle carries an authored template for. A vendor missing here still
	// renders (by falling back to the primary Cisco dialect) — it is simply not
	// claimed as covered.
	Vendors  []string        `json:"vendors"`
	Commands []pdCommandView `json:"commands"`
}

// pdIssueViewOf renders one catalog issue for the wire in the requested dialect.
// Symptoms and vendors are always non-nil slices so the UI never has to
// distinguish "absent" from "empty" in JSON.
func pdIssueViewOf(is protocoldiag.Issue, vendor protocoldiag.Vendor) pdIssueView {
	symptoms := is.Symptoms
	if symptoms == nil {
		symptoms = []string{}
	}
	vendors := make([]string, 0, 3)
	for _, v := range is.Vendors() {
		vendors = append(vendors, string(v))
	}
	return pdIssueView{
		ID:          is.ID,
		Protocol:    string(is.Protocol),
		Title:       is.Title,
		Description: is.Description,
		Symptoms:    symptoms,
		Vendors:     vendors,
		Commands:    pdBundleView(is, vendor),
	}
}

type pdEvidenceView struct {
	Command string `json:"command"`
	SpecID  string `json:"spec_id"`
	Line    string `json:"line"`
}

type pdFindingView struct {
	SignatureID string         `json:"signature_id"`
	Verdict     string         `json:"verdict"`
	Cause       string         `json:"cause"`
	Remediation string         `json:"remediation"`
	Confidence  string         `json:"confidence"`
	Evidence    pdEvidenceView `json:"evidence"`
}

// ── catalog ─────────────────────────────────────────────────────────────────

// handleProtocolDiagCatalog serves the 15-issue matrix so the UI can render the
// BGP/OSPF/IS-IS tabs and their per-issue command bundles. It is per-tenant
// operator data in the RBAC sense (infrastructure:read) but carries no
// tenant-specific rows — the catalog is the same version-pinned ruleset for
// everyone; ?vendor= only chooses which dialect the command text renders in.
func (s *server) handleProtocolDiagCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	// §3a: gate on the per-tenant infrastructure module (read). Deriving the
	// tenant is not ceremony here — ?device= resolves through the CALLER'S OWN
	// inventory below, so the catalog's dialect choice can never be steered by
	// (or reveal) another tenant's device.
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)

	// A silently-ignored selector that changes which CLI commands an operator is
	// shown is a trap: before this, `?device=spine1` was dropped and the response
	// fell back to the Cisco IOS-XE default while looking authoritative
	// (QA 2026-09-03, D-5). Every accepted parameter is now named, and anything
	// else is a 400 rather than a silent no-op.
	if err := httppage.RejectUnknownQuery(r, "vendor", "device"); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	vendorParam := strings.TrimSpace(r.URL.Query().Get("vendor"))
	deviceParam := strings.TrimSpace(r.URL.Query().Get("device"))
	if vendorParam != "" && deviceParam != "" {
		writeError(w, http.StatusBadRequest,
			errors.New("vendor and device select the same thing; supply one, not both"))
		return
	}

	vendor := protocoldiag.VendorCiscoIOSXE
	resolvedDevice, resolvedPlatform := "", ""
	switch {
	case deviceParam != "":
		// §3a: a device the caller cannot see (another tenant's, or nonexistent)
		// is a 404 — the same rule collect applies, so the catalog is not an
		// existence oracle for another tenant's inventory.
		dev, found := s.discovery.Get(deviceParam)
		if !found || !canSeeDevice(dev, tenant, cross) {
			http.NotFound(w, r)
			return
		}
		resolvedDevice, resolvedPlatform = dev.ID, pdPlatformString(dev)
		vendor = protocoldiag.VendorFromPlatform(resolvedPlatform)
	case vendorParam != "":
		vendor = protocoldiag.VendorFromPlatform(vendorParam)
	}

	cat := s.pdCatalog()
	byProtocol := map[string][]pdIssueView{}
	for _, p := range []protocoldiag.Protocol{protocoldiag.ProtocolBGP, protocoldiag.ProtocolOSPF, protocoldiag.ProtocolISIS} {
		views := make([]pdIssueView, 0, 5)
		for _, is := range cat.IssuesFor(p) {
			views = append(views, pdIssueViewOf(is, vendor))
		}
		byProtocol[string(p)] = views
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ruleset_version": protocoldiag.RulesetVersion,
		"vendor":          string(vendor),
		"vendor_display":  protocoldiag.DisplayVendor(vendor),
		// Echo what the dialect was resolved FROM when ?device= was used, so an
		// operator can see which platform string produced these commands rather
		// than having to trust that the selector was honoured.
		"device":          resolvedDevice,
		"device_platform": resolvedPlatform,
		"protocols":       []string{string(protocoldiag.ProtocolBGP), string(protocoldiag.ProtocolOSPF), string(protocoldiag.ProtocolISIS)},
		"issues":          byProtocol,
	})
}

// pdBundleView renders an issue's command bundle in the requested dialect, in
// its stable authored order, with an empty (unscoped) target — the catalog view
// shows the shape of each command, not a specific interface/peer.
func pdBundleView(is protocoldiag.Issue, vendor protocoldiag.Vendor) []pdCommandView {
	var tgt protocoldiag.Target
	out := make([]pdCommandView, 0, 8)
	for _, spec := range is.Bundle() {
		out = append(out, pdCommandView{
			SpecID:  spec.ID,
			Purpose: spec.Purpose,
			Command: spec.Render(vendor, tgt),
		})
	}
	return out
}

// ── analyze ─────────────────────────────────────────────────────────────────

// pdDeviceContext is optional free-text context for the TAC-export header and
// the dialect the command text renders in. It is NOT an inventory lookup —
// analyze and export are request-scoped over pasted text, so there is no device
// to authorize and nothing tenant-owned to resolve.
type pdDeviceContext struct {
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`
}

// pdOutputInput is one operator-pasted raw output, keyed by command spec id.
type pdOutputInput struct {
	SpecID string `json:"spec_id"`
	Output string `json:"output"`
}

type pdAnalyzeRequest struct {
	Protocol string          `json:"protocol"`
	IssueID  string          `json:"issue_id"`
	Device   pdDeviceContext `json:"device"`
	Outputs  []pdOutputInput `json:"outputs"`
}

// pdBuildCollection validates an untrusted (protocol, issue, device, outputs)
// payload and assembles the in-memory Collection analyze and export both score
// and render. It is the SINGLE validation path for the two endpoints, so they
// can never drift into accepting different things.
//
// Every rule here is a §3 "validate at the boundary" rule: the issue must exist;
// a supplied protocol must AGREE with the issue's own (never trust the client to
// pair them); the output count and each output's size are capped; and every
// spec id must belong to THIS issue's bundle — an unknown key is refused rather
// than ignored. The tenant is stamped from the token (§3a.2), never the body.
//
// It returns an error whose text is safe to hand back with a 400.
func pdBuildCollection(cat *protocoldiag.Catalog, tenant string, protocol, issueID string, devCtx pdDeviceContext, outputs []pdOutputInput) (*protocoldiag.Collection, protocoldiag.Issue, error) {
	issue, ok := cat.Issue(strings.TrimSpace(issueID))
	if !ok {
		return nil, protocoldiag.Issue{}, fmt.Errorf("unknown issue %q", issueID)
	}
	if p := strings.TrimSpace(protocol); p != "" && !strings.EqualFold(p, string(issue.Protocol)) {
		return nil, protocoldiag.Issue{}, fmt.Errorf("protocol %q does not match issue %q (%s)", p, issue.ID, issue.Protocol)
	}
	if len(outputs) > pdAnalyzeMaxOutputs {
		return nil, protocoldiag.Issue{}, fmt.Errorf("too many outputs (max %d)", pdAnalyzeMaxOutputs)
	}

	// Build the set of spec ids that belong to THIS issue's bundle; reject any
	// pasted output keyed to a spec that is not part of the issue (untrusted key).
	bundle := issue.Bundle()
	specByID := make(map[string]protocoldiag.CommandSpec, len(bundle))
	for _, spec := range bundle {
		specByID[spec.ID] = spec
	}

	vendor := protocoldiag.VendorFromPlatform(devCtx.Platform)
	rendered := pdRenderedVendor(vendor)
	var tgt protocoldiag.Target

	col := &protocoldiag.Collection{
		TenantID:       tenant, // §3a: stamped from the token, never a request body
		Hostname:       clampString(devCtx.Hostname, pdMaxTargetField),
		Platform:       clampString(devCtx.Platform, pdMaxTargetField),
		Vendor:         vendor,
		RenderedVendor: rendered,
		Protocol:       issue.Protocol,
		IssueID:        issue.ID,
		IssueTitle:     issue.Title,
		RulesetVersion: protocoldiag.RulesetVersion,
	}
	for _, o := range outputs {
		spec, known := specByID[o.SpecID]
		if !known {
			return nil, protocoldiag.Issue{}, fmt.Errorf("spec id %q is not part of issue %q", o.SpecID, issue.ID)
		}
		if len(o.Output) > pdAnalyzeMaxOutput {
			return nil, protocoldiag.Issue{}, fmt.Errorf("output for %q exceeds %d bytes", o.SpecID, pdAnalyzeMaxOutput)
		}
		col.Commands = append(col.Commands, protocoldiag.CollectedCommand{
			SpecID:  spec.ID,
			Command: spec.Render(vendor, tgt),
			Purpose: spec.Purpose,
			Output:  o.Output,
		})
	}
	return col, issue, nil
}

// handleProtocolDiagAnalyze runs the failure signatures for one issue over
// operator-pasted `show` output and returns the honest verdict plus a redacted
// TAC-export blob. It touches no device and persists nothing — the tenant is
// derived from the token for §3a consistency, and the request body is bounded and
// validated as untrusted input.
func (s *server) handleProtocolDiagAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, _ := principalTenant(claims)

	var req pdAnalyzeRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, pdAnalyzeMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return
	}

	col, issue, err := pdBuildCollection(s.pdCatalog(), tenant, req.Protocol, req.IssueID, req.Device, req.Outputs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// D-4 — "nothing was collected" is NOT "nothing matched". Scoring an empty
	// capture and returning "no known signature matched" tells an operator the
	// platform looked and found the protocol healthy. It never looked. The two
	// outcomes are now separate states on the wire, and the analysis is not run
	// at all when there is nothing to run it over.
	supplied := pdOutputsWithContent(col)
	if supplied == 0 {
		res := protocoldiag.AnalyzeResult{
			Protocol:       issue.Protocol,
			IssueID:        issue.ID,
			IssueTitle:     issue.Title,
			RulesetVersion: protocoldiag.RulesetVersion,
			Unmatched:      "",
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"protocol":         string(res.Protocol),
			"issue_id":         res.IssueID,
			"issue_title":      res.IssueTitle,
			"ruleset_version":  res.RulesetVersion,
			"analyzed":         false,
			"outputs_received": len(col.Commands),
			"outputs_supplied": 0,
			"matched":          false,
			"findings":         []pdFindingView{},
			"unmatched":        "",
			"not_analyzed":     pdNotAnalyzedReason,
			"tac_export":       protocoldiag.TACExport(col, res),
		})
		return
	}

	res := s.pdAnalyzer().Analyze(col)
	tac := protocoldiag.TACExport(col, res)

	writeJSON(w, http.StatusOK, map[string]any{
		"protocol":         string(res.Protocol),
		"issue_id":         res.IssueID,
		"issue_title":      res.IssueTitle,
		"ruleset_version":  res.RulesetVersion,
		"analyzed":         true,
		"outputs_received": len(col.Commands),
		"outputs_supplied": supplied,
		"matched":          res.Matched(),
		"findings":         pdFindingViews(res),
		"unmatched":        res.Unmatched,
		"not_analyzed":     "",
		"tac_export":       tac,
	})
}

// pdNotAnalyzedReason is the honest statement for an analyze call that carried
// no output. It deliberately does NOT say "no signature matched": that sentence
// asserts the signatures were scored, and they were not.
const pdNotAnalyzedReason = "no command output was supplied, so nothing was analysed — this is NOT " +
	"\"no signature matched\": the protocol's state is unknown. Collect from the device or paste the " +
	"output. If a live collect returned nothing, its per-command `error` fields say why each command failed."

// pdOutputsWithContent counts the commands that actually carry output. Blank
// and whitespace-only captures are absent evidence, never empty evidence.
func pdOutputsWithContent(col *protocoldiag.Collection) int {
	n := 0
	for _, cc := range col.Commands {
		if strings.TrimSpace(cc.Output) != "" {
			n++
		}
	}
	return n
}

func pdFindingViews(res protocoldiag.AnalyzeResult) []pdFindingView {
	out := make([]pdFindingView, 0, len(res.Findings))
	for _, f := range res.Findings {
		out = append(out, pdFindingView{
			SignatureID: f.SignatureID,
			Verdict:     f.Verdict,
			Cause:       f.Cause,
			Remediation: f.Remediation,
			Confidence:  string(f.Confidence),
			Evidence: pdEvidenceView{
				Command: f.Evidence.Command,
				SpecID:  f.Evidence.SpecID,
				Line:    f.Evidence.Line,
			},
		})
	}
	return out
}

// ── collect ─────────────────────────────────────────────────────────────────

type pdCollectRequest struct {
	DeviceID string `json:"device_id"`
	IssueID  string `json:"issue_id"`
	Target   struct {
		Interface string `json:"interface"`
		Peer      string `json:"peer"`
		Prefix    string `json:"prefix"`
		VRF       string `json:"vrf"`
	} `json:"target"`
}

// handleProtocolDiagCollect runs an issue's read-only command bundle against one
// of the caller's OWN devices via the injected CommandRunner. §3a: the device is
// resolved through the principal-scoped inventory and a cross-tenant/unknown id
// returns 404 (existence never revealed); the Collection's tenant is stamped from
// the resolved device. When no CommandRunner is wired (the default until the
// SSH/gNMI transport is connected at deploy time) it returns 503 — never a
// fabricated capture.
func (s *server) handleProtocolDiagCollect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	// Collect performs an operation against a device → write level.
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)

	var req pdCollectRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return
	}
	deviceID := strings.TrimSpace(req.DeviceID)
	issueID := strings.TrimSpace(req.IssueID)
	if deviceID == "" || issueID == "" {
		writeError(w, http.StatusBadRequest, errors.New("device_id and issue_id are required"))
		return
	}
	if _, known := s.pdCatalog().Issue(issueID); !known {
		writeError(w, http.StatusBadRequest, fmt.Errorf("unknown issue %q", issueID))
		return
	}

	// §3a: resolve the subject device in the caller's scope. A device the caller
	// cannot see (another tenant's, or nonexistent) is a 404 — never reveal it.
	dev, found := s.discovery.Get(deviceID)
	if !found || !canSeeDevice(dev, tenant, cross) {
		http.NotFound(w, r)
		return
	}

	// Fail-closed: no runner wired ⇒ honest 503, not a fake capture.
	if s.protocolCollector == nil {
		writeError(w, http.StatusServiceUnavailable, errPDCollectorUnwired)
		return
	}

	tgt := protocoldiag.Target{
		Interface: clampString(req.Target.Interface, pdMaxTargetField),
		Peer:      clampString(req.Target.Peer, pdMaxTargetField),
		Prefix:    clampString(req.Target.Prefix, pdMaxTargetField),
		VRF:       clampString(req.Target.VRF, pdMaxTargetField),
	}

	col, err := s.pdRunCollection(r.Context(), dev, issueID, tgt)
	if err != nil {
		// A read-only-guard or unknown-issue failure is a bad request; a context
		// cancellation/timeout is a client/timeout condition.
		switch {
		case errors.Is(err, protocoldiag.ErrUnknownIssue):
			writeError(w, http.StatusBadRequest, err)
		case errors.Is(err, protocoldiag.ErrNotReadOnly):
			// The curated catalog can never trip this; if it does, it is a hard
			// safety refusal, not a client error.
			logError("protocol-diag", "read-only guard refused a catalog command", map[string]any{
				"device_id": deviceID, "issue_id": issueID, "error": err.Error()})
			writeError(w, http.StatusInternalServerError, errors.New("collection aborted by read-only safety guard"))
		default:
			writeError(w, http.StatusBadGateway, fmt.Errorf("collect failed: %w", err))
		}
		return
	}

	logInfo("protocol-diag", "collection captured", map[string]any{
		"device_id": deviceID, "tenant": deviceTenant(dev), "issue_id": issueID,
		"user": claims.Sub, "commands": len(col.Commands),
	})
	// §8: a live capture reveals a device's operational state and is the moment
	// secrets could have been read off it — audited with the `sensitive` tag, the
	// same treatment the stored-configuration read gets.
	s.pdAudit(r, claims, deviceTenant(dev), "protocol_diagnostics.collect", map[string]any{
		"device_id": deviceID, "issue_id": issueID, "commands": len(col.Commands),
	})

	// §8 REDACT AT CAPTURE: the on-screen output is the redacted copy (pdRunCollection
	// redacts before it returns). The raw Collection never leaves that helper — an
	// operator reading (or copy-pasting) the panel can only ever see masked secrets.
	writeJSON(w, http.StatusOK, pdCollectionView(col))
}

// pdRunCollection performs one read-only capture against an ALREADY-AUTHORIZED
// device and returns the REDACTED collection. It is the single capture path:
// the HTTP collect handler and the AI assistant's read-only protocol-diagnostic
// tool both go through it, so the §8 "redact at capture" rule cannot be applied
// on one path and forgotten on the other.
//
// It does NOT authorize: the caller must already have resolved `dev` in the
// principal's scope (canSeeDevice) and gated on the write level a device
// operation needs. It DOES fail closed — a nil CommandRunner is an error, never
// a fabricated capture.
func (s *server) pdRunCollection(ctx context.Context, dev models.Device, issueID string, tgt protocoldiag.Target) (*protocoldiag.Collection, error) {
	if s.protocolCollector == nil {
		return nil, errPDCollectorUnwired
	}
	// pdDeviceFromDiscovery carries the resolved inventory row's ADDRESS and the
	// configured SSH port through as well — without them a live collect fails
	// with "device has no address" — and stamps the owning tenant from the
	// device (§3a), never from a request.
	col, err := s.protocolCollector.Collect(ctx, pdDeviceFromDiscovery(dev), issueID, tgt)
	if err != nil {
		return nil, err
	}
	return protocoldiag.Redact(col), nil
}

// errPDCollectorUnwired is the honest "no capture transport on this deployment"
// error. The HTTP handler answers 503; the assistant's tool turns it into the
// read-only command bundle for a human to run.
var errPDCollectorUnwired = errors.New("protocol-diagnostics collector is not configured on this deployment")

// pdAudit records a protocol-diagnostics action into the immutable audit trail
// with the `sensitive` tag. It mirrors configAudit's shape so the two device-
// reading features read identically in the compliance view. A nil audit sink
// (bare test servers) is a no-op, never a panic.
func (s *server) pdAudit(r *http.Request, claims jwtClaims, tenant, action string, detail map[string]any) {
	if s.audit == nil {
		return
	}
	_, cross := principalTenant(claims)
	if detail == nil {
		detail = map[string]any{}
	}
	detail["action"] = action
	detail["sensitive"] = true
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross,
		Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
		Remote: auditClientIP(r), Detail: detail,
	})
}

// pdCollectionView renders a Collection for the same-tenant operator. The tenant
// id is deliberately not echoed (the caller already is that tenant); every
// command carries its rendered text, purpose, timestamp, output and any
// per-command transport error (honest partial captures).
//
// The caller passes the REDACTED copy (protocoldiag.Redact). The `redacted`
// flag on the response says so explicitly, so the UI can label the panel rather
// than let an operator assume they are looking at raw device output.
func pdCollectionView(col *protocoldiag.Collection) map[string]any {
	cmds := make([]map[string]any, 0, len(col.Commands))
	for _, cc := range col.Commands {
		cmds = append(cmds, map[string]any{
			"spec_id":   cc.SpecID,
			"command":   cc.Command,
			"purpose":   cc.Purpose,
			"output":    cc.Output,
			"timestamp": cc.Timestamp,
			"error":     cc.Err,
		})
	}
	return map[string]any{
		"device_id":       col.DeviceID,
		"hostname":        col.Hostname,
		"platform":        col.Platform,
		"vendor":          string(col.Vendor),
		"rendered_vendor": string(col.RenderedVendor),
		"protocol":        string(col.Protocol),
		"issue_id":        col.IssueID,
		"issue_title":     col.IssueTitle,
		"ruleset_version": col.RulesetVersion,
		"collected_at":    col.CollectedAt,
		"redacted":        true,
		"commands":        cmds,
	}
}

// clampString truncates s to at most n bytes — a defensive cap on every free-text
// field so an oversized single field cannot bloat a Collection even within the
// overall body budget. A trailing partial UTF-8 rune left by the byte cut is
// dropped (ToValidUTF8 with an empty replacement) so the result is always valid
// UTF-8.
func clampString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// ── export ──────────────────────────────────────────────────────────────────

// pdExportRequest is the "Send to TAC" payload: the same (issue, device
// context, outputs) shape analyze takes, plus a flag asking whether the failure
// signatures should be folded into the bundle.
//
// It is deliberately its OWN endpoint rather than a mode of analyze. The honest
// case this feature exists for is "no known signature matched" — an operator
// must be able to hand a capture to a vendor TAC precisely when the platform
// could not explain it, without first being made to run an analysis that will
// come back empty.
type pdExportRequest struct {
	Protocol string          `json:"protocol"`
	IssueID  string          `json:"issue_id"`
	Device   pdDeviceContext `json:"device"`
	Outputs  []pdOutputInput `json:"outputs"`
	// Analyze folds the signature verdicts into the bundle's ANALYSIS section.
	// Default false: a bare export is a raw (redacted) evidence bundle.
	Analyze bool `json:"analyze"`
}

// handleProtocolDiagExport assembles the redacted, shareable TAC bundle from
// operator-supplied outputs, optionally with the signature analysis folded in.
//
// It touches no device and persists nothing: infrastructure:READ is the right
// gate (it reveals nothing the caller did not supply), the body is bounded and
// validated through the same pdBuildCollection path analyze uses, and
// protocoldiag.TACExport runs the redaction pass itself so a caller cannot
// forget it (§8). The export is audited with the `sensitive` tag because it is
// the explicit act of producing something meant to LEAVE the platform.
func (s *server) handleProtocolDiagExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, _ := principalTenant(claims)

	var req pdExportRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, pdAnalyzeMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return
	}

	col, issue, err := pdBuildCollection(s.pdCatalog(), tenant, req.Protocol, req.IssueID, req.Device, req.Outputs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// The ANALYSIS section is either the real verdicts or an explicit statement
	// that no analysis was run. It is never left blank and never implies a clean
	// bill of health the platform did not give.
	res := protocoldiag.AnalyzeResult{
		Protocol:       issue.Protocol,
		IssueID:        issue.ID,
		IssueTitle:     issue.Title,
		RulesetVersion: protocoldiag.RulesetVersion,
		Unmatched:      "Analysis was not run for this export — the raw redacted capture below is the evidence.",
	}
	if req.Analyze {
		res = s.pdAnalyzer().Analyze(col)
	}
	blob := protocoldiag.TACExport(col, res)

	s.pdAudit(r, claims, tenant, "protocol_diagnostics.export", map[string]any{
		"issue_id": issue.ID, "commands": len(col.Commands), "analyzed": req.Analyze,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"ruleset_version": protocoldiag.RulesetVersion,
		"protocol":        string(issue.Protocol),
		"issue_id":        issue.ID,
		"issue_title":     issue.Title,
		"analyzed":        req.Analyze,
		"matched":         res.Matched(),
		"findings":        pdFindingViews(res),
		"filename":        pdExportFilename(col),
		"redacted":        true,
		"tac_export":      blob,
	})
}

// pdExportFilename suggests a download name for the bundle. It is built only
// from the issue id and the sanitized hostname — no tenant, no device id — so
// the name itself leaks nothing when the file is forwarded to a vendor.
func pdExportFilename(col *protocoldiag.Collection) string {
	host := pdSlug(col.Hostname)
	if host == "" {
		host = "capture"
	}
	return "correlix-tac-" + host + "-" + pdSlug(col.IssueID) + ".txt"
}

// pdSlug reduces a string to lowercase [a-z0-9-] so it is safe in a filename on
// every platform, with no path separators and no shell-significant characters.
func pdSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.' || r == ' ':
			b.WriteByte('-')
		}
		if b.Len() >= 64 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

// TAC-ROUTES-BEGIN
//
// The TAC ESCALATION PACK's HTTP surface (docs/design/TAC_ESCALATION_2026-09-05.md).
// It lives in this file rather than a new one because the root-package ratchet
// (package_growth_guard_test.go) is at its floor and this is the same bounded
// context: the escalation pack REPLACES the protocol-diagnostics bench on the
// Investigate page, reuses its runner, its closed-table pattern and its
// redactor, and shares its feature flag and SSH custody.
//
// Everything below is ADAPTER ONLY. Classification, planning, collection,
// bundling, the case seam and the bundle store are internal/tac; these handlers
// resolve the caller's own incident and device, hand ids to that package, and
// render its answers. No decision is made here.
//
//	GET  /api/incidents/{id}/tac            — the escalation's state
//	POST /api/incidents/{id}/tac/classify   — evidence → issue class + why
//	POST /api/incidents/{id}/tac/plan       — class + device → the command plan
//	POST /api/incidents/{id}/tac/collect    — start the read-only collection
//	GET  /api/incidents/{id}/tac/bundle     — download the redacted zip
//	POST /api/incidents/{id}/tac/case       — pre-fill / submit the case
//
// §3a: every route resolves {id} through the caller's OWN incident/correlation
// scope and 404s anything else (an absent id and another tenant's id answer
// identically, so the subtree is not an existence oracle); the subject device is
// resolved through the principal-scoped inventory the same way; the escalation's
// tenant is stamped from those resolved records and NEVER from a request body.

// tacMaxLogExcerpts bounds how many timeline lines become classification input
// and bundle evidence.
const tacMaxLogExcerpts = 200

// errTACUnavailable is the honest "this build has no TAC catalog" condition. It
// can only happen if the embedded data failed to load, which the package's own
// test would have caught — so it is a 503, not a 500 pretending to be one.
var errTACUnavailable = errors.New("the TAC escalation catalog is not available on this build")

// tacSvc returns the escalation service, or nil.
func (s *server) tacSvc() *tac.Service { return s.tacService }

// tacResolveIncident authorises the caller and resolves {id} in their own scope.
// It returns the incident facts the escalation is built from. A cross-tenant or
// unknown id is a 404 — never a 403, which would confirm the id exists.
func (s *server) tacResolveIncident(w http.ResponseWriter, r *http.Request, level int) (tacIncident, jwtClaims, bool) {
	claims, ok := s.requirePerm(w, r, "infrastructure", level)
	if !ok {
		return tacIncident{}, claims, false
	}
	if s.tacSvc() == nil {
		writeError(w, http.StatusServiceUnavailable, errTACUnavailable)
		return tacIncident{}, claims, false
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" || len(id) > 128 {
		http.NotFound(w, r)
		return tacIncident{}, claims, false
	}
	tenant, cross := principalTenant(claims)
	inc, found := s.tacLookupIncident(r, tenant, cross, id)
	if !found {
		http.NotFound(w, r)
		return tacIncident{}, claims, false
	}
	inc.Tenant = tenant
	inc.Cross = cross
	return inc, claims, true
}

// tacIncident is the resolved subject of an escalation.
type tacIncident struct {
	ID     string
	Ref    string
	Title  string
	Tenant string
	Cross  bool

	WindowStart time.Time
	WindowEnd   time.Time

	// Hypotheses are the RCA hypothesis template ids ranked for this case.
	Hypotheses []string
	// Devices are the affected device ids/names from the correlation object.
	Devices []string
	// Sources records WHICH evidence stores actually answered, and which did
	// not. It is rendered to the operator: an escalation built without the alert
	// store must not look like one built with it.
	Sources []string
	Missing []string
}

// tacLookupIncident resolves an id as EITHER an incident record OR a correlation
// object, both in the caller's own scope. Correlix's Investigate page works from
// correlation ids and its incident register from incident ids; an operator
// escalating should not have to know which one they are holding.
func (s *server) tacLookupIncident(r *http.Request, tenant string, cross bool, id string) (tacIncident, bool) {
	out := tacIncident{ID: id, Ref: id}
	found := false

	if s.incidents != nil {
		if inc, _, ok, err := s.incidents.Get(r.Context(), tenant, cross, id); err == nil && ok {
			found = true
			out.Ref = incident.DisplayID(inc.ID)
			out.Title = inc.Title
			out.WindowStart = inc.FirstSeenAt
			out.WindowEnd = inc.LastSeenAt
			out.Sources = append(out.Sources, "incident register")
			if inc.SourceType == "correlation" && isUUIDToken(inc.SourceID) {
				id = inc.SourceID
			}
		}
	}
	if isUUIDToken(id) {
		if obj, ok := s.tacCorrelationFacts(r, id); ok {
			found = true
			out.Sources = append(out.Sources, "correlation object")
			out.Hypotheses = obj.hypotheses
			out.Devices = obj.devices
			if out.Title == "" {
				out.Title = obj.title
			}
			if out.WindowStart.IsZero() {
				out.WindowStart = obj.windowStart
				out.WindowEnd = obj.windowEnd
			}
		} else {
			out.Missing = append(out.Missing, "correlation object (not readable for this id)")
		}
	}
	return out, found
}

// tacCorrFacts is what the correlation object contributes.
type tacCorrFacts struct {
	title       string
	hypotheses  []string
	devices     []string
	windowStart time.Time
	windowEnd   time.Time
}

// tacCorrelationFacts reads the latest version of one correlation object. The
// read goes through s.chRows, so the ClickHouse row policies scope it to the
// caller's tenant exactly as the RCA workspace's own read is scoped — this
// handler adds no tenant predicate of its own and cannot widen that scope.
func (s *server) tacCorrelationFacts(r *http.Request, id string) (tacCorrFacts, bool) {
	if !isUUIDToken(id) {
		return tacCorrFacts{}, false
	}
	sql := `
SELECT top_hypothesis, hypotheses, affected,
       ` + chschema.ISO("window_start") + ` AS window_start,
       ` + chschema.ISO("window_end") + ` AS window_end
  FROM netops.corr_objects
 WHERE correlation_id = '` + id + `'
 ORDER BY version DESC
 LIMIT 1
 FORMAT JSON`
	rows, err := s.chRows(r, sql)
	if err != nil { // a ClickHouse failure is NOT "no facts": log it, then classify without them
		logWarn("tac", "correlation facts could not be read — classifying without them", map[string]any{"correlation_id": id, "error": err.Error()})
		return tacCorrFacts{}, false
	}
	if len(rows) == 0 {
		return tacCorrFacts{}, false
	}
	row := rows[0]
	out := tacCorrFacts{}
	if top := fmt.Sprintf("%v", row["top_hypothesis"]); top != "" && top != "<nil>" && top != "undetermined" {
		out.title = top
		out.hypotheses = append(out.hypotheses, top)
	}
	out.hypotheses = append(out.hypotheses, tac.HypothesisIDs(fmt.Sprintf("%v", row["hypotheses"]))...)
	out.devices = tac.AffectedDevices(fmt.Sprintf("%v", row["affected"]))
	out.windowStart = tac.ParseTime(fmt.Sprintf("%v", row["window_start"]))
	out.windowEnd = tac.ParseTime(fmt.Sprintf("%v", row["window_end"]))
	return out, true
}

// tacEvidence assembles the CLOSED classification input from stores the caller
// can already read. Everything here is server-derived: the client sends an
// incident id, never evidence.
func (s *server) tacEvidence(r *http.Request, claims jwtClaims, inc tacIncident) (tac.Evidence, []string, []string) {
	ev := tac.Evidence{IncidentID: inc.ID, TenantID: inc.Tenant, Hypotheses: inc.Hypotheses}
	sources := append([]string(nil), inc.Sources...)
	missing := append([]string(nil), inc.Missing...)

	// The correlation case timeline is the alert/log evidence the RCA workspace
	// already shows. Reusing it means the escalation classifies on exactly what
	// the operator was looking at.
	if fn := s.aiCaseTimeline(claims); fn != nil && isUUIDToken(inc.ID) {
		events, err := fn(r.Context(), tacPrincipal(claims), inc.ID)
		switch {
		case err != nil:
			missing = append(missing, "case timeline ("+operatorSafeErr(err)+")")
		default:
			sources = append(sources, "case timeline")
			for _, e := range events {
				if len(ev.LogLines) >= tacMaxLogExcerpts {
					break
				}
				ev.LogLines = append(ev.LogLines, strings.TrimSpace(e.Kind+" "+e.Entity+" "+e.Text))
				if e.Kind == "alert" && e.Entity != "" {
					ev.Alerts = append(ev.Alerts, e.Entity)
				}
			}
		}
	}
	// The incident's own title is operator-visible text, not a store read, but a
	// log pattern in it is a legitimate hint.
	if inc.Title != "" {
		ev.LogLines = append(ev.LogLines, inc.Title)
	}
	return ev, sources, missing
}

func tacPrincipal(claims jwtClaims) ai.Principal {
	tenant, cross := principalTenant(claims)
	return ai.Principal{Tenant: tenant, Cross: cross}
}

// operatorSafeErr renders an error for an operator without leaking internals.
func operatorSafeErr(err error) string {
	if err == nil {
		return ""
	}
	return clampString(err.Error(), 160)
}

func (s *server) tacResolveDevice(w http.ResponseWriter, r *http.Request, inc tacIncident, deviceID string) (tac.Device, bool) {
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, errors.New("device_id is required"))
		return tac.Device{}, false
	}
	dev, found := s.discovery.Get(deviceID)
	if !found || !canSeeDevice(dev, inc.Tenant, inc.Cross) {
		http.NotFound(w, r)
		return tac.Device{}, false
	}
	return tac.Device{
		ID: dev.ID, Hostname: dev.Name, Platform: pdPlatformString(dev),
		TenantID: deviceTenant(dev), // §3a: owner from the resolved device
		// The management endpoint comes from the resolved inventory row, the
		// same one the diagnostics collector and the operator terminal dial.
		Address: dev.Address, Port: envInt(protocoldiag.EnvSSHPort, 22),
		// The device's identity AS THE VENDOR CHECKS IT, from the same resolved
		// row. This is what lets the confirmation screen arrive already carrying
		// the serial a vendor's entitlement check demands, instead of asking an
		// operator to go and read a label off a chassis at three in the morning.
		Vendor: strings.ToLower(strings.TrimSpace(dev.Vendor)),
		Serial: dev.SerialNumber, Model: dev.Model,
	}, true
}

// tacTopology reads Correlix's own neighbourhood for the device through the
// SAME principal-scoped adapter the assistant uses.
func (s *server) tacTopology(r *http.Request, claims jwtClaims, deviceID string) []tac.TopologyNote {
	fn := s.aiTopologyContext(claims)
	if fn == nil {
		return nil
	}
	ctxInfo, err := fn(r.Context(), tacPrincipal(claims), deviceID)
	if err != nil {
		return nil
	}
	out := make([]tac.TopologyNote, 0, len(ctxInfo.Neighbors)+len(ctxInfo.Seams)+len(ctxInfo.Paths)+1)
	if ctxInfo.Site != "" || ctxInfo.Role != "" {
		out = append(out, tac.TopologyNote{Kind: "site", Ref: ctxInfo.Site, Detail: ctxInfo.Role})
	}
	for _, n := range ctxInfo.Neighbors {
		out = append(out, tac.TopologyNote{
			Kind: "neighbor", Ref: n.PeerName,
			Detail: n.LocalPort + " → " + n.PeerPort + " (observed by " + n.Source + ")",
		})
	}
	for _, sm := range ctxInfo.Seams {
		out = append(out, tac.TopologyNote{Kind: "seam", Ref: sm.ID, Detail: sm.Type + " owned by " + sm.Owner})
	}
	for _, p := range ctxInfo.Paths {
		out = append(out, tac.TopologyNote{Kind: "link", Ref: p.ID, Detail: p.Label + " " + p.Health})
	}
	return out
}

// ── GET /api/incidents/{id}/tac/bundle ──────────────────────────────────────

func (s *server) handleTACBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	inc, claims, ok := s.tacResolveIncident(w, r, LevelRead)
	if !ok {
		return
	}
	profile := tac.BundleProfile(strings.TrimSpace(r.URL.Query().Get("profile")))
	switch profile {
	case "", tac.ProfileFull, tac.ProfileEmail, tac.ProfileLinkOnly:
	default:
		writeError(w, http.StatusBadRequest, errors.New("profile must be full, email or link_only"))
		return
	}
	b, meta, err := s.tacSvc().Bundle(r.Context(), inc.Tenant, inc.ID, s.tacBundleInput(r, claims, inc, profile))
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	// §8: producing something meant to LEAVE the platform is audited, with the
	// sensitive tag, exactly like the protocol-diagnostics export.
	s.pdAudit(r, claims, inc.Tenant, "tac.bundle", map[string]any{
		"incident_id": inc.ID, "bundle": meta.Name, "bytes": meta.Bytes,
		"profile": b.Manifest.Profile, "statement_by": b.Statement.WrittenBy,
	})
	// The escalation becomes REAL the first time a bundle is produced, so that is
	// when it is written into the investigation memory Iris recalls from — once,
	// not once per download, and regardless of whether a case is ever opened.
	if s.tacSvc().MarkRemembered(inc.Tenant, inc.ID) {
		s.tacRememberEscalation(r, claims, inc, b, tac.CaseResult{})
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+b.Name+"\"")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(b.Zip)))
	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- this is a binary attachment, not a rendered document: the
	// bytes are a zip this process just built, the response is served as
	// application/zip with `X-Content-Type-Options: nosniff` and a
	// Content-Disposition attachment, and every text inside it has already been
	// through the redaction pass. There is no HTML context for a script to
	// execute in, and the browser is told not to invent one.
	if _, err := w.Write(b.Zip); err != nil {
		logError("tac", "bundle write failed", map[string]any{"incident_id": inc.ID, "error": err.Error()})
	}
}

// tacBundleInput gathers the evidence the bundle carries, each read through the
// same principal-scoped adapter the assistant uses.
func (s *server) tacBundleInput(r *http.Request, claims jwtClaims, inc tacIncident, profile tac.BundleProfile) tac.BundleInput {
	in := tac.BundleInput{
		IncidentRef: inc.Ref, Title: inc.Title,
		WindowStart: inc.WindowStart, WindowEnd: inc.WindowEnd,
		Actor: claims.Sub, Profile: profile,
	}
	for _, h := range inc.Hypotheses {
		in.Hypotheses = append(in.Hypotheses, tac.HypothesisFact{TemplateID: h})
	}
	if fn := s.aiCaseTimeline(claims); fn != nil && isUUIDToken(inc.ID) {
		if events, err := fn(r.Context(), tacPrincipal(claims), inc.ID); err == nil {
			for _, e := range events {
				if len(in.Logs) >= tacMaxLogExcerpts {
					break
				}
				at := tac.ParseTime(e.At)
				if e.Kind == "alert" && e.Entity != "" {
					in.Alerts = append(in.Alerts, tac.AlertFact{Name: e.Entity, Summary: e.Text, At: at})
					continue
				}
				in.Logs = append(in.Logs, tac.LogLine{At: at, Device: e.Entity, Severity: e.Kind, Message: e.Text})
			}
		}
	}
	if fn := s.aiSecurityFindings(claims); fn != nil {
		if rows, err := fn(r.Context(), tacPrincipal(claims), ai.FindingsQuery{Current: true, Limit: 25}); err == nil {
			for _, f := range rows {
				in.Findings = append(in.Findings, tac.FindingFact{
					ID: f.ID, Title: f.Title, Severity: f.Severity, Device: f.Entity,
				})
			}
		}
	}
	return in
}

// tacRememberEscalation writes the escalation into the SAME investigation memory
// Iris recalls from (ai.InvestigationStore). It is best-effort: a memory that
// could not be written is logged, never a reason to fail a case the operator
// just opened.
func (s *server) tacRememberEscalation(r *http.Request, claims jwtClaims, inc tacIncident, b *tac.Bundle, res tac.CaseResult) {
	if s.irisMemory == nil {
		return
	}
	verdict := "Escalated to TAC as " + b.Manifest.Classification.Title +
		" (" + b.Manifest.Classification.ClassID + "), plan " + b.Manifest.PlanVersion +
		", bundle " + b.Name
	if res.CaseID != "" {
		verdict += ", case " + res.CaseID
	}
	row, err := ai.NormalizeInvestigation(ai.InvestigationRow{
		TenantID:      inc.Tenant,
		DeviceID:      b.Manifest.Device.ID,
		DeviceName:    b.Manifest.Device.Hostname,
		CorrelationID: inc.ID,
		Skills:        []string{"tac-escalation", b.Manifest.Classification.ClassID},
		Verdict:       verdict,
		Citations:     b.Statement.CitedIDs,
		Outcome:       ai.OutcomeUnknown,
	})
	if err != nil {
		logError("tac", "escalation memory rejected", map[string]any{"incident_id": inc.ID, "error": err.Error()})
		return
	}
	if err := s.irisMemory.Record(r.Context(), row); err != nil {
		logError("tac", "escalation memory not written", map[string]any{"incident_id": inc.ID, "error": err.Error()})
	}
	_ = claims
}

// ── GET /api/troubleshoot/tac/knowledge ─────────────────────────────────────
//
// The Iris → Knowledge coverage view. It is version-pinned REFERENCE DATA,
// identical for every tenant — what Correlix knows, per vendor dialect — and it
// reveals nothing about any tenant's devices or incidents.

func (s *server) handleTACKnowledge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	if s.tacSvc() == nil {
		writeError(w, http.StatusServiceUnavailable, errTACUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, s.tacSvc().Catalog().Knowledge(tac.KnownDialects()))
}

// GET /api/tac/connectors — the case connectors as THIS tenant sees them, with
// no incident (Administration → Ticket delivery). §3a: the tenant is the
// caller's own, from the token; `configured` is the only per-tenant field.
func (s *server) handleTACConnectors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	if s.tacSvc() == nil {
		writeError(w, http.StatusServiceUnavailable, errTACUnavailable)
		return
	}
	tenant, _ := principalTenant(claims)
	if tenant == TenantGlobal {
		tenant = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{"connectors": s.tacSvc().Connectors(r.Context(), tenant)})
}

// tacConnectorConfig resolves ONE tenant's case-connector configuration for ONE
// connector.
//
// The connector id matters: ServiceNow and Jira share a config record but need
// DIFFERENT ITSM connections, and the seam's resolver is handed only a tenant.
// Binding the connector id per opener (below) is what lets the right connection
// reach the right adapter without widening internal/ticketing's interface.
//
// §3a: the tenant is the one the caller was resolved to. `Get(tenant, false,
// tenant)` reads that tenant's own row and nothing else — a cross-tenant read is
// not merely filtered, it is refused by the store.
func (s *server) tacConnectorConfig(_ context.Context, tenantID, connectorID string) (ticketing.TACConnectorConfig, error) {
	if s.tacConnectors == nil {
		return ticketing.TACConnectorConfig{}, ticketing.ErrTenantNotFound
	}
	cfg, err := s.tacConnectors.Get(tenantID, false, tenantID)
	if err != nil {
		return ticketing.TACConnectorConfig{}, err
	}
	// The ITSM connection is resolved at CALL TIME from the tenant's existing
	// ServiceNow/Jira config and is never persisted in the TAC record.
	if s.itsmCfg != nil {
		switch connectorID {
		case "servicenow", "jira":
			if sc, ok := s.itsmCfg.SystemConfigFor(tenantID, connectorID); ok {
				cfg.ITSM = sc
			}
		}
	}
	return cfg, nil
}

// tacOpenBundle streams one stored bundle to a case connector. The path is a
// `<incident>/<bundle-name>` reference INSIDE the tenant's own bundle tree — the
// store validates both segments, so a connector can never be handed a path from
// anywhere else (§3a rule 4 / the CaseRequest contract).
func (s *server) tacOpenBundle(_ context.Context, tenantID, ref string) (ticketing.Bundle, error) {
	if s.tacBundles == nil {
		return ticketing.Bundle{}, errors.New("no TAC bundle store is configured")
	}
	incidentID, name, ok := strings.Cut(ref, "/")
	if !ok {
		return ticketing.Bundle{}, tac.ErrNotFound
	}
	data, meta, err := s.tacBundles.Get(tenantID, incidentID, name)
	if err != nil {
		return ticketing.Bundle{}, err
	}
	sum := sha256.Sum256(data)
	return ticketing.Bundle{
		Name: meta.Name, ContentType: "application/zip", Size: int64(len(data)),
		SHA256: hex.EncodeToString(sum[:]),
		Open:   func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil },
	}, nil
}

// tacCaseOpeners builds the W2 connectors behind the published CaseOpener seam.
// Each adapter's Resolve is REBOUND to a connector-aware closure (see
// tacConnectorConfig); every field it touches is exported and documented as
// injected, so this is the intended wiring point rather than a reach into the
// package's internals.
func (s *server) tacCaseOpeners() []tac.CaseOpener {
	openers := ticketing.TACOpenersFromRegistry(
		ticketing.DefaultCaseConnectorRegistry(),
		func(ctx context.Context, tenantID string) (ticketing.TACConnectorConfig, error) {
			return s.tacConnectorConfig(ctx, tenantID, "")
		},
		s.tacOpenBundle,
	)
	for _, o := range openers {
		to, ok := o.(*ticketing.TACOpener)
		if !ok {
			continue
		}
		id := to.Connector.Name()
		to.Resolve = func(ctx context.Context, tenantID string) (ticketing.TACConnectorConfig, error) {
			return s.tacConnectorConfig(ctx, tenantID, id)
		}
	}
	return openers
}

// buildTACService constructs the escalation service. The live collector is wired
// only when the SAME feature flag the protocol-diagnostics collector uses is on
// and its runner built — one flag, one SSH custody, one read-only account.
func (s *server) buildTACService() error {
	cat, err := tac.Default()
	if err != nil {
		return fmt.Errorf("tac catalog: %w", err)
	}
	opts := []tac.ServiceOption{}
	// The reviewed allow set (tracker 250): the gate and the service must share
	// ONE registry, or a command the operator approved would be refused at the
	// wire. That is the safe direction to fail, and a test asserts it, but the
	// correct wiring is this — built here, handed to both.
	reviews := tac.NewReviewRegistry()
	opts = append(opts, tac.WithReviews(reviews))
	if protocolDiagCollectEnabled() && s.sshHosts != nil {
		runner, rerr := protocoldiag.NewSSHGatedRunner(tac.NewGate(cat, tac.WithReviewRegistry(reviews)), s.protocolDiagGateway())
		if rerr != nil {
			return fmt.Errorf("tac runner: %w", rerr)
		}
		col, cerr := tac.NewCollector(runner)
		if cerr != nil {
			return fmt.Errorf("tac collector: %w", cerr)
		}
		opts = append(opts, tac.WithCollector(col))
	}
	store, serr := tac.NewStore(filepath.Join(envOr("DATA_DIR", "/data"), "tac"), tac.WithWarn(func(m string, f map[string]any) { logWarn("tac", m, f) }))
	if serr != nil {
		return fmt.Errorf("tac bundle store: %w", serr)
	}
	opts = append(opts, tac.WithStore(store))
	s.tacBundles = store
	// The per-tenant case-connector credentials (W2). The store is always built:
	// a tenant with no configuration simply has no configured connector, which
	// the UI shows greyed with its reason — the honest state, not an absence.
	s.tacConnectors = ticketing.NewTACConnectorStore(
		envOr("TAC_CONNECTOR_CONFIG_FILE", filepath.Join(envOr("DATA_DIR", "/data"), "tac_connectors.json")))
	opts = append(opts, tac.WithOpeners(s.tacCaseOpeners()...))
	// The learning backlog (tracker 243). Always built: without it the Knowledge
	// page would say "not yet tracked" forever.
	s.tacLearningStore = newTACLearningStore()
	opts = append(opts,
		tac.WithLearning(s.tacLearningStore),
		tac.WithServiceWarn(func(m string, f map[string]any) { logWarn("tac", m, f) }),
		// A finished collection has already read `show version` / `show
		// inventory` on its way to opening a case, so the chassis serial it
		// printed is folded back onto the inventory row through the SAME apply
		// rules the OS-version ladder uses — provenance stamped as the
		// escalation, never dressed up as a probe result. It is best-effort: a
		// device that left the inventory mid-collection simply gets nothing.
		tac.WithIdentitySink(s.tacRecordDeviceIdentity),
	)
	svc, err := tac.NewService(cat, opts...)
	if err != nil {
		return err
	}
	s.tacService = svc
	s.tacTemplateStore = newTACTemplateStore()
	api, aerr := tac.NewTemplateAPI(tac.TemplateAPIDeps{
		Authz: s.tacTemplateAuthz, Store: s.tacTemplateStore, Validator: svc.Validator(),
		Catalog: cat, Audit: s.tacTemplateAudit,
		WriteJSON: writeJSON, WriteError: writeError,
		Now: func() time.Time { return time.Now().UTC() },
	})
	if aerr != nil {
		return fmt.Errorf("tac templates: %w", aerr)
	}
	s.tacTemplates = api

	learn, lerr := tac.NewLearningAPI(tac.LearningAPIDeps{
		// The SAME gate the templates use: both are this tenant's operator data.
		Authz: s.tacTemplateAuthz, Store: s.tacLearningStore, Validator: svc.Validator(),
		Catalog: cat, Audit: s.tacTemplateAudit,
		WriteJSON: writeJSON, WriteError: writeError,
		Now: func() time.Time { return time.Now().UTC() },
	})
	if lerr != nil {
		return fmt.Errorf("tac learning: %w", lerr)
	}
	s.tacLearning = learn

	// The tenant's TAC ROUTING record — contact, per-vendor route, per-dialect
	// preferred capture, vendor contracts. Always built: a tenant with none
	// simply has a blank record, and the connector's own required-field list is
	// what refuses a case, by name.
	s.tacRouting = ticketing.NewTACRoutingStore(
		envOr("TAC_ROUTING_CONFIG_FILE", filepath.Join(envOr("DATA_DIR", "/data"), "tac_routing.json")))

	// The case tracker and its poller. They are built unconditionally so an
	// operator's "Refresh now" works on any deployment that opened a case; the
	// background loop is started by the caller (Run) so a test can drive Round
	// deterministically instead of racing a ticker.
	s.tacCases = tac.NewCaseTracker(func() time.Time { return time.Now().UTC() })
	poller, perr := tac.NewCasePoller(s.tacCases,
		func(ctx context.Context, tenant, connectorID string, h tac.CaseHandle) (tac.CaseResult, error) {
			return svc.PollCase(ctx, tenant, connectorID, h)
		},
		func(ctx context.Context, tenant, incidentID string, link tac.CaseLink) error {
			s.tacPersistCase(ctx, tenant, incidentID, link)
			return nil
		},
		func(m string, f map[string]any) { logWarn("tac", m, f) })
	if perr != nil {
		return fmt.Errorf("tac case poller: %w", perr)
	}
	s.tacPoller = poller

	// The ONE-ACTION surface and the routing-settings surface, both injectable
	// modules in their own packages. They are built LAST because they take the
	// tracker and the poller above.
	if err := s.buildTACEscalateAPI(svc); err != nil {
		return fmt.Errorf("tac escalate surface: %w", err)
	}
	return nil
}

// tacRecordDeviceIdentity folds a collection's own reading of the chassis serial
// and model onto the device record.
//
// The PARSING is internal/deviceident's, over the vendor profile data — this
// file carries no regex and no vendor name, which is what keeps the platform on
// one vendor vocabulary (§13). The WRITE goes through the discovery
// aggregator's RecordIdentity, which applies the ladder's own overwrite rules
// so a serial read here and a serial read by the probe cannot disagree about
// which one wins.
func (s *server) tacRecordDeviceIdentity(deviceID string, obs []tac.IdentityObservation) {
	if s.discovery == nil || len(obs) == 0 {
		return
	}
	cmds := make([]deviceident.CapturedCommand, 0, len(obs))
	for _, o := range obs {
		cmds = append(cmds, deviceident.CapturedCommand{
			Command: o.Command, Output: o.Output, Platform: o.Platform,
		})
	}
	ident := deviceident.FromCapture(cmds)
	if ident.Empty() {
		return // nothing this collection printed was a hardware identity
	}
	s.discovery.RecordIdentity(deviceID, ident, tacIdentityMethod, time.Now().UTC())
}

// tacIdentityMethod is the provenance stamp a serial learned this way carries.
// It is deliberately its OWN value rather than "ssh": an operator looking at the
// row must be able to tell that the serial came from an escalation's collection,
// which happens on a bad day and against one device, from one the inventory's
// own probe learned on its regular walk.
const tacIdentityMethod = osprobe.Method("tac-escalation")

// newTACLearningStore builds the backlog's backend: FILE-backed, the sibling of
// the BUNDLE store rather than of the template store, because a learning record
// is per-collection evidence with a ceiling, not control-plane state. Isolation
// is the store's own (§3a rule 4), and a corrupt file serves an empty backlog
// and SAYS so — one that failed to load must not look like one never written.
func newTACLearningStore() tac.LearningStore {
	fs := tac.NewFileLearningStore(envOr(tac.EnvLearningFile, filepath.Join(envOr("DATA_DIR", "/data"), "tac_learning.json")))
	if err := fs.LoadErr(); err != nil {
		logError("tac", "the TAC learning backlog could not be read — it starts EMPTY; collections still run and file new records",
			map[string]any{"err": err.Error()})
	}
	return fs
}

// The two learning entry points, resolved at REQUEST time; the module nil-checks
// its receiver, so an unbuilt surface answers 404 rather than reading unscoped.
func (s *server) handleTACLearning(w http.ResponseWriter, r *http.Request) {
	s.tacLearning.HandleLearning(w, r)
}

func (s *server) handleTACLearningSubtree(w http.ResponseWriter, r *http.Request) {
	s.tacLearning.HandleLearningSubtree(w, r)
}

// newTACTemplateStore picks the template backend the way every other per-tenant
// store does: Postgres (migration 0045, FORCE-RLS) when it is active, the file
// store otherwise. A corrupt file still SERVES (an empty set) but says so — a
// template set that failed to load must never look like one a tenant never
// wrote, because the visible consequence of both is the same empty list.
func newTACTemplateStore() tac.TemplateStore {
	if ps, ok := platformdb.ActivePG(); ok {
		return tac.NewPGTemplateStore(ps.DB())
	}
	fs := tac.NewFileTemplateStore(envOr(tac.EnvTemplatesFile, filepath.Join(envOr("DATA_DIR", "/data"), "tac_templates.json")))
	if err := fs.LoadErr(); err != nil {
		logError("tac", "the TAC command templates could not be read — they start EMPTY; Correlix's own defaults are unaffected",
			map[string]any{"err": err.Error()})
	}
	return fs
}

// tacTemplateAuthz maps the module's gates onto the RBAC model. Templates are
// per-tenant OPERATOR data about the tenant's own escalations — not platform
// plumbing — so both gates are requirePerm(infrastructure, …) plus the tenant
// filter, the same gate the escalation routes themselves use (§3a rule 3).
func (s *server) tacTemplateAuthz(w http.ResponseWriter, r *http.Request, gate tac.TemplateGate) (tac.TemplatePrincipal, bool) {
	level := LevelRead
	if gate == tac.TemplateGateWrite {
		level = LevelWrite
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", level)
	if !ok {
		return tac.TemplatePrincipal{}, false
	}
	tenant, cross := principalTenant(claims)
	if tenant == TenantGlobal {
		// The platform tenant is not a customer: treat it as scopeless so the
		// module's own refusal fires rather than reading a shared bucket.
		tenant = ""
	}
	return tac.TemplatePrincipal{Tenant: tenant, Cross: cross, Subject: claims.Sub}, true
}

// tacTemplateAudit records a template write. A template decides which commands
// reach a customer's routers, so no change to one is silent (§10).
func (s *server) tacTemplateAudit(r *http.Request, p tac.TemplatePrincipal, action string, detail map[string]any) {
	if s.audit == nil {
		return
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detail["action"] = action
	detail["sensitive"] = true
	s.audit.Record(AuditEvent{
		Actor: p.Subject, Tenant: p.Tenant, Cross: p.Cross,
		Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
		Remote: auditClientIP(r), Detail: detail,
	})
}

// The template and capture route entry points. They resolve s.tacTemplates at
// REQUEST time (a bound method value would capture a nil surface at
// registration time), and the module's handlers nil-check their receiver, so an
// unbuilt surface answers 404 rather than degrading into an unscoped read.
func (s *server) handleTACTemplates(w http.ResponseWriter, r *http.Request) {
	s.tacTemplates.HandleTemplates(w, r)
}

func (s *server) handleTACTemplateItem(w http.ResponseWriter, r *http.Request) {
	s.tacTemplates.HandleTemplateItem(w, r)
}

func (s *server) handleTACTemplateDefaults(w http.ResponseWriter, r *http.Request) {
	s.tacTemplates.HandleDefaults(w, r)
}

func (s *server) handleTACTemplateValidate(w http.ResponseWriter, r *http.Request) {
	s.tacTemplates.HandleValidate(w, r)
}

func (s *server) handleTACCaptures(w http.ResponseWriter, r *http.Request) {
	s.tacTemplates.HandleCaptures(w, r)
}

func (s *server) handleTACCaptureSubtree(w http.ResponseWriter, r *http.Request) {
	s.tacTemplates.HandleCaptureSubtree(w, r)
}

// ── the ONE ACTION ──────────────────────────────────────────────────────────
//
// Owner's goal (2026-09-06): "ease of collecting data and open the case with one
// or two clicks". The whole surface — escalate, prepare, dry-run, confirm and
// the case refresh — is tac.EscalateAPI, in the same injectable shape the
// template and learning surfaces already have. What stays HERE is the only part
// the api can do: resolving the caller's own incident and device through the
// principal-scoped stores, gathering the evidence they can already read, and
// resolving the tenant's routing record. Every decision is the package's.

func (s *server) handleTACState(w http.ResponseWriter, r *http.Request) {
	s.tacEscalate.HandleState(w, r)
}

func (s *server) handleTACClassify(w http.ResponseWriter, r *http.Request) {
	s.tacEscalate.HandleClassify(w, r)
}

func (s *server) handleTACPlan(w http.ResponseWriter, r *http.Request) {
	s.tacEscalate.HandlePlan(w, r)
}

func (s *server) handleTACCollect(w http.ResponseWriter, r *http.Request) {
	s.tacEscalate.HandleCollect(w, r)
}

func (s *server) handleTACCase(w http.ResponseWriter, r *http.Request) {
	s.tacEscalate.HandleCase(w, r)
}

func (s *server) handleTACEscalate(w http.ResponseWriter, r *http.Request) {
	s.tacEscalate.HandleEscalate(w, r)
}

func (s *server) handleTACEscalatePrepare(w http.ResponseWriter, r *http.Request) {
	s.tacEscalate.HandlePrepare(w, r)
}

func (s *server) handleTACEscalateDryRun(w http.ResponseWriter, r *http.Request) {
	s.tacEscalate.HandleDryRun(w, r)
}

func (s *server) handleTACEscalateConfirm(w http.ResponseWriter, r *http.Request) {
	s.tacEscalate.HandleConfirm(w, r)
}

func (s *server) handleTACCaseRefresh(w http.ResponseWriter, r *http.Request) {
	s.tacEscalate.HandleRefresh(w, r)
}

// handleTACRouting is the tenant's TAC ROUTING record (contact, per-vendor
// route, preferred capture, vendor contracts), served by ticketing.TACRoutingAPI
// — the same module shape, and the same gate, the connector settings use.
func (s *server) handleTACRouting(w http.ResponseWriter, r *http.Request) {
	s.tacRoutingAPI.HandleRouting(w, r)
}

// tacEscalateSubject adapts tacResolveIncident onto the package's Subject.
func (s *server) tacEscalateSubject(w http.ResponseWriter, r *http.Request, write bool) (tac.Subject, bool) {
	level := LevelRead
	if write {
		level = LevelWrite
	}
	inc, claims, ok := s.tacResolveIncident(w, r, level)
	if !ok {
		return tac.Subject{}, false
	}
	return tac.Subject{
		IncidentID: inc.ID, Ref: inc.Ref, Title: inc.Title, Devices: inc.Devices,
		Tenant: inc.Tenant, Cross: inc.Cross, Actor: claims.Sub,
	}, true
}

// tacSubjectIncident rebuilds the adapter's own incident record from a Subject,
// for the helpers that were written against it.
func (s *server) tacSubjectIncident(r *http.Request, subj tac.Subject) tacIncident {
	inc, _ := s.tacLookupIncident(r, subj.Tenant, subj.Cross, subj.IncidentID)
	inc.ID, inc.Tenant, inc.Cross = subj.IncidentID, subj.Tenant, subj.Cross
	if inc.Ref == "" {
		inc.Ref = subj.Ref
	}
	return inc
}

// tacSettingsFor resolves the tenant's routing record for ONE device and folds
// in the contract that covers it. The serial comes from the DEVICE RECORD and
// the contract from the tenant's own settings, which is what lets the
// confirmation screen arrive complete.
func (s *server) tacSettingsFor(tenant string, cross bool, vendor, serial string) tac.EscalationSettings {
	if s.tacRouting == nil {
		return tac.EscalationSettings{}
	}
	cfg, ok, err := s.tacRouting.Get(tenant, cross, tenant)
	if err != nil {
		// A store that could not answer is an ERROR, not an empty record. The
		// visible consequence of both is the same blank screen, so the
		// difference has to live in the log or it lives nowhere (§10).
		logWarn("tac", "this tenant's TAC routing record could not be read — the escalation continues with nothing pre-filled",
			map[string]any{"tenant": tenant, "error": err.Error()})
		return tac.EscalationSettings{}
	}
	if !ok {
		return tac.EscalationSettings{} // configured nothing: a state, not a failure
	}
	return ticketing.EscalationSettingsFor(cfg, vendor, serial, time.Now().UTC())
}

// tacPersistCase writes the case link onto the incident record, so it survives a
// restart and shows in the Operations incident list.
func (s *server) tacPersistCase(ctx context.Context, tenant, incidentID string, link tac.CaseLink) {
	if s.incidents == nil || strings.TrimSpace(link.CaseID) == "" {
		return
	}
	at := link.LastCheckedAt
	if at.IsZero() {
		at = link.OpenedAt
	}
	if err := s.incidents.MarkSync(ctx, incidentID, link.Connector, link.CaseID, link.CaseURL,
		tac.CaseSyncStatus(link), at); err != nil {
		logWarn("tac", "the vendor case could not be written onto the incident record",
			map[string]any{"tenant": tenant, "incident_id": incidentID, "case_id": link.CaseID, "error": err.Error()})
	}
}

// buildTACEscalateAPI wires the one-action surface. Every dependency it takes is
// something only the api can supply — a principal-scoped read, a platform writer
// or a clock — and nothing it takes is a decision.
func (s *server) buildTACEscalateAPI(svc *tac.Service) error {
	api, err := tac.NewEscalateAPI(tac.EscalateAPIDeps{
		Service: svc,
		Resolve: s.tacEscalateSubject,
		ResolveDevice: func(w http.ResponseWriter, r *http.Request, subj tac.Subject, id string) (tac.Device, bool) {
			return s.tacResolveDevice(w, r, s.tacSubjectIncident(r, subj), id)
		},
		Evidence: func(r *http.Request, subj tac.Subject) (tac.Evidence, []string, []string) {
			claims, _ := userFrom(r.Context())
			return s.tacEvidence(r, claims, s.tacSubjectIncident(r, subj))
		},
		Topology: func(r *http.Request, deviceID string) []tac.TopologyNote {
			claims, _ := userFrom(r.Context())
			return s.tacTopology(r, claims, deviceID)
		},
		BundleInput: func(r *http.Request, subj tac.Subject) tac.BundleInput {
			claims, _ := userFrom(r.Context())
			return s.tacBundleInput(r, claims, s.tacSubjectIncident(r, subj), "")
		},
		Settings: func(_ *http.Request, subj tac.Subject, vendor, serial string) tac.EscalationSettings {
			return s.tacSettingsFor(subj.Tenant, subj.Cross, vendor, serial)
		},
		Tracker: s.tacCases, Poller: s.tacPoller,
		Templates:   func() tac.TemplateStore { return s.tacTemplateStore },
		PersistCase: s.tacPersistCase,
		Remember: func(r *http.Request, subj tac.Subject, b *tac.Bundle, res tac.CaseResult) {
			claims, _ := userFrom(r.Context())
			s.tacRememberEscalation(r, claims, s.tacSubjectIncident(r, subj), b, res)
		},
		Audit: func(r *http.Request, tenant, action string, detail map[string]any) {
			claims, _ := userFrom(r.Context())
			s.pdAudit(r, claims, tenant, action, detail)
		},
		WriteJSON: writeJSON, WriteError: writeError,
		Now: func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return err
	}
	s.tacEscalate = api

	routing, rerr := ticketing.NewTACRoutingAPI(ticketing.TACRoutingAPIDeps{
		Authz: s.tacRoutingAuthz,
		Store: func() *ticketing.TACRoutingStore { return s.tacRouting },
		Connectors: func(ctx context.Context, tenant string) []tac.ConnectorInfo {
			return svc.Connectors(ctx, tenant)
		},
		Dialects: func() []ticketing.RoutingDialect {
			out := []ticketing.RoutingDialect{}
			for _, d := range svc.DialectChoices() {
				out = append(out, ticketing.RoutingDialect{Dialect: d.Dialect, Display: d.Display})
			}
			return out
		},
		Audit:     ticketing.DefaultCaseAuditSink(),
		WriteJSON: writeJSON, WriteError: writeError,
		Now: func() time.Time { return time.Now().UTC() },
	})
	if rerr != nil {
		return rerr
	}
	s.tacRoutingAPI = routing
	return nil
}

// tacRoutingAuthz maps the routing surface's abstract gate onto the platform's
// RBAC model. It is the SAME mapping the connector settings use, because it is
// the same class of data: one tenant's own commercial relationship with a vendor.
func (s *server) tacRoutingAuthz(w http.ResponseWriter, r *http.Request, gate ticketing.ConnectorGate) (ticketing.ConnectorPrincipal, bool) {
	level := LevelRead
	if gate == ticketing.ConnectorGateWrite {
		level = LevelWrite
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", level)
	if !ok {
		return ticketing.ConnectorPrincipal{}, false
	}
	tenant, cross := principalTenant(claims)
	return ticketing.ConnectorPrincipal{Tenant: tenant, Cross: cross, Subject: claims.Sub}, true
}

// TAC-ROUTES-END
