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
//
// §3a: every surface is per-tenant operator data gated with requirePerm on the
// "infrastructure" module. Collect resolves the subject device through the
// principal-scoped inventory and 404s a cross-tenant id (existence never
// revealed); the Collection's tenant is stamped from the RESOLVED DEVICE, never
// a request body. Analyze is request-scoped (operator-pasted text) — the tenant
// is still derived from the token, and no other tenant's data is reachable.
//
// §3/§8/§15: analyze ingests untrusted operator-pasted text — the body is bounded
// (MaxBytesReader + per-field char caps), spec ids are validated against the
// issue's own bundle, and the TAC export runs the library's redaction pass so
// secrets/PII never leave in the shareable blob.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"netops/backend/internal/protocoldiag"
	"netops/backend/models"
)

// Body/size caps for the untrusted analyze payload (§3/§8/§15 LLM-adjacent
// hygiene: bound the request, then bound each field within it).
const (
	pdAnalyzeMaxBody    = 2 << 20 // 2 MiB total request body
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
	ID          string          `json:"id"`
	Protocol    string          `json:"protocol"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Commands    []pdCommandView `json:"commands"`
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
	// tenant proves the caller is a real scoped principal even though the catalog
	// itself is tenant-invariant.
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	_, _ = principalTenant(claims)

	vendor := protocoldiag.VendorCiscoIOSXE
	if v := strings.TrimSpace(r.URL.Query().Get("vendor")); v != "" {
		vendor = protocoldiag.VendorFromPlatform(v)
	}

	cat := s.pdCatalog()
	byProtocol := map[string][]pdIssueView{}
	for _, p := range []protocoldiag.Protocol{protocoldiag.ProtocolBGP, protocoldiag.ProtocolOSPF, protocoldiag.ProtocolISIS} {
		views := make([]pdIssueView, 0, 5)
		for _, is := range cat.IssuesFor(p) {
			views = append(views, pdIssueView{
				ID:          is.ID,
				Protocol:    string(is.Protocol),
				Title:       is.Title,
				Description: is.Description,
				Commands:    pdBundleView(is, vendor),
			})
		}
		byProtocol[string(p)] = views
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ruleset_version": protocoldiag.RulesetVersion,
		"vendor":          string(vendor),
		"vendor_display":  protocoldiag.DisplayVendor(vendor),
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

type pdAnalyzeRequest struct {
	Protocol string `json:"protocol"`
	IssueID  string `json:"issue_id"`
	// Device is optional free-text context for the TAC-export header and the
	// dialect the command text renders in. It is NOT an inventory lookup — analyze
	// is request-scoped over pasted text, so there is no device to authorize.
	Device struct {
		Hostname string `json:"hostname"`
		Platform string `json:"platform"`
	} `json:"device"`
	// Outputs is the operator-pasted raw output per command spec id.
	Outputs []struct {
		SpecID string `json:"spec_id"`
		Output string `json:"output"`
	} `json:"outputs"`
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

	cat := s.pdCatalog()
	issue, ok := cat.Issue(strings.TrimSpace(req.IssueID))
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Errorf("unknown issue %q", req.IssueID))
		return
	}
	// The protocol, when supplied, must agree with the issue's own protocol —
	// never trust the client to pair them (§3 validate all inputs).
	if p := strings.TrimSpace(req.Protocol); p != "" && !strings.EqualFold(p, string(issue.Protocol)) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("protocol %q does not match issue %q (%s)", p, issue.ID, issue.Protocol))
		return
	}
	if len(req.Outputs) > pdAnalyzeMaxOutputs {
		writeError(w, http.StatusBadRequest, fmt.Errorf("too many outputs (max %d)", pdAnalyzeMaxOutputs))
		return
	}

	// Build the set of spec ids that belong to THIS issue's bundle; reject any
	// pasted output keyed to a spec that is not part of the issue (untrusted key).
	bundle := issue.Bundle()
	specByID := make(map[string]protocoldiag.CommandSpec, len(bundle))
	for _, spec := range bundle {
		specByID[spec.ID] = spec
	}

	vendor := protocoldiag.VendorFromPlatform(req.Device.Platform)
	rendered := pdRenderedVendor(vendor)
	var tgt protocoldiag.Target

	col := &protocoldiag.Collection{
		TenantID:       tenant, // §3a: stamped from the token, never a request body
		Hostname:       clampString(req.Device.Hostname, pdMaxTargetField),
		Platform:       clampString(req.Device.Platform, pdMaxTargetField),
		Vendor:         vendor,
		RenderedVendor: rendered,
		Protocol:       issue.Protocol,
		IssueID:        issue.ID,
		IssueTitle:     issue.Title,
		RulesetVersion: protocoldiag.RulesetVersion,
	}
	for _, o := range req.Outputs {
		spec, known := specByID[o.SpecID]
		if !known {
			writeError(w, http.StatusBadRequest, fmt.Errorf("spec id %q is not part of issue %q", o.SpecID, issue.ID))
			return
		}
		if len(o.Output) > pdAnalyzeMaxOutput {
			writeError(w, http.StatusBadRequest, fmt.Errorf("output for %q exceeds %d bytes", o.SpecID, pdAnalyzeMaxOutput))
			return
		}
		col.Commands = append(col.Commands, protocoldiag.CollectedCommand{
			SpecID:  spec.ID,
			Command: spec.Render(vendor, tgt),
			Purpose: spec.Purpose,
			Output:  o.Output,
		})
	}

	res := s.pdAnalyzer().Analyze(col)
	tac := protocoldiag.TACExport(col, res)

	writeJSON(w, http.StatusOK, map[string]any{
		"protocol":        string(res.Protocol),
		"issue_id":        res.IssueID,
		"issue_title":     res.IssueTitle,
		"ruleset_version": res.RulesetVersion,
		"matched":         res.Matched(),
		"findings":        pdFindingViews(res),
		"unmatched":       res.Unmatched,
		"tac_export":      tac,
	})
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
		writeError(w, http.StatusServiceUnavailable, errors.New("protocol-diagnostics collector is not configured on this deployment"))
		return
	}

	pdDev := protocoldiag.Device{
		ID:       dev.ID,
		Hostname: dev.Name,
		Platform: pdPlatformString(dev),
		TenantID: deviceTenant(dev), // §3a: owner stamped from the resolved device
	}
	tgt := protocoldiag.Target{
		Interface: clampString(req.Target.Interface, pdMaxTargetField),
		Peer:      clampString(req.Target.Peer, pdMaxTargetField),
		Prefix:    clampString(req.Target.Prefix, pdMaxTargetField),
		VRF:       clampString(req.Target.VRF, pdMaxTargetField),
	}

	col, err := s.protocolCollector.Collect(r.Context(), pdDev, issueID, tgt)
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

	writeJSON(w, http.StatusOK, pdCollectionView(col))
}

// pdCollectionView renders a Collection for the same-tenant operator. The tenant
// id is deliberately not echoed (the caller already is that tenant); every
// command carries its rendered text, purpose, timestamp, output and any
// per-command transport error (honest partial captures).
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
