// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisreplay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/aidecision"
	"netops/backend/internal/evalsplit"
)

// Capture statuses: what became of one ledgered tool step at capture.
const (
	// CaptureMatches: the re-read hashes as the ledger recorded.
	CaptureMatches = "matches_ledger"
	// CaptureMoved: the re-read differs. Live data moved since the decision, so
	// what the case holds is NOT what the decision saw.
	CaptureMoved = "live_data_moved"
	// CaptureArgsUnknown: the ledger holds the argument hash only, and no
	// argument this capture can name produces it.
	CaptureArgsUnknown = "args_not_recoverable"
	// CaptureNotReRead: a probe, or a tool that may call a model. A capture
	// never opens a device session or spends a model call.
	CaptureNotReRead = "not_re_read"
	// CaptureReadFailed: the re-read did not return.
	CaptureReadFailed = "re_read_failed"
)

// Capture bounds. A capture is a bounded set of reads on one request.
const (
	maxCaptureDevices = 8
	maxCaptureChecks  = 32
	captureQuestion   = "explain this incident"
)

// Snapshot is the engine's stored output for one correlation, exactly as stored.
type Snapshot struct {
	TenantID       string
	Hypotheses     string
	EngineVersion  string
	CatalogVersion string
	// Synthetic marks a synthetic or digital-twin incident. Everything else
	// exported is field data and held out.
	Synthetic bool
}

// CaptureSeams are the reads a capture may make. All of them are the server's
// own tenant-scoped reads for the caller; this package holds no store.
type CaptureSeams struct {
	Principal ai.Principal
	DS        ai.DataSource
	Deps      ai.TroubleshootDeps
	Toolbox   ai.Toolbox
	// Snapshot reads the stored engine output. ai.ErrNotFound covers unknown and
	// another tenant's alike.
	Snapshot func(ctx context.Context, id string) (Snapshot, error)
	// Decision returns the newest ledgered decision that names this incident, in
	// sequence order (nil when there is none). tenant is the incident's own.
	Decision func(ctx context.Context, tenant, id string) ([]aidecision.Entry, error)
	// ContextFacts returns the frozen Network context lines and their version.
	ContextFacts func(ctx context.Context) (version string, facts []string)
	Now          func() time.Time
}

// Capture builds the frozen case for one correlation the caller may see.
// ai.ErrNotFound means unknown or another tenant's; the two are the same.
//
// A case holds correlation data, so administration:read alone is not enough: a
// custom role that reads the admin area but not incidents gets ai.ErrForbidden.
func Capture(ctx context.Context, s CaptureSeams, id string) (*Case, error) {
	if !s.Principal.Can("correlations:read") {
		return nil, ai.ErrForbidden
	}
	snap, err := s.Snapshot(ctx, id)
	if err != nil {
		return nil, err
	}
	pr, err := s.DS.GetProblem(ctx, s.Principal, id)
	if err != nil {
		return nil, err
	}
	tenant := s.Principal.Tenant
	if s.Principal.Cross {
		tenant = snap.TenantID
	}
	if strings.TrimSpace(tenant) == "" {
		tenant = "global"
	}
	source := evalsplit.SourceField
	if snap.Synthetic {
		source = evalsplit.SourceSynthetic
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	stamp := now().UTC().Format(time.RFC3339)
	c := &Case{
		ID:          "field-" + strings.ToLower(id),
		Category:    ai.ReplayCategoryField,
		Description: "Captured from one correlation. Tool outputs were re-read at capture, not as seen by the decision.",
		Path:        ai.ReplayPathAsk,
		Source:      string(source),
		Principal:   ai.ReplayPrincipal{Tenant: tenant, Perms: grantedPerms(s.Principal)},
		Question:    captureQuestion,
		UI:          map[string]string{"correlation_id": id},
		// The ledger holds no reply text, so the offline leg runs evidence-only
		// until someone scripts a reply. Nothing is invented for it.
		ProviderDown:   true,
		FrozenAt:       stamp,
		EngineVersion:  pinToken(snap.EngineVersion),
		CatalogVersion: pinToken(snap.CatalogVersion),
		Expect:         ai.ReplayExpect{Verdict: pr.Verdict, Status: ai.StatusLabel(pr.Verdict)},
		Expected:       &ai.ReplayExpected{Verdict: pr.Verdict},
		Capture:        &ai.ReplayCapture{CapturedAt: stamp},
	}
	if ranked := ai.ParseRankedHypotheses(snap.Hypotheses); len(ranked) > 0 {
		c.Expected.LeadingHypothesis = ranked[0].ID
	}

	stored := ai.ReplayProblem{
		ID: pr.ID, DisplayID: pr.DisplayID, Title: pr.Title, Verdict: pr.Verdict, Confidence: pr.Confidence,
		Devices: pr.Devices, MissingEvidence: pr.MissingEvidence, Owner: pr.Owner,
		SignalCount: pr.SignalCount, NodeCount: pr.NodeCount, Timeline: pr.Timeline,
	}
	if json.Valid([]byte(snap.Hypotheses)) {
		stored.Hypotheses = json.RawMessage(snap.Hypotheses)
	} else if snap.Hypotheses != "" {
		c.Capture.Notes = append(c.Capture.Notes, "the stored hypotheses blob is not JSON and was left out")
	}
	stored.Evidence = extraEvidence(ctx, s, c, id, snap.Hypotheses, pr.Devices)
	tn := ai.ReplayTenant{Problems: []ai.ReplayProblem{stored}}

	if s.Deps.RCAResult != nil {
		res, err := s.Deps.RCAResult(ctx, s.Principal, id)
		switch {
		case err == nil:
			tn.RCA = map[string]ai.RCAResult{id: res}
		case errors.Is(err, ai.ErrNotFound):
			c.Capture.Notes = append(c.Capture.Notes, "no RCA report is held for this incident")
		default:
			c.Capture.Notes = append(c.Capture.Notes, "the RCA report could not be read at capture")
		}
	}
	tn.Devices = captureTopology(ctx, s, c, pr.Devices)
	c.Tenants = map[string]ai.ReplayTenant{tenant: tn}
	captureChanges(ctx, s, c)
	if s.ContextFacts != nil {
		if version, facts := s.ContextFacts(ctx); len(facts) > 0 {
			c.ContextVersion, c.ContextFacts = version, facts
		}
	}
	captureLedger(ctx, s, c, tenant, id, pr.Devices)
	c.AllowedTools = captureAllowedTools(c)
	return c, nil
}

// grantedPerms lists what the principal holds, sorted.
func grantedPerms(p ai.Principal) []string {
	out := make([]string, 0, len(p.Perms))
	for perm, on := range p.Perms {
		if on {
			out = append(out, perm)
		}
	}
	sort.Strings(out)
	return out
}

// pinToken keeps a pin only when it is a version token: a stored value is data.
func pinToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 128 || strings.ContainsAny(s, " \t\r\n") {
		return ""
	}
	return aidecision.Token(s)
}

// extraEvidence returns the evidence rows the frozen reader will not derive from
// the blob by itself.
func extraEvidence(ctx context.Context, s CaptureSeams, c *Case, id, hypotheses string, devices []string) []ai.EvidenceItem {
	all, err := s.DS.GetProblemEvidence(ctx, s.Principal, id)
	if err != nil {
		c.Capture.Notes = append(c.Capture.Notes, "the problem evidence could not be read at capture")
		return nil
	}
	derived := map[string]bool{}
	for _, it := range ai.ReplayProjectedEvidence(id, hypotheses, devices) {
		derived[it.CitationID] = true
	}
	var extra []ai.EvidenceItem
	for _, it := range all {
		if !derived[it.CitationID] {
			extra = append(extra, it)
		}
	}
	return extra
}

// captureTopology resolves the incident's devices in the caller's inventory and
// freezes their topology. It is a tool result as of capture, and reports say so.
func captureTopology(ctx context.Context, s CaptureSeams, c *Case, devices []string) []ai.ReplayDevice {
	if s.Deps.ResolveDevice == nil {
		return nil
	}
	var out []ai.ReplayDevice
	for i, name := range devices {
		if i == maxCaptureDevices {
			c.Capture.Notes = append(c.Capture.Notes, fmt.Sprintf("only the first %d devices were captured", maxCaptureDevices))
			break
		}
		ref, err := s.Deps.ResolveDevice(ctx, s.Principal, name)
		if err != nil {
			continue // not in the caller's inventory: it stays a name in the object
		}
		out = append(out, ai.ReplayDevice{ID: ref.ID, Name: ref.Name})
		if s.Deps.TopologyContext == nil {
			continue
		}
		tc, err := s.Deps.TopologyContext(ctx, s.Principal, ref.ID)
		if err != nil {
			c.Capture.Notes = append(c.Capture.Notes, "the topology of one device could not be read at capture")
			continue
		}
		if c.Topology == nil {
			c.Topology = map[string]ai.TopologyContext{}
		}
		c.Topology[ref.ID] = tc
	}
	return out
}

// captureChanges freezes the change register for the day before capture.
func captureChanges(ctx context.Context, s CaptureSeams, c *Case) {
	if s.Deps.RecentChanges == nil {
		return
	}
	rep, err := s.Deps.RecentChanges(ctx, s.Principal, ai.ChangeQuery{SinceSeconds: 86400, Limit: 20})
	if err != nil {
		c.Capture.Notes = append(c.Capture.Notes, "the change register could not be read at capture")
		return
	}
	c.Config = &ai.ReplayConfig{Changes: &rep}
}

// reReadable says whether a capture may run this tool again: reads only. A probe
// opens a device session and compile_query may call a model.
func reReadable(tool string) bool {
	contract, ok := ai.ContractFor(tool)
	return ok && contract.Risk == ai.CapRead && tool != "compile_query"
}

// candidateArgs are the arguments a capture can name for this incident. The
// ledger holds a hash, so an argument it cannot name is never guessed further.
func candidateArgs(id string, devices []string) []ai.ToolArgs {
	out := []ai.ToolArgs{{"problem_id": id}, {"correlation_id": id}, {}}
	for i, d := range devices {
		if i == maxCaptureDevices {
			break
		}
		out = append(out, ai.ToolArgs{"device": d}, ai.ToolArgs{"device_id": d})
	}
	return out
}

// dsTools are projected from the stored object by the frozen reader, so a re-read
// of them is compared but not scripted.
var dsTools = map[string]bool{"get_problem": true, "get_problem_evidence": true, "get_active_major_incidents": true, "get_actionable_incidents": true}

// captureLedger compares each ledgered tool step with its re-read. The ledger
// holds hashes only: what lands in the case is what the store answers NOW, and
// reports say "re-read at capture", never "as seen".
func captureLedger(ctx context.Context, s CaptureSeams, c *Case, tenant, id string, devices []string) {
	if s.Decision == nil {
		return
	}
	entries, err := s.Decision(ctx, tenant, id)
	if err != nil {
		c.Capture.Notes = append(c.Capture.Notes, "the decision ledger could not be read at capture")
		return
	}
	if len(entries) == 0 {
		c.Capture.Notes = append(c.Capture.Notes, "no ledgered decision names this incident")
		return
	}
	c.Capture.DecisionID = entries[0].DecisionID
	checks := 0
	for _, e := range entries {
		if e.EventType == aidecision.AnswerReturned && (e.ModelProvider != "" || e.ModelName != "") {
			c.Model = &ai.ReplayModel{Provider: e.ModelProvider, Name: e.ModelName, Tier: e.ModelTier}
		}
		if e.EventType != aidecision.ToolExecuted {
			continue
		}
		if checks == maxCaptureChecks {
			c.Capture.Notes = append(c.Capture.Notes, fmt.Sprintf("only the first %d tool steps were compared", maxCaptureChecks))
			break
		}
		checks++
		c.Capture.ToolChecks = append(c.Capture.ToolChecks, ai.ReplayToolCheck{Tool: e.Tool, Status: checkOneStep(ctx, s, c, e, id, devices)})
	}
}

func checkOneStep(ctx context.Context, s CaptureSeams, c *Case, e aidecision.Entry, id string, devices []string) string {
	if !reReadable(e.Tool) {
		return CaptureNotReRead
	}
	for _, args := range candidateArgs(id, devices) {
		if ai.HashToolArgs(args) != e.ArgsSHA256 {
			continue
		}
		iv := s.Toolbox.Invoke(ctx, s.Principal, e.Tool, args)
		if !iv.OK() {
			return CaptureReadFailed
		}
		if ai.ReplayToolAllowed(e.Tool) && !dsTools[e.Tool] {
			if c.Tools == nil {
				c.Tools = map[string]ai.ReplayToolFixture{}
			}
			c.Tools[e.Tool] = ai.ReplayToolFixture{Items: iv.Result.Items, Notes: iv.Result.Notes, Signals: iv.Result.Signals}
		}
		if ai.HashToolResult(iv.Result) == e.ResultSHA256 {
			return CaptureMatches
		}
		return CaptureMoved
	}
	return CaptureArgsUnknown
}

// captureAllowedTools closes the case's tool set: what the classic path plans
// for this question, what the capture froze, and the ledgered steps that exist.
func captureAllowedTools(c *Case) []string {
	set := map[string]bool{"get_problem": true, "get_problem_evidence": true}
	for name := range c.Tools {
		set[name] = true
	}
	if len(c.Topology) > 0 {
		set["get_topology_context"] = true
	}
	if c.Config != nil {
		set["get_recent_changes"] = true
	}
	if c.Tenants != nil && len(c.Tenants[c.Principal.Tenant].RCA) > 0 {
		set["get_causal_chain"] = true
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// RedactedJSON is the export body: the case as a one-element array (what the
// loader reads), with every text field through the outbound filter, and proved
// loadable by the strict loader before it leaves.
func RedactedJSON(c *Case) ([]byte, error) {
	raw, err := json.Marshal([]*Case{c})
	if err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}
	var doc any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}
	out, err := json.MarshalIndent(redactTree(doc), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}
	if _, err := ai.ParseReplayCases("export", out); err != nil {
		return nil, fmt.Errorf("export: the redacted case does not load: %w", err)
	}
	return out, nil
}

// redactTree applies the full outbound filter to every string and map key in a
// decoded JSON document. Walking the document rather than naming fields means a
// field added later cannot be forgotten.
func redactTree(v any) any {
	switch x := v.(type) {
	case string:
		return ai.Redact(x)
	case []any:
		for i := range x {
			x[i] = redactTree(x[i])
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[ai.Redact(k)] = redactTree(val)
		}
		return out
	}
	return v
}

// FindDecision returns the newest ledgered decision that named this incident, in
// sequence order, or nil. list is the caller's own tenant-scoped ledger read; for
// a platform-wide reader, owner keeps it to the incident's own tenant.
func FindDecision(ctx context.Context, cross bool, owner, id string, list func(context.Context, aidecision.ListFilter) ([]aidecision.Entry, error)) ([]aidecision.Entry, error) {
	recent, err := list(ctx, aidecision.ListFilter{Limit: aidecision.MaxListLimit})
	if err != nil {
		return nil, err
	}
	ref := aidecision.IncidentRef(id)
	if ref == "" {
		return nil, nil
	}
	for _, e := range recent {
		if e.EventType != aidecision.QuestionReceived || e.IncidentRef != ref {
			continue
		}
		if cross && !sameOwner(e.TenantID, owner) {
			continue
		}
		return list(ctx, aidecision.ListFilter{DecisionID: e.DecisionID, Limit: aidecision.MaxListLimit})
	}
	return nil, nil
}

// sameOwner: "" and "global" are one owner.
func sameOwner(a, b string) bool {
	norm := func(s string) string {
		if s == "" {
			return "global"
		}
		return s
	}
	return norm(a) == norm(b)
}

// Export captures and renders one correlation.
func Export(ctx context.Context, s CaptureSeams, id string) ([]byte, error) {
	c, err := Capture(ctx, s, id)
	if err != nil {
		return nil, err
	}
	return RedactedJSON(c)
}
