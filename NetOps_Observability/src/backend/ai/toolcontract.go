// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// toolcontract.go — tool contract v2 (tracker 337 N-A8).
//
// Every Iris tool in the ONE registry (N-A5) declares, beside its argument
// spec (toolspec.go), a CONTRACT:
//
//   - Version   — ledgered with every call as "<version>@<build>";
//   - Risk      — read or probe (a probe opens a device session, read-only).
//     write / execute are STRUCTURALLY unregistrable: register() refuses them
//     whatever the policy configuration says;
//   - Timeout   — the most one call may take;
//   - RatePerMin — calls per tenant per minute for this tool;
//   - Output    — the bounds a result must fit before it reaches the model.
//     A result that does not fit is DROPPED (and recorded), never trimmed and
//     passed on.
//
// A tool whose contract is missing or invalid is not registered (fail closed),
// and CheckToolContracts validates the table at boot.

// ToolContract is one tool's declared limits.
type ToolContract struct {
	Version    int
	Risk       Capability
	Timeout    time.Duration
	RatePerMin int
	Output     OutputSchema
}

// OutputSchema bounds a ToolResult. Every field is a ceiling and must be > 0.
type OutputSchema struct {
	MaxItems     int
	MaxTextChars int
	MaxNotes     int
	MaxSignals   int
}

// Contract bounds that hold for every tool.
const (
	maxContractTimeout   = 90 * time.Second
	maxCitationIDBytes   = 160
	maxHrefBytes         = 512
	maxNoteChars         = 600
	maxSignalChars       = 160
	defaultMaxNotes      = 20
	defaultMaxSignals    = 32
	defaultMaxTextChars  = 2000
	contractRiskReadOnly = "read-only v1"
)

// kindShape is the closed SHAPE of an evidence kind (finding, log, device …):
// a short lowercase token. The set of kinds itself is open — a new tool may
// add one — but nothing else can pass as a kind.
var kindShape = regexp.MustCompile(`^[a-z][a-z_]{0,31}$`)

// ErrSchemaRejected marks a result that did not fit its tool's output schema.
var ErrSchemaRejected = errors.New("tool result does not fit the tool's declared output schema")

// Validate checks a result against the schema. Any violation rejects the
// WHOLE result: partial evidence is worse than an honest "unavailable".
func (s OutputSchema) Validate(r ToolResult) error {
	if len(r.Items) > s.MaxItems {
		return fmt.Errorf("%w: %d items (max %d)", ErrSchemaRejected, len(r.Items), s.MaxItems)
	}
	for i, it := range r.Items {
		if err := validateItem(it, s.MaxTextChars); err != nil {
			return fmt.Errorf("%w: item %d: %w", ErrSchemaRejected, i, err)
		}
	}
	if len(r.Notes) > s.MaxNotes {
		return fmt.Errorf("%w: %d notes (max %d)", ErrSchemaRejected, len(r.Notes), s.MaxNotes)
	}
	for i, n := range r.Notes {
		if err := cleanText(n, maxNoteChars); err != nil {
			return fmt.Errorf("%w: note %d: %w", ErrSchemaRejected, i, err)
		}
	}
	if len(r.Signals) > s.MaxSignals {
		return fmt.Errorf("%w: %d signals (max %d)", ErrSchemaRejected, len(r.Signals), s.MaxSignals)
	}
	for i, sg := range r.Signals {
		if err := cleanText(sg, maxSignalChars); err != nil {
			return fmt.Errorf("%w: signal %d: %w", ErrSchemaRejected, i, err)
		}
	}
	return nil
}

func validateItem(it EvidenceItem, maxText int) error {
	if it.CitationID == "" || len(it.CitationID) > maxCitationIDBytes || !utf8.ValidString(it.CitationID) ||
		strings.ContainsAny(it.CitationID, "[]") || hasControl(it.CitationID) {
		return errors.New("citation id is missing, too long, or not a plain token")
	}
	if !kindShape.MatchString(it.Kind) {
		return fmt.Errorf("kind %q is not a kind", it.Kind)
	}
	if strings.TrimSpace(it.Text) == "" {
		return errors.New("empty text")
	}
	if err := cleanText(it.Text, maxText); err != nil {
		return err
	}
	if it.Href != "" {
		if len(it.Href) > maxHrefBytes || !(strings.HasPrefix(it.Href, "#/") || strings.HasPrefix(it.Href, "/docs/")) ||
			strings.Contains(it.Href, "://") || strings.ContainsAny(it.Href, " \t\r\n\\") || hasControl(it.Href) {
			return fmt.Errorf("href %q is not an in-app link", it.Href)
		}
	}
	switch it.CauseRole {
	case "", CauseRoleEngine, CauseRoleCandidate:
	default:
		return fmt.Errorf("cause role %q", it.CauseRole)
	}
	return nil
}

// cleanText: valid UTF-8, within maxChars runes, no control characters other
// than newline and tab.
func cleanText(s string, maxChars int) error {
	if !utf8.ValidString(s) {
		return errors.New("not valid UTF-8")
	}
	if utf8.RuneCountInString(s) > maxChars {
		return fmt.Errorf("longer than %d characters", maxChars)
	}
	for _, r := range s {
		if r != '\n' && r != '\t' && unicode.IsControl(r) {
			return errors.New("control character")
		}
	}
	return nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// validContract checks a contract's own fields.
func validContract(name string, c ToolContract) error {
	var errs []error
	if c.Version <= 0 {
		errs = append(errs, errors.New("version must be > 0"))
	}
	switch c.Risk {
	case CapRead, CapProbe:
	case CapWrite, CapExecute:
		errs = append(errs, fmt.Errorf("risk %q is not registrable (%s)", c.Risk, contractRiskReadOnly))
	default:
		errs = append(errs, fmt.Errorf("risk %q is not a risk tier", c.Risk))
	}
	if c.Timeout <= 0 || c.Timeout > maxContractTimeout {
		errs = append(errs, fmt.Errorf("timeout %s outside (0, %s]", c.Timeout, maxContractTimeout))
	}
	if c.RatePerMin <= 0 {
		errs = append(errs, errors.New("rate per minute must be > 0"))
	}
	o := c.Output
	if o.MaxItems <= 0 || o.MaxTextChars <= 0 || o.MaxNotes <= 0 || o.MaxSignals <= 0 {
		errs = append(errs, errors.New("every output bound must be > 0"))
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("tool %q: %w", name, errors.Join(errs...))
}

// out builds an OutputSchema with the common note/signal ceilings.
func out(items, text int) OutputSchema {
	return OutputSchema{MaxItems: items, MaxTextChars: text, MaxNotes: defaultMaxNotes, MaxSignals: defaultMaxSignals}
}

// toolContracts is every registrable tool's contract. Timeouts and rates
// reflect the backend each tool reads (ClickHouse aggregation, OpenSearch,
// an in-memory index, a device SSH session) and its cost; item ceilings are
// the caps the tools themselves apply, text ceilings ~2× what they emit.
var toolContracts = map[string]ToolContract{
	// Correlation reads.
	"get_problem":                {1, CapRead, 10 * time.Second, 60, out(4, defaultMaxTextChars)},
	"get_problem_evidence":       {1, CapRead, 10 * time.Second, 60, out(50, defaultMaxTextChars)},
	"get_active_major_incidents": {1, CapRead, 10 * time.Second, 60, out(25, defaultMaxTextChars)},
	"get_actionable_incidents":   {1, CapRead, 10 * time.Second, 60, out(25, defaultMaxTextChars)},
	"get_incident_history":       {1, CapRead, 15 * time.Second, 30, out(25, defaultMaxTextChars)},
	// Wireless inventory (engine-only).
	"get_wireless_ap_inventory": {1, CapRead, 10 * time.Second, 30, out(200, defaultMaxTextChars)},
	"get_wireless_controllers":  {1, CapRead, 10 * time.Second, 30, out(50, defaultMaxTextChars)},
	// Module reads.
	"get_top_talkers":                {1, CapRead, 15 * time.Second, 30, out(20, defaultMaxTextChars)},
	"get_flow_summary":               {1, CapRead, 15 * time.Second, 30, out(20, defaultMaxTextChars)},
	"get_service_flow_summary":       {1, CapRead, 15 * time.Second, 30, out(20, defaultMaxTextChars)},
	"get_metric_anomalies":           {1, CapRead, 15 * time.Second, 30, out(20, defaultMaxTextChars)},
	"search_logs":                    {1, CapRead, 15 * time.Second, 30, out(50, defaultMaxTextChars)},
	"get_device_health":              {1, CapRead, 10 * time.Second, 60, out(10, defaultMaxTextChars)},
	"get_app_identity_summary":       {1, CapRead, 15 * time.Second, 30, out(20, defaultMaxTextChars)},
	"get_low_confidence_app_matches": {1, CapRead, 15 * time.Second, 30, out(20, defaultMaxTextChars)},
	"get_integration_health":         {1, CapRead, 5 * time.Second, 60, out(20, defaultMaxTextChars)},
	"get_ticket_status":              {1, CapRead, 5 * time.Second, 60, out(20, defaultMaxTextChars)},
	// RCA.
	"get_rca_verdict":          {1, CapRead, 10 * time.Second, 60, out(4, defaultMaxTextChars)},
	"get_case_timeline":        {1, CapRead, 10 * time.Second, 60, out(40, defaultMaxTextChars)},
	"get_causal_chain":         {1, CapRead, 10 * time.Second, 60, out(40, defaultMaxTextChars)},
	"get_blast_radius":         {1, CapRead, 10 * time.Second, 60, out(40, defaultMaxTextChars)},
	"get_owner":                {1, CapRead, 10 * time.Second, 60, out(40, defaultMaxTextChars)},
	"get_confidence_breakdown": {1, CapRead, 10 * time.Second, 60, out(40, defaultMaxTextChars)},
	"get_affected_entities":    {1, CapRead, 10 * time.Second, 60, out(40, defaultMaxTextChars)},
	// Query compilation — may fall back to a model call, so it is costed.
	"compile_query": {1, CapRead, 30 * time.Second, 20, out(1, 1700)},
	// BGP.
	"get_bgp_watchlist":   {1, CapRead, 10 * time.Second, 60, out(40, defaultMaxTextChars)},
	"get_bgp_rpki":        {1, CapRead, 10 * time.Second, 60, out(40, defaultMaxTextChars)},
	"get_bgp_feed_recent": {1, CapRead, 5 * time.Second, 60, out(30, defaultMaxTextChars)},
	// Investigation memory.
	"recall_investigations": {1, CapRead, 5 * time.Second, 60, out(5, defaultMaxTextChars)},
	// Device-scoped.
	"get_security_findings": {1, CapRead, 10 * time.Second, 60, out(50, defaultMaxTextChars)},
	"get_topology_context":  {1, CapRead, 10 * time.Second, 60, out(46, defaultMaxTextChars)},
	// PROBES: open a read-only SSH session to a device. The collector's own
	// 60 s per-device timeout fires first; the contract is the backstop.
	"run_protocol_diagnostic": {1, CapProbe, 75 * time.Second, 6, out(60, defaultMaxTextChars)},
	"get_device_state":        {1, CapProbe, 75 * time.Second, 6, out(60, defaultMaxTextChars)},
	// Configuration history.
	"get_recent_changes": {1, CapRead, 10 * time.Second, 60, out(25, defaultMaxTextChars)},
	"get_config_diff":    {1, CapRead, 10 * time.Second, 60, out(16, 2600)},
	// Product documentation (in-process index).
	"search_docs": {1, CapRead, 3 * time.Second, 120, out(3, defaultMaxTextChars)},
}

// ContractFor returns a tool's contract.
func ContractFor(name string) (ToolContract, bool) {
	c, ok := toolContracts[name]
	return c, ok
}

// CheckToolContracts validates the whole table; the server calls it at boot
// and refuses to start on an invalid table (a programming error, not input).
func CheckToolContracts() error {
	names := make([]string, 0, len(toolContracts))
	for n := range toolContracts {
		names = append(names, n)
	}
	sort.Strings(names)
	var errs []error
	for _, n := range names {
		if err := validContract(n, toolContracts[n]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// register adds a tool after checking its contract: present, valid, and
// declaring the same risk the tool itself reports. Write/execute tools are
// refused here, structurally — not only by policy at call time.
func (r *ToolRegistry) register(t AITool) error {
	name := t.Name()
	if _, dup := r.byName[name]; dup {
		return fmt.Errorf("tool %q: registered twice", name)
	}
	c, ok := toolContracts[name]
	if !ok {
		return fmt.Errorf("tool %q: no contract", name)
	}
	if err := validContract(name, c); err != nil {
		return err
	}
	if t.Capability() != c.Risk {
		return fmt.Errorf("tool %q: reports capability %q but its contract declares %q", name, t.Capability(), c.Risk)
	}
	r.byName[name] = t
	return nil
}

// Rejected lists the tools that failed registration (empty in a correct build;
// TestEveryRegisteredToolHasAValidContract proves it).
func (r *ToolRegistry) Rejected() []error {
	return append([]error(nil), r.rejected...)
}
