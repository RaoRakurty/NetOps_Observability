// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// config_changes.go — the two configuration-change tools the external strategy
// names and this codebase already had the data for: `get_recent_changes` and
// `get_config_diff`, over the shipped internal/configstore version register and
// internal/configdrift state register. Only the wrappers were missing.
//
// "WHAT CHANGED" is the single most useful question an investigator can ask
// before reading telemetry, and until now Iris could not ask it: every tool it
// had reported STATE, none reported CHANGE. A device that started dropping
// sessions twenty minutes after someone touched its configuration is a different
// investigation from one that did not, and the engine could see neither.
//
// Contract, identical to the rest of the Phase-A tool set (CLAUDE.md §3a/§4/§15):
//
//   - READ-ONLY (CapRead). Neither tool captures, promotes a golden baseline, or
//     writes anything. The capture and golden-baseline WRITES live in
//     internal/configstore behind their own infrastructure:WRITE gate and the
//     assistant has no path to them.
//   - TENANT-SCOPED THROUGH THE SAME GATES the HTTP handlers use. This package
//     owns no store: both tools call injected TroubleshootDeps functions that the
//     server fills with the same principal (tenant, cross, and the
//     operator-visibility restriction) configAuthz/configDriftAuthz resolve. A
//     foreign or unknown device is ErrNotFound — never "forbidden", never a
//     leaked existence signal.
//   - BOUNDED. A configuration diff is the one tool output that can be genuinely
//     large, so it is capped HERE as well as in configstore.Diff: the prompt
//     budget is ours to defend (LLM04/LLM10), and the cap is disclosed rather
//     than silently applied.
//   - REDACTED. The unified diff arrives already rendered through
//     internal/configstore's redaction dialect (the counts are computed on the
//     unredacted text, so a rotated secret still counts as a real change) and
//     then rides the orchestrator's own outbound DLP like any other evidence.
//   - HONEST. A deployment without config backup leaves the seams nil, the tools
//     are not registered, and the assistant cannot answer from a capability that
//     is absent. A device that has never been captured says exactly that — it is
//     never reported as "unchanged".
//
// SIGNAL-FREE on purpose. Neither tool declares skill-chain `Signals`: change
// proximity is an RCA SCORING feature (review item 12, with its own replay and
// determinism contract), not a routing rule, and smuggling it in as a chain
// condition here would let it influence hypotheses before the scoring work that
// makes it defensible exists.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Output caps. Deliberately tighter than the HTTP surface's — this becomes
// prompt text.
const (
	// MaxRecentChanges bounds how many changed devices one answer carries.
	MaxRecentChanges = 25
	// MaxDeviceChangeVersions bounds the per-device change history.
	MaxDeviceChangeVersions = 15
	// MaxConfigDiffChars bounds the rendered unified diff handed to a model.
	// internal/configstore already bounds it (MaxDiffOutput); this is the second,
	// prompt-side bound, and the two are independent on purpose.
	MaxConfigDiffChars = 2400
	// configChangesRoute is the operator-facing page these citations deep-link to.
	configChangesRoute = "#/infrastructure/config-drift"
)

// changeWindows is the CLOSED lookback vocabulary. A model never supplies a
// duration — an unbounded or model-chosen window is an unbounded store scan.
// The defaults are deliberately longer than the telemetry tools': a
// configuration change that broke something last Tuesday is still the cause.
var changeWindows = map[string]int{
	"24h": 24 * 3600,
	"7d":  7 * 24 * 3600,
	"30d": 30 * 24 * 3600,
	"90d": 90 * 24 * 3600,
}

const defaultChangeWindow = "7d"

// diffAnchors is the CLOSED symbolic vocabulary for the diff's endpoints, so a
// caller that does not know a version id can still ask the useful question.
// Anything else must be a real version id, validated as one.
const (
	DiffAnchorLatest   = "latest"   // the newest successful capture
	DiffAnchorPrevious = "previous" // the capture before the newest one
	DiffAnchorGolden   = "golden"   // the device's marked golden baseline
)

var diffAnchors = map[string]bool{
	DiffAnchorLatest: true, DiffAnchorPrevious: true, DiffAnchorGolden: true,
}

// ---- injected seams (filled by the server, see ai_troubleshoot_deps.go) --------

// ChangeQuery is a validated recent-changes ask. DeviceID, when set, has ALREADY
// been resolved through the caller's own inventory by the tool.
type ChangeQuery struct {
	DeviceID     string // "" = every device the caller may see
	SinceSeconds int    // resolved from the closed window vocabulary
	Limit        int
}

// DeviceChange is one configuration change, projected for the assistant.
//
// METADATA ONLY: it carries fingerprints, counts and timestamps, never a line of
// configuration text. The text is reachable only through the diff tool, which
// renders it through the redaction dialect.
type DeviceChange struct {
	DeviceID   string
	DeviceName string
	// State is the drift verdict this capture produced: in_sync | changed |
	// drifted | unknown (internal/configdrift's closed vocabulary).
	State string
	// SHA / PreviousSHA fingerprint the configuration this change produced and
	// the one before it. PreviousSHA is empty for the first capture ever taken.
	SHA         string
	PreviousSHA string
	Added       int
	Removed     int
	// ChangedAt is when the configuration last moved; CapturedAt is when it was
	// last READ. They differ, and conflating them is how "nothing changed" gets
	// reported for a device nobody has captured in a month.
	ChangedAt  time.Time
	CapturedAt time.Time
	Golden     bool
	// Error is the scrubbed capture failure behind an `unknown` state. Empty with
	// state unknown means the device has never been captured at all.
	Error string
}

// ChangeReport is the recent-changes answer.
type ChangeReport struct {
	Scope   string // device name, or "" for the caller's whole estate
	Window  string // the closed-vocabulary token actually used
	Changes []DeviceChange
	// Truncated says the source had more rows than the cap allowed.
	Truncated bool
	// NotWired is the honest sentence for a deployment where configuration
	// backup is not enabled. Non-empty means Changes is meaningless, not empty.
	NotWired string
}

// ConfigDiffRequest is a validated diff ask. DeviceID has ALREADY been resolved
// through the caller's own inventory; From/To are either a version id or one of
// the closed symbolic anchors.
type ConfigDiffRequest struct {
	DeviceID string
	From     string
	To       string
}

// ConfigDiffReport is one rendered comparison.
type ConfigDiffReport struct {
	DeviceID   string
	DeviceName string
	FromSHA    string
	ToSHA      string
	// FromLabel / ToLabel are how each end was chosen ("golden baseline", "the
	// capture before it", …) so the answer can say what it compared.
	FromLabel string
	ToLabel   string
	FromAt    time.Time
	ToAt      time.Time
	Added     int
	Removed   int
	// Unified is the REDACTED unified diff, already bounded by the store.
	Unified   string
	Truncated bool
	// Unavailable is the honest sentence when the comparison could not be made:
	// no capture history, no golden baseline, only one version on file. It is a
	// STATE, not an error — the device exists and the caller may see it.
	Unavailable string
	NotWired    string
}

// ---- get_recent_changes ----------------------------------------------------

type recentChangesTool struct{ deps TroubleshootDeps }

func (t recentChangesTool) Name() string            { return "get_recent_changes" }
func (t recentChangesTool) Module() string          { return "config_changes" }
func (t recentChangesTool) Capability() Capability  { return CapRead }
func (t recentChangesTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t recentChangesTool) Freshness() Freshness    { return FreshnessRecent }

func (t recentChangesTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	window := strings.ToLower(strings.TrimSpace(args["window"]))
	if window == "" {
		window = defaultChangeWindow
	}
	secs, ok := changeWindows[window]
	if !ok {
		return ToolResult{}, fmt.Errorf("window must be one of 24h, 7d, 30d, 90d")
	}
	q := ChangeQuery{SinceSeconds: secs, Limit: MaxRecentChanges}
	scope := ""
	if raw := strings.TrimSpace(args["device"]); raw != "" {
		ref, err := validIDArg("device", raw, 128)
		if err != nil {
			return ToolResult{}, err
		}
		// Resolve through the caller's OWN inventory first: a device the caller
		// cannot see must read as not-found, not as "no changes" — the latter
		// would confirm the device exists somewhere else.
		dev, rerr := t.deps.ResolveDevice(ctx, p, ref)
		if rerr != nil {
			return ToolResult{}, rerr
		}
		q.DeviceID = dev.ID
		q.Limit = MaxDeviceChangeVersions
		scope = firstNonEmpty(dev.Name, dev.ID)
	}
	rep, err := t.deps.RecentChanges(ctx, p, q)
	if err != nil {
		return ToolResult{}, err
	}
	tr := ToolResult{Truncated: rep.Truncated}
	if rep.NotWired != "" {
		tr.Notes = append(tr.Notes, rep.NotWired)
		return tr, nil
	}
	if scope == "" {
		scope = rep.Scope
	}
	// Order here rather than trusting the seam: the cap below DROPS rows, so the
	// order decides which changes an investigator is shown, and that must not
	// depend on which store backend the deployment runs.
	sortChangesNewestFirst(rep.Changes)
	if len(rep.Changes) > q.Limit {
		rep.Changes = rep.Changes[:q.Limit]
		tr.Truncated = true
	}
	if len(rep.Changes) == 0 {
		// "No change" and "never captured" are different facts, and a tool that
		// blurs them turns an unmonitored device into a clean bill of health.
		where := "any device in your scope"
		if scope != "" {
			where = scope
		}
		tr.Notes = append(tr.Notes,
			"no configuration change was recorded for "+where+" in the last "+window+
				" — say that no change was RECORDED, not that nothing changed (a device whose configuration is not backed up records nothing)")
		return tr, nil
	}
	for _, c := range rep.Changes {
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: changeCitationID(c),
			Kind:       "config",
			Text:       clampText(changeLine(c), maxToolTextChars),
			Href:       configChangesRoute,
		})
	}
	tr.Notes = append(tr.Notes, "window: last "+window)
	if tr.Truncated {
		tr.Notes = append(tr.Notes, fmt.Sprintf("capped at %d change rows", q.Limit))
	}
	return tr, nil
}

// changeCitationID is stable per (device, version) so the same change cited
// twice in one answer is the same chip.
func changeCitationID(c DeviceChange) string {
	sha := c.SHA
	if len(sha) > 12 {
		sha = sha[:12]
	}
	if sha == "" {
		sha = "nocapture"
	}
	return "config:" + c.DeviceID + ":" + sha
}

// changeLine renders one change as an operator sentence. It never says a device
// is unchanged when what we actually know is that nothing was captured.
func changeLine(c DeviceChange) string {
	name := firstNonEmpty(c.DeviceName, c.DeviceID)
	switch {
	case c.State == "unknown" && c.Error == "":
		return name + " — configuration has never been captured, so no change history exists"
	case c.State == "unknown":
		return name + " — configuration state unknown; the last capture failed: " + c.Error
	}
	when := "at an unrecorded time"
	if !c.ChangedAt.IsZero() {
		when = "on " + c.ChangedAt.UTC().Format(time.RFC3339)
	}
	verdict := "changed"
	if c.State == "drifted" {
		verdict = "drifted from its golden baseline"
	} else if c.State == "in_sync" {
		verdict = "in sync with its baseline"
	}
	out := fmt.Sprintf("%s — %s %s", name, verdict, when)
	if c.Added > 0 || c.Removed > 0 {
		out += fmt.Sprintf(" (+%d/-%d lines)", c.Added, c.Removed)
	}
	if c.SHA != "" {
		out += "; version " + shortSHA(c.SHA)
		if c.PreviousSHA != "" {
			out += " (previous " + shortSHA(c.PreviousSHA) + ")"
		}
	}
	if c.Golden {
		out += "; this version is the golden baseline"
	}
	if !c.CapturedAt.IsZero() {
		out += "; last captured " + c.CapturedAt.UTC().Format(time.RFC3339)
	}
	return out
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// ---- get_config_diff -------------------------------------------------------

type configDiffTool struct{ deps TroubleshootDeps }

func (t configDiffTool) Name() string            { return "get_config_diff" }
func (t configDiffTool) Module() string          { return "config_changes" }
func (t configDiffTool) Capability() Capability  { return CapRead }
func (t configDiffTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t configDiffTool) Freshness() Freshness    { return FreshnessRecent }

func (t configDiffTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	ref, err := validIDArg("device", args["device"], 128)
	if err != nil {
		return ToolResult{}, err
	}
	dev, rerr := t.deps.ResolveDevice(ctx, p, ref)
	if rerr != nil {
		return ToolResult{}, rerr // cross-tenant / unknown → ErrNotFound, never 403
	}
	from, err := diffEndpoint("from", args["from"], DiffAnchorPrevious)
	if err != nil {
		return ToolResult{}, err
	}
	to, err := diffEndpoint("to", args["to"], DiffAnchorLatest)
	if err != nil {
		return ToolResult{}, err
	}
	if from == to {
		return ToolResult{}, fmt.Errorf("from and to must name different configuration versions")
	}
	rep, derr := t.deps.ConfigDiff(ctx, p, ConfigDiffRequest{DeviceID: dev.ID, From: from, To: to})
	if derr != nil {
		return ToolResult{}, derr
	}
	tr := ToolResult{Truncated: rep.Truncated}
	if rep.NotWired != "" {
		tr.Notes = append(tr.Notes, rep.NotWired)
		return tr, nil
	}
	name := firstNonEmpty(rep.DeviceName, dev.Name, dev.ID)
	if rep.Unavailable != "" {
		tr.Notes = append(tr.Notes, name+" — "+rep.Unavailable)
		return tr, nil
	}
	header := fmt.Sprintf("%s — %s vs %s: +%d/-%d lines",
		name, firstNonEmpty(rep.FromLabel, shortSHA(rep.FromSHA)), firstNonEmpty(rep.ToLabel, shortSHA(rep.ToSHA)),
		rep.Added, rep.Removed)
	if !rep.ToAt.IsZero() {
		header += "; newer version captured " + rep.ToAt.UTC().Format(time.RFC3339)
	}
	cite := "configdiff:" + rep.DeviceID + ":" + shortSHA(rep.FromSHA) + "-" + shortSHA(rep.ToSHA)
	tr.Items = append(tr.Items, EvidenceItem{
		CitationID: cite, Kind: "config", Text: clampText(header, maxToolTextChars), Href: configChangesRoute,
	})
	if body := strings.TrimSpace(rep.Unified); body != "" {
		clipped := body
		if len(clipped) > MaxConfigDiffChars {
			clipped = clipped[:MaxConfigDiffChars]
			tr.Truncated = true
		}
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: cite + ":diff", Kind: "config",
			Text: clipped, Href: configChangesRoute,
		})
	}
	if rep.Added == 0 && rep.Removed == 0 {
		tr.Notes = append(tr.Notes, "the two versions are identical after normalization — the capture ran, the configuration did not move")
	}
	tr.Notes = append(tr.Notes, "configuration values are redacted before they leave the store; line counts are computed on the unredacted text")
	if tr.Truncated {
		tr.Notes = append(tr.Notes, "the diff was truncated — say so rather than implying you saw all of it")
	}
	return tr, nil
}

// diffEndpoint validates one end of the comparison: a symbolic anchor from the
// closed set, or a real version id. It is the argument-validation half of §3 —
// nothing model-supplied reaches a store lookup unchecked.
func diffEndpoint(field, raw, fallback string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return fallback, nil
	}
	if diffAnchors[v] {
		return v, nil
	}
	// Not an anchor: it must be a configuration version id (a hex digest).
	if !validVersionID(v) {
		return "", fmt.Errorf("%s must be a configuration version id, or one of latest, previous, golden", field)
	}
	return v, nil
}

// validVersionID accepts the store's version-id shape: a lower-case hex digest.
// It is deliberately stricter than "a string the store will not find", because a
// rejected argument never becomes a store query at all.
func validVersionID(s string) bool {
	if len(s) < 8 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// sortChangesNewestFirst orders a report the way an investigator reads it: the
// most recent movement first, ties broken by device id so the answer is stable
// across runs (an unstable order makes a golden fixture flap).
func sortChangesNewestFirst(rows []DeviceChange) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		ai, bi := a.ChangedAt, b.ChangedAt
		if ai.IsZero() {
			ai = a.CapturedAt
		}
		if bi.IsZero() {
			bi = b.CapturedAt
		}
		if !ai.Equal(bi) {
			return ai.After(bi)
		}
		return a.DeviceID < b.DeviceID
	})
}
