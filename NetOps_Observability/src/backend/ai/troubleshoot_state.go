package ai

// troubleshoot_state.go — `get_device_state`: the SHOW-FIRST tool (IRIS Phase
// A4, design IRIS_TROUBLESHOOTING_MODEL_2026-09-02 §3.2).
//
// NetClaw's load-bearing rule, adopted here: **never guess device state — run a
// show command first, always.** This tool is how a skill obeys it. It asks the
// server for one AREA of one device's live state; the server renders the closed
// per-vendor state battery, captures it over the read-only SSH runner, redacts
// it, and parses it with internal/showparse into TYPED rows. What arrives here
// is already typed and already redacted — the model never sees raw CLI text it
// could hallucinate structure into.
//
// The contract this file owns:
//
//   - READ-ONLY (CapRead). Every battery command is a `show`/`display` proven
//     read-only at battery construction. There is no write path.
//   - CLOSED ARGUMENTS. `area` is one of seven; `target` is validated per area
//     and is REFUSED where the area takes none. Nothing here is free text.
//   - BOUNDED. Per-area row caps, a cap on unparsed fallback lines, and the same
//     per-line character clamp every other tool applies (§9, LLM04).
//   - HONEST. A device whose platform has no established command, a read that
//     did not complete, a parser that could not read the output, and a
//     deployment with no capture transport are four DIFFERENT answers, and each
//     says which it is. "Unparsed" is stated in those words; nothing is invented.
//   - MACHINE FACTS. Rows may carry one `state:<facet>=<value>` signal from the
//     closed vocabulary in skill.go, re-validated here, so an authored `next=`
//     rule can branch on a typed field (§3.1's chaining grammar).

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Per-area evidence caps. The battery itself bounds the CAPTURE; these bound the
// PROMPT, which is a different budget and ours to defend.
const (
	MaxStateRowsInterfaces = 24
	MaxStateRowsIGP        = 20
	MaxStateRowsBGP        = 24
	MaxStateRowsRoutes     = 16
	MaxStateRowsL2         = 20
	MaxStateRowsPlatform   = 12
	MaxStateRowsLogs       = 30
	// MaxStateUnparsedLines bounds the raw-but-redacted fallback lines a single
	// unreadable capture may contribute.
	MaxStateUnparsedLines = 6
	// MaxStateCommands bounds the read-only command list handed back when live
	// collection is not available.
	MaxStateCommands = 12
	// maxStateLineChars bounds ONE rendered state line.
	maxStateLineChars = 300
	// deviceStateRouteHref is where an operator sees device state in the UI.
	deviceStateRouteHref = "#/infrastructure/devices"
)

// StateArea is the closed set of state-battery areas, in the battery's own
// order. It is duplicated here deliberately: the ai package must not import
// internal/protocoldiag, and a tool argument vocabulary that could drift with a
// library is not a closed vocabulary. TestDeviceStateAreasMatchTheBattery in the
// root package pins the two together.
var stateAreaOrder = []string{"interfaces", "igp", "bgp", "routes", "l2", "platform", "logs"}

var stateAreas = func() map[string]bool {
	m := make(map[string]bool, len(stateAreaOrder))
	for _, a := range stateAreaOrder {
		m[a] = true
	}
	return m
}()

// StateAreas returns the closed area vocabulary in a stable order.
func StateAreas() []string {
	out := make([]string, len(stateAreaOrder))
	copy(out, stateAreaOrder)
	return out
}

// stateRowCap is the per-area prompt cap.
func stateRowCap(area string) int {
	switch area {
	case "interfaces":
		return MaxStateRowsInterfaces
	case "igp":
		return MaxStateRowsIGP
	case "bgp":
		return MaxStateRowsBGP
	case "routes":
		return MaxStateRowsRoutes
	case "l2":
		return MaxStateRowsL2
	case "platform":
		return MaxStateRowsPlatform
	case "logs":
		return MaxStateRowsLogs
	default:
		return MaxStateRowsPlatform
	}
}

// stateTargetRule says what `target` means for an area: required, optional, or
// refused. A refused target is an ERROR, never a silently-dropped argument — a
// model that thinks it scoped a read must not be told it succeeded.
type stateTargetRule int

const (
	stateTargetOptional stateTargetRule = iota
	stateTargetRequired
	stateTargetNone
)

// stateTargetRules is the per-area rule table.
//
//	interfaces  optional  an interface name; without one the read is the L3
//	                      interface summary (the per-interface detail and the
//	                      optics read both need a named interface).
//	igp         optional  a neighbour id; used to NARROW the rendered rows.
//	bgp         optional  a peer address; used to NARROW the rendered rows.
//	routes      required  a routing-table lookup with no prefix is the whole
//	                      table — the one genuinely expensive read in the
//	                      battery, so it is refused rather than run by accident.
//	l2          optional  an address; without one only the ARP table renders
//	                      (the MAC read requires an address and is omitted).
//	platform    none      CPU/memory/environment/uptime take no subject.
//	logs        none      the buffer read is bounded by a constant, not an arg.
var stateTargetRules = map[string]stateTargetRule{
	"interfaces": stateTargetOptional,
	"igp":        stateTargetOptional,
	"bgp":        stateTargetOptional,
	"routes":     stateTargetRequired,
	"l2":         stateTargetOptional,
	"platform":   stateTargetNone,
	"logs":       stateTargetNone,
}

// ---- injected types --------------------------------------------------------

// DeviceStateRequest is a validated show-first state ask. Every field has
// already passed the tool's closed-vocabulary checks.
type DeviceStateRequest struct {
	DeviceID string
	Area     string // one of StateAreas()
	Target   string // "" when the area takes none
}

// StateRow is ONE typed evidence line the state battery produced, already
// projected to text by the server from a showparse typed row.
type StateRow struct {
	// Text is the operator-readable rendering of a TYPED row. It is never raw
	// device output (see DeviceStateReport.Gaps for that).
	Text string
	// Kind is the EvidenceItem kind ("device" for state rows, "log" for buffer
	// lines). An unknown kind is normalized to "device" here.
	Kind string
	// Signals are the `state:<facet>=<value>` machine facts derived from the
	// TYPED fields of this row — at most one per facet. Each is re-validated
	// against the closed vocabulary before it can reach the chain evaluator.
	Signals []string
}

// StateGap is one captured command whose output NO parser could read. It exists
// so an unreadable capture is visible as unreadable — with its (redacted) raw
// lines as honest evidence — rather than as silence that reads like "clean".
type StateGap struct {
	Command string
	Reason  string
	Lines   []string // already redacted upstream
}

// DeviceStateReport is the show-first answer for one (device, area).
//
// Collected=false with a non-empty NotWired is the honest "no capture transport
// on this deployment (or this caller may not operate a device)" case: Commands
// still carries the curated read-only list so an operator can run it by hand.
type DeviceStateReport struct {
	DeviceID   string
	DeviceName string
	Platform   string
	// Dialect is the resolved vendor CLI dialect, or "" when the platform is
	// unassessed (which is an answer, not a failure).
	Dialect string
	Area    string
	// Status is the battery's own per-device outcome: ok | partial | failed |
	// timed_out | unsupported | not_run. Anything else is treated as failed.
	Status         string
	Note           string
	RulesetVersion string
	Rows           []StateRow
	Gaps           []StateGap
	Commands       []DiagnosticCommand
	Collected      bool
	NotWired       string
}

// ---- get_device_state ------------------------------------------------------

type deviceStateTool struct{ deps TroubleshootDeps }

func (t deviceStateTool) Name() string            { return "get_device_state" }
func (t deviceStateTool) Module() string          { return "device_state" }
func (t deviceStateTool) Capability() Capability  { return CapRead }
func (t deviceStateTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t deviceStateTool) Freshness() Freshness    { return FreshnessLive }

func (t deviceStateTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	devRef, err := validIDArg("device_id", args["device_id"], 128)
	if err != nil {
		return ToolResult{}, err
	}
	area := strings.ToLower(strings.TrimSpace(args["area"]))
	if !stateAreas[area] {
		return ToolResult{}, fmt.Errorf("area must be one of %s", strings.Join(StateAreas(), ", "))
	}
	target, err := validateStateTarget(area, args["target"])
	if err != nil {
		return ToolResult{}, err
	}
	dev, err := t.deps.ResolveDevice(ctx, p, devRef)
	if err != nil {
		return ToolResult{}, err // ErrNotFound for unknown OR another tenant's device
	}
	rep, err := t.deps.DeviceState(ctx, p, DeviceStateRequest{
		DeviceID: dev.ID, Area: area, Target: target,
	})
	if err != nil {
		return ToolResult{}, err
	}
	return renderDeviceState(rep, dev, area, target), nil
}

// validateStateTarget applies the per-area target rule and the per-area shape.
// Addresses and prefixes get a TIGHTER alphabet than validIDArg's, because a
// hostname-shaped string is never a valid prefix and should not reach a seam
// pretending to be one.
func validateStateTarget(area, raw string) (string, error) {
	v := strings.TrimSpace(raw)
	rule := stateTargetRules[area]
	if v == "" {
		if rule == stateTargetRequired {
			return "", fmt.Errorf("area %q needs a target (the prefix to look up)", area)
		}
		return "", nil
	}
	switch rule {
	case stateTargetNone:
		return "", fmt.Errorf("area %q takes no target", area)
	case stateTargetRequired: // routes: a prefix or an address
		return validAddrArg("target", v, 64)
	}
	switch area {
	case "l2":
		return validAddrArg("target", v, 64)
	default: // interfaces (an interface name), igp/bgp (a neighbour id or address)
		return validIDArg("target", v, 64)
	}
}

// validAddrArg bounds an address/prefix-shaped argument: hex digits, dots,
// colons, hyphens and one mask separator. It admits IPv4, IPv6, a CIDR prefix
// and every vendor MAC formatting, and nothing else.
func validAddrArg(name, v string, max int) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	if len(v) > max {
		return "", fmt.Errorf("%s is too long (max %d characters)", name, max)
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		case r == '.' || r == ':' || r == '-' || r == '/':
		default:
			return "", fmt.Errorf("%s must be an IP address, a prefix or a MAC address", name)
		}
	}
	return v, nil
}

// renderDeviceState projects the report into bounded, cited evidence.
func renderDeviceState(rep DeviceStateReport, dev DeviceRef, area, target string) ToolResult {
	label := firstNonEmpty(rep.DeviceName, dev.Name, dev.ID)
	cite := stateCiteToken(firstNonEmpty(rep.DeviceID, dev.ID))
	href := deviceStateRouteHref
	tr := ToolResult{}

	head := fmt.Sprintf("%s — live %s state", label, area)
	if target != "" {
		head += " for " + target
	}
	switch {
	case rep.Dialect != "":
		head += fmt.Sprintf(" (read as %s)", rep.Dialect)
	case rep.Platform != "":
		head += fmt.Sprintf(" (platform %q resolves to no known CLI dialect)", clampText(rep.Platform, 60))
	}
	tr.Items = append(tr.Items, EvidenceItem{
		CitationID: fmt.Sprintf("state:%s:%s:0", area, cite), Kind: "device",
		Text: clampText(head, maxStateLineChars), Href: href,
	})

	// The collection outcome is itself a machine fact: an unread device is not a
	// clean device, and a rule must be able to branch on that.
	if outcome := stateCollectOutcome(rep); outcome != "" {
		tr.Signals = append(tr.Signals, CondStatePrefix+"collect="+outcome)
	}

	if !rep.Collected {
		tr.Notes = append(tr.Notes, firstNonEmpty(rep.NotWired,
			"live device state could not be read on this deployment — no command was run"))
		tr.Notes = append(tr.Notes, "treat this device's "+area+" state as UNKNOWN, not healthy; ask the operator to run the read-only checks below and paste the output")
		cmds := rep.Commands
		if len(cmds) > MaxStateCommands {
			cmds = cmds[:MaxStateCommands]
			tr.Truncated = true
		}
		for _, c := range cmds {
			tr.Items = append(tr.Items, EvidenceItem{
				CitationID: "statecmd:" + area + ":" + c.SpecID, Kind: "device",
				Text: clampText(fmt.Sprintf("suggested read-only check (%s): `%s`", c.Purpose, c.Command), maxStateLineChars),
				Href: href,
			})
		}
		return tr
	}

	if rep.Note != "" {
		tr.Notes = append(tr.Notes, clampText(rep.Note, maxStateLineChars))
	}

	n := 0
	rowCap := stateRowCap(area)
	seenSignal := map[string]bool{}
	for _, row := range rep.Rows {
		if strings.TrimSpace(row.Text) == "" {
			continue
		}
		// A row's signals count even when the row itself is past the prompt cap:
		// the machine fact is small and is the whole point of reading state.
		for _, raw := range row.Signals {
			if sig := normalizeStateSignal(raw); sig != "" && !seenSignal[sig] {
				seenSignal[sig] = true
				tr.Signals = append(tr.Signals, sig)
			}
		}
		if n >= rowCap {
			tr.Truncated = true
			continue
		}
		n++
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: fmt.Sprintf("state:%s:%s:%d", area, cite, n), Kind: stateRowKind(row.Kind),
			Text: clampText(row.Text, maxStateLineChars), Href: href,
		})
	}
	if tr.Truncated {
		tr.Notes = append(tr.Notes, fmt.Sprintf("the %s state read returned more than %d rows — only the first %d are shown", area, rowCap, rowCap))
	}

	// Unparsed captures. Stated in those words: an output no parser could read is
	// INCONCLUSIVE evidence, and quoting it raw (already redacted) is the honest
	// alternative to inventing a typed row for it.
	for _, gap := range rep.Gaps {
		lines := gap.Lines
		if len(lines) > MaxStateUnparsedLines {
			lines = lines[:MaxStateUnparsedLines]
			tr.Truncated = true
		}
		reason := firstNonEmpty(gap.Reason, "no parser is established for this output")
		tr.Notes = append(tr.Notes, fmt.Sprintf("the output of %q was UNPARSED (%s) — read the quoted lines literally and do not infer fields from them",
			clampText(gap.Command, 80), clampText(reason, 160)))
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			n++
			tr.Items = append(tr.Items, EvidenceItem{
				CitationID: fmt.Sprintf("state:%s:%s:%d", area, cite, n), Kind: "device",
				Text: clampText("unparsed output of `"+gap.Command+"`: "+line, maxStateLineChars), Href: href,
			})
		}
	}

	if len(tr.Items) == 1 {
		tr.Notes = append(tr.Notes, "the "+area+" read completed but returned no rows — say the device reported NOTHING here, which is different from a healthy reading")
	}
	sort.Strings(tr.Signals)
	return tr
}

// stateCollectOutcome maps the battery's own device status onto the closed
// `state:collect` vocabulary. An unrecognized status is reported as failed —
// never as ok.
func stateCollectOutcome(rep DeviceStateReport) string {
	switch rep.Status {
	case "ok", "partial", "timed_out", "unsupported":
		return rep.Status
	case "failed", "not_run":
		return "failed"
	}
	if rep.Collected {
		return "ok" // a collected report that named no status is a completed read
	}
	return "not_wired"
}

// normalizeStateSignal re-validates a server-declared row signal against the
// closed `state:` vocabulary. Defence in depth: the seam derives it from a typed
// field, and nothing outside the vocabulary can reach the chain evaluator.
func normalizeStateSignal(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	facetKey, value, ok := strings.Cut(raw, "=")
	if !ok {
		return ""
	}
	facet, isState := strings.CutPrefix(strings.TrimSpace(facetKey), CondStatePrefix)
	if !isState || !validStateFact(facet, strings.TrimSpace(value)) {
		return ""
	}
	return CondStatePrefix + facet + "=" + strings.TrimSpace(value)
}

// stateRowKind normalizes a row kind onto the evidence-kind vocabulary.
func stateRowKind(k string) string {
	if k = strings.ToLower(strings.TrimSpace(k)); skillEvidenceKinds[k] {
		return k
	}
	return "device"
}

// stateCiteToken bounds the device id inside a citation id so a pathological id
// cannot inflate every citation on the answer.
func stateCiteToken(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "device"
	}
	if len(id) > 40 {
		return id[:40]
	}
	return id
}
