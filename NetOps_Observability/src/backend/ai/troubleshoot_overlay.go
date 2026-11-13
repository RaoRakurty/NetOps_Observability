// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// troubleshoot_overlay.go — three read-only WAN reads for one device (NetClaw
// ingestion Batch 2, 2026-11-13):
//
//	get_overlay_state   the SD-WAN overlay as this edge holds it: its control
//	                    plane (OMP sessions to the controllers) and its data
//	                    plane (BFD sessions, folded per transport colour)
//	get_tunnel_state    the device's tunnels (IPsec / GRE / SD-WAN) and their
//	                    state, from the tunnel inventory the collectors keep
//	get_path_evidence   the measured paths this device takes part in, hop by
//	                    hop: where loss first appears, whether it persists to
//	                    the destination, and whether the hop sequence changed
//
// WHY THESE ARE NOT DEVICE COMMANDS. Each answers from what Correlix ALREADY
// collected (the overlay facts the SNMP and controller collectors publish, the
// tunnel inventory, the path graph's own probes). Nothing is sent to the
// device, and nothing is originated FROM it: the owner's rule (2026-11-13) is
// no ping or traceroute launched from a customer device — path evidence comes
// from Correlix's own probers.
//
// §3a: every seam resolves the device through the caller's own inventory
// first (another tenant's device is ErrNotFound) and reads only that
// device's rows. The tool takes one argument, the device, which is resolved
// by the SAME ResolveDevice every device tool uses.
//
// §15: every value is data. Peer names that are addresses are replaced by an
// ordinal ("unnamed edge 2"), hop addresses are never rendered (a hop is its
// position and, when resolved, its owner's seam), lists are capped with the
// true totals, and the machine facts (state:<facet>=<value>) come from the
// counts the server read — never from device text.

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// ── get_overlay_state ────────────────────────────────────────────────────────

// OverlayState is one device's SD-WAN overlay, as the server read it.
type OverlayState struct {
	DeviceName string
	// Read is false when the overlay has not been read since the server
	// started: no facts then means UNKNOWN, never "not an overlay member".
	Read bool
	// Member is true when the device published overlay facts this cycle.
	Member bool
	// Source is "snmp" (the edge's SD-WAN MIB) or "controller" (the NMS
	// integration's stored sessions).
	Source string
	ReadAt time.Time
	Site   string
	// DataRead says the BFD session table has been read at least once (no
	// transports then means none read yet, not "no tunnels").
	DataRead        bool
	Transports      []OverlayTransportState
	TransportsTotal int
	// Peers is how many remote edges this device holds sessions with;
	// PeersDown names those whose every session is down.
	Peers          int
	PeersDown      []string
	PeersDownTotal int
	// ControlRead says the OMP table was read. OMPUp / OMPNotUp count the
	// device's OMP sessions (an edge's are its controllers).
	ControlRead     bool
	OMPUp, OMPNotUp int
	// Truncated: a walk hit its row cap; peers beyond it are UNKNOWN.
	Truncated bool
	Notes     []string
}

// OverlayTransportState is the BFD sessions of one local transport colour.
type OverlayTransportState struct {
	Color        string
	Sessions, Up int
}

// Bounds of the rendered overlay answer.
const (
	maxOverlayTransports = 12
	maxOverlayPeersDown  = 15
)

// OverlayStateCitationPrefix is the citation namespace of the overlay items.
const OverlayStateCitationPrefix = "ovl:"

type overlayStateTool struct{ deps TroubleshootDeps }

func (t overlayStateTool) Name() string            { return "get_overlay_state" }
func (t overlayStateTool) Module() string          { return "topology" }
func (t overlayStateTool) Capability() Capability  { return CapRead }
func (t overlayStateTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t overlayStateTool) Freshness() Freshness    { return FreshnessRecent }

func (t overlayStateTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	ref, err := validIDArg("device_id", args["device_id"], 128)
	if err != nil {
		return ToolResult{}, err
	}
	dev, err := t.deps.ResolveDevice(ctx, p, ref)
	if err != nil {
		return ToolResult{}, err
	}
	st, err := t.deps.OverlayState(ctx, p, dev.ID)
	if err != nil {
		return ToolResult{}, err
	}
	return RenderOverlayState(st, dev), nil
}

// overlaySignals derives the machine facts of an overlay read. An unread
// plane declares nothing: unread is never "down".
func overlaySignals(st OverlayState) []string {
	var out []string
	if st.Member && st.ControlRead {
		total := st.OMPUp + st.OMPNotUp
		switch {
		case total == 0:
			out = append(out, CondStatePrefix+"overlay_ctl=none")
		case st.OMPNotUp == 0:
			out = append(out, CondStatePrefix+"overlay_ctl=up")
		case st.OMPUp == 0:
			out = append(out, CondStatePrefix+"overlay_ctl=down")
		default:
			out = append(out, CondStatePrefix+"overlay_ctl=partial")
		}
	}
	if st.Member && st.DataRead {
		sessions, up := 0, 0
		for _, tr := range st.Transports {
			sessions += tr.Sessions
			up += tr.Up
		}
		switch {
		case sessions == 0:
			out = append(out, CondStatePrefix+"overlay_bfd=none")
		case up == sessions:
			out = append(out, CondStatePrefix+"overlay_bfd=up")
		case up == 0:
			out = append(out, CondStatePrefix+"overlay_bfd=down")
		default:
			out = append(out, CondStatePrefix+"overlay_bfd=partial")
		}
	}
	return out
}

// RenderOverlayState turns one device's overlay read into bounded evidence.
func RenderOverlayState(st OverlayState, dev DeviceRef) ToolResult {
	const href = "#/investigate/tunnels"
	label := firstNonEmpty(safeLabel(st.DeviceName), safeLabel(dev.Name), "the device")
	tr := ToolResult{}
	item := func(id, text string) {
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: OverlayStateCitationPrefix + id, Kind: "topology",
			Text: clampText(text, maxToolTextChars), Href: href,
		})
	}
	switch {
	case !st.Read:
		tr.Notes = append(tr.Notes, "the SD-WAN overlay has not been read since the server started — say the overlay state is UNKNOWN for "+label+", never that it is down or absent")
		return tr
	case !st.Member:
		item(dev.ID+":member", label+" holds no SD-WAN overlay sessions in what Correlix read — it is not an overlay member, so the SD-WAN method does not apply to it")
		tr.Notes = append(tr.Notes, st.Notes...)
		return tr
	}
	head := label + " — SD-WAN overlay member"
	if st.Site != "" {
		head += ", site " + safeLabel(st.Site)
	}
	if st.Source == "controller" {
		head += " (read through the SD-WAN controller)"
	} else {
		head += " (read from the edge's SD-WAN MIB)"
	}
	if !st.ReadAt.IsZero() {
		head += ", read " + st.ReadAt.UTC().Format(time.RFC3339)
	}
	item(dev.ID+":scope", head)

	// Control plane first: an edge that lost its controllers keeps forwarding on
	// stale routes for a while and then loses them, which BFD alone never shows.
	if st.ControlRead {
		if total := st.OMPUp + st.OMPNotUp; total == 0 {
			item(dev.ID+":control", "control plane: no OMP session to any controller is held")
		} else {
			item(dev.ID+":control", fmt.Sprintf("control plane: %d of %d OMP sessions to the controllers up", st.OMPUp, total))
		}
	} else {
		tr.Notes = append(tr.Notes, "the OMP (control-plane) table was not read for "+label+" — its control connections are UNKNOWN, not down")
	}

	if !st.DataRead {
		tr.Notes = append(tr.Notes, "the BFD session table has not been read for "+label+" yet — its tunnels are UNKNOWN, not down")
	} else {
		ts := append([]OverlayTransportState(nil), st.Transports...)
		sort.SliceStable(ts, func(i, j int) bool { return ts[i].Color < ts[j].Color })
		if len(ts) > maxOverlayTransports {
			ts = ts[:maxOverlayTransports]
			tr.Truncated = true
		}
		if len(ts) == 0 {
			item(dev.ID+":data", "data plane: no BFD session is held on any transport")
		}
		for i, t := range ts {
			health := "all up"
			switch {
			case t.Sessions == 0:
				health = "no sessions"
			case t.Up == 0:
				health = "every session down"
			case t.Up < t.Sessions:
				health = "some sessions down"
			}
			item(fmt.Sprintf("%s:transport:%d", dev.ID, i+1),
				fmt.Sprintf("transport %s: %d of %d BFD sessions up (%s)", safeLabel(firstNonEmpty(t.Color, "unnamed")), t.Up, t.Sessions, health))
		}
		if total := max(st.TransportsTotal, len(st.Transports)); total > len(ts) {
			tr.Notes = append(tr.Notes, fmt.Sprintf("showing %d of %d transports", len(ts), total))
		}
		item(dev.ID+":peers", fmt.Sprintf("tunnels to %s; %d with every session down", plural(st.Peers, "remote edge"), max(st.PeersDownTotal, len(st.PeersDown))))
		down := st.PeersDown
		if len(down) > maxOverlayPeersDown {
			down = down[:maxOverlayPeersDown]
			tr.Truncated = true
		}
		unnamed := 0
		for i, n := range down {
			name := safeLabel(n)
			if name == "" {
				unnamed++
				name = fmt.Sprintf("unnamed edge %d", unnamed)
			}
			item(fmt.Sprintf("%s:peer-down:%d", dev.ID, i+1), "every session to "+name+" is down")
		}
		if total := max(st.PeersDownTotal, len(st.PeersDown)); total > len(down) {
			tr.Notes = append(tr.Notes, fmt.Sprintf("showing %d of %d edges with every session down", len(down), total))
		}
	}
	if st.Truncated {
		tr.Truncated = true
		tr.Notes = append(tr.Notes, "the overlay walk hit its row cap — sessions beyond it are UNKNOWN, not down")
	}
	tr.Notes = append(tr.Notes, st.Notes...)
	tr.Signals = overlaySignals(st)
	return tr
}

// ── get_tunnel_state ─────────────────────────────────────────────────────────

// TunnelState is one device's tunnels, as the tunnel inventory holds them.
type TunnelState struct {
	DeviceName string
	// Read is false when the tunnel inventory could not be read: no tunnels
	// then means UNKNOWN, never "no tunnels".
	Read    bool
	Tunnels []TunnelEntry
	// Total, Up and Down count every tunnel the inventory holds for the
	// device (Tunnels may be capped).
	Total, Up, Down int
	Notes           []string
}

// TunnelEntry is one tunnel. Type is sdwan | ipsec | gre | tunnel. Interface
// is the tunnel interface (IPsec/GRE), Transport the local transport colour
// (SD-WAN); Remote is the far end's device name, empty when it is unknown.
type TunnelEntry struct {
	Type, Remote, Interface, Transport, Status string
	// Measured is false when the inventory carries no path quality for the
	// tunnel (IF-MIB and the SD-WAN MIB carry none): latency and loss are then
	// absent, never zero.
	Measured           bool
	LatencyMs, LossPct float64
}

// maxTunnelRows bounds the rendered tunnel list.
const maxTunnelRows = 20

// TunnelStateCitationPrefix is the citation namespace of the tunnel items.
const TunnelStateCitationPrefix = "tun:"

type tunnelStateTool struct{ deps TroubleshootDeps }

func (t tunnelStateTool) Name() string            { return "get_tunnel_state" }
func (t tunnelStateTool) Module() string          { return "topology" }
func (t tunnelStateTool) Capability() Capability  { return CapRead }
func (t tunnelStateTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t tunnelStateTool) Freshness() Freshness    { return FreshnessRecent }

func (t tunnelStateTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	ref, err := validIDArg("device_id", args["device_id"], 128)
	if err != nil {
		return ToolResult{}, err
	}
	dev, err := t.deps.ResolveDevice(ctx, p, ref)
	if err != nil {
		return ToolResult{}, err
	}
	st, err := t.deps.TunnelState(ctx, p, dev.ID)
	if err != nil {
		return ToolResult{}, err
	}
	return RenderTunnelState(st, dev), nil
}

// tunnelTypeFacet maps an inventory tunnel type onto the closed facet values.
func tunnelTypeFacet(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "sdwan":
		return "sdwan"
	case "ipsec":
		return "ipsec"
	case "gre":
		return "gre"
	}
	return "other"
}

// tunnelSignals derives the machine facts of a tunnel read. An unread
// inventory declares nothing.
func tunnelSignals(st TunnelState) []string {
	if !st.Read {
		return nil
	}
	var out []string
	switch {
	case st.Total == 0:
		out = append(out, CondStatePrefix+"tunnel=none")
	case st.Down == 0:
		out = append(out, CondStatePrefix+"tunnel=up")
	case st.Up == 0:
		out = append(out, CondStatePrefix+"tunnel=down")
	default:
		out = append(out, CondStatePrefix+"tunnel=partial")
	}
	seen := map[string]bool{}
	for _, tn := range st.Tunnels {
		f := tunnelTypeFacet(tn.Type)
		if !seen[f] {
			seen[f] = true
			out = append(out, CondStatePrefix+"tunnel_type="+f)
		}
	}
	sort.Strings(out[1:])
	return out
}

// RenderTunnelState turns one device's tunnel read into bounded evidence,
// tunnels that are down first.
func RenderTunnelState(st TunnelState, dev DeviceRef) ToolResult {
	const href = "#/investigate/tunnels"
	label := firstNonEmpty(safeLabel(st.DeviceName), safeLabel(dev.Name), "the device")
	tr := ToolResult{}
	if !st.Read {
		tr.Notes = append(tr.Notes, "the tunnel inventory could not be read — say the tunnels of "+label+" are UNKNOWN, never that it has none")
		tr.Notes = append(tr.Notes, st.Notes...)
		return tr
	}
	item := func(id, text string) {
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: TunnelStateCitationPrefix + id, Kind: "topology",
			Text: clampText(text, maxToolTextChars), Href: href,
		})
	}
	if st.Total == 0 {
		item(dev.ID+":scope", label+" terminates no tunnel in Correlix's tunnel inventory (IPsec, GRE or SD-WAN)")
		tr.Notes = append(tr.Notes, st.Notes...)
		tr.Signals = tunnelSignals(st)
		return tr
	}
	item(dev.ID+":scope", fmt.Sprintf("%s — %s: %d up, %d down", label, plural(st.Total, "tunnel"), st.Up, st.Down))
	rows := append([]TunnelEntry(nil), st.Tunnels...)
	sort.SliceStable(rows, func(i, j int) bool {
		di, dj := rows[i].Status != "up", rows[j].Status != "up"
		if di != dj {
			return di
		}
		return rows[i].Remote < rows[j].Remote
	})
	if len(rows) > maxTunnelRows {
		rows = rows[:maxTunnelRows]
		tr.Truncated = true
	}
	unnamed := 0
	for i, tn := range rows {
		remote := safeLabel(tn.Remote)
		if remote == "" {
			unnamed++
			remote = fmt.Sprintf("unnamed endpoint %d", unnamed)
		}
		kind := map[string]string{"sdwan": "SD-WAN tunnel", "ipsec": "IPsec tunnel", "gre": "GRE tunnel"}[tunnelTypeFacet(tn.Type)]
		text := fmt.Sprintf("%s to %s", firstNonEmpty(kind, "tunnel"), remote)
		if ifn := safeLabel(tn.Interface); ifn != "" {
			text += " on interface " + ifn
		}
		if tp := safeLabel(tn.Transport); tp != "" {
			text += " over transport " + tp
		}
		text += " — " + firstNonEmpty(safeLabel(tn.Status), "state unknown")
		if tn.Measured {
			text += fmt.Sprintf(", %.1f ms, %.1f%% loss", tn.LatencyMs, tn.LossPct)
		} else {
			text += ", path quality not measured"
		}
		item(fmt.Sprintf("%s:%d", dev.ID, i+1), text)
	}
	if st.Total > len(rows) {
		tr.Notes = append(tr.Notes, fmt.Sprintf("showing %d of %d tunnels (down first)", len(rows), st.Total))
	}
	tr.Notes = append(tr.Notes, "the inventory reports each tunnel up or down; IKE (phase 1) and IPsec (phase 2) are not read separately here, so a tunnel that is up with no traffic passing cannot be told from a healthy one by this read")
	tr.Notes = append(tr.Notes, st.Notes...)
	tr.Signals = tunnelSignals(st)
	return tr
}

// ── get_path_evidence ────────────────────────────────────────────────────────

// PathEvidence is the measured paths one device takes part in.
type PathEvidence struct {
	DeviceName string
	// Enabled is false when path measurement is not wired on this deployment.
	Enabled bool
	Paths   []PathEvidencePath
	// Total is every path the device takes part in (Paths may be capped).
	Total int
	Notes []string
}

// PathEvidencePath is one measured path, read from its latest live
// observation. Hop positions are 1-based; 0 means "none".
type PathEvidencePath struct {
	Label  string
	Status string // complete | partial | failed | "" (no live observation)
	At     time.Time
	Hops   int
	// FirstLossHop is the first hop that reported loss and LossAtFirst its
	// loss; LossPersists is true when every later responding hop, through the
	// last, also reports loss — real loss, not one router de-prioritising ICMP.
	FirstLossHop int
	LossAtFirst  float64
	LossPersists bool
	FinalLossPct float64
	// SeamAtLoss is the seam the first lossy hop sits on, when resolved.
	SeamAtLoss string
	MaxRTTms   float64
	// Changed is true when the hop count differs from the previous live
	// observation of the same path (PrevHops).
	Changed  bool
	PrevHops int
}

// maxPathRows bounds the rendered path list.
const maxPathRows = 10

// PathEvidenceCitationPrefix is the citation namespace of the path items.
const PathEvidenceCitationPrefix = "path:"

type pathEvidenceTool struct{ deps TroubleshootDeps }

func (t pathEvidenceTool) Name() string            { return "get_path_evidence" }
func (t pathEvidenceTool) Module() string          { return "topology" }
func (t pathEvidenceTool) Capability() Capability  { return CapRead }
func (t pathEvidenceTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t pathEvidenceTool) Freshness() Freshness    { return FreshnessRecent }

func (t pathEvidenceTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	ref, err := validIDArg("device_id", args["device_id"], 128)
	if err != nil {
		return ToolResult{}, err
	}
	dev, err := t.deps.ResolveDevice(ctx, p, ref)
	if err != nil {
		return ToolResult{}, err
	}
	pe, err := t.deps.PathEvidence(ctx, p, dev.ID)
	if err != nil {
		return ToolResult{}, err
	}
	return RenderPathEvidence(pe, dev), nil
}

// pathRank orders the path facet from best to worst; the worst path decides.
var pathRank = map[string]int{"clean": 1, "loss_transient": 2, "changed": 3, "loss_persistent": 4}

// pathFacet is one measured path's facet value ("" = not measured).
func pathFacet(p PathEvidencePath) string {
	switch {
	case p.Status == "":
		return ""
	case p.FirstLossHop > 0 && p.LossPersists:
		return "loss_persistent"
	case p.Changed:
		return "changed"
	case p.FirstLossHop > 0:
		return "loss_transient"
	}
	return "clean"
}

// pathSignals derives the one path fact: the WORST measured path decides, and
// a device with no live observation at all is not_measured.
func pathSignals(pe PathEvidence) []string {
	if !pe.Enabled {
		return nil
	}
	worst := ""
	for _, p := range pe.Paths {
		if f := pathFacet(p); f != "" && pathRank[f] > pathRank[worst] {
			worst = f
		}
	}
	if worst == "" {
		worst = "not_measured"
	}
	return []string{CondStatePrefix + "path=" + worst}
}

// RenderPathEvidence turns one device's measured paths into bounded evidence,
// the worst path first.
func RenderPathEvidence(pe PathEvidence, dev DeviceRef) ToolResult {
	const href = "#/infrastructure/paths"
	label := firstNonEmpty(safeLabel(pe.DeviceName), safeLabel(dev.Name), "the device")
	tr := ToolResult{}
	if !pe.Enabled {
		tr.Notes = append(tr.Notes, "path measurement is not enabled on this deployment — no measured path is available for "+label+"; say the path is UNMEASURED, never that it is clean")
		return tr
	}
	paths := append([]PathEvidencePath(nil), pe.Paths...)
	sort.SliceStable(paths, func(i, j int) bool { return pathRank[pathFacet(paths[i])] > pathRank[pathFacet(paths[j])] })
	if len(paths) > maxPathRows {
		paths = paths[:maxPathRows]
		tr.Truncated = true
	}
	total := max(pe.Total, len(pe.Paths))
	if total == 0 {
		tr.Notes = append(tr.Notes, "no measured path starts at "+label+" — Correlix's probers do not measure from or through it, so path loss and latency are UNMEASURED here, not clean")
		tr.Notes = append(tr.Notes, pe.Notes...)
		tr.Signals = pathSignals(pe)
		return tr
	}
	for i, p := range paths {
		name := safePathLabel(p.Label, i+1)
		var text string
		switch p.Status {
		case "":
			text = name + " — no live measurement"
		default:
			text = fmt.Sprintf("%s — %s, %s", name, p.Status, plural(p.Hops, "hop"))
			if p.MaxRTTms > 0 {
				text += fmt.Sprintf(", worst hop RTT %.1f ms", p.MaxRTTms)
			}
			switch {
			case p.FirstLossHop > 0 && p.LossPersists:
				text += fmt.Sprintf("; loss first appears at hop %d (%.1f%%) and PERSISTS to the destination (%.1f%% at the last hop)", p.FirstLossHop, p.LossAtFirst, p.FinalLossPct)
			case p.FirstLossHop > 0:
				text += fmt.Sprintf("; hop %d reports %.1f%% loss that does NOT continue to the destination (that router de-prioritising probes, not path loss)", p.FirstLossHop, p.LossAtFirst)
			default:
				text += "; no hop reports loss"
			}
			if p.FirstLossHop > 0 {
				if s := safeLabel(p.SeamAtLoss); s != "" {
					text += ", on seam " + s
				}
			}
			if p.Changed {
				text += fmt.Sprintf("; the hop count CHANGED from %d to %d since the previous measurement", p.PrevHops, p.Hops)
			}
			if !p.At.IsZero() {
				text += ", measured " + p.At.UTC().Format(time.RFC3339)
			}
		}
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: fmt.Sprintf("%s%s:%d", PathEvidenceCitationPrefix, dev.ID, i+1), Kind: "metric",
			Text: clampText(text, maxToolTextChars), Href: href,
		})
	}
	if total > len(paths) {
		tr.Notes = append(tr.Notes, fmt.Sprintf("showing %d of %d measured paths (worst first)", len(paths), total))
	}
	tr.Notes = append(tr.Notes, pe.Notes...)
	tr.Signals = pathSignals(pe)
	return tr
}

// ── shared ───────────────────────────────────────────────────────────────────

// safeLabel clamps a device-supplied name and drops one that IS an address
// (an unresolved peer, a management IP): a name the answer may show, or "".
func safeLabel(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || isAddressText(s) {
		return ""
	}
	return clampText(s, 80)
}

// safePathLabel keeps a path label readable without its addresses: each
// whitespace-separated token that is an address becomes "an address".
func safePathLabel(label string, n int) string {
	fields := strings.Fields(label)
	if len(fields) == 0 {
		return fmt.Sprintf("path %d", n)
	}
	for i, f := range fields {
		if isAddressText(strings.Trim(f, "()[],")) {
			fields[i] = "an address"
		}
	}
	return clampText("path "+strings.Join(fields, " "), 120)
}

// isAddressText reports whether s is an IP address, with or without a port
// or a prefix length.
func isAddressText(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if host, _, err := net.SplitHostPort(s); err == nil && net.ParseIP(host) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return false
}
