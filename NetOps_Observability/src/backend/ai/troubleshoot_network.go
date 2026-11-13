// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// troubleshoot_network.go — get_network_topology: the WHOLE-NETWORK topology
// read (what connects to what, the overlay's shape and transports, the roles
// and sites, and each role's likely function).
//
// get_topology_context answers for ONE device. "Explain the network topology"
// is a question about the estate, and before this tool the only grounded
// answer was the inventory list — which is what an operator called "just
// listing the devices". This tool hands the model the same view the Topology
// canvas draws, read in network terms by the server (topology.Summarize).
//
// STATEMENT CLASSES: the tool is OBSERVED (counts, adjacencies, transports,
// pairs with no tunnel). Two kinds of item are the server's own reading of
// that evidence and are stamped DERIVED on the item (EvidenceItem.Class): the
// overlay SHAPE and each role's LIKELY FUNCTION. A sentence that narrates them
// cites a DERIVED item and is classified DERIVED, never as an observation.
//
// §3a: the seam (TroubleshootDeps.NetworkTopology) is built by the server from
// the caller's token and reads only the caller's devices; the tool takes no
// argument a model could aim at another tenant.
//
// §15: every value is data. Names and ports are clamped, management addresses
// never appear (the provider drops them), and the item count is bounded here
// AND by the tool contract.

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"
)

// NetworkTopology is the caller's whole-network topology, already read in
// network terms by the server. Every list is bounded by the provider; the
// *Total fields carry the true counts.
type NetworkTopology struct {
	// Collected is false when the caller's view holds no managed device yet
	// (a fresh install, or discovery has not run): the answer must say the
	// topology is NOT YET COLLECTED, never describe an empty network.
	Collected     bool
	Devices       []NetworkDevice
	DevicesTotal  int
	Roles         []NamedCount
	Sites         []NamedCount
	Vendors       []NamedCount
	Links         []NetworkLink
	LinksTotal    int
	LinkProtocols []NamedCount
	External      int
	Overlay       *NetworkOverlay
	RoleNotes     []NetworkRoleNote
	// OverlayRead is false when the overlay has not been read since the
	// server started: no overlay then means UNKNOWN, not "no SD-WAN".
	OverlayRead bool
	Notes       []string
}

// NamedCount is one name with its count.
type NamedCount struct {
	Name  string
	Count int
}

// NetworkDevice is one device of the whole-network read.
type NetworkDevice struct {
	Name, Role, RoleConfidence, Vendor, Model, Site, Health string
	Adjacencies, OverlayPeers                               int
}

// NetworkLink is one physical or routed adjacency.
type NetworkLink struct {
	A, APort, B, BPort, Protocol, Status string
	External                             bool
}

// NetworkOverlay is the SD-WAN overlay read in network terms.
type NetworkOverlay struct {
	Members, Pairs, PossiblePairs, SameSitePairs int
	Shape                                        string
	Hubs                                         []string
	Transports                                   []NetworkTransport
	Missing                                      []NetworkPair
	MissingTotal                                 int
	SameSiteNoTunnel                             []NetworkPair
	NotUp                                        []NetworkPairStatus
	NotUpTotal                                   int
}

// NetworkTransport is one overlay transport (an SD-WAN colour).
type NetworkTransport struct {
	Name                  string
	Members, Sessions, Up int
	Health                string
}

// NetworkPair names two overlay members.
type NetworkPair struct {
	A, B, Site string
}

// NetworkPairStatus is a pair whose tunnels are not all up.
type NetworkPairStatus struct {
	A, B, Status string
	Sessions, Up int
	Colors       []string
}

// NetworkRoleNote is a role's members and its likely function (an inference).
type NetworkRoleNote struct {
	Role         string
	Members      []string
	MembersTotal int
	Likely       string
}

// Bounds of the rendered answer (the contract allows a little more).
const (
	maxNetDevices = 30
	maxNetLinks   = 25
)

// NetworkTopologyCitationPrefix is the citation namespace of the tool's items.
const NetworkTopologyCitationPrefix = "topo-net:"

type networkTopologyTool struct{ deps TroubleshootDeps }

func (t networkTopologyTool) Name() string            { return "get_network_topology" }
func (t networkTopologyTool) Module() string          { return "topology" }
func (t networkTopologyTool) Capability() Capability  { return CapRead }
func (t networkTopologyTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t networkTopologyTool) Freshness() Freshness    { return FreshnessLive }

func (t networkTopologyTool) Run(ctx context.Context, p Principal, _ ToolArgs) (ToolResult, error) {
	nt, err := t.deps.NetworkTopology(ctx, p)
	if err != nil {
		return ToolResult{}, err
	}
	return RenderNetworkTopology(nt), nil
}

// RenderNetworkTopology turns the read into bounded evidence items, most
// informative first (a caller that keeps only the first N keeps the scope,
// the overlay and its gaps before the per-device lines).
func RenderNetworkTopology(nt NetworkTopology) ToolResult {
	const href = "#/infrastructure/topology-canvas"
	tr := ToolResult{}
	item := func(id, text, class string) {
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: NetworkTopologyCitationPrefix + id, Kind: "topology",
			Text: clampRunes(text, maxToolTextChars), Href: href, Class: class,
		})
	}
	if !nt.Collected {
		item("scope", "No managed device is in this workspace's topology yet — the topology is NOT YET COLLECTED (discovery has not run or found nothing), so nothing can be said about how the network is connected.", "")
		tr.Notes = append(tr.Notes, "say the topology has not been collected yet; do not describe an empty or isolated network")
		tr.Notes = append(tr.Notes, nt.Notes...)
		return tr
	}

	// 1. scope
	scope := plural(nt.DevicesTotal, "managed device")
	if len(nt.Sites) > 0 {
		scope += fmt.Sprintf(" across %s (%s)", plural(len(nt.Sites), "site"), countList(nt.Sites, 8))
	}
	if len(nt.Roles) > 0 {
		scope += "; roles: " + countList(nt.Roles, 8)
	}
	if len(nt.Vendors) > 0 {
		scope += "; vendors: " + countList(nt.Vendors, 6)
	}
	scope += fmt.Sprintf("; %s", plural(nt.LinksTotal, "physical or routed adjacency"))
	if len(nt.LinkProtocols) > 0 {
		scope += " (" + countList(nt.LinkProtocols, 5) + ")"
	}
	if nt.External > 0 {
		scope += fmt.Sprintf("; %s outside the managed inventory", plural(nt.External, "neighbour"))
	}
	if nt.Overlay != nil {
		scope += fmt.Sprintf("; SD-WAN overlay of %s", plural(nt.Overlay.Members, "edge"))
	}
	item("scope", scope, "")

	// 2. overlay: shape (DERIVED), gaps and transports (OBSERVED)
	if ov := nt.Overlay; ov != nil {
		item("overlay", overlayShapeLine(ov), ClassDerived)
		if ov.MissingTotal > 0 {
			var ps []string
			for _, m := range ov.Missing {
				ps = append(ps, m.A+" ↔ "+m.B)
			}
			line := fmt.Sprintf("No tunnel observed between %s of different sites: %s", plural(ov.MissingTotal, "pair"), strings.Join(ps, "; "))
			if ov.MissingTotal > len(ov.Missing) {
				line += fmt.Sprintf(" (showing %d of %d)", len(ov.Missing), ov.MissingTotal)
			}
			item("overlay-gaps", line, "")
		}
		if len(ov.SameSiteNoTunnel) > 0 {
			var ps []string
			for _, m := range ov.SameSiteNoTunnel {
				ps = append(ps, fmt.Sprintf("%s ↔ %s (site %s)", m.A, m.B, m.Site))
			}
			item("overlay-same-site", "No tunnel between edges in the same site (SD-WAN edges in one site normally build none to each other): "+strings.Join(ps, "; "), "")
		}
		for _, x := range ov.Transports {
			item("transport:"+citeSafe(x.Name), fmt.Sprintf("Transport %s: %s attach; %d of %d BFD sessions up (the provider network behind it is not visible)",
				x.Name, plural(x.Members, "edge"), x.Up, x.Sessions), "")
		}
		for i, s := range ov.NotUp {
			item(fmt.Sprintf("overlay-down:%d", i+1), fmt.Sprintf("Tunnels %s between %s and %s: %d of %d sessions up over %s",
				s.Status, s.A, s.B, s.Up, s.Sessions, strings.Join(s.Colors, ", ")), "")
		}
		if ov.NotUpTotal > len(ov.NotUp) {
			tr.Truncated = true
			tr.Notes = append(tr.Notes, fmt.Sprintf("showing %d of %d overlay pairs that are not fully up", len(ov.NotUp), ov.NotUpTotal))
		}
	} else if !nt.OverlayRead {
		tr.Notes = append(tr.Notes, "the SD-WAN overlay has not been read since the server started — overlay tunnels are UNKNOWN here, not absent")
	}

	// 3. role functions (DERIVED)
	for _, rn := range nt.RoleNotes {
		members := strings.Join(rn.Members, ", ")
		if rn.MembersTotal > len(rn.Members) {
			members += fmt.Sprintf(" and %d more", rn.MembersTotal-len(rn.Members))
		}
		item("role:"+citeSafe(rn.Role), fmt.Sprintf("Likely function (inferred from the role classification, not read from configuration) — %s (%s): %s", rn.Role, members, rn.Likely), ClassDerived)
	}

	// 4. devices (OBSERVED)
	devs := nt.Devices
	if len(devs) > maxNetDevices {
		devs = devs[:maxNetDevices]
	}
	for i, d := range devs {
		line := d.Name + " — " + firstNonEmpty(d.Role, "role not classified")
		if d.RoleConfidence != "" && d.Role != "" {
			line += " (" + d.RoleConfidence + ")"
		}
		if hw := strings.TrimSpace(d.Vendor + " " + d.Model); hw != "" {
			line += ", " + hw
		}
		if d.Site != "" {
			line += ", site " + d.Site
		}
		line += ", health " + firstNonEmpty(d.Health, "unknown")
		line += fmt.Sprintf("; %s", plural(d.Adjacencies, "adjacency"))
		if d.OverlayPeers > 0 {
			line += fmt.Sprintf(", tunnels to %s", plural(d.OverlayPeers, "overlay peer"))
		}
		item(fmt.Sprintf("dev:%d", i+1), line, "")
	}
	if nt.DevicesTotal > len(devs) {
		tr.Truncated = true
		tr.Notes = append(tr.Notes, fmt.Sprintf("showing %d of %d devices", len(devs), nt.DevicesTotal))
	}

	// 5. adjacencies (OBSERVED)
	links := nt.Links
	if len(links) > maxNetLinks {
		links = links[:maxNetLinks]
	}
	for i, l := range links {
		a, b := l.A, l.B
		if l.APort != "" {
			a += " " + l.APort
		}
		if l.BPort != "" {
			b += " " + l.BPort
		}
		where := ""
		if l.External {
			where = ", neighbour not in the managed inventory"
		}
		item(fmt.Sprintf("link:%d", i+1), fmt.Sprintf("%s ↔ %s (%s, %s%s)", a, b, l.Protocol, l.Status, where), "")
	}
	if nt.LinksTotal > len(links) {
		tr.Truncated = true
		tr.Notes = append(tr.Notes, fmt.Sprintf("showing %d of %d adjacencies", len(links), nt.LinksTotal))
	}
	if nt.LinksTotal == 0 {
		tr.Notes = append(tr.Notes, "no physical adjacency (LLDP, CDP or routing-protocol link) is recorded — say how devices are cabled is UNKNOWN, not that they are unconnected")
	}

	tr.Notes = append(tr.Notes,
		"overlay shape and likely functions are Iris's reading of the evidence — say \"likely\" or \"appears\" for them",
		"describe the topology; do not use cause wording (\"caused\", \"resulting in\", \"due to\") — this is a map, not a diagnosis")
	tr.Notes = append(tr.Notes, nt.Notes...)
	return tr
}

func overlayShapeLine(ov *NetworkOverlay) string {
	cov := ""
	if ov.PossiblePairs > 0 {
		cov = fmt.Sprintf("%d of %d possible cross-site edge pairs hold tunnels", min(ov.Pairs, ov.PossiblePairs), ov.PossiblePairs)
	}
	switch ov.Shape {
	case "full_mesh":
		return "Overlay appears to be a FULL MESH (inferred from the BFD session pairs): " + cov + "."
	case "hub_and_spoke":
		return fmt.Sprintf("Overlay appears to be HUB AND SPOKE (inferred from the BFD session pairs): hubs %s; the other edges hold tunnels only to the hubs; %s.", strings.Join(ov.Hubs, ", "), cov)
	case "partial_mesh":
		return "Overlay appears to be a PARTIAL MESH (inferred from the BFD session pairs): " + cov + "."
	}
	return "Overlay shape could not be read from the observed pairs: " + cov + "."
}

func countList(cs []NamedCount, max int) string {
	var parts []string
	for i, c := range cs {
		if i >= max {
			parts = append(parts, fmt.Sprintf("%d more", len(cs)-max))
			break
		}
		parts = append(parts, fmt.Sprintf("%s %d", c.Name, c.Count))
	}
	return strings.Join(parts, ", ")
}

// clampRunes is clampText cut at a rune boundary: these lines carry "↔" and
// "—", and a byte cut through one would hand the provider invalid UTF-8.
func clampRunes(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + " …"
}

// citeSafe keeps a citation-id segment to the closed id alphabet.
func citeSafe(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
		if b.Len() >= 40 {
			break
		}
	}
	if b.Len() == 0 {
		return "x"
	}
	return b.String()
}
