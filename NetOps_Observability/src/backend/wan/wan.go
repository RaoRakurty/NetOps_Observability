// Package wan is the WAN path-metrics projection core (Phase-2 W1.6),
// extracted from package main: the endpoint/circuit model, the per-tenant
// measurement policy vocabulary, the ranked target derivation
// (next-hop override → directly-connected peer → reachability anchor) and the
// neighbor index over the merged topology links. NO hub/spoke — every WAN
// interface is measured to a target derived per interface.
//
// The projector loop, policy store, publisher, VM reads and handlers stay in
// main: they hold srv and its DI seams. This package is pure — deterministic
// in its inputs, no I/O, no env.
package wan

import (
	"crypto/sha1" //nolint:gosec // G505: non-crypto stable fingerprint (CircuitID doc)
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
)

// DefaultPattern selects WAN devices by name.
const DefaultPattern = "wan|edge|gw|dmz"

// mgmtIfPattern matches out-of-band MANAGEMENT interfaces, which are never WAN
// transport. Excluding them is essential: on a shared management segment every
// device is an LLDP/CDP neighbour of every other, so without this filter the WAN
// router's mgmt port pulls the whole fabric in and derives arbitrary "peers".
var mgmtIfPattern = regexp.MustCompile(`(?i)(^|[^a-z])(mgmt|management|oob)|^(ma|me|fxp|em)\d`)

func IsMgmtInterface(ifn string) bool { return mgmtIfPattern.MatchString(ifn) }

// DefaultAnchors are the reachability anchors used when an interface has no
// directly-connected peer and no configured next-hop (prod internet-facing case).
var DefaultAnchors = []string{"1.1.1.1", "8.8.8.8"}

// TargetKind is how an interface's measurement target was derived (provenance).
type TargetKind string

const (
	TargetDirectPeer TargetKind = "direct_peer" // LLDP/CDP-connected neighbor (lab, internal P2P)
	TargetNextHop    TargetKind = "next_hop"    // operator-configured ISP next-hop
	TargetAnchor     TargetKind = "anchor"      // public-DNS / reachability anchor (prod default)
	TargetNone       TargetKind = ""            // no target could be derived
)

// Label is the customer-facing kind name (no raw tokens — customer-language rule).
func (k TargetKind) Label() string {
	switch k {
	case TargetDirectPeer:
		return "Directly-connected peer"
	case TargetNextHop:
		return "ISP next-hop"
	case TargetAnchor:
		return "Reachability anchor"
	default:
		return "—"
	}
}

// Endpoint is one WAN (or WAN-connected) transport interface, with its derived
// measurement target.
type Endpoint struct {
	TenantID   string `json:"tenant_id,omitempty"`
	Device     string `json:"device"`
	Interface  string `json:"interface"`       // ifName (Ethernet1)
	Address    string `json:"address"`         // interface IP
	Measurable string `json:"measurable_addr"` // address the OTHER end targets; default = Address
	Site       string `json:"site,omitempty"`
	// ConnectedToWAN marks an interface that was included because it is directly
	// connected to a WAN device (e.g. the lab Spine's link to the WAN router),
	// rather than living on a WAN device itself.
	ConnectedToWAN bool `json:"connected_to_wan,omitempty"`

	// Derived measurement target (no hub/spoke).
	Target      string     `json:"target,omitempty"`       // dst host we measure to
	TargetKind  TargetKind `json:"target_kind,omitempty"`  // how the target was derived
	TargetLabel string     `json:"target_label,omitempty"` // customer-facing target description
}

// Circuit is one interface → its measurement target (a 1:1 link, NOT a mesh).
// The name is retained for the /api/wan/circuits surface + the echo publisher;
// Remote is the target rendered as an endpoint (its device/if for a direct peer,
// or the anchor address for an anchor target).
type Circuit struct {
	TenantID string     `json:"tenant_id,omitempty"`
	ID       string     `json:"id"` // deterministic over (local interface, target)
	Local    Endpoint   `json:"local"`
	Remote   Endpoint   `json:"remote"`
	Kind     TargetKind `json:"kind"`
	Source   string     `json:"source"` // registry
	Enabled  bool       `json:"enabled"`
}

// MeasurementPolicy is the per-tenant measurement policy — one row per tenant.
// It replaces the old hub/spoke topology policy: no roles, no mesh mode. All
// operator intent for the WAN interface view lives here.
type MeasurementPolicy struct {
	TenantID         string            `json:"tenant_id,omitempty"`
	WanPattern       string            `json:"wan_pattern,omitempty"`       // which devices are WAN devices
	Anchors          []string          `json:"anchors,omitempty"`           // reachability anchors (default 1.1.1.1/8.8.8.8)
	NextHops         map[string]string `json:"next_hops,omitempty"`         // device or device/ifName → explicit target (ISP next-hop)
	IncludeConnected *bool             `json:"include_connected,omitempty"` // include ifaces connected to a WAN device (default true)
	UpdatedBy        string            `json:"updated_by,omitempty"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

// withDefaults fills empty fields with the safe baseline a tenant gets before it
// has ever saved a policy.
func (p MeasurementPolicy) WithDefaults() MeasurementPolicy {
	if p.WanPattern == "" {
		p.WanPattern = DefaultPattern
	}
	if len(p.Anchors) == 0 {
		p.Anchors = append([]string(nil), DefaultAnchors...)
	}
	if p.IncludeConnected == nil {
		t := true
		p.IncludeConnected = &t
	}
	return p
}

func (p MeasurementPolicy) Validate() error {
	if p.WanPattern != "" {
		if _, err := regexp.Compile("(?i)" + p.WanPattern); err != nil {
			return fmt.Errorf("wan_pattern is not a valid regex: %w", err)
		}
	}
	return nil
}

func (p MeasurementPolicy) IncludeConnectedOn() bool {
	return p.IncludeConnected == nil || *p.IncludeConnected
}

// wanNeighborIndex indexes directly-connected neighbours by the LOCAL interface
// (deviceID, ifName) → the peer (device id, ifName, measurable IP). Built from the
// merged LLDP/CDP/BGP-LS topology links, joined to the interface-IP table so we
// know the peer's probe-able address.
type Peer struct {
	Device string // peer device name
	Iface  string // peer ifName
	Addr   string // peer interface IP (probe target)
}

// NeighborIndex builds (localDevID, localIfName) → peer, from the merged
// topology links, restricted to devices visible to the principal and joined to
// the peer's interface IP. LLDP/CDP carry LocalDevice (id) + RemSysName (name);
// we resolve the peer name to a visible device id and look up its interface IP.
// Pure: the caller fetches the links (its DI seam) and passes them in.
func NeighborIndex(links []collectors.LLDPNeighbor, visible map[string]models.Device, nameToID map[string]string, ipByDevIf map[string]map[string]string) map[string]Peer {
	out := map[string]Peer{}
	for _, l := range links {
		if l.Proto == "bgp_ls" { // BGP-LS is a control-plane view, not a directly-probeable L2 peer
			continue
		}
		if l.LocalDevice == "" || l.LocalPort == "" {
			continue
		}
		if _, ok := visible[l.LocalDevice]; !ok {
			continue // not this principal's device
		}
		peerID := nameToID[strings.ToLower(l.RemSysName)]
		if peerID == "" {
			continue // unknown / cross-tenant peer — skip (never leak another tenant)
		}
		peerAddr := ipByDevIf[peerID][l.RemPort]
		peerName := visible[peerID].Name
		k := IfKey(l.LocalDevice, l.LocalPort)
		if _, seen := out[k]; !seen {
			out[k] = Peer{Device: peerName, Iface: l.RemPort, Addr: peerAddr}
		}
	}
	return out
}

// DeriveTarget picks an interface's measurement target by the ranked strategy:
// operator next-hop override → directly-connected peer → reachability anchor.
func DeriveTarget(devID, ifn string, neighbors map[string]Peer, pol MeasurementPolicy) (string, TargetKind, string) {
	// 1. operator next-hop override, keyed by "device/ifName" then "device".
	if pol.NextHops != nil {
		if t := pol.NextHops[devID+"/"+ifn]; t != "" {
			return t, TargetNextHop, "Configured next-hop " + t
		}
		if t := pol.NextHops[devID]; t != "" {
			return t, TargetNextHop, "Configured next-hop " + t
		}
	}
	// 2. directly-connected peer (LLDP/CDP) with a resolvable IP.
	if peer, ok := neighbors[IfKey(devID, ifn)]; ok && peer.Addr != "" {
		return peer.Addr, TargetDirectPeer, "Directly-connected peer " + peer.Device + " " + peer.Iface
	}
	// 3. reachability anchor (prod internet-facing default).
	anchors := pol.Anchors
	if len(anchors) == 0 {
		anchors = DefaultAnchors
	}
	if len(anchors) > 0 && anchors[0] != "" {
		return anchors[0], TargetAnchor, "Reachability anchor " + anchors[0]
	}
	return "", TargetNone, ""
}

// DeviceIDForName resolves a device NAME back to its id (endpoints store the name).
func DeviceIDForName(name string, nameToID map[string]string) string {
	return nameToID[strings.ToLower(name)]
}

// CircuitID derives the stable circuit identifier. SHA-1 here is a
// non-cryptographic fingerprint: the ids are already persisted in metric
// series and the UI, so the algorithm must stay put for continuity.
func CircuitID(local, remote Endpoint) string {
	h := sha1.Sum([]byte(local.Device + "|" + local.Interface + "|" + remote.Measurable)) //nolint:gosec // G401: see doc comment
	return "wan-" + hex.EncodeToString(h[:6])
}

// IfKey indexes a device_if_* sample / endpoint by device + interface name.
func IfKey(device, iface string) string { return device + "\x00" + iface }

func SplitIfKey(k string) (string, string) {
	if i := strings.IndexByte(k, 0); i >= 0 {
		return k[:i], k[i+1:]
	}
	return "", ""
}

// wanInterfaceRows builds the per-interface table: every in-scope WAN interface
// for the principal, joined with its derived target, the resolved SLA, and live
// util. Target metrics are keyed by target HOST (the resolver's identity).
