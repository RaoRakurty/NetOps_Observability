// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ctloverlay

// Package ctloverlay projects an NMS integration's stored BFD sessions into
// the SD-WAN overlay — the SD-WAN overlay from the NMS integration
// (NMS-first plan T4b, 2026-10-25).
//
// Until now the overlay was inferred ONLY from SNMP walks of each edge's SD-WAN
// MIB. An NMS-only customer has no SNMP, and IOS XE before 17.6.1a exposes no
// SD-WAN tables at all (the lab's cEDGEs run 17.03.02), so the topology said
// "N SD-WAN edge(s) are shown without their tunnels" while vManage was
// reporting every one of those tunnels.
//
// This projects the controller's stored BFD sessions (controller_state_current,
// T4a) into the SAME per-device facts the SNMP collector publishes
// (collectors.OverlayDeviceFacts), so topology.InferOverlay — its system-ip
// resolution, transport nodes, scale shapes and tenant partitioning — runs
// unchanged on both sources. Per device, controller facts replace SNMP facts:
// the integration is the source of record, and two sources must never both
// count one device's sessions.
//
// IDENTITY: only NATIVE keys are used. The canonical tunnel id carries both
// ends' system-ips; the reporting end is the one that is not the peer. Each
// system-ip is resolved to an inventory id within the integration's OWN tenant
// (nms.InventoryResolver), so a session never attaches to another tenant's
// device (§3a).

import (
	"context"
	"sort"
	"strings"
	"time"

	"netops/backend/collectors"
	"netops/backend/nms"
)

// Window is how far back a stored session still draws. BFD
// state is re-polled every cycle (default 120 s), but a large fabric is polled
// 200 devices per cycle, so a session can legitimately be minutes old. Older
// than this, the controller has stopped reporting it and it is not drawn.
const Window = 30 * time.Minute

// RowCap bounds one tenant's read (≈ 10k edges × 2 ends).
const RowCap = 20000

// Stats is what the projection could not place, for the log.
type Stats struct {
	Tenants    int
	Sessions   int
	Unresolved int // a system-ip no device of the integration's tenant owns
	Malformed  int // a stored tunnel id that does not parse
	Truncated  int // tenants whose read hit the row cap
}

// SessionStore is the slice of the NMS store the projection reads.
type SessionStore interface {
	ListEnabled(ctx context.Context) ([]nms.Integration, error)
	OverlaySessions(ctx context.Context, tenant string, since time.Time, limit int) ([]nms.StateRecord, bool, error)
}

// KeyResolver maps a native controller key to an inventory id in a tenant.
type KeyResolver interface {
	ResolveDevice(tenant string, kind nms.KeyKind, key, name string) (string, bool)
}

// Facts returns per-device overlay facts built from the
// controller sessions of every tenant with an enabled integration. A store
// error is returned, never folded into "no overlay" (an unread source keeps
// the previous snapshot — tracker 307).
func Facts(ctx context.Context, st SessionStore, res KeyResolver, now time.Time) (map[string]collectors.OverlayDeviceFacts, Stats, error) {
	var stats Stats
	ints, err := st.ListEnabled(ctx)
	if err != nil {
		return nil, stats, err
	}
	tenants := map[string]bool{}
	for _, ic := range ints {
		tenants[ic.Tenant] = true
	}
	order := make([]string, 0, len(tenants))
	for t := range tenants {
		order = append(order, t)
	}
	sort.Strings(order)

	out := map[string]collectors.OverlayDeviceFacts{}
	for _, tenant := range order {
		recs, truncated, err := st.OverlaySessions(ctx, tenant, now.Add(-Window), RowCap)
		if err != nil {
			return nil, stats, err
		}
		stats.Tenants++
		if truncated {
			stats.Truncated++
		}
		projectTenantSessions(tenant, recs, res, out, &stats)
	}
	return out, stats, nil
}

// projectTenantSessions folds one tenant's sessions into out. Pure apart from
// the resolver.
func projectTenantSessions(tenant string, recs []nms.StateRecord, res KeyResolver, out map[string]collectors.OverlayDeviceFacts, stats *Stats) {
	resolve := func(sys string) (string, bool) {
		if res == nil {
			return "", false
		}
		return res.ResolveDevice(tenant, nms.KeySystemIP, sys, "")
	}
	type peerKey struct{ dev, peerSys string }
	type colorKey struct {
		peerKey
		local, remote string
	}
	cp := map[colorKey]*collectors.OverlayColorPairs{}
	for _, r := range recs {
		local, peer, ok := TunnelEnds(r.TunnelID, r.PeerID)
		if !ok {
			stats.Malformed++
			continue
		}
		stats.Sessions++
		dev, ok := resolve(local)
		if !ok {
			stats.Unresolved++
			continue
		}
		f := out[dev]
		if f.DeviceID == "" {
			f = collectors.OverlayDeviceFacts{DeviceID: dev, MIB: "controller", Capability: "available",
				Personality: "controller", SystemIP: local, DetailRead: true, Source: collectors.OverlaySourceController}
		}
		if r.LastSeen.After(f.DetailAt) {
			f.DetailAt, f.WalkedAt = r.LastSeen, r.LastSeen
		}
		if f.SiteID == "" {
			f.SiteID = r.SiteID
		}
		f.SessionsRead++
		out[dev] = f
		pk := peerKey{dev, peer}
		ck := colorKey{pk, r.LocalColor, r.RemoteColor}
		c := cp[ck]
		if c == nil {
			c = &collectors.OverlayColorPairs{LocalColor: r.LocalColor, RemoteColor: r.RemoteColor, Proto: "ipsec"}
			cp[ck] = c
		}
		c.Sessions++
		if r.CurrentState == "up" {
			c.Up++
		}
		// The far end may not have reported this cycle (vManage is polled 200
		// devices per cycle): give it an explicit, resolved system-ip so the
		// pair still resolves. It adds no sessions of its own.
		if pdev, ok := resolve(peer); ok {
			if pf, have := out[pdev]; !have || pf.SystemIP == "" {
				if !have {
					pf = collectors.OverlayDeviceFacts{DeviceID: pdev, MIB: "controller", Capability: "partial",
						Personality: "controller", Source: collectors.OverlaySourceController}
				}
				pf.SystemIP = peer
				out[pdev] = pf
			}
		}
	}
	// Attach peers and colour pairs in a stable order.
	keys := make([]colorKey, 0, len(cp))
	for k := range cp {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.dev != b.dev {
			return a.dev < b.dev
		}
		if a.peerSys != b.peerSys {
			return a.peerSys < b.peerSys
		}
		if a.local != b.local {
			return a.local < b.local
		}
		return a.remote < b.remote
	})
	peerAt := map[peerKey]int{}
	for _, k := range keys {
		f := out[k.dev]
		i, ok := peerAt[k.peerKey]
		if !ok {
			i = len(f.Peers)
			f.Peers = append(f.Peers, collectors.OverlayPeer{SystemIP: k.peerSys})
			peerAt[k.peerKey] = i
		}
		f.Peers[i].ColorPairs = append(f.Peers[i].ColorPairs, *cp[k])
		out[k.dev] = f
	}
}

// TunnelEnds splits a canonical tunnel id ("<ipA>/<colA>|<ipB>/<colB>") into
// the reporting end's system-ip and the peer's, using the stored peer key to
// tell them apart. A malformed id, or a peer that is neither end, is refused.
func TunnelEnds(tunnelID, peer string) (local, remote string, ok bool) {
	a, b, found := strings.Cut(tunnelID, "|")
	if !found {
		return "", "", false
	}
	ipA, _, okA := strings.Cut(a, "/")
	ipB, _, okB := strings.Cut(b, "/")
	if !okA || !okB || ipA == "" || ipB == "" || ipA == ipB {
		return "", "", false
	}
	switch peer {
	case ipA:
		return ipB, ipA, true
	case ipB:
		return ipA, ipB, true
	}
	return "", "", false
}
