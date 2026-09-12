// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package igpmon

import (
	"context"
	"net/http"
	"sort"
	"strings"
)

// live.go — the OPTIONAL half: adjacency state read live from
// VictoriaMetrics, where such a series is actually collected.
//
// Every read here carries the caller's device boundary as `extra_filters[]`,
// which VictoriaMetrics AND-injects into every series selector server-side. The
// module refuses to issue an unfiltered read for a scoped principal: an absent
// filter is a wiring bug, and answering it with the fleet is the leak.
//
// "No series" and "query failed" are BOTH reported as live_series:false with a
// note. They are never reported as zero adjacencies — a protocol nobody is
// watching must not render as a protocol with nothing wrong.

// LiveAdj is one live adjacency sample, decoded.
type LiveAdj struct {
	Device string `json:"device"`
	Peer   string `json:"peer,omitempty"`
	IfName string `json:"ifname,omitempty"`
	Level  string `json:"level,omitempty"` // IS-IS level (L1/L2); empty for OSPF
	VRF    string `json:"vrf,omitempty"`
	State  string `json:"state"` // decoded MIB state name
	Up     bool   `json:"up"`
	Value  int    `json:"value"` // the raw canonical MIB numeric
}

// liveSet is the outcome of a live-series read: rows plus the honest reason
// there are none.
type liveSet struct {
	rows      []LiveAdj
	available bool // a query ran AND at least one series came back
	note      string
}

// promQuote renders an already-sanitized identifier for a PromQL `=~` matcher.
// The chToken charset admits no quote and no backslash, so escaping the single
// remaining metacharacter is complete: an unescaped '.' would let one device's
// selector match a different device of the same shape.
func promQuote(tok string) string {
	return strings.ReplaceAll(tok, ".", `\\.`)
}

// deviceSelector renders {device=~"a|b"} for the resolved device identities, or
// "" when the read is fleet-wide (the tenant extra_filters[] still bound it).
func deviceSelector(ids []string) string {
	parts := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		t := chToken(id)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		parts = append(parts, promQuote(t))
	}
	if len(parts) == 0 {
		return ""
	}
	return `{device=~"` + strings.Join(parts, "|") + `"}`
}

// seriesQuery builds the instant query for a metric, optionally narrowed to a
// device identity set.
func seriesQuery(metric string, ids []string) string {
	return metric + deviceSelector(ids)
}

// metricFilters returns the caller's VictoriaMetrics device boundary, or an
// error when a SCOPED principal has none. Cross-tenant principals legitimately
// carry no filter (nothing to restrict).
func (a *API) metricFilters(r *http.Request, p Principal) ([]string, error) {
	f := a.deps.ScopeFilters(r, p)
	if p.Cross {
		return f, nil
	}
	if len(f) == 0 {
		return nil, errScopeless
	}
	return f, nil
}

// fetchLive reads the protocol's adjacency-state series for the given device
// identities (empty = every device the caller's filters admit).
func (a *API) fetchLive(ctx context.Context, r *http.Request, p Principal, proto Proto, ids []string) liveSet {
	filters, err := a.metricFilters(r, p)
	if err != nil {
		a.deps.LogWarn("refusing an unscoped metrics read", map[string]any{
			"proto": string(proto), "tenant": p.Tenant, "subject": p.Subject,
		})
		return liveSet{note: "live series unavailable: no device scope could be derived for this principal"}
	}
	samples, err := a.deps.VMQuery(ctx, seriesQuery(proto.AdjMetric(), ids), filters)
	if err != nil {
		return liveSet{note: "live series unavailable: the metric store could not be queried"}
	}
	if len(samples) == 0 {
		return liveSet{note: noSeriesNote(proto)}
	}
	rows := make([]LiveAdj, 0, len(samples))
	for _, s := range samples {
		dev := s.Labels["device"]
		if dev == "" {
			// A series with no device label cannot be attributed to a device and
			// is therefore not evidence about one.
			continue
		}
		rows = append(rows, LiveAdj{
			Device: dev,
			Peer:   s.Labels[proto.PeerLabel()],
			IfName: s.Labels["ifName"],
			Level:  s.Labels["isis_level"],
			VRF:    s.Labels["vrf"],
			State:  proto.stateName(s.Value),
			Up:     proto.isUp(s.Value),
			Value:  int(s.Value),
		})
	}
	if len(rows) == 0 {
		return liveSet{note: noSeriesNote(proto)}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Device != rows[j].Device {
			return rows[i].Device < rows[j].Device
		}
		return rows[i].Peer < rows[j].Peer
	})
	return liveSet{rows: rows, available: true}
}

// noSeriesNote is the honest sentence a UI renders when a protocol has no live
// series here. It names the transport that would carry it, so the reader can
// tell "not collected" from "collected and healthy".
//
// The subject is "these devices" — plural — because fetchLive serves BOTH the
// per-device handlers AND the fleet roll-up (handleSummary passes no device
// ids). Saying "this device" on a fleet answer misattributes the gap to one
// box, and it is the only one of the five coverage notes that ever did: the
// LSDB/SPF/area/timer notes in advanced.go all say "these devices". All five
// agree now, and copy_denylist_test.go keeps them that way.
func noSeriesNote(proto Proto) string {
	if proto == ProtoOSPF {
		return "no live series collected for these devices; adjacency history is from syslog/trap events only " +
			"(device_ospf_nbr_state is SNMP-owned via OSPF-MIB ospfNbrTable and the OpenConfig ospfv2 gNMI path is unvalidated)"
	}
	return "no live series collected for these devices; adjacency history is from syslog/trap events only " +
		"(device_isis_adj_state is carried by gNMI on gNMI-capable devices)"
}
