// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package tunnelview folds the SD-WAN overlay facts into ONE row per tunnel,
// keyed by the identity the correlation engine uses, and joins what an
// operator needs beside it: path quality, the open case and both ends' sites
// (Paths P4).
//
// Before it, /api/tunnels listed each tunnel once per reporting end, keyed by
// (device, peer, colours): one tunnel was two rows and neither could name the
// correlation object the engine built for it, because the engine keys a tunnel
// by the sorted TLOC pair (nms.CanonicalTunnelID; controller_events.py binds
// `<tid>@<controller instance>`, the trap lane the bare `<tid>`).
//
// Everything here is pure: no IO, no clock, no globals. The root package reads
// VictoriaMetrics and ClickHouse with the caller's scope and hands the results
// in; this package never widens what it is given.
//
// TENANT (§3a): every key is (tenant, tunnel id). Two tenants whose overlays
// reuse the same system-ips and colours never fold into one row, never join
// each other's quality and never attach each other's case.
package tunnelview

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
	"strings"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/owner"
	"netops/backend/nms"
)

// Tunnel states. StateDisagree: both ends reported and they differ.
const (
	StateUp       = "up"
	StateDown     = "down"
	StateDisagree = "disagree"
)

// End is one end of a tunnel.
type End struct {
	// DeviceID is the inventory id of the device at this end; "" when the
	// end's system-ip resolves to no device of the tunnel's tenant, or (after
	// Visible) when the caller may not see that device.
	DeviceID string
	SystemIP string
	Color    string
	// Addr is this end's transport address as the OTHER end reaches it.
	Addr string
	// Reported: this end's own device reported the session state.
	Reported bool
	Sessions int
	Up       int
	// Source is where the report came from: "snmp" or "controller".
	Source string
}

// State is the end's reported state ("" when it did not report).
func (e End) State() string {
	switch {
	case !e.Reported:
		return ""
	case e.Up > 0:
		return StateUp
	default:
		return StateDown
	}
}

// Tunnel is one SD-WAN tunnel. A folded tunnel has TunnelID set and A is the
// end whose TLOC sorts first in it. An unfolded one (no canonical id could be
// formed) has TunnelID "" and A is the reporting end.
type Tunnel struct {
	Tenant   string
	TunnelID string
	A, B     End
	// key is the unfolded row's legacy id; "" on a folded tunnel.
	key string
}

// EndsReported is how many ends reported state.
func (t Tunnel) EndsReported() int {
	n := 0
	if t.A.Reported {
		n++
	}
	if t.B.Reported {
		n++
	}
	return n
}

// State is up | down | disagree over the reported ends.
func (t Tunnel) State() string {
	a, b := t.A.State(), t.B.State()
	switch {
	case a != "" && b != "" && a != b:
		return StateDisagree
	case a == StateDown || b == StateDown:
		return StateDown
	default:
		return StateUp
	}
}

// Status is the legacy up | down: down if any reporting end says down, so the
// widgets that count up/down keep reading a disagreeing tunnel as down.
func (t Tunnel) Status() string {
	if t.State() == StateUp {
		return StateUp
	}
	return StateDown
}

// ID is the row id: the tunnel id plus a short tenant digest (two tenants'
// identical tunnels stay distinct ids), or the legacy per-end id when unfolded.
func (t Tunnel) ID() string {
	if t.TunnelID == "" {
		return t.key
	}
	sum := sha256.Sum256([]byte(t.Tenant))
	return "sdwan|" + t.TunnelID + "|" + hex.EncodeToString(sum[:6])
}

// FoldInput is what the reconcile cycle has: every device's tenant, the
// published overlay facts and the overlay inference's system-ip owners.
type FoldInput struct {
	DevTenant map[string]string                        // device id → normalised tenant
	Facts     map[string]collectors.OverlayDeviceFacts // device id → facts
	SystemIPs map[string]map[string]string             // tenant → system-ip → device id
}

// FoldStats says what the fold could not place, for the log.
type FoldStats struct {
	Folded    int // tunnels with a canonical id
	Unfolded  int // rows kept per end (no canonical id)
	Conflicts int // a second device claimed an end another device already reported
	NoTenant  int // facts from a device the inventory does not know
}

// Fold builds tenant → tunnels. Deterministic for a given input.
func Fold(in FoldInput) (map[string][]Tunnel, FoldStats) {
	var st FoldStats
	devs := make([]string, 0, len(in.Facts))
	for id := range in.Facts {
		devs = append(devs, id)
	}
	sort.Strings(devs)
	own := ownSystemIPs(in.SystemIPs)
	type key struct{ tenant, id string }
	folded := map[key]*Tunnel{}
	unfolded := map[key]*Tunnel{}
	for _, dev := range devs {
		tenant, ok := in.DevTenant[dev]
		if !ok {
			st.NoTenant++
			continue
		}
		f := in.Facts[dev]
		src := "snmp"
		if f.Source != "" {
			src = f.Source
		}
		local := normIPv4(f.SystemIP)
		if local == "" {
			local = own[tenant][dev]
		}
		owners := in.SystemIPs[tenant]
		for _, p := range f.Peers {
			peerIP := strings.TrimSpace(p.SystemIP)
			peerAddr := ""
			if len(p.TLOCAddrs) > 0 {
				peerAddr = p.TLOCAddrs[0]
			}
			for _, cp := range p.ColorPairs {
				lc := strings.ToLower(strings.TrimSpace(cp.LocalColor))
				rc := strings.ToLower(strings.TrimSpace(cp.RemoteColor))
				tid := ""
				if local != "" {
					tid = nms.CanonicalTunnelID(local, lc, peerIP, rc)
				}
				if tid == "" {
					k := key{tenant, "sdwan|" + dev + "|" + peerIP + "|" + cp.LocalColor + "|" + cp.RemoteColor}
					t := unfolded[k]
					if t == nil {
						t = &Tunnel{Tenant: tenant, key: k.id,
							A: End{DeviceID: dev, SystemIP: local, Color: lc, Reported: true, Source: src},
							B: End{DeviceID: owners[peerIP], SystemIP: peerIP, Color: rc, Addr: peerAddr}}
						unfolded[k] = t
					}
					t.A.Sessions += cp.Sessions
					t.A.Up += cp.Up
					continue
				}
				k := key{tenant, tid}
				t := folded[k]
				if t == nil {
					t = &Tunnel{Tenant: tenant, TunnelID: tid}
					folded[k] = t
				}
				first, _, _ := strings.Cut(tid, "|")
				rep, other := &t.B, &t.A
				if first == local+"/"+lc {
					rep, other = &t.A, &t.B
				}
				switch {
				case rep.Reported && rep.DeviceID != dev:
					// Devices are walked in sorted order, so the first claim
					// stands and the outcome does not depend on map order.
					st.Conflicts++
					continue
				case !rep.Reported:
					rep.DeviceID, rep.SystemIP, rep.Color, rep.Reported, rep.Source = dev, local, lc, true, src
				}
				rep.Sessions += cp.Sessions
				rep.Up += cp.Up
				if other.SystemIP == "" {
					other.SystemIP, other.Color = normIPv4(peerIP), rc
				}
				if other.DeviceID == "" && !other.Reported {
					other.DeviceID = owners[other.SystemIP]
				}
				if other.Addr == "" {
					other.Addr = peerAddr
				}
			}
		}
	}
	out := map[string][]Tunnel{}
	for k, t := range folded {
		out[k.tenant] = append(out[k.tenant], *t)
		st.Folded++
	}
	for k, t := range unfolded {
		out[k.tenant] = append(out[k.tenant], *t)
		st.Unfolded++
	}
	for tn := range out {
		sortTunnels(out[tn])
	}
	return out, st
}

// ownSystemIPs inverts the overlay's system-ip owners: tenant → device → its
// system-ip, keeping only a device that owns exactly one system-ip.
func ownSystemIPs(owners map[string]map[string]string) map[string]map[string]string {
	out := make(map[string]map[string]string, len(owners))
	for tn, m := range owners {
		inv := map[string]string{}
		dup := map[string]bool{}
		for ip, dev := range m {
			ip = normIPv4(ip)
			if ip == "" {
				continue
			}
			if prev, ok := inv[dev]; ok && prev != ip {
				dup[dev] = true
			}
			inv[dev] = ip
		}
		for dev := range dup {
			delete(inv, dev)
		}
		out[tn] = inv
	}
	return out
}

func normIPv4(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !a.Is4() {
		return ""
	}
	return a.String()
}

// sortTunnels orders worst first (down, disagree, up), then by id.
func sortTunnels(ts []Tunnel) {
	sort.SliceStable(ts, func(i, j int) bool {
		ri, rj := stateRank(ts[i].State()), stateRank(ts[j].State())
		if ri != rj {
			return ri > rj
		}
		if ts[i].Tenant != ts[j].Tenant {
			return ts[i].Tenant < ts[j].Tenant
		}
		return ts[i].ID() < ts[j].ID()
	})
}

func stateRank(s string) int {
	switch s {
	case StateDown:
		return 3
	case StateDisagree:
		return 2
	case StateUp:
		return 1
	}
	return 0
}

// Visible narrows a fold to what the caller may see. A report from a device
// the caller cannot see is dropped and that end is named by its system-ip
// only; a tunnel left with no visible report is dropped. The input is not
// modified.
func Visible(byTenant map[string][]Tunnel, visible map[string]bool) []Tunnel {
	var out []Tunnel
	tenants := make([]string, 0, len(byTenant))
	for tn := range byTenant {
		tenants = append(tenants, tn)
	}
	sort.Strings(tenants)
	for _, tn := range tenants {
		for _, t := range byTenant[tn] {
			t.A, t.B = hideEnd(t.A, visible), hideEnd(t.B, visible)
			if t.EndsReported() == 0 {
				continue
			}
			out = append(out, t)
		}
	}
	sortTunnels(out)
	return out
}

func hideEnd(e End, visible map[string]bool) End {
	if e.DeviceID != "" && !visible[e.DeviceID] {
		e.DeviceID = ""
		e.Reported, e.Sessions, e.Up, e.Source = false, 0, 0, ""
	}
	return e
}

// ── Quality (controller app-route statistics) ───────────────────────────────

// QualityWindow is how far back the quality read looks. vManage app-route
// statistics settle 30 min and arrive in 10-min buckets, so an instant read
// finds nothing; the newest sample in this window is the reading, stamped
// with its own time.
const QualityWindow = 3 * time.Hour

// QualityQuery and AsOfQuery are the two reads. Only the per-tunnel gauges:
// the *_octets_total / *_packets_total series label `tunnel` differently and
// are never joined.
const (
	QualityQuery = `last_over_time({__name__=~"controller_metric_tunnel_(latency_ms|jitter_ms|loss_pct|qoe)"}[3h]) keep_metric_names`
	AsOfQuery    = `tlast_over_time(controller_metric_tunnel_loss_pct[3h])`
)

// Sample is one VictoriaMetrics series value.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// Quality is a tunnel's measured path quality: the worst reading across the
// ends that reported it, as of the OLDER end's newest sample.
type Quality struct {
	LatencyMs float64   `json:"latency_ms"`
	JitterMs  float64   `json:"jitter_ms"`
	LossPct   float64   `json:"loss_pct"`
	QoE       float64   `json:"qoe"`
	AsOf      time.Time `json:"as_of"`
	Ends      int       `json:"ends"`
	Source    string    `json:"source"`
}

type direction struct {
	tenant, tid, reporter string
}

type dirQuality struct {
	lat, jit, loss, qoe     float64
	hasLat, hasJit, hasLoss bool
	hasQoE                  bool
	asOf                    time.Time
}

// QualityIndex is the per-direction readings, keyed by (tenant, tunnel id,
// reporting system-ip).
type QualityIndex struct {
	dirs map[direction]*dirQuality
}

// NewQualityIndex folds the two reads. A series whose labels do not form a
// canonical tunnel id is skipped, never guessed.
func NewQualityIndex(values, asOf []Sample) QualityIndex {
	qi := QualityIndex{dirs: map[direction]*dirQuality{}}
	get := func(l map[string]string) *dirQuality {
		d, ok := seriesDirection(l)
		if !ok {
			return nil
		}
		q := qi.dirs[d]
		if q == nil {
			q = &dirQuality{}
			qi.dirs[d] = q
		}
		return q
	}
	for _, s := range values {
		q := get(s.Labels)
		if q == nil {
			continue
		}
		switch s.Labels["__name__"] {
		case "controller_metric_tunnel_latency_ms":
			q.lat, q.hasLat = s.Value, true
		case "controller_metric_tunnel_jitter_ms":
			q.jit, q.hasJit = s.Value, true
		case "controller_metric_tunnel_loss_pct":
			q.loss, q.hasLoss = s.Value, true
		case "controller_metric_tunnel_qoe":
			q.qoe, q.hasQoE = s.Value, true
		}
	}
	for _, s := range asOf {
		d, ok := seriesDirection(s.Labels)
		if !ok || s.Value <= 0 {
			continue
		}
		if q := qi.dirs[d]; q != nil {
			q.asOf = time.Unix(int64(s.Value), 0).UTC()
		}
	}
	return qi
}

// seriesDirection reads a series' direction: the reporting end is
// controller_device (the reporting system-ip), else an IPv4 `device`.
func seriesDirection(l map[string]string) (direction, bool) {
	rep := normIPv4(l["controller_device"])
	if rep == "" {
		rep = normIPv4(l["device"])
	}
	if rep == "" {
		return direction{}, false
	}
	tid := nms.CanonicalTunnelID(rep, l["local_color"], l["peer"], l["remote_color"])
	if tid == "" {
		return direction{}, false
	}
	return direction{tenant: tenantKey(l["tenant_id"]), tid: tid, reporter: rep}, true
}

// Len is how many directions carry a reading.
func (qi QualityIndex) Len() int { return len(qi.dirs) }

// For returns the tunnel's quality from the directions reported by an end the
// caller can see (DeviceID set after Visible), or nil when there is none.
func (qi QualityIndex) For(t Tunnel) *Quality {
	if t.TunnelID == "" || len(qi.dirs) == 0 {
		return nil
	}
	var out *Quality
	for _, e := range []End{t.A, t.B} {
		if e.DeviceID == "" || e.SystemIP == "" {
			continue
		}
		q := qi.dirs[direction{tenant: tenantKey(t.Tenant), tid: t.TunnelID, reporter: e.SystemIP}]
		if q == nil || !(q.hasLat || q.hasJit || q.hasLoss || q.hasQoE) {
			continue
		}
		if out == nil {
			out = &Quality{Source: "controller_statistics", AsOf: q.asOf, QoE: -1}
		}
		out.Ends++
		if q.hasLat && q.lat > out.LatencyMs {
			out.LatencyMs = q.lat
		}
		if q.hasJit && q.jit > out.JitterMs {
			out.JitterMs = q.jit
		}
		if q.hasLoss && q.loss > out.LossPct {
			out.LossPct = q.loss
		}
		if q.hasQoE && (out.QoE < 0 || q.qoe < out.QoE) {
			out.QoE = q.qoe
		}
		if !q.asOf.IsZero() && (out.AsOf.IsZero() || q.asOf.Before(out.AsOf)) {
			out.AsOf = q.asOf
		}
	}
	if out != nil && out.QoE < 0 {
		out.QoE = 0
	}
	return out
}

// tenantKey is the tenant spelling every join compares: lower-cased, and ""
// is the platform realm, as the engine and the series stamp it.
func tenantKey(t string) string { return owner.Of(t) }

// ── Cases (open correlation objects) ────────────────────────────────────────

// OpenObject is one open correlation object's id, tier, tenant and the PATH
// entities it names (corr_current.affected.paths).
type OpenObject struct {
	ID        string
	Tier      string
	Tenant    string
	CreatedAt time.Time
	Paths     []string
}

// Case is the open object a tunnel is a node of.
type Case struct {
	ID       string `json:"id"`
	Tier     string `json:"tier"`
	EntityID string `json:"entity_id"`
}

// CaseIndex maps (tenant, tunnel id) to the open object naming it.
type CaseIndex struct {
	by map[direction]Case
	at map[direction]time.Time
}

// NewCaseIndex indexes open objects by every tunnel they name: the engine's
// controller lane binds `<tid>@<controller instance>` and the trap lane the
// bare `<tid>`, so both spellings match. When two objects name one tunnel the
// newest wins, then the smaller id, so the answer never depends on row order.
func NewCaseIndex(objs []OpenObject) CaseIndex {
	ci := CaseIndex{by: map[direction]Case{}, at: map[direction]time.Time{}}
	for _, o := range objs {
		for _, p := range o.Paths {
			base, _, _ := strings.Cut(p, "@")
			if !strings.Contains(base, "|") {
				continue // a device-id path is not a tunnel
			}
			k := direction{tenant: tenantKey(o.Tenant), tid: base}
			prev, ok := ci.by[k]
			if ok {
				pa := ci.at[k]
				if pa.After(o.CreatedAt) || (pa.Equal(o.CreatedAt) && prev.ID <= o.ID) {
					continue
				}
			}
			ci.by[k] = Case{ID: o.ID, Tier: o.Tier, EntityID: p}
			ci.at[k] = o.CreatedAt
		}
	}
	return ci
}

// For returns the tunnel's open case, or nil.
func (ci CaseIndex) For(t Tunnel) *Case {
	if t.TunnelID == "" {
		return nil
	}
	c, ok := ci.by[direction{tenant: tenantKey(t.Tenant), tid: t.TunnelID}]
	if !ok {
		return nil
	}
	return &c
}
