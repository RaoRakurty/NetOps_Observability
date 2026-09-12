// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package igpmon

import (
	"context"
	"net/http"
	"sort"
)

// advanced.go — the "IGP advanced" depth beyond adjacency state: the LSP/LSA
// database size, area (or level) membership, the SPF-run counter and the
// adjacency/interface timers.
//
// These four are collected by DIFFERENT transports for the two protocols and,
// on any given deployment, quite possibly by neither:
//
//	IS-IS  gNMI, Nokia SR Linux native — device_isis_lsp_count,
//	       device_isis_area, device_isis_spf_runs_total,
//	       device_isis_adj_hold_seconds.
//	OSPF   SNMP, OSPF-MIB — device_ospf_lsdb_count, device_ospf_area,
//	       device_ospf_spf_runs_total, device_ospf_if_hello_seconds /
//	       device_ospf_if_dead_seconds.
//
// The rule this file exists to enforce is the package rule: each block is
// probed independently and reports its OWN coverage flag, and a block whose
// series is absent is null plus a note — never a zero. Four sources that fail
// separately must be reported separately, because "the LSDB is not collected"
// and "the SPF counter is not collected" are different facts and an operator
// acts differently on each. Collapsing them into one "advanced: unavailable"
// would hide which half of the answer is real.
//
// A FAILED read and an ABSENT series stay distinct in every probe below, for
// the same reason fetchLSDB has always kept them apart: saying "nothing
// collects this" when the metric store merely timed out is a claim the module
// has not earned.

// ── shared probe results ────────────────────────────────────────────────────

// ScopeCount is one count within the protocol's natural scope: an IS-IS level
// ("L2") or an OSPF area ("0.0.0.0"). The scope is carried as an opaque string
// and named by the block's ScopeLabel, so neither protocol's vocabulary is
// bent into the other's.
type ScopeCount struct {
	Scope string `json:"scope"`
	Count int    `json:"count"`
}

// countSet is the outcome of a counting probe (LSDB size, SPF runs).
type countSet struct {
	byDevice  map[string]int
	byScope   map[string]int
	available bool
	note      string
}

// total sums the per-device counts. Only meaningful when available.
func (c countSet) total() int {
	n := 0
	for _, v := range c.byDevice {
		n += v
	}
	return n
}

// scopes renders byScope as a sorted, stable list.
func (c countSet) scopes() []ScopeCount {
	if len(c.byScope) == 0 {
		return nil
	}
	out := make([]ScopeCount, 0, len(c.byScope))
	for k, v := range c.byScope {
		out = append(out, ScopeCount{Scope: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scope < out[j].Scope })
	return out
}

// areaSet is the outcome of the area/level-membership probe.
type areaSet struct {
	byDevice  map[string][]string
	all       []string
	available bool
	note      string
}

// TimerRow is one collected IGP timer. Which fields are populated is decided by
// the protocol, and the ones that are not collected are ABSENT rather than zero:
// IS-IS has a per-adjacency hold countdown and no interface timers; OSPF has
// per-interface hello/dead intervals and — by the shape of OSPF-MIB — no
// per-neighbour timer at all.
type TimerRow struct {
	Device string `json:"device"`
	// Scope names WHAT the timer belongs to: for IS-IS the neighbour system-id,
	// for OSPF the ospfIfTable index (ospfIfIpAddress.ospfAddressLessIf).
	Scope  string `json:"scope"`
	IfName string `json:"ifname,omitempty"`
	Level  string `json:"level,omitempty"`
	// HoldSeconds is the IS-IS remaining hold time: a COUNTDOWN reset by every
	// received hello, not a configured interval. It is sampled, so a mid-range
	// value is normal and only a value trending to zero (or a series that stops)
	// is evidence of anything.
	HoldSeconds *int `json:"hold_seconds,omitempty"`
	// HelloSeconds / DeadSeconds are the OSPF per-interface configured
	// intervals (ospfIfHelloInterval / ospfIfRtrDeadInterval).
	HelloSeconds *int `json:"hello_seconds,omitempty"`
	DeadSeconds  *int `json:"dead_seconds,omitempty"`
}

// timerSet is the outcome of the timer probe.
type timerSet struct {
	rows      []TimerRow
	byAdj     map[adjKey]int // IS-IS only: (device, neighbour) → remaining hold
	available bool
	note      string
}

// ── the response blocks ─────────────────────────────────────────────────────

// LSDBBlock is the link-state database size. LSPCount is null whenever no
// count could be measured — an LSDB whose size nobody is collecting must not
// render as an LSDB of size 0, which reads as "the database is empty", the most
// alarming possible false statement about a healthy IGP.
type LSDBBlock struct {
	LSPCount   *int         `json:"lsp_count"`
	ScopeLabel string       `json:"scope_label,omitempty"`
	ByScope    []ScopeCount `json:"by_scope,omitempty"`
	Note       string       `json:"note,omitempty"`
}

// AreasBlock is area (OSPF) or area-address (IS-IS) membership. Areas is null,
// not [], when nothing collects it: an empty list would say "this router is in
// no area", which is not a thing an operational router can be.
type AreasBlock struct {
	Areas []string `json:"areas"`
	Note  string   `json:"note,omitempty"`
}

// SPFBlock is the SPF-run counter. Runs is a monotonic counter as collected;
// this module reports the value, never a rate — a rate over a window the
// counter may have reset inside is a number nobody can check.
type SPFBlock struct {
	Runs       *int         `json:"runs"`
	ScopeLabel string       `json:"scope_label,omitempty"`
	ByScope    []ScopeCount `json:"by_scope,omitempty"`
	Note       string       `json:"note,omitempty"`
}

// TimersBlock is the adjacency/interface timer set. Rows is null when no timer
// series is collected.
type TimersBlock struct {
	// ScopeKind names what a row's Scope identifies: "adjacency" (IS-IS,
	// per-neighbour) or "interface" (OSPF, per ospfIfTable row).
	ScopeKind string     `json:"scope_kind,omitempty"`
	Rows      []TimerRow `json:"rows"`
	Note      string     `json:"note,omitempty"`
}

// advanced bundles the four probes so a handler runs them once and every
// response reports the same four coverage flags from the same reads.
type advanced struct {
	lsdb   countSet
	areas  areaSet
	spf    countSet
	timers timerSet
}

// notes returns the honest sentence for every ABSENT block, in a fixed order so
// a response body is stable across calls.
func (a advanced) notes() []string {
	out := make([]string, 0, 4)
	for _, n := range []struct {
		ok   bool
		note string
	}{
		{a.lsdb.available, a.lsdb.note},
		{a.areas.available, a.areas.note},
		{a.spf.available, a.spf.note},
		{a.timers.available, a.timers.note},
	} {
		if !n.ok && n.note != "" {
			out = append(out, n.note)
		}
	}
	return out
}

// lsdbBlock renders the LSDB block, honestly, for either outcome.
func (a advanced) lsdbBlock(proto Proto) LSDBBlock {
	if !a.lsdb.available {
		return LSDBBlock{Note: a.lsdb.note}
	}
	total := a.lsdb.total()
	return LSDBBlock{LSPCount: &total, ScopeLabel: proto.ScopeLabel(), ByScope: a.lsdb.scopes()}
}

func (a advanced) areasBlock() AreasBlock {
	if !a.areas.available {
		return AreasBlock{Note: a.areas.note}
	}
	return AreasBlock{Areas: a.areas.all}
}

func (a advanced) spfBlock(proto Proto) SPFBlock {
	if !a.spf.available {
		return SPFBlock{Note: a.spf.note}
	}
	total := a.spf.total()
	return SPFBlock{Runs: &total, ScopeLabel: proto.ScopeLabel(), ByScope: a.spf.scopes()}
}

func (a advanced) timersBlock(proto Proto) TimersBlock {
	if !a.timers.available {
		return TimersBlock{Note: a.timers.note}
	}
	return TimersBlock{ScopeKind: proto.TimerScopeKind(), Rows: a.timers.rows}
}

// ── the probes ──────────────────────────────────────────────────────────────

// fetchAdvanced runs the four depth probes for one protocol over the given
// device identities (empty = every device the caller's filters admit).
//
// They are issued as four independent reads on purpose. Merging them into one
// PromQL expression would make a single absent series indistinguishable from
// four absent series, and this package's entire contract is that each source
// answers for itself.
func (a *API) fetchAdvanced(ctx context.Context, r *http.Request, p Principal, proto Proto, ids []string) advanced {
	return advanced{
		lsdb:   a.fetchLSDB(ctx, r, p, proto, ids),
		areas:  a.fetchAreas(ctx, r, p, proto, ids),
		spf:    a.fetchSPF(ctx, r, p, proto, ids),
		timers: a.fetchTimers(ctx, r, p, proto, ids),
	}
}

// fetchCounts is the shared body of the two counting probes.
//
// `what` names the measurement that is unavailable ("LSDB size") and `kind`
// names the SERIES the disclaimer is about ("LSDB"). They are separate words on
// purpose: the failure sentence has to read as a statement about the read, not
// about the deployment, and "LSDB size unavailable … no LSDB size series
// exists" quietly turns one into the other.
func (a *API) fetchCounts(ctx context.Context, r *http.Request, p Principal, proto Proto,
	metric, what, kind, absent string, ids []string) countSet {
	filters, err := a.metricFilters(r, p)
	if err != nil {
		a.deps.LogWarn("refusing an unscoped metrics read", map[string]any{
			"proto": string(proto), "metric": metric, "tenant": p.Tenant, "subject": p.Subject,
		})
		return countSet{note: what + " unavailable: no device scope could be derived for this principal — " +
			"this is a wiring fault, NOT evidence that no " + kind + " series exists"}
	}
	samples, err := a.deps.VMQuery(ctx, seriesQuery(metric, ids), filters)
	if err != nil {
		return countSet{note: what + " unavailable: the metric store could not be queried — " +
			"this is NOT evidence that no " + kind + " series exists"}
	}
	if len(samples) == 0 {
		return countSet{note: absent}
	}
	byDevice := map[string]int{}
	byScope := map[string]int{}
	scopeLabel := proto.ScopeLabel()
	for _, s := range samples {
		dev := s.Labels["device"]
		if dev == "" {
			// A count that cannot be attributed to a device is not a count OF
			// anything, and summing it would inflate the total silently.
			continue
		}
		byDevice[dev] += int(s.Value)
		if sc := s.Labels[scopeLabel]; sc != "" {
			byScope[sc] += int(s.Value)
		}
	}
	if len(byDevice) == 0 {
		return countSet{note: absent}
	}
	return countSet{byDevice: byDevice, byScope: byScope, available: true}
}

// fetchLSDB probes for the LSDB / LSP-database count.
//
// It is a live probe rather than a hardcoded verdict so the block lights up by
// itself the day a collector starts emitting the series — with no code change
// and, critically, no window in which the UI shows a fabricated count.
func (a *API) fetchLSDB(ctx context.Context, r *http.Request, p Principal, proto Proto, ids []string) countSet {
	return a.fetchCounts(ctx, r, p, proto, proto.LSDBMetric(), "LSDB size", "LSDB", lsdbNote(proto), ids)
}

// fetchSPF probes for the SPF-run counter.
func (a *API) fetchSPF(ctx context.Context, r *http.Request, p Principal, proto Proto, ids []string) countSet {
	return a.fetchCounts(ctx, r, p, proto, proto.SPFMetric(), "SPF-run count", "SPF-run", spfNote(proto), ids)
}

// fetchAreas probes for the area-membership info series. Only the `area` LABEL
// is read: the series value is a constant (1 for the gNMI info series, the
// OSPF-MIB RowStatus for the SNMP one) and carries no information, so treating
// it as a measurement would be reading meaning into a placeholder.
func (a *API) fetchAreas(ctx context.Context, r *http.Request, p Principal, proto Proto, ids []string) areaSet {
	filters, err := a.metricFilters(r, p)
	if err != nil {
		a.deps.LogWarn("refusing an unscoped metrics read", map[string]any{
			"proto": string(proto), "metric": proto.AreaMetric(), "tenant": p.Tenant, "subject": p.Subject,
		})
		return areaSet{note: "area membership unavailable: no device scope could be derived for this principal — " +
			"this is a wiring fault, NOT evidence that no area series exists"}
	}
	samples, err := a.deps.VMQuery(ctx, seriesQuery(proto.AreaMetric(), ids), filters)
	if err != nil {
		return areaSet{note: "area membership unavailable: the metric store could not be queried — " +
			"this is NOT evidence that no area series exists"}
	}
	if len(samples) == 0 {
		return areaSet{note: areaNote(proto)}
	}
	byDevice := map[string][]string{}
	seen := map[string]map[string]bool{}
	all := map[string]bool{}
	for _, s := range samples {
		dev, area := s.Labels["device"], s.Labels["area"]
		if dev == "" || area == "" {
			// A series with no area label names no area; an area with no device
			// cannot be attributed. Neither is membership evidence.
			continue
		}
		if seen[dev] == nil {
			seen[dev] = map[string]bool{}
		}
		if !seen[dev][area] {
			seen[dev][area] = true
			byDevice[dev] = append(byDevice[dev], area)
		}
		all[area] = true
	}
	if len(byDevice) == 0 {
		return areaSet{note: areaNote(proto)}
	}
	for dev := range byDevice {
		sort.Strings(byDevice[dev])
	}
	flat := make([]string, 0, len(all))
	for area := range all {
		flat = append(flat, area)
	}
	sort.Strings(flat)
	return areaSet{byDevice: byDevice, all: flat, available: true}
}

// fetchTimers probes for the protocol's timer series.
//
// The two protocols are genuinely different shapes and are NOT forced into one:
// IS-IS exposes a per-ADJACENCY remaining hold time, OSPF-MIB exposes only
// per-INTERFACE hello/dead intervals (ospfNbrTable has no timer column at all,
// so a per-neighbour OSPF timer is not collectable over SNMP). The block says
// which shape it returned rather than letting a reader assume.
func (a *API) fetchTimers(ctx context.Context, r *http.Request, p Principal, proto Proto, ids []string) timerSet {
	filters, err := a.metricFilters(r, p)
	if err != nil {
		a.deps.LogWarn("refusing an unscoped metrics read", map[string]any{
			"proto": string(proto), "metric": "timers", "tenant": p.Tenant, "subject": p.Subject,
		})
		return timerSet{note: "IGP timers unavailable: no device scope could be derived for this principal — " +
			"this is a wiring fault, NOT evidence that no timer series exists"}
	}
	if proto == ProtoISIS {
		return a.fetchISISTimers(ctx, filters, proto, ids)
	}
	return a.fetchOSPFTimers(ctx, filters, proto, ids)
}

// fetchISISTimers reads device_isis_adj_hold_seconds, one row per adjacency.
func (a *API) fetchISISTimers(ctx context.Context, filters []string, proto Proto, ids []string) timerSet {
	samples, err := a.deps.VMQuery(ctx, seriesQuery(proto.HoldMetric(), ids), filters)
	if err != nil {
		return timerSet{note: timerQueryNote}
	}
	if len(samples) == 0 {
		return timerSet{note: timerNote(proto)}
	}
	rows := make([]TimerRow, 0, len(samples))
	byAdj := map[adjKey]int{}
	for _, s := range samples {
		dev, peer := s.Labels["device"], s.Labels[proto.PeerLabel()]
		if dev == "" {
			continue
		}
		hold := int(s.Value)
		rows = append(rows, TimerRow{
			Device:      dev,
			Scope:       peer,
			IfName:      s.Labels["ifName"],
			Level:       s.Labels["isis_level"],
			HoldSeconds: &hold,
		})
		byAdj[adjKey{dev, peer}] = hold
	}
	if len(rows) == 0 {
		return timerSet{note: timerNote(proto)}
	}
	sortTimerRows(rows)
	return timerSet{rows: rows, byAdj: byAdj, available: true}
}

// fetchOSPFTimers reads the two ospfIfTable interval columns and joins them on
// the interface identity they share. A row with only one of the two is still a
// real row: the missing half stays nil rather than being defaulted.
func (a *API) fetchOSPFTimers(ctx context.Context, filters []string, proto Proto, ids []string) timerSet {
	hello, herr := a.deps.VMQuery(ctx, seriesQuery(proto.HelloMetric(), ids), filters)
	dead, derr := a.deps.VMQuery(ctx, seriesQuery(proto.DeadMetric(), ids), filters)
	if herr != nil || derr != nil {
		return timerSet{note: timerQueryNote}
	}
	if len(hello) == 0 && len(dead) == 0 {
		return timerSet{note: timerNote(proto)}
	}
	type key struct{ device, scope string }
	rows := map[key]*TimerRow{}
	get := func(s Sample) *TimerRow {
		dev := s.Labels["device"]
		if dev == "" {
			return nil
		}
		// The SNMP collector labels an ospfIfTable row by its table index; a
		// device that labels it something else still yields one row per series,
		// it just has an empty scope rather than a wrong one.
		k := key{dev, s.Labels["index"]}
		if row, ok := rows[k]; ok {
			return row
		}
		row := &TimerRow{Device: dev, Scope: k.scope, IfName: s.Labels["ifName"]}
		rows[k] = row
		return row
	}
	for _, s := range hello {
		if row := get(s); row != nil {
			v := int(s.Value)
			row.HelloSeconds = &v
		}
	}
	for _, s := range dead {
		if row := get(s); row != nil {
			v := int(s.Value)
			row.DeadSeconds = &v
		}
	}
	if len(rows) == 0 {
		return timerSet{note: timerNote(proto)}
	}
	out := make([]TimerRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, *row)
	}
	sortTimerRows(out)
	return timerSet{rows: out, available: true}
}

// sortTimerRows gives the rows a stable order: device, then scope.
func sortTimerRows(rows []TimerRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Device != rows[j].Device {
			return rows[i].Device < rows[j].Device
		}
		return rows[i].Scope < rows[j].Scope
	})
}

// ── the honest sentences ────────────────────────────────────────────────────

// timerQueryNote is the shared "the read failed" sentence. It says explicitly
// that a failed read is not a coverage verdict.
const timerQueryNote = "IGP timers unavailable: the metric store could not be queried — " +
	"this is NOT evidence that no timer series exists"

// lsdbNote is the honest sentence for an absent LSDB source.
func lsdbNote(proto Proto) string {
	if proto == ProtoOSPF {
		return "no LSDB/LSA-count series is collected for these devices (" + proto.LSDBMetric() +
			" comes from OSPF-MIB ospfAreaLsaCount and only materializes on a device that answers " +
			"ospfAreaTable); LSDB size is not reported rather than reported as zero"
	}
	return "no LSDB/LSP-count series is collected for these devices (" + proto.LSDBMetric() +
		" comes from the SR Linux IS-IS level statistics over gNMI); LSDB size is not reported " +
		"rather than reported as zero"
}

// spfNote is the honest sentence for an absent SPF counter.
func spfNote(proto Proto) string {
	if proto == ProtoOSPF {
		return "no SPF-run counter is collected for these devices (" + proto.SPFMetric() +
			" comes from OSPF-MIB ospfSpfRuns, which is PER AREA and needs a device that answers ospfAreaTable)"
	}
	return "no SPF-run counter is collected for these devices (" + proto.SPFMetric() +
		" comes from the SR Linux IS-IS level statistics over gNMI)"
}

// areaNote is the honest sentence for absent area membership.
func areaNote(proto Proto) string {
	if proto == ProtoOSPF {
		return "OSPF area membership is not collected for these devices (" + proto.AreaMetric() +
			" comes from OSPF-MIB ospfAreaTable; ospfNbrTable carries no area and the OpenConfig " +
			"ospfv2 gNMI path is unvalidated here)"
	}
	return "IS-IS area addresses are not collected for these devices (" + proto.AreaMetric() +
		" comes from the SR Linux IS-IS instance oper-area-id over gNMI)"
}

// timerNote is the honest sentence for absent timers, and it names the SHAPE
// each protocol's timers would have — a reader should not have to discover from
// an empty panel that OSPF has no per-neighbour timer to collect.
func timerNote(proto Proto) string {
	if proto == ProtoOSPF {
		return "no OSPF timer series is collected for these devices (" + proto.HelloMetric() + " / " +
			proto.DeadMetric() + " come from OSPF-MIB ospfIfTable and are PER INTERFACE — OSPF-MIB's " +
			"ospfNbrTable has no hello or dead column, so a per-neighbour OSPF timer cannot be collected over SNMP)"
	}
	return "no IS-IS timer series is collected for these devices (" + proto.HoldMetric() +
		" is the per-adjacency REMAINING hold time from SR Linux over gNMI — a countdown reset by every " +
		"received hello, not a configured interval)"
}
