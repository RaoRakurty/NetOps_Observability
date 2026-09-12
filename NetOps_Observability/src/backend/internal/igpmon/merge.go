// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package igpmon

import (
	"math"
	"sort"
	"strings"
)

// merge.go — the pure join of the two evidence sources.
//
// Events are the HISTORY (what changed, and when). Live series are the PRESENT
// (what the adjacency is right now). Neither substitutes for the other:
//
//   - events with no live series  → history is real, "current" is the last thing
//     we were TOLD, marked state_source="events";
//   - live series with no events  → the adjacency exists and its state is known,
//     but the window contains no change: an EMPTY timeline, not a fabricated one;
//   - neither                     → the adjacency is not reported at all, and
//     coverage says both sources are absent.
//
// Nothing in here invents a value. Every count that cannot be measured is a nil
// pointer that serializes as JSON null.

// Coverage states which evidence classes actually backed the response. The UI
// reads this before it renders anything green: an absent source must never be
// drawn as a healthy one.
type Coverage struct {
	Events     bool `json:"events"`
	LiveSeries bool `json:"live_series"`
	// The four "advanced" depth sources. Each is probed and reported
	// SEPARATELY: on a real deployment they are collected by different
	// transports and fail independently, so one flag for all of them would tell
	// an operator that something is missing without telling them what.
	LSDB    bool `json:"lsdb"`
	Areas   bool `json:"areas"`
	SPFRuns bool `json:"spf_runs"`
	Timers  bool `json:"timers"`
}

// applyAdvanced records which of the four depth probes actually returned data.
// It is the only place those flags are set, so a handler can never report a
// block as covered while rendering its null.
func (c *Coverage) applyAdvanced(a advanced) {
	c.LSDB = a.lsdb.available
	c.Areas = a.areas.available
	c.SPFRuns = a.spf.available
	c.Timers = a.timers.available
}

// Adjacency is one (device, neighbour) adjacency with its evidence.
type Adjacency struct {
	Device string `json:"device"`
	Peer   string `json:"peer,omitempty"`
	IfName string `json:"ifname,omitempty"`
	Level  string `json:"level,omitempty"`
	VRF    string `json:"vrf,omitempty"`
	// CurrentState is the live decoded state when a series exists, else the
	// state of the most recent event, else null.
	CurrentState *string `json:"current_state"`
	// StateSource names WHERE current_state came from: live_series | events | none.
	StateSource string `json:"state_source"`
	// Up is the live verdict only. It is null when no live series exists — an
	// event-only adjacency is not evidence that the adjacency is up NOW.
	Up *bool `json:"up"`
	// LastChange is the newest event's timestamp in the window ("" = none).
	LastChange string `json:"last_change,omitempty"`
	Flaps      int    `json:"flaps"`   // transitions INTO down
	Changes    int    `json:"changes"` // all adjacency-change events
	UpEvents   int    `json:"up_events"`
	DownEvents int    `json:"down_events"`
	// HoldSeconds is the adjacency's remaining hold time where a timer series
	// exists (IS-IS only — OSPF-MIB has no per-neighbour timer). It is a
	// sampled COUNTDOWN, not a configured interval, and is null whenever no
	// such series is collected for this adjacency.
	HoldSeconds *int `json:"hold_seconds"`
	// Timeline is the window's events for this adjacency, NEWEST FIRST.
	Timeline []Event `json:"timeline"`
}

// adjKey identifies an adjacency across the two sources. The parsers and the
// series agree on the neighbour vocabulary — IS-IS system-id for IS-IS
// (canon-tags isis_neighbor vs the syslog rule's xxxx.xxxx.xxxx capture), the
// neighbour address for OSPF (ospfNbrTable index vs %OSPF-5-ADJCHG's Nbr) — so a
// plain (device, peer) key is a real join and not a guess.
type adjKey struct{ device, peer string }

// MergeAdjacencies joins live samples, windowed events and (where collected)
// the per-adjacency hold timer into the per-adjacency view, sorted by
// (device, peer) and each timeline newest-first.
//
// holds may be nil — no timer series is collected — in which case every row's
// HoldSeconds stays null. It is never defaulted to 0: a hold countdown of zero
// means "this adjacency is expiring right now", which is the single most
// alarming value the field can carry and must never be invented.
func MergeAdjacencies(live []LiveAdj, events []Event, holds map[adjKey]int, capTimeline int) []Adjacency {
	byKey := map[adjKey]*Adjacency{}
	order := make([]adjKey, 0, len(live)+len(events))

	get := func(k adjKey) *Adjacency {
		if a, ok := byKey[k]; ok {
			return a
		}
		a := &Adjacency{Device: k.device, Peer: k.peer, StateSource: "none", Timeline: []Event{}}
		byKey[k] = a
		order = append(order, k)
		return a
	}

	for _, l := range live {
		a := get(adjKey{l.Device, l.Peer})
		a.IfName, a.Level, a.VRF = l.IfName, l.Level, l.VRF
		state := l.State
		up := l.Up
		a.CurrentState = &state
		a.Up = &up
		a.StateSource = "live_series"
	}

	// Events arrive newest-first; append in that order so each timeline keeps it.
	for _, e := range events {
		a := get(adjKey{e.Device, e.Peer})
		if a.IfName == "" {
			a.IfName = e.IfName
		}
		a.Changes++
		switch e.State {
		case "down":
			a.DownEvents++
			a.Flaps++
		case "up":
			a.UpEvents++
		}
		if a.LastChange == "" {
			a.LastChange = e.TS
			if a.StateSource == "none" {
				state := e.State
				a.CurrentState = &state
				a.StateSource = "events"
			}
		}
		if capTimeline <= 0 || len(a.Timeline) < capTimeline {
			a.Timeline = append(a.Timeline, e)
		}
	}

	for k, hold := range holds {
		if a, ok := byKey[k]; ok {
			h := hold
			a.HoldSeconds = &h
		}
	}

	out := make([]Adjacency, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Device != out[j].Device {
			return out[i].Device < out[j].Device
		}
		return out[i].Peer < out[j].Peer
	})
	return out
}

// DeviceSummary is the per-device roll-up.
type DeviceSummary struct {
	Device     string `json:"device"`
	Flaps      int    `json:"flaps"`
	Changes    int    `json:"changes"`
	UpEvents   int    `json:"up_events"`
	DownEvents int    `json:"down_events"`
	LastChange string `json:"last_change,omitempty"`
	// Adjacencies / DownAdjacencies are LIVE counts. They are null without a
	// live series: "0 adjacencies down" from a protocol nobody is watching is
	// the single most dangerous number this API could return.
	Adjacencies     *int `json:"adjacencies"`
	DownAdjacencies *int `json:"down_adjacencies"`
	// The advanced depth, per device. Each is null unless its OWN series was
	// collected for THIS device — a fleet where one router streams an LSDB count
	// and the rest do not must show the count on that one row and "not
	// collected" on the others, never 0 on the others.
	LSPCount *int     `json:"lsp_count"`
	SPFRuns  *int     `json:"spf_runs"`
	Areas    []string `json:"areas"`
}

// Summarize rolls events and live samples up per device, worst-first (most
// flaps, then most recent change, then name).
func Summarize(live []LiveAdj, events []Event, liveAvailable bool) []DeviceSummary {
	byDev := map[string]*DeviceSummary{}
	order := make([]string, 0, 16)
	get := func(dev string) *DeviceSummary {
		if d, ok := byDev[dev]; ok {
			return d
		}
		d := &DeviceSummary{Device: dev}
		byDev[dev] = d
		order = append(order, dev)
		return d
	}
	for _, e := range events {
		d := get(e.Device)
		d.Changes++
		switch e.State {
		case "down":
			d.DownEvents++
			d.Flaps++
		case "up":
			d.UpEvents++
		}
		if d.LastChange == "" {
			d.LastChange = e.TS
		}
	}
	if liveAvailable {
		counts := map[string][2]int{} // device → {total, down}
		for _, l := range live {
			c := counts[l.Device]
			c[0]++
			if !l.Up {
				c[1]++
			}
			counts[l.Device] = c
		}
		for dev, c := range counts {
			d := get(dev)
			total, down := c[0], c[1]
			d.Adjacencies = &total
			d.DownAdjacencies = &down
		}
	}
	out := make([]DeviceSummary, 0, len(order))
	for _, dev := range order {
		out = append(out, *byDev[dev])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Flaps != out[j].Flaps {
			return out[i].Flaps > out[j].Flaps
		}
		if out[i].LastChange != out[j].LastChange {
			return out[i].LastChange > out[j].LastChange
		}
		return out[i].Device < out[j].Device
	})
	return out
}

// Stability is the flap-rate verdict, always with the basis it was computed
// from — a bare score is not an explanation.
type Stability struct {
	FlapsPerHour float64 `json:"flaps_per_hour"`
	Score        float64 `json:"score"` // 100 = no flaps in the window
	Basis        string  `json:"basis"`
}

// stabilityScore maps a flap rate onto 0..100. One flap per hour halves the
// score; the curve is monotonic and has no cliff, so a small change in the
// rate never produces a large jump in the number an operator is reading.
func stabilityScore(flaps int, windowSeconds int) Stability {
	hours := float64(windowSeconds) / 3600
	if hours <= 0 {
		hours = 1
	}
	rate := float64(flaps) / hours
	score := 100 / (1 + rate)
	return Stability{
		FlapsPerHour: math.Round(rate*1000) / 1000,
		Score:        math.Round(score*10) / 10,
		Basis:        basisSentence(flaps, hours),
	}
}

func basisSentence(flaps int, hours float64) string {
	var b strings.Builder
	b.WriteString(plural(flaps, "adjacency down-transition", "adjacency down-transitions"))
	b.WriteString(" over ")
	b.WriteString(trimFloat(math.Round(hours*10) / 10))
	b.WriteString("h, counted from syslog/trap adjacency-change events")
	return b.String()
}

// plural renders "<n> <singular|plural>" — small, but it keeps the honest
// basis sentence from reading "1 adjacency down-transitions".
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

// itoa avoids pulling strconv into this pure file for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// trimFloat renders a one-decimal float without a trailing ".0".
func trimFloat(f float64) string {
	s := strings.TrimRight(strings.TrimRight(formatFloat1(f), "0"), ".")
	if s == "" || s == "-" {
		return "0"
	}
	return s
}

func formatFloat1(f float64) string {
	whole := int(f)
	frac := int(math.Round(math.Abs(f-float64(whole)) * 10))
	if frac >= 10 { // rounding carried into the whole part
		if f < 0 {
			whole--
		} else {
			whole++
		}
		frac = 0
	}
	return itoa(whole) + "." + itoa(frac)
}

// AttachAdvanced annotates a roll-up with the per-device advanced depth.
//
// It is separate from Summarize because the two answer to different sources:
// Summarize folds events + adjacency state, while these three come from three
// independently-probed series that each may be absent. Only a device the probe
// actually returned a value FOR is annotated; the rest keep their null, which
// is what makes "collected here, not collected there" visible in one table.
//
// A device that appears ONLY in the advanced maps — it streams an LSDB count
// but produced no adjacency event and no adjacency-state series in the window —
// is APPENDED rather than dropped. It is a device participating in the protocol,
// and silently omitting it would be the same class of error as reporting a zero.
func AttachAdvanced(devices []DeviceSummary, lsdb, spf map[string]int, areas map[string][]string) []DeviceSummary {
	idx := make(map[string]int, len(devices))
	for i, d := range devices {
		idx[d.Device] = i
	}
	extra := make([]string, 0, 4)
	seenExtra := map[string]bool{}
	touch := func(dev string) *DeviceSummary {
		if i, ok := idx[dev]; ok {
			return &devices[i]
		}
		if !seenExtra[dev] {
			seenExtra[dev] = true
			extra = append(extra, dev)
		}
		return nil
	}
	// Pass 1: discover any device known only to the advanced probes, so pass 2
	// can annotate a slice that already contains it (append invalidates the
	// pointers pass 1 would have handed out).
	for _, m := range []map[string]int{lsdb, spf} {
		for dev := range m {
			touch(dev)
		}
	}
	for dev := range areas {
		touch(dev)
	}
	sort.Strings(extra)
	for _, dev := range extra {
		idx[dev] = len(devices)
		devices = append(devices, DeviceSummary{Device: dev})
	}
	for dev, n := range lsdb {
		v := n
		devices[idx[dev]].LSPCount = &v
	}
	for dev, n := range spf {
		v := n
		devices[idx[dev]].SPFRuns = &v
	}
	for dev, list := range areas {
		devices[idx[dev]].Areas = append([]string(nil), list...)
	}
	return devices
}
