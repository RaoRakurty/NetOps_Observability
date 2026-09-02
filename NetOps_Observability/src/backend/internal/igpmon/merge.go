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
	LSDB       bool `json:"lsdb"`
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
	// Timeline is the window's events for this adjacency, NEWEST FIRST.
	Timeline []Event `json:"timeline"`
}

// adjKey identifies an adjacency across the two sources. The parsers and the
// series agree on the neighbour vocabulary — IS-IS system-id for IS-IS
// (canon-tags isis_neighbor vs the syslog rule's xxxx.xxxx.xxxx capture), the
// neighbour address for OSPF (ospfNbrTable index vs %OSPF-5-ADJCHG's Nbr) — so a
// plain (device, peer) key is a real join and not a guess.
type adjKey struct{ device, peer string }

// MergeAdjacencies joins live samples and windowed events into the per-
// adjacency view, sorted by (device, peer) and each timeline newest-first.
func MergeAdjacencies(live []LiveAdj, events []Event, capTimeline int) []Adjacency {
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
