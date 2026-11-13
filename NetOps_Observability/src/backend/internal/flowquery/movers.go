// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
)

// MoversBy names what "what changed" ranks on one link.
type MoversBy string

const (
	// ByTalker: the hosts at either end of the link's conversations. A
	// conversation's bytes count toward BOTH its hosts, so talker figures do not
	// add up to the link total (the totals come from their own statement).
	ByTalker MoversBy = "talker"
	// ByApp: applications, resolved in Go from the top address pairs by the same
	// catalogue /api/flows/apps uses.
	ByApp MoversBy = "app"
	// ByPort: the likely service end of a conversation, "<proto>/<lower port>"
	// (the flows.go service_port heuristic), named from the IANA tables.
	ByPort MoversBy = "port"
)

// ParseMoversBy reads `by`: talker (default), app or port.
func ParseMoversBy(v string) (MoversBy, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "talker":
		return ByTalker, nil
	case "app":
		return ByApp, nil
	case "port":
		return ByPort, nil
	}
	return "", errors.New("by must be talker, app or port")
}

// MoverAppPairs bounds the address pairs read for app movers (the coverage the
// answer reports, as /api/flows/apps does).
const MoverAppPairs = 1000

// MoversSQL ranks one link's keys by how much they changed against the
// previous window: one scan over [PrevFrom, To), current and previous bytes per
// key, largest absolute change first. For ByApp it returns address pairs
// (d, s, xi, xn) ranked by their larger window, for Go-side resolution.
func MoversSQL(l Link, d Dir, w Window, by MoversBy, scope string, limit int) string {
	cur := w.CurCond()
	where := w.ScanPredicate() + " AND " + l.Cond(d) + scope
	sums := `sumIf(` + ScaledBytes + `, ` + cur + `) AS cur_b,
       sumIf(` + ScaledBytes + `, NOT ` + cur + `) AS prev_b`
	switch by {
	case ByApp:
		return `
SELECT dst_addr AS d, src_addr AS s, exporter_app_id AS xi, exporter_app_name AS xn,
       ` + sums + `
  FROM netops.flows
 WHERE ` + where + `
 GROUP BY d, s, xi, xn
 ORDER BY greatest(cur_b, prev_b) DESC, d, s
 LIMIT ` + strconv.Itoa(MoverAppPairs) + `
 FORMAT JSON`
	case ByPort:
		return `
SELECT concat(toString(proto), '/', toString(least(src_port, dst_port))) AS k,
       ` + sums + `
  FROM netops.flows
 WHERE ` + where + ` AND least(src_port, dst_port) > 0
 GROUP BY k
 ORDER BY abs(toInt64(cur_b) - toInt64(prev_b)) DESC, k
 LIMIT ` + strconv.Itoa(limit) + `
 FORMAT JSON`
	}
	return `
SELECT arrayJoin(arrayDistinct([src_addr, dst_addr])) AS k,
       ` + sums + `
  FROM netops.flows
 WHERE ` + where + `
 GROUP BY k
 ORDER BY abs(toInt64(cur_b) - toInt64(prev_b)) DESC, k
 LIMIT ` + strconv.Itoa(limit) + `
 FORMAT JSON`
}

// MoverTotalsSQL is the link's own total in each window (one row): the base
// the movers are read against, counted once per record.
func MoverTotalsSQL(l Link, d Dir, w Window, scope string) string {
	cur := w.CurCond()
	return `
SELECT sumIf(` + ScaledBytes + `, ` + cur + `) AS cur_b,
       sumIf(` + ScaledBytes + `, NOT ` + cur + `) AS prev_b,
       countIf(` + cur + `) AS fl,
       countIf(` + cur + ` AND ` + RateReported + `) AS fl_rr
  FROM netops.flows
 WHERE ` + w.ScanPredicate() + ` AND ` + l.Cond(d) + scope + `
 FORMAT JSON`
}

// KeyBytes is one key's bytes in the current and the previous window.
type KeyBytes struct {
	Key       string
	Cur, Prev float64
}

// Mover statuses.
const (
	MoverNew        = "new"         // nothing in the previous window
	MoverGone       = "gone"        // nothing in the current window
	MoverUp         = "up"          // grew by 5 % or more
	MoverDown       = "down"        // shrank by 5 % or more
	MoverSame       = "same"        // within ±5 %
	MoverNoPrevious = "no_previous" // the previous window is not known (retention)
)

// SameBand is the relative change below which a key reads "same".
const SameBand = 0.05

// Mover is one row of "what changed".
type Mover struct {
	Key        string   `json:"key"`
	Label      string   `json:"label,omitempty"`
	LabelBasis string   `json:"label_basis,omitempty"`
	Bytes      float64  `json:"bytes"`
	PrevBytes  *float64 `json:"prev_bytes"`
	Delta      *float64 `json:"delta"`
	// Change is (now − before) / before; null when before is zero or unknown.
	Change *float64 `json:"change"`
	Status string   `json:"status"`
}

// BuildMovers classifies and ranks keys: largest absolute change first (or, when
// the previous window is unknown, largest current volume), ties by key, at most
// limit rows.
func BuildMovers(in []KeyBytes, prevKnown bool, limit int) []Mover {
	out := make([]Mover, 0, len(in))
	for _, kb := range in {
		m := Mover{Key: kb.Key, Bytes: kb.Cur}
		if !prevKnown {
			m.Status = MoverNoPrevious
			out = append(out, m)
			continue
		}
		prev, delta := kb.Prev, kb.Cur-kb.Prev
		m.PrevBytes, m.Delta = &prev, &delta
		switch {
		case kb.Cur == 0 && kb.Prev == 0:
			continue // nothing either side: not a mover
		case kb.Prev == 0:
			m.Status = MoverNew
		case kb.Cur == 0:
			m.Status = MoverGone
			c := -1.0
			m.Change = &c
		default:
			c := round4(delta / kb.Prev)
			m.Change = &c
			switch {
			case c >= SameBand:
				m.Status = MoverUp
			case c <= -SameBand:
				m.Status = MoverDown
			default:
				m.Status = MoverSame
			}
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := moverWeight(out[i], prevKnown), moverWeight(out[j], prevKnown)
		if a != b {
			return a > b
		}
		return out[i].Key < out[j].Key
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func moverWeight(m Mover, prevKnown bool) float64 {
	if !prevKnown || m.Delta == nil {
		return m.Bytes
	}
	return math.Abs(*m.Delta)
}

// ParseKeyBytes reads a MoversSQL (talker/port) answer.
func ParseKeyBytes(rows []map[string]any) []KeyBytes {
	out := make([]KeyBytes, 0, len(rows))
	for _, r := range rows {
		out = append(out, KeyBytes{Key: Str(r["k"]), Cur: Num(r["cur_b"]), Prev: Num(r["prev_b"])})
	}
	return out
}

func round4(v float64) float64 { return math.Round(v*10000) / 10000 }
