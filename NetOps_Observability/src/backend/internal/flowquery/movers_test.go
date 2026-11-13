// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"strings"
	"testing"
	"time"
)

func TestParseMoversBy(t *testing.T) {
	for v, want := range map[string]MoversBy{"": ByTalker, "talker": ByTalker, "APP": ByApp, " port ": ByPort} {
		if got, err := ParseMoversBy(v); err != nil || got != want {
			t.Errorf("ParseMoversBy(%q) = %q, %v", v, got, err)
		}
	}
	for _, v := range []string{"host", "talker;", "1"} {
		if _, err := ParseMoversBy(v); err == nil {
			t.Errorf("ParseMoversBy(%q) accepted", v)
		}
	}
}

func TestMoversSQLShape(t *testing.T) {
	w := Window{From: time.Unix(1794549600, 0).UTC(), To: time.Unix(1794553200, 0).UTC()}
	l := Link{Exporter: "10.1.0.1", IfIndex: 12}
	scope := " AND (tenant_id = 'acme')"
	talker := MoversSQL(l, DirIn, w, ByTalker, scope, 10)
	for _, want := range []string{
		"arrayJoin(arrayDistinct([src_addr, dst_addr])) AS k",
		"WHERE ts >= toDateTime64(1794546000, 3, 'UTC') AND ts < toDateTime64(1794553200, 3, 'UTC') AND sampler_address = '10.1.0.1' AND in_if = 12 AND (tenant_id = 'acme')",
		"ORDER BY abs(toInt64(cur_b) - toInt64(prev_b)) DESC, k",
		"LIMIT 10",
	} {
		if !strings.Contains(talker, want) {
			t.Errorf("talker SQL missing %q:\n%s", want, talker)
		}
	}
	port := MoversSQL(l, DirBoth, w, ByPort, scope, 10)
	if !strings.Contains(port, "concat(toString(proto), '/', toString(least(src_port, dst_port))) AS k") ||
		!strings.Contains(port, "AND least(src_port, dst_port) > 0") || !strings.Contains(port, "(in_if = 12 OR out_if = 12)") {
		t.Errorf("port SQL:\n%s", port)
	}
	app := MoversSQL(l, DirOut, w, ByApp, scope, 10)
	if !strings.Contains(app, "GROUP BY d, s, xi, xn") || !strings.Contains(app, "LIMIT 1000") || !strings.Contains(app, "out_if = 12") {
		t.Errorf("app SQL:\n%s", app)
	}
	tot := MoverTotalsSQL(l, DirBoth, w, scope)
	for name, sql := range map[string]string{"talker": talker, "port": port, "app": app, "totals": tot} {
		if m := forbiddenAlias.FindString(sql); m != "" {
			t.Errorf("%s: %q shadows a column:\n%s", name, m, sql)
		}
	}
}

func TestBuildMoversStepChange(t *testing.T) {
	got := BuildMovers([]KeyBytes{
		{Key: "198.51.100.1", Cur: 400, Prev: 100}, // step change: +300 %
		{Key: "198.51.100.2", Cur: 0, Prev: 250},   // gone
		{Key: "198.51.100.3", Cur: 90, Prev: 0},    // new
		{Key: "198.51.100.4", Cur: 102, Prev: 100}, // +2 %: same
		{Key: "198.51.100.5", Cur: 50, Prev: 100},  // −50 %
		{Key: "198.51.100.6", Cur: 0, Prev: 0},     // nothing: dropped
	}, true, 10)
	if len(got) != 5 {
		t.Fatalf("movers = %+v", got)
	}
	order := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.5", "198.51.100.4"}
	for i, k := range order {
		if got[i].Key != k {
			t.Fatalf("rank %d = %s, want %s (all: %+v)", i, got[i].Key, k, got)
		}
	}
	step := got[0]
	if step.Status != MoverUp || *step.Change != 3 || *step.Delta != 300 || *step.PrevBytes != 100 || step.Bytes != 400 {
		t.Errorf("step change = %+v", step)
	}
	if got[1].Status != MoverGone || *got[1].Change != -1 {
		t.Errorf("gone = %+v", got[1])
	}
	if got[2].Status != MoverNew || got[2].Change != nil {
		t.Errorf("new = %+v (no change ratio from zero)", got[2])
	}
	if got[3].Status != MoverDown || *got[3].Change != -0.5 {
		t.Errorf("down = %+v", got[3])
	}
	if got[4].Status != MoverSame {
		t.Errorf("same = %+v", got[4])
	}
	if lim := BuildMovers([]KeyBytes{{"a", 1, 0}, {"b", 2, 0}, {"c", 3, 0}}, true, 2); len(lim) != 2 || lim[0].Key != "c" {
		t.Errorf("limit/rank = %+v", lim)
	}
}

func TestBuildMoversWithoutAPreviousWindow(t *testing.T) {
	got := BuildMovers([]KeyBytes{{"a", 10, 999}, {"b", 30, 0}}, false, 10)
	if len(got) != 2 || got[0].Key != "b" {
		t.Fatalf("unknown previous ranks by volume: %+v", got)
	}
	for _, m := range got {
		if m.Status != MoverNoPrevious || m.PrevBytes != nil || m.Delta != nil || m.Change != nil {
			t.Errorf("a previous figure leaked past retention: %+v", m)
		}
	}
}
