// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package mql

import (
	"strings"
	"testing"
	"time"
)

func TestSelectorEscapesEveryValue(t *testing.T) {
	cases := []struct {
		m    Matcher
		want string
	}{
		{Matcher{"device", "=", []string{"edge-1"}}, `up{device="edge-1"}`},
		{Matcher{"device", "=", []string{`a"b`}}, `up{device="a\"b"}`},
		{Matcher{"device", "=", []string{`a\`}}, `up{device="a\\"}`},
		{Matcher{"device", "=~", []string{"core.1", "edge-2"}}, `up{device=~"core\\.1|edge-2"}`},
		// A "}" / quote break-out attempt stays inside the string literal.
		{Matcher{"device", "=", []string{`x"} or vector(1) #`}}, `up{device="x\"} or vector(1) #"}`},
		{Matcher{"device", "=~", []string{`.*`}}, `up{device=~"\\.\\*"}`},
	}
	for _, c := range cases {
		e, err := Selector("up", c.m)
		if err != nil || e.String() != c.want {
			t.Errorf("Selector(%+v) = %q, %v — want %q", c.m, e.String(), err, c.want)
		}
	}
}

// Every value is exactly one string literal: scanning the output with
// MetricsQL's own escape rules yields no text outside literals except the
// label syntax.
func TestNoValueEscapesItsLiteral(t *testing.T) {
	for _, v := range []string{`"`, `\`, `\"`, `"}`, `\\"} or up{`, "a\nb", `a"b\c`} {
		e, err := Selector("up", Matcher{"device", "=", []string{v}})
		if err != nil {
			t.Fatal(err)
		}
		lits, outside := scan(e.String())
		if len(lits) != 1 || outside != `up{device=}` {
			t.Fatalf("value %q escaped its literal: lits=%q outside=%q", v, lits, outside)
		}
	}
}

func scan(s string) (lits []string, outside string) {
	var b, o strings.Builder
	in := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case in && c == '\\' && i+1 < len(s):
			b.WriteByte(s[i+1])
			i++
		case in && c == '"':
			lits, in = append(lits, b.String()), false
			b.Reset()
		case !in && c == '"':
			in = true
		case in:
			b.WriteByte(c)
		default:
			o.WriteByte(c)
		}
	}
	return lits, o.String()
}

func TestSelectorRejects(t *testing.T) {
	bad := []struct {
		metric string
		m      Matcher
	}{
		{"up}or{", Matcher{"device", "=", []string{"x"}}},
		{"up", Matcher{"de vice", "=", []string{"x"}}},
		{"up", Matcher{"device", "!~", []string{"x"}}},
		{"up", Matcher{"device", "=~", nil}},
		{"up", Matcher{"device", "=", []string{"a", "b"}}},
	}
	for _, b := range bad {
		if _, err := Selector(b.metric, b.m); err == nil {
			t.Errorf("Selector(%q, %+v) accepted", b.metric, b.m)
		}
	}
}

func TestComposedExpressions(t *testing.T) {
	sel, _ := Selector("device_if_in_octets", Matcher{"device", "=~", []string{"edge-1"}})
	r, _ := Range("rate", sel, 5*time.Minute)
	bps, _ := Bin(r, "*", Scalar(8))
	top, _ := TopK(5, bps)
	if got := top.String(); got != `topk(5, (rate(device_if_in_octets{device=~"edge-1"}[5m]) * 8))` {
		t.Fatalf("got %s", got)
	}
	q, _ := QuantileOverTime(0.95, sel, 7*24*time.Hour)
	off, _ := Offset(q, 2*time.Hour)
	if off.String() != `(quantile_over_time(0.95, device_if_in_octets{device=~"edge-1"}[7d]) offset 2h)` {
		t.Fatalf("got %s", off)
	}
	agg, _ := Agg("avg", sel, "device")
	if agg.String() != `avg by (device) (device_if_in_octets{device=~"edge-1"})` {
		t.Fatalf("got %s", agg)
	}
}

func TestClosedVocabularies(t *testing.T) {
	sel, _ := Selector("up")
	if _, err := Range("label_replace", sel, time.Minute); err == nil {
		t.Error("a function outside the range vocabulary must be refused")
	}
	if _, err := Agg("count_values", sel); err == nil {
		t.Error("an aggregation outside the vocabulary must be refused")
	}
	if _, err := Agg("sum", sel, "bad label"); err == nil {
		t.Error("a bad by-label must be refused")
	}
	if _, err := Bin(sel, "or", sel); err == nil {
		t.Error("set operators are not arithmetic")
	}
	if _, err := Cmp(sel, "=~", sel); err == nil {
		t.Error("regex comparison is not a comparison")
	}
	if _, err := TopK(0, sel); err == nil {
		t.Error("k must be positive")
	}
	if !Scalar(func() float64 { var z float64; return z / z }()).IsZero() {
		t.Error("NaN must not render")
	}
	if _, err := QuantileOverTime(1.5, sel, time.Minute); err == nil {
		t.Error("quantile must be in (0,1)")
	}
}

func TestDur(t *testing.T) {
	for d, want := range map[time.Duration]string{30 * time.Second: "30s", 5 * time.Minute: "5m", 2 * time.Hour: "2h",
		7 * 24 * time.Hour: "7d", 90 * time.Second: "90s", 0: "1s"} {
		if got := Dur(d); got != want {
			t.Errorf("Dur(%v) = %s want %s", d, got, want)
		}
	}
}

func TestSubqueryAndGreatest(t *testing.T) {
	sel, _ := Selector("device_if_in_octets")
	r, _ := Range("rate", sel, 5*time.Minute)
	sq, err := Subquery("avg_over_time", r, 2*time.Hour, 5*time.Minute)
	if err != nil || sq.String() != `avg_over_time(rate(device_if_in_octets[5m])[2h:5m])` {
		t.Fatalf("got %s %v", sq, err)
	}
	q, _ := QuantileSubquery(0.95, r, time.Hour, time.Minute)
	if q.String() != `quantile_over_time(0.95, rate(device_if_in_octets[5m])[1h:1m])` {
		t.Fatalf("got %s", q)
	}
	g, _ := Greatest(sel, r)
	if g.String() != `((device_if_in_octets >= rate(device_if_in_octets[5m])) or rate(device_if_in_octets[5m]))` {
		t.Fatalf("got %s", g)
	}
	if _, err := Subquery("avg_over_time", r, time.Hour, 0); err == nil {
		t.Fatal("a zero step must be refused")
	}
}
