// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 13, 6, 30, 0, 0, time.UTC)

func vals(kv ...string) url.Values {
	q := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	return q
}

func TestParseWindow(t *testing.T) {
	for _, c := range []struct {
		name     string
		q        url.Values
		from, to time.Time
		explicit bool
		wantErr  string
	}{
		{"default is one hour", vals(), now.Add(-time.Hour), now, false, ""},
		{"since duration", vals("since", "6h"), now.Add(-6 * time.Hour), now, false, ""},
		{"since seconds", vals("since", "900"), now.Add(-15 * time.Minute), now, false, ""},
		{"since sub-second truncated", vals("since", "10m0.5s"), now.Add(-10 * time.Minute), now, false, ""},
		{"rfc3339", vals("from", "2026-11-13T05:00:00Z", "to", "2026-11-13T06:00:00Z"), now.Add(-90 * time.Minute), now.Add(-30 * time.Minute), true, ""},
		{"rfc3339 offset", vals("from", "2026-11-12T23:00:00-06:00", "to", "2026-11-13T07:00:00+01:00"), now.Add(-90 * time.Minute), now.Add(-30 * time.Minute), true, ""},
		{"unix seconds", vals("from", "1794546000", "to", "1794549600"), time.Unix(1794546000, 0).UTC(), time.Unix(1794549600, 0).UTC(), true, ""},
		{"unix millis", vals("from", "1794546000123", "to", "1794549600999"), time.Unix(1794546000, 0).UTC(), time.Unix(1794549600, 0).UTC(), true, ""},
		{"future to clamps to now", vals("from", "2026-11-13T06:00:00Z", "to", "2026-11-13T09:00:00Z"), now.Add(-30 * time.Minute), now, true, ""},

		{"both forms", vals("since", "1h", "from", "2026-11-13T05:00:00Z", "to", "2026-11-13T06:00:00Z"), time.Time{}, time.Time{}, false, "not both"},
		{"from alone", vals("from", "2026-11-13T05:00:00Z"), time.Time{}, time.Time{}, false, "together"},
		{"to alone", vals("to", "2026-11-13T05:00:00Z"), time.Time{}, time.Time{}, false, "together"},
		{"reversed", vals("from", "2026-11-13T06:00:00Z", "to", "2026-11-13T05:00:00Z"), time.Time{}, time.Time{}, false, "before to"},
		{"entirely future", vals("from", "2026-11-13T07:00:00Z", "to", "2026-11-13T08:00:00Z"), time.Time{}, time.Time{}, false, "before now"},
		{"too short", vals("since", "4m"), time.Time{}, time.Time{}, false, "between"},
		{"too long", vals("since", "721h"), time.Time{}, time.Time{}, false, "between"},
		{"explicit too long", vals("from", "2026-10-01T00:00:00Z", "to", "2026-11-13T00:00:00Z"), time.Time{}, time.Time{}, false, "between"},
		{"negative since", vals("since", "-1h"), time.Time{}, time.Time{}, false, "duration"},
		{"garbage since", vals("since", "1h; DROP TABLE"), time.Time{}, time.Time{}, false, "duration"},
		{"nine digits", vals("from", "179454960", "to", "1794553200"), time.Time{}, time.Time{}, false, "10 digits"},
		{"garbage from", vals("from", "yesterday", "to", "2026-11-13T06:00:00Z"), time.Time{}, time.Time{}, false, "RFC 3339"},
		{"injection in from", vals("from", "2026-11-13T05:00:00Z') OR 1=1 --", "to", "2026-11-13T06:00:00Z"), time.Time{}, time.Time{}, false, "RFC 3339"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, err := ParseWindow(c.q, now, DefaultLimits)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !w.From.Equal(c.from) || !w.To.Equal(c.to) || w.Explicit != c.explicit {
				t.Fatalf("window = %v..%v explicit=%v, want %v..%v explicit=%v", w.From, w.To, w.Explicit, c.from, c.to, c.explicit)
			}
		})
	}
}

func TestWindowPredicatesRenderIntegersOnly(t *testing.T) {
	w := Window{From: time.Unix(1794549600, 0).UTC(), To: time.Unix(1794553200, 0).UTC()}
	if got, want := w.Predicate(), "ts >= toDateTime64(1794549600, 3, 'UTC') AND ts < toDateTime64(1794553200, 3, 'UTC')"; got != want {
		t.Errorf("Predicate = %q, want %q", got, want)
	}
	if got, want := w.ScanPredicate(), "ts >= toDateTime64(1794546000, 3, 'UTC') AND ts < toDateTime64(1794553200, 3, 'UTC')"; got != want {
		t.Errorf("ScanPredicate = %q, want %q", got, want)
	}
	if got, want := w.CurCond(), "ts >= toDateTime64(1794549600, 3, 'UTC')"; got != want {
		t.Errorf("CurCond = %q, want %q", got, want)
	}
}

func TestWindowEchoRetention(t *testing.T) {
	w := Window{From: now.Add(-6*24*time.Hour - time.Hour), To: now.Add(-6 * 24 * time.Hour)}
	e := w.Echo(now, 7)
	if e.StartsBeforeRetention || e.PrevBeforeRetention {
		// From is 6d1h back: inside 7d. Prev starts 6d2h back: inside too.
		t.Fatalf("echo = %+v", e)
	}
	w = Window{From: now.Add(-7*24*time.Hour + 30*time.Minute), To: now.Add(-7*24*time.Hour + 90*time.Minute)}
	e = w.Echo(now, 7)
	if e.StartsBeforeRetention || !e.PrevBeforeRetention {
		t.Fatalf("prev window reaches past 7d, from does not: %+v", e)
	}
	e = w.Echo(now, 0)
	if e.StartsBeforeRetention || e.PrevBeforeRetention {
		t.Fatalf("unknown retention claims nothing: %+v", e)
	}
	if e.Seconds != 3600 || e.From == "" || e.PrevFrom == "" {
		t.Fatalf("echo fields: %+v", e)
	}
}

func TestParseLink(t *testing.T) {
	ok := []struct{ dev, ifx, exp string }{
		{"10.1.0.1", "12", "10.1.0.1"},
		{" 10.1.0.1 ", "4294967294", "10.1.0.1"},
		{"::ffff:10.1.0.1", "1", "10.1.0.1"},
		{"2001:DB8::1", "7", "2001:db8::1"},
	}
	for _, c := range ok {
		l, err := ParseLink(vals("device", c.dev, "if", c.ifx))
		if err != nil || l.Exporter != c.exp {
			t.Errorf("ParseLink(%q,%q) = %+v, %v", c.dev, c.ifx, l, err)
		}
	}
	bad := [][2]string{
		{"", "1"}, {"10.1.0.1", ""}, {"10.1.0.1:2055", "1"}, {"fe80::1%eth0", "1"}, {"host.example", "1"},
		{"10.1.0.1' OR '1'='1", "1"}, {"10.1.0.1", "0"}, {"10.1.0.1", "4294967295"}, {"10.1.0.1", "4294967296"},
		{"10.1.0.1", "-1"}, {"10.1.0.1", "+1"}, {"10.1.0.1", "1 OR 1=1"}, {"10.1.0.1", "0x10"},
	}
	for _, c := range bad {
		if l, err := ParseLink(vals("device", c[0], "if", c[1])); err == nil {
			t.Errorf("ParseLink(%q,%q) = %+v, want an error", c[0], c[1], l)
		}
	}
}

func TestLinkCond(t *testing.T) {
	l := Link{Exporter: "10.1.0.1", IfIndex: 12}
	for d, want := range map[Dir]string{
		DirBoth: "sampler_address = '10.1.0.1' AND (in_if = 12 OR out_if = 12)",
		DirIn:   "sampler_address = '10.1.0.1' AND in_if = 12",
		DirOut:  "sampler_address = '10.1.0.1' AND out_if = 12",
	} {
		if got := l.Cond(d); got != want {
			t.Errorf("Cond(%s) = %q, want %q", d, got, want)
		}
	}
	for _, v := range []string{"", "both", "IN", "out"} {
		if _, err := ParseDir(v); err != nil {
			t.Errorf("ParseDir(%q): %v", v, err)
		}
	}
	if _, err := ParseDir("sideways"); err == nil {
		t.Error("ParseDir accepted sideways")
	}
}

func TestQuoteEscapesBackslashAndQuote(t *testing.T) {
	if got, want := Quote(`a'b\`), `'a\'b\\'`; got != want {
		t.Fatalf("Quote = %s, want %s", got, want)
	}
	if got := QuoteList([]string{"10.1.0.1", "x'y"}); got != `'10.1.0.1', 'x\'y'` {
		t.Fatalf("QuoteList = %s", got)
	}
}

func TestPickStep(t *testing.T) {
	for _, c := range []struct {
		span time.Duration
		req  string
		want int64
		err  bool
	}{
		{time.Hour, "", 60, false},
		{4 * time.Hour, "", 60, false},
		{4*time.Hour + time.Minute, "", 300, false},
		{20 * time.Hour, "", 300, false},
		{24 * time.Hour, "auto", 900, false},
		{7 * 24 * time.Hour, "", 3600, false},
		{30 * 24 * time.Hour, "", 21600, false},
		{time.Hour, "5m", 300, false},
		{time.Hour, "300", 300, false},
		{24 * time.Hour, "1m", 60, false}, // 1440 points ≤ 1500
		{2 * 24 * time.Hour, "1m", 0, true},
		{time.Hour, "2m", 0, true},
		{time.Hour, "90s", 0, true},
		{time.Hour, "1.5s", 0, true},
		{time.Hour, "1h; SELECT 1", 0, true},
		{time.Hour, "-60", 0, true},
	} {
		got, err := PickStep(c.span, c.req)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("PickStep(%v,%q) = %d,%v want %d err=%v", c.span, c.req, got, err, c.want, c.err)
		}
	}
}

func TestSnapWidensToWholeBuckets(t *testing.T) {
	from := time.Date(2026, 11, 13, 5, 7, 30, 0, time.UTC)
	to := time.Date(2026, 11, 13, 6, 7, 30, 0, time.UTC)
	f, tt := Snap(from, to, 300)
	if !f.Equal(time.Date(2026, 11, 13, 5, 5, 0, 0, time.UTC)) || !tt.Equal(time.Date(2026, 11, 13, 6, 10, 0, 0, time.UTC)) {
		t.Fatalf("Snap = %v..%v", f, tt)
	}
	f, tt = Snap(time.Date(2026, 11, 13, 5, 0, 0, 0, time.UTC), time.Date(2026, 11, 13, 6, 0, 0, 0, time.UTC), 3600)
	if !f.Equal(time.Date(2026, 11, 13, 5, 0, 0, 0, time.UTC)) || !tt.Equal(time.Date(2026, 11, 13, 6, 0, 0, 0, time.UTC)) {
		t.Fatalf("aligned window must not move: %v..%v", f, tt)
	}
	f, _ = Snap(time.Date(2026, 11, 13, 5, 0, 0, 0, time.UTC), time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC), 86400)
	if !f.Equal(time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("a day bucket starts at UTC midnight: %v", f)
	}
}

// forbiddenAlias is the code-184 class: an output aliased onto a column name.
var forbiddenAlias = regexp.MustCompile(`(?i)\bAS\s+(bytes|packets|ts|in_if|out_if|sampler_address|tenant_id)\b`)

func TestStatementsNeverAliasOntoAColumn(t *testing.T) {
	w := Window{From: now.Add(-time.Hour), To: now}
	l := Link{Exporter: "10.1.0.1", IfIndex: 12}
	for name, sql := range map[string]string{
		"links":    LinksSQL(w, " AND (tenant_id = 'acme')", 50),
		"coverage": CoverageSQL(w, "", []string{"10.1.0.1"}),
		"series":   SeriesSQL(l, w.From, w.To, 60, ""),
	} {
		if m := forbiddenAlias.FindString(sql); m != "" {
			t.Errorf("%s: %q shadows a column (ClickHouse code 184):\n%s", name, m, sql)
		}
		if strings.Contains(sql, "WITH FILL") {
			t.Errorf("%s: WITH FILL fails on DateTime64 bounds in 24.8 (code 475)", name)
		}
		if !strings.HasSuffix(strings.TrimSpace(sql), "FORMAT JSON") {
			t.Errorf("%s: not FORMAT JSON", name)
		}
	}
}

func TestLinksSQLShape(t *testing.T) {
	w := Window{From: time.Unix(1794549600, 0).UTC(), To: time.Unix(1794553200, 0).UTC()}
	sql := LinksSQL(w, " AND (tenant_id = 'acme')", 50)
	for _, want := range []string{
		"ARRAY JOIN [(in_if, 'in'), (out_if, 'out')] AS d",
		"WHERE ts >= toDateTime64(1794546000, 3, 'UTC') AND ts < toDateTime64(1794553200, 3, 'UTC') AND (tenant_id = 'acme')",
		"AND d.1 NOT IN (0, 4294967295)",
		"GROUP BY tid, exporter, ifx",
		"sumIf(bytes * if(sampling_rate = 0, 1, sampling_rate), d.2 = 'in' AND ts >= toDateTime64(1794549600, 3, 'UTC'))",
		"d.2 = 'in' AND NOT ts >= toDateTime64(1794549600, 3, 'UTC')",
		"ON n.tenant_id = a.tid AND n.exporter_addr = a.exporter AND n.ifindex = a.ifx",
		"LIMIT 50",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("links SQL missing %q:\n%s", want, sql)
		}
	}
	cov := CoverageSQL(w, " AND (tenant_id = 'acme')", []string{"10.1.0.1", "10.1.0.2"})
	if !strings.Contains(cov, "AND sampler_address IN ('10.1.0.1', '10.1.0.2')") || !strings.Contains(cov, "GROUP BY tid, exporter") {
		t.Errorf("coverage SQL:\n%s", cov)
	}
	if strings.Contains(CoverageSQL(w, "", nil), "sampler_address IN") {
		t.Error("an empty exporter list must not render IN ()")
	}
}

func TestSeriesSQLShape(t *testing.T) {
	l := Link{Exporter: "10.1.0.1", IfIndex: 12}
	sql := SeriesSQL(l, time.Unix(1794549600, 0), time.Unix(1794553200, 0), 300, " AND (tenant_id = 'acme')")
	for _, want := range []string{
		"toUnixTimestamp(toStartOfInterval(ts, INTERVAL 300 SECOND)) AS t",
		"sumIf(bytes * if(sampling_rate = 0, 1, sampling_rate), in_if = 12)    AS in_b",
		"sumIf(bytes * if(sampling_rate = 0, 1, sampling_rate), out_if = 12)   AS out_b",
		"AND sampler_address = '10.1.0.1' AND (in_if = 12 OR out_if = 12) AND (tenant_id = 'acme')",
		"GROUP BY t",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("series SQL missing %q:\n%s", want, sql)
		}
	}
}

func TestNumReadsClickHouseJSON(t *testing.T) {
	for v, want := range map[any]float64{"123": 123, float64(4.5): 4.5, "": 0, "x": 0, nil: 0, true: 0} {
		if got := Num(v); got != want {
			t.Errorf("Num(%v) = %v, want %v", v, got, want)
		}
	}
}

func TestExportAndSamplingBasis(t *testing.T) {
	if ExportBasis(100, 0) != Measured || ExportBasis(100, 15) != PartlyExported || ExportBasis(100, 100) != NotExported || ExportBasis(0, 0) != Measured {
		t.Fatal("ExportBasis table")
	}
	for _, c := range []struct {
		fl, rr float64
		want   string
	}{{0, 0, "no_flows"}, {10, 0, "not_reported"}, {10, 10, "reported"}, {10, 3, "mixed"}} {
		if got := SamplingOf(c.fl, c.rr); got != c.want {
			t.Errorf("SamplingOf(%v,%v) = %s, want %s", c.fl, c.rr, got, c.want)
		}
	}
}

func f(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestBuildLinks(t *testing.T) {
	rows := []map[string]any{
		{"tid": "acme", "exporter": "10.1.0.1", "ifx": float64(12), "if_name": "Gi0/0/1", "if_name_basis": "resolved",
			"in_b": "4000", "out_b": "1000", "prev_in_b": "1000", "prev_out_b": "0", "in_p": "40", "out_p": "10", "fl": "7"},
		{"tid": "acme", "exporter": "10.1.0.2", "ifx": float64(3), "if_name": "", "if_name_basis": "absent",
			"in_b": "0", "out_b": "9000", "prev_in_b": "0", "prev_out_b": "500", "in_p": "0", "out_p": "90", "fl": "9"},
		{"tid": "acme", "exporter": "10.1.0.3", "ifx": float64(4294967295), "in_b": "1", "fl": "1"}, // sentinel: dropped
	}
	cov := ParseCoverage([]map[string]any{
		{"tid": "acme", "exporter": "10.1.0.1", "fl": "100", "prev_fl": "80", "fl_rr": "0", "fl_no_in": "15", "fl_no_out": "0", "b_all": "10000", "b_no_in": "1500", "b_no_out": "0"},
		{"tid": "acme", "exporter": "10.1.0.2", "fl": "50", "prev_fl": "0", "fl_rr": "50", "fl_no_in": "50", "fl_no_out": "0", "b_all": "9000", "b_no_in": "9000", "b_no_out": "0"},
	})
	got := BuildLinks(rows, cov, true)
	if len(got) != 2 {
		t.Fatalf("links = %+v", got)
	}
	// Busiest first: 10.1.0.2 carries 9000 (in not exported), 10.1.0.1 carries 5000.
	a, b := got[1], got[0]
	if b.Exporter != "10.1.0.2" || a.Exporter != "10.1.0.1" {
		t.Fatalf("order = %s, %s", got[0].Exporter, got[1].Exporter)
	}
	if f(a.InBytes) != 4000.0 || f(a.OutBytes) != 1000.0 || f(a.PrevInBytes) != 1000.0 || f(a.PrevOutBytes) != 0.0 {
		t.Errorf("a bytes = %v %v %v %v", f(a.InBytes), f(a.OutBytes), f(a.PrevInBytes), f(a.PrevOutBytes))
	}
	if a.InBasis != PartlyExported || a.OutBasis != Measured || f(a.InUnnamedPct) != 15.0 || a.OutUnnamedPct != nil || a.Sampling != "not_reported" {
		t.Errorf("a basis = %+v", a)
	}
	if a.IfName != "Gi0/0/1" || a.IfNameBasis != "resolved" || a.IfIndex != 12 || a.Flows != 7 {
		t.Errorf("a identity = %+v", a)
	}
	if b.InBytes != nil || b.InBasis != NotExported || f(b.OutBytes) != 9000.0 {
		t.Errorf("b: a direction the router does not export is null, not 0: %+v", b)
	}
	if b.PrevOutBytes != nil || b.PrevInBytes != nil {
		t.Errorf("b: no records in the previous window → previous unknown, not 0: %+v", b)
	}
	if b.Sampling != "reported" || b.IfNameBasis != "absent" {
		t.Errorf("b basis = %+v", b)
	}
	// Previous window past retention: no previous figure anywhere.
	for _, r := range BuildLinks(rows, cov, false) {
		if r.PrevInBytes != nil || r.PrevOutBytes != nil {
			t.Errorf("prevKnown=false still gave a previous figure: %+v", r)
		}
	}
	if tot := Totals(cov); tot.Flows != 150 || tot.FlowsRateReported != 50 || tot.Sampling != "mixed" || tot.BucketTime != "received" {
		t.Errorf("Totals = %+v", tot)
	}
	if ex := Exporters(rows); strings.Join(ex, ",") != "10.1.0.1,10.1.0.2,10.1.0.3" {
		t.Errorf("Exporters = %v", ex)
	}
}

func TestBuildSeriesZeroFills(t *testing.T) {
	from := time.Unix(1794549600, 0).UTC()
	to := from.Add(5 * time.Minute)
	rows := []map[string]any{
		{"t": float64(from.Unix() + 60), "in_b": "100", "out_b": "50", "in_p": "1", "out_p": "1"},
		{"t": float64(from.Unix() + 240), "in_b": "300", "out_b": "0", "in_p": "3", "out_p": "0"},
		{"t": float64(from.Unix() + 90), "in_b": "999"},  // off the grid: ignored
		{"t": float64(from.Unix() + 600), "in_b": "999"}, // past the end: ignored
		{"t": float64(from.Unix() - 60), "in_b": "999"},  // before the start: ignored
	}
	c := Coverage{Flows: 10, RateReported: 10, Bytes: 450}
	b := BuildSeries(rows, from, to, 60, to, c)
	if len(b.T) != 5 || b.T[0] != from.Unix() || b.T[4] != from.Unix()+240 {
		t.Fatalf("t = %v", b.T)
	}
	if got := b.InBytes; got[0] != 0 || got[1] != 100 || got[2] != 0 || got[3] != 0 || got[4] != 300 {
		t.Errorf("in = %v", got)
	}
	if got := b.OutBytes; got[1] != 50 || got[4] != 0 {
		t.Errorf("out = %v", got)
	}
	if !b.LastBucketComplete || b.Basis.Sampling != "reported" || b.InBasis != Measured {
		t.Errorf("body = %+v", b)
	}
	if BuildSeries(rows, from, to, 60, to.Add(-time.Second), c).LastBucketComplete {
		t.Error("a bucket ending after now is not complete")
	}
	nx := BuildSeries(rows, from, to, 60, to, Coverage{Flows: 10, NoIn: 10})
	if nx.InBytes != nil || nx.InPackets != nil || nx.OutBytes == nil || nx.InBasis != NotExported {
		t.Errorf("not-exported direction must be null: %+v", nx)
	}
}
