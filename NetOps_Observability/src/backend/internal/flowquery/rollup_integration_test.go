// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build integration

package flowquery

// rollup_integration_test.go — tracker 401 against a REAL ClickHouse (the
// pinned 24.8 image; see flowquery_integration_test.go for how to run it).
//
// It proves what only a server can:
//   - the rollup statement is accepted and the link figures read from the
//     rollup are IDENTICAL to the ones read from raw records — links, coverage
//     and series, current and previous window, to the byte;
//   - a long flow is spread across the minutes it covered, in parts that add up
//     exactly, and a flow with no duration stays in its received minute;
//   - one exporter's observation domains stay apart in storage and are counted;
//   - rollup rows never mix tenants, even when two tenants share one exporter
//     address and the app-layer clause is missing (the row policy alone holds);
//   - a declared sampling rate multiplies only its owner's records that
//     reported no rate.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

type durRec struct {
	flowRec
	odid       int
	start, end time.Time
}

// longFlows adds records with a flow duration and observation domains to the
// corpus. All are acme's, on 10.0.0.2 (an exporter the base corpus does not use).
func longFlows(t0 time.Time) []durRec {
	base := flowRec{tenant: "acme", exporter: "10.0.0.2", src: "192.0.2.40", dst: "198.51.100.40", srcPort: 40100, dstPort: 443, proto: 6, inIf: 30, outIf: 31, status: "not_reported_1to1"}
	r := func(odid, bytes int, recv time.Time, dur time.Duration) durRec {
		f := base
		f.ts, f.bytes, f.packets = recv, bytes, bytes/100
		d := durRec{flowRec: f, odid: odid}
		if dur > 0 {
			d.start, d.end = recv.Add(-dur).Add(-17*time.Second), recv.Add(-17*time.Second) // an exporter clock 17 s behind: only the duration counts
		}
		return d
	}
	return []durRec{
		// 600 B received at :10:30 having lasted 5 minutes → minutes 5..10:
		// 30 s, 60, 60, 60, 60, 30 s → 60, 120, 120, 120, 120, 60 B.
		r(1, 600, t0.Add(10*time.Minute+30*time.Second), 5*time.Minute),
		// Same link, a second observation domain, no duration: whole in :20.
		r(2, 1000, t0.Add(20*time.Minute+15*time.Second), 0),
		// A flow received INSIDE the window but begun before it: only the part
		// at or after t0 counts in the current window, the rest in the previous.
		r(1, 120, t0.Add(1*time.Minute+30*time.Second), 3*time.Minute),
	}
}

func loadLongFlows(t *testing.T, c chTest, t0 time.Time) {
	t.Helper()
	var b strings.Builder
	b.WriteString("INSERT INTO netops.flows (ts, sampler_address, odid, src_addr, dst_addr, src_port, dst_port, proto, bytes, packets, in_if, out_if, sampling_rate, flow_type, tenant_id, sampling_status, flow_start, flow_end) FORMAT JSONEachRow\n")
	for _, r := range longFlows(t0) {
		row := map[string]any{
			"ts": r.ts.UTC().Format("2006-01-02 15:04:05.000"), "sampler_address": r.exporter, "odid": r.odid, "src_addr": r.src, "dst_addr": r.dst,
			"src_port": r.srcPort, "dst_port": r.dstPort, "proto": r.proto, "bytes": r.bytes, "packets": r.packets,
			"in_if": r.inIf, "out_if": r.outIf, "sampling_rate": r.rate, "flow_type": "ipfix", "tenant_id": r.tenant, "sampling_status": r.status,
		}
		if !r.start.IsZero() {
			row["flow_start"], row["flow_end"] = r.start.UTC().Format("2006-01-02 15:04:05.000"), r.end.UTC().Format("2006-01-02 15:04:05.000")
		}
		line, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	// A globex record on the SHARED exporter 10.0.0.1 that reports no rate: an
	// acme declaration for 10.0.0.1 must never multiply it.
	b.WriteString(`{"ts":"` + t0.Add(7*time.Minute+30*time.Second).UTC().Format("2006-01-02 15:04:05.000") + `","sampler_address":"10.0.0.1","src_addr":"10.9.9.1","dst_addr":"10.8.8.1","src_port":1,"dst_port":2,"proto":6,"bytes":500,"packets":5,"in_if":12,"out_if":20,"sampling_rate":0,"flow_type":"ipfix","tenant_id":"globex","sampling_status":"not_reported_1to1"}` + "\n")
	c.exec(t, "", b.String())
}

// loadRollup recreates netops.flow_iface_1m from init.sql and rolls every
// record of the corpus into it, the way the Roller does (platform scope).
func loadRollup(t *testing.T, c chTest, t0 time.Time) Source {
	t.Helper()
	c.exec(t, "", "DROP ROW POLICY IF EXISTS tenant_iso_flow_iface_1m ON netops.flow_iface_1m")
	c.exec(t, "", "DROP TABLE IF EXISTS netops.flow_iface_1m")
	for _, st := range schemaStatements(t, "flow_iface_1m") {
		c.exec(t, "", st)
	}
	from, to := t0.Add(-2*time.Hour), t0.Add(3*time.Hour)
	c.exec(t, "__all__", RollupInsertSQL(from, to, "", 1))
	return Source{RollupLo: from, RollupHi: to, PlatformSig: PlatformSignature("")}
}

func setup(t *testing.T) (chTest, time.Time, Source) {
	c := chFromEnv(t)
	t0 := testT0()
	loadCorpus(t, c, t0)
	loadLongFlows(t, c, t0)
	return c, t0, loadRollup(t, c, t0)
}

func keyed(rows []map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, r := range rows {
		out[fmt.Sprintf("%s|%s|%v", Str(r["tid"]), Str(r["exporter"]), Num(r["ifx"]))] = r
	}
	return out
}

// The rollup and raw records give the same answer, field by field.
func TestIntegrationRollupEqualsRaw(t *testing.T) {
	c, t0, roll := setup(t)
	w := Window{From: t0, To: t0.Add(time.Hour), Explicit: true}
	for _, scope := range []string{"__all__", "acme"} {
		app := ""
		if scope == "acme" {
			app = " AND (tenant_id = 'acme' OR sampler_address IN ('10.0.0.1', '10.0.0.2', '10.0.0.3'))"
		}
		rawSrc := Source{RawScope: app}
		rollSrc := roll
		rollSrc.RawScope, rollSrc.RollupScope = app, app
		raw := keyed(c.rows(t, scope, LinksSourceSQL(w, rawSrc, 100)))
		got := keyed(c.rows(t, scope, LinksSourceSQL(w, rollSrc, 100)))
		if len(raw) == 0 || len(raw) != len(got) {
			t.Fatalf("%s: raw %d links, rollup %d", scope, len(raw), len(got))
		}
		for k, r := range raw {
			g := got[k]
			for _, f := range []string{"in_b", "out_b", "prev_in_b", "prev_out_b", "in_p", "out_p", "fl", "doms"} {
				if Num(r[f]) != Num(g[f]) {
					t.Errorf("%s %s %s: raw %v rollup %v", scope, k, f, r[f], g[f])
				}
			}
		}
		rc := ParseCoverage(c.rows(t, scope, CoverageSourceSQL(w, rawSrc, nil)))
		gc := ParseCoverage(c.rows(t, scope, CoverageSourceSQL(w, rollSrc, nil)))
		if len(rc) == 0 || fmt.Sprint(rc) != fmt.Sprint(gc) {
			t.Errorf("%s coverage differs:\nraw    %v\nrollup %v", scope, rc, gc)
		}
	}
	// The base corpus figures are unchanged by the new placement (no durations).
	acme := keyed(c.rows(t, "acme", LinksSourceSQL(w, Source{RawScope: " AND (tenant_id = 'acme')", RollupScope: " AND (tenant_id = 'acme')", RollupLo: roll.RollupLo, RollupHi: roll.RollupHi, PlatformSig: roll.PlatformSig}, 100)))
	if l := acme["acme|10.0.0.1|12"]; Num(l["in_b"]) != 24000 || Num(l["out_b"]) != 6000 || Num(l["prev_in_b"]) != 6000 || Num(l["fl"]) != 66 {
		t.Errorf("acme 10.0.0.1|12 = %v", l)
	}
}

// A long flow is spread across the minutes it covered; a flow with no duration
// stays whole in its received minute; the parts add up exactly; raw and rollup
// agree minute by minute.
func TestIntegrationLongFlowIsSpreadAcrossMinutes(t *testing.T) {
	c, t0, roll := setup(t)
	l := Link{Exporter: "10.0.0.2", IfIndex: 30}
	scope := " AND (tenant_id = 'acme')"
	for name, src := range map[string]Source{
		"raw":    {RawScope: scope},
		"rollup": {RawScope: scope, RollupScope: scope, RollupLo: roll.RollupLo, RollupHi: roll.RollupHi, PlatformSig: roll.PlatformSig},
	} {
		rows := c.rows(t, "acme", SeriesSourceSQL(l, t0, t0.Add(time.Hour), 60, src))
		b := BuildSeries(rows, t0, t0.Add(time.Hour), 60, time.Now(), Coverage{Flows: 1})
		want := map[int]float64{0: 40, 1: 20, 5: 60, 6: 120, 7: 120, 8: 120, 9: 120, 10: 60, 20: 1000}
		var sum float64
		for i, v := range b.InBytes {
			sum += v
			if v != want[i] {
				t.Errorf("%s minute %d: in %v, want %v", name, i, v, want[i])
			}
		}
		// 600 + 1000 + the 120 B flow's part inside the window: it covered
		// 23:58:30–00:01:30, so 20 / 40 / 40 / 20 B, and 60 B fall inside.
		if sum != 1660 {
			t.Errorf("%s: window total %v, want 1660", name, sum)
		}
	}
	// The 120 B flow's first 60 B fall in the PREVIOUS window — counted there,
	// never twice.
	w := Window{From: t0, To: t0.Add(time.Hour), Explicit: true}
	got := keyed(c.rows(t, "acme", LinksSourceSQL(w, Source{RawScope: scope}, 100)))
	if l := got["acme|10.0.0.2|30"]; Num(l["in_b"]) != 1660 || Num(l["prev_in_b"]) != 60 || Num(l["fl"]) != 3 {
		t.Errorf("10.0.0.2|30 = %v (want in 1660, prev 60, 3 records)", l)
	}
}

// One exporter's observation domains are stored apart and counted.
func TestIntegrationObservationDomainsStayApart(t *testing.T) {
	c, t0, roll := setup(t)
	rows := c.rows(t, "__all__", `SELECT odid, sum(records) AS rec FROM netops.flow_iface_1m FINAL
 WHERE sampler_address = '10.0.0.2' AND direction = 'in' GROUP BY odid ORDER BY odid FORMAT JSON`)
	if len(rows) != 2 || Num(rows[0]["odid"]) != 1 || Num(rows[0]["rec"]) != 2 || Num(rows[1]["odid"]) != 2 || Num(rows[1]["rec"]) != 1 {
		t.Fatalf("domains in the rollup = %v", rows)
	}
	w := Window{From: t0, To: t0.Add(time.Hour), Explicit: true}
	src := Source{RawScope: " AND (tenant_id = 'acme')", RollupScope: " AND (tenant_id = 'acme')", RollupLo: roll.RollupLo, RollupHi: roll.RollupHi, PlatformSig: roll.PlatformSig}
	cov := ParseCoverage(c.rows(t, "acme", CoverageSourceSQL(w, src, []string{"10.0.0.2"})))
	if d := cov[CovKey{"acme", "10.0.0.2"}].Domains; d != 2 {
		t.Errorf("coverage domains = %v, want 2", d)
	}
}

// Rollup rows never mix tenants: under acme's scope with NO app-layer clause the
// row policy alone keeps globex's record on the shared exporter out, and the
// All-tenants view keeps the two apart.
func TestIntegrationRollupNeverMergesTenants(t *testing.T) {
	c, t0, roll := setup(t)
	for _, r := range c.rows(t, "acme", "SELECT DISTINCT tenant_id FROM netops.flow_iface_1m FORMAT JSON") {
		if tid := Str(r["tenant_id"]); tid == "globex" {
			t.Fatalf("TENANT LEAK: acme's scope read a globex rollup row")
		}
	}
	w := Window{From: t0, To: t0.Add(time.Hour), Explicit: true}
	src := roll
	for _, r := range c.rows(t, "acme", LinksSourceSQL(w, src, 100)) {
		if Str(r["tid"]) == "globex" || Str(r["if_name"]) == "GLOBEX-SECRET" {
			t.Fatalf("TENANT LEAK under scope acme: %v", r)
		}
	}
	all := keyed(c.rows(t, "__all__", LinksSourceSQL(w, src, 100)))
	if Num(all["acme|10.0.0.1|12"]["in_b"]) != 24000 || Num(all["globex|10.0.0.1|12"]["in_b"]) != 7777+500 {
		t.Errorf("cross view merged or lost a tenant: acme %v globex %v", all["acme|10.0.0.1|12"], all["globex|10.0.0.1|12"])
	}
}

// A declared rate multiplies only its owner's records that reported no rate —
// never a reported record, never another tenant's on the same exporter.
func TestIntegrationDeclaredSamplingOnlyForTheOwner(t *testing.T) {
	c, t0, roll := setup(t)
	w := Window{From: t0, To: t0.Add(time.Hour), Explicit: true}
	decl := map[DeclKey]uint32{{Tenant: "acme", Exporter: "10.0.0.1"}: 10, {Tenant: "acme", Exporter: "10.0.0.3"}: 1000}
	for name, src := range map[string]Source{
		"raw":    {Declared: decl},
		"rollup": {Declared: decl, RollupLo: roll.RollupLo, RollupHi: roll.RollupHi, PlatformSig: roll.PlatformSig},
	} {
		all := keyed(c.rows(t, "__all__", LinksSourceSQL(w, src, 100)))
		if v := Num(all["acme|10.0.0.1|12"]["in_b"]); v != 240000 {
			t.Errorf("%s: acme's undeclared-rate bytes ×10 = %v, want 240000", name, v)
		}
		// globex: 7777 reported at 1:1 plus its 500 B unreported record, untouched by acme's declaration.
		if v := Num(all["globex|10.0.0.1|12"]["in_b"]); v != 8277 {
			t.Errorf("%s: globex's bytes = %v, want 8277 (an acme declaration leaked onto globex)", name, v)
		}
		// 10.0.0.3 REPORTS 1:100: the reported rate wins over a declaration.
		if v := Num(all["acme|10.0.0.3|5"]["in_b"]); v != 1000 {
			t.Errorf("%s: a reported rate was overridden by a declaration: %v", name, v)
		}
		cov := ParseCoverage(c.rows(t, "__all__", CoverageSourceSQL(w, src, []string{"10.0.0.1"})))
		if a := cov[CovKey{"acme", "10.0.0.1"}]; a.RateDeclared != a.Flows || SamplingOfDeclared(a.Flows, a.RateReported, a.RateDeclared) != SamplingDeclared {
			t.Errorf("%s: acme coverage = %+v, want every record declared", name, a)
		}
		if g := cov[CovKey{"globex", "10.0.0.1"}]; g.RateDeclared != 0 {
			t.Errorf("%s: globex counted as declared: %+v", name, g)
		}
	}
}
