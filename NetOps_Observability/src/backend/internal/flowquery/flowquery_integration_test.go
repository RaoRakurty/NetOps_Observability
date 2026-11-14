// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build integration

package flowquery

// flowquery_integration_test.go — the link-level flow statements against a REAL
// ClickHouse (the pinned 24.8 image), with a fixed corpus and exact numbers.
//
// The hermetic tests prove the SQL's shape and the Go shaping. Only a server can
// prove that the statements are accepted (alias shadowing, DateTime64 bounds,
// ARRAY JOIN) and that they ADD UP: a step change reads as exactly +300 %, a
// partly exported direction reads low by exactly the missing share, a sampled
// exporter that reports no rate is labelled, and — the §3a case — two tenants
// behind ONE exporter address are never summed together, with the row policy
// alone holding even when the app-layer clause is missing.
//
// The schema is read from deployment/docker/clickhouse/init.sql (the flows and
// iface_names tables and their row policies), so it cannot drift from what
// ships. Run it against a THROWAWAY server — it drops and recreates those two
// tables:
//
//	docker run -d --rm --name chflows -p 18123:8123 \
//	  -e CLICKHOUSE_USER=drill -e CLICKHOUSE_PASSWORD=drillpw \
//	  -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
//	  -v "$PWD/deployment/docker/clickhouse/custom-settings.xml:/etc/clickhouse-server/config.d/custom-settings.xml:ro" \
//	  --tmpfs /var/lib/clickhouse:rw,size=512m \
//	  clickhouse/clickhouse-server:24.8-alpine@sha256:b002e56ed5c16e224c312527f6fcba7e77216fec5d7a88a7828f59efc614feb5
//	CH_TEST_URL=http://localhost:18123 CH_TEST_USER=drill CH_TEST_PASSWORD=drillpw \
//	  go test -tags=integration ./internal/flowquery/
//
// CI runs exactly this (backend-ci.yml, job clickhouse-integration).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type chTest struct {
	base, user, pass string
}

func chFromEnv(t *testing.T) chTest {
	t.Helper()
	u := os.Getenv("CH_TEST_URL")
	if u == "" {
		t.Skip("CH_TEST_URL not set: this test needs a throwaway ClickHouse (see the file comment)")
	}
	return chTest{base: strings.TrimRight(u, "/"), user: os.Getenv("CH_TEST_USER"), pass: os.Getenv("CH_TEST_PASSWORD")}
}

// exec runs one statement at a tenant scope and returns the body.
func (c chTest) exec(t *testing.T, scope, sql string) []byte {
	t.Helper()
	q := url.Values{}
	if scope != "" {
		q.Set("tenant_scope", scope)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/?"+q.Encode(), strings.NewReader(sql))
	if err != nil {
		t.Fatal(err)
	}
	if c.user != "" {
		req.Header.Set("X-ClickHouse-User", c.user)
		req.Header.Set("X-ClickHouse-Key", c.pass)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clickhouse %d: %s\nSQL:\n%s", resp.StatusCode, b, sql)
	}
	return b
}

func (c chTest) rows(t *testing.T, scope, sql string) []map[string]any {
	t.Helper()
	var out struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(c.exec(t, scope, sql), &out); err != nil {
		t.Fatal(err)
	}
	return out.Data
}

// schemaStatements returns init.sql's CREATE TABLE and CREATE ROW POLICY
// statements for the named tables, verbatim.
func schemaStatements(t *testing.T, tables ...string) []string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(here), "..", "..", "..", "..", "deployment", "docker", "clickhouse", "init.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("init.sql: %v", err)
	}
	var lines []string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "--") {
			continue
		}
		if i := strings.Index(l, " --"); i >= 0 {
			l = l[:i]
		}
		lines = append(lines, l)
	}
	var out []string
	for _, st := range strings.Split(strings.Join(lines, "\n"), ";") {
		s := strings.TrimSpace(st)
		for _, tb := range tables {
			if strings.HasPrefix(s, "CREATE TABLE IF NOT EXISTS netops."+tb+"\n") ||
				strings.HasPrefix(s, "CREATE TABLE IF NOT EXISTS netops."+tb+" ") ||
				(strings.HasPrefix(s, "CREATE ROW POLICY") && strings.Contains(s, " ON netops."+tb+"\n")) {
				out = append(out, s)
			}
		}
	}
	if len(out) != 2*len(tables) {
		t.Fatalf("expected a table and a row policy per table from init.sql, found %d statements", len(out))
	}
	return out
}

type flowRec struct {
	ts               time.Time
	tenant, exporter string
	src, dst         string
	srcPort, dstPort int
	proto            int
	inIf, outIf      uint32
	bytes, packets   int
	rate             int
	status           string
}

// corpus is the fixed scenario set. T0 is an hour boundary; the current window
// is [T0, T0+1h), the previous one [T0-1h, T0).
func corpus(t0 time.Time) []flowRec {
	var out []flowRec
	min := func(m int) time.Duration { return time.Duration(m)*time.Minute + 30*time.Second }
	for m := 0; m < 60; m++ {
		// Step change on acme's link 10.0.0.1|12: 100 B/min before, 400 B/min now.
		out = append(out,
			flowRec{ts: t0.Add(-time.Hour + min(m)), tenant: "acme", exporter: "10.0.0.1", src: "192.0.2.10", dst: "198.51.100.1", srcPort: 40000, dstPort: 443, proto: 6, inIf: 12, outIf: 20, bytes: 100, packets: 1, status: "not_reported_1to1"},
			flowRec{ts: t0.Add(min(m)), tenant: "acme", exporter: "10.0.0.1", src: "192.0.2.10", dst: "198.51.100.1", srcPort: 40000, dstPort: 443, proto: 6, inIf: 12, outIf: 20, bytes: 400, packets: 4, status: "not_reported_1to1"},
		)
	}
	// Partly exported input interface: six records name no in_if (20 % of bytes).
	for m := 0; m < 60; m += 10 {
		out = append(out, flowRec{ts: t0.Add(min(m)), tenant: "acme", exporter: "10.0.0.1", src: "203.0.113.5", dst: "192.0.2.10", srcPort: 53, dstPort: 50000, proto: 17, inIf: 0, outIf: 12, bytes: 1000, packets: 10, status: "not_reported_1to1"})
	}
	// A second tenant behind the SAME exporter address and ifIndex.
	out = append(out, flowRec{ts: t0.Add(min(5)), tenant: "globex", exporter: "10.0.0.1", src: "10.9.9.9", dst: "10.8.8.8", srcPort: 1, dstPort: 2, proto: 6, inIf: 12, outIf: 20, bytes: 7777, packets: 7, status: "reported", rate: 1})
	// An exporter that reports its sampling rate (1:100).
	out = append(out, flowRec{ts: t0.Add(min(15)), tenant: "acme", exporter: "10.0.0.3", src: "192.0.2.20", dst: "198.51.100.2", srcPort: 40001, dstPort: 80, proto: 6, inIf: 5, outIf: 6, bytes: 10, packets: 1, rate: 100, status: "reported"})
	// An untagged record from an exporter nobody owns unambiguously.
	out = append(out, flowRec{ts: t0.Add(min(20)), tenant: "", exporter: "10.0.0.9", src: "192.0.2.30", dst: "198.51.100.3", srcPort: 40002, dstPort: 22, proto: 6, inIf: 7, outIf: 8, bytes: 50, packets: 1, status: "not_reported_1to1"})
	return out
}

func loadCorpus(t *testing.T, c chTest, t0 time.Time) {
	t.Helper()
	c.exec(t, "", "CREATE DATABASE IF NOT EXISTS netops")
	for _, tb := range []string{"flows", "iface_names"} {
		c.exec(t, "", "DROP ROW POLICY IF EXISTS tenant_iso_"+tb+" ON netops."+tb)
		c.exec(t, "", "DROP TABLE IF EXISTS netops."+tb)
	}
	for _, st := range schemaStatements(t, "flows", "iface_names") {
		c.exec(t, "", st)
	}
	var b strings.Builder
	b.WriteString("INSERT INTO netops.flows (ts, sampler_address, src_addr, dst_addr, src_port, dst_port, proto, bytes, packets, in_if, out_if, sampling_rate, flow_type, tenant_id, sampling_status) FORMAT JSONEachRow\n")
	for _, r := range corpus(t0) {
		line, err := json.Marshal(map[string]any{
			"ts": r.ts.UTC().Format("2006-01-02 15:04:05.000"), "sampler_address": r.exporter, "src_addr": r.src, "dst_addr": r.dst,
			"src_port": r.srcPort, "dst_port": r.dstPort, "proto": r.proto, "bytes": r.bytes, "packets": r.packets,
			"in_if": r.inIf, "out_if": r.outIf, "sampling_rate": r.rate, "flow_type": "ipfix", "tenant_id": r.tenant, "sampling_status": r.status,
		})
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	c.exec(t, "", b.String())
	c.exec(t, "", `INSERT INTO netops.iface_names (tenant_id, device_id, exporter_addr, ifindex, ifname) VALUES
		('acme', 'acme-edge', '10.0.0.1', 12, 'Gi0/0/1'),
		('globex', 'globex-edge', '10.0.0.1', 12, 'GLOBEX-SECRET')`)
}

func testT0() time.Time { return time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour) }

func TestIntegrationLinksStepChangePartlyExportedAndSampling(t *testing.T) {
	c := chFromEnv(t)
	t0 := testT0()
	loadCorpus(t, c, t0)
	w := Window{From: t0, To: t0.Add(time.Hour), Explicit: true}
	// The stricter links rule for acme: own stamped rows, or its exporter.
	scope := " AND (tenant_id = 'acme' OR sampler_address IN ('10.0.0.1', '10.0.0.3'))"
	rows := c.rows(t, "acme", LinksSQL(w, scope, 50))
	cov := ParseCoverage(c.rows(t, "acme", CoverageSQL(w, scope, Exporters(rows))))
	links := BuildLinks(rows, cov, true)

	got := map[string]LinkRow{}
	for _, l := range links {
		if l.TenantID != "acme" {
			t.Fatalf("TENANT LEAK: a %q row in acme's links: %+v", l.TenantID, l)
		}
		got[fmt.Sprintf("%s|%d", l.Exporter, l.IfIndex)] = l
	}
	if len(got) != 4 {
		t.Fatalf("links = %+v", links)
	}
	l12 := got["10.0.0.1|12"]
	// 60 × 400 in; 6 × 1000 out (the in_if-less records left on 12); before: 60 × 100 in, nothing out.
	if f(l12.InBytes) != 24000.0 || f(l12.OutBytes) != 6000.0 || f(l12.PrevInBytes) != 6000.0 || f(l12.PrevOutBytes) != 0.0 {
		t.Errorf("10.0.0.1|12 bytes = in %v out %v prev in %v prev out %v", f(l12.InBytes), f(l12.OutBytes), f(l12.PrevInBytes), f(l12.PrevOutBytes))
	}
	if l12.InPackets != 240 || l12.OutPackets != 60 || l12.Flows != 66 {
		t.Errorf("10.0.0.1|12 packets/flows = %v %v %v", l12.InPackets, l12.OutPackets, l12.Flows)
	}
	if l12.IfName != "Gi0/0/1" || l12.IfNameBasis != "resolved" {
		t.Errorf("TENANT LEAK or missing name: %q %q", l12.IfName, l12.IfNameBasis)
	}
	if l12.InBasis != PartlyExported || f(l12.InUnnamedPct) != 20.0 || l12.OutBasis != Measured || l12.Sampling != SamplingNotReported {
		t.Errorf("10.0.0.1|12 basis = %+v", l12)
	}
	l20 := got["10.0.0.1|20"]
	if f(l20.InBytes) != 0.0 || f(l20.OutBytes) != 24000.0 || f(l20.PrevOutBytes) != 6000.0 || l20.IfNameBasis != "absent" {
		t.Errorf("10.0.0.1|20 = %+v", l20)
	}
	// The reported 1:100 rate scales; nothing else does.
	if l5 := got["10.0.0.3|5"]; f(l5.InBytes) != 1000.0 || l5.Sampling != SamplingReported || l5.PrevInBytes != nil {
		t.Errorf("10.0.0.3|5 = %+v (no previous-window records → previous unknown)", l5)
	}
	if _, ok := got["10.0.0.9|7"]; ok {
		t.Error("an untagged record from a non-owned exporter reached the stricter links view")
	}
	if links[0].Exporter != "10.0.0.1" || links[0].IfIndex != 12 {
		t.Errorf("busiest first: %+v", links[0])
	}
	if tot := Totals(cov); tot.Flows != 67 || tot.FlowsRateReported != 1 || tot.Sampling != SamplingMixed {
		t.Errorf("totals = %+v", tot)
	}
}

// The row policy alone holds when the app-layer clause is missing: acme's scope
// never reads globex's record, even on the shared exporter address.
func TestIntegrationRowPolicyAloneNeverMergesTwoTenantsOnOneExporter(t *testing.T) {
	c := chFromEnv(t)
	t0 := testT0()
	loadCorpus(t, c, t0)
	w := Window{From: t0, To: t0.Add(time.Hour), Explicit: true}
	for _, r := range c.rows(t, "acme", LinksSQL(w, "", 50)) {
		if tid := Str(r["tid"]); tid == "globex" || Str(r["if_name"]) == "GLOBEX-SECRET" {
			t.Fatalf("TENANT LEAK under scope acme: %v", r)
		}
		if Str(r["exporter"]) == "10.0.0.1" && Num(r["ifx"]) == 12 && Num(r["in_b"]) != 24000 {
			t.Fatalf("acme's 10.0.0.1|12 summed another tenant's bytes: %v", r)
		}
	}
	// The All-tenants view keeps the two tenants apart, each with its own name.
	seen := map[string]map[string]any{}
	for _, r := range c.rows(t, "__all__", LinksSQL(w, "", 50)) {
		if Str(r["exporter"]) == "10.0.0.1" && Num(r["ifx"]) == 12 {
			seen[Str(r["tid"])] = r
		}
	}
	if len(seen) != 2 || Num(seen["acme"]["in_b"]) != 24000 || Num(seen["globex"]["in_b"]) != 7777 {
		t.Fatalf("cross view merged or lost a tenant: %v", seen)
	}
	if Str(seen["acme"]["if_name"]) != "Gi0/0/1" || Str(seen["globex"]["if_name"]) != "GLOBEX-SECRET" {
		t.Fatalf("names crossed tenants: %v", seen)
	}
}

func TestIntegrationSeriesZeroFilledAndExact(t *testing.T) {
	c := chFromEnv(t)
	t0 := testT0()
	loadCorpus(t, c, t0)
	l := Link{Exporter: "10.0.0.1", IfIndex: 12}
	from, to := Snap(t0, t0.Add(time.Hour), 300)
	scope := " AND (tenant_id = 'acme')"
	rows := c.rows(t, "acme", SeriesSQL(l, from, to, 300, scope))
	cov := ParseCoverage(c.rows(t, "acme", CoverageSQL(Window{From: t0, To: t0.Add(time.Hour)}, scope, []string{l.Exporter})))
	b := BuildSeries(rows, from, to, 300, time.Now(), cov[CovKey{"acme", l.Exporter}])
	if len(b.T) != 12 {
		t.Fatalf("buckets = %d", len(b.T))
	}
	for i := range b.T {
		wantOut := 0.0
		if i%2 == 0 {
			wantOut = 1000 // the in_if-less records at minutes 0, 10, … 50
		}
		if b.InBytes[i] != 2000 || b.OutBytes[i] != wantOut || b.T[i] != t0.Unix()+int64(i)*300 {
			t.Errorf("bucket %d: t=%d in=%v out=%v, want in=2000 out=%v", i, b.T[i], b.InBytes[i], b.OutBytes[i], wantOut)
		}
	}
	if !b.LastBucketComplete || b.InBasis != PartlyExported || b.Basis.Sampling != SamplingNotReported {
		t.Errorf("series basis = %+v", b)
	}
	// An hour of one-minute buckets: 60 points, every one filled.
	rows = c.rows(t, "acme", SeriesSQL(l, t0, t0.Add(time.Hour), 60, scope))
	b = BuildSeries(rows, t0, t0.Add(time.Hour), 60, time.Now(), Coverage{Flows: 1})
	var sum float64
	for _, v := range b.InBytes {
		sum += v
	}
	if len(b.T) != 60 || sum != 24000 {
		t.Errorf("1m series: %d buckets, in total %v, want 60 and 24000", len(b.T), sum)
	}
}

// What changed on acme's 10.0.0.1|12: the talker 192.0.2.10 went from 6000 B
// (60 × 100) to 24000 B (60 × 400) — exactly +300 % — and the DNS server that
// only appears in the current window (6 × 1000 B leaving on 12) is new. The
// port view names 6/443 and 17/53. Totals are counted once per record.
// The Iris flow statements (tracker 406 / N-C4) against the real server: they
// are accepted, they add up to the corpus exactly, the device and interface
// conditions narrow as the page's do, the platform-traffic exclusion removes
// exactly its records, and under acme's scope the row policy keeps globex's
// record on the SHARED exporter out even though the device condition names
// that exporter.
func TestIntegrationToolStatementsExactAndIsolated(t *testing.T) {
	c := chFromEnv(t)
	t0 := testT0()
	loadCorpus(t, c, t0)
	w := Window{From: t0, To: t0.Add(time.Hour), Explicit: true}
	dev := " AND (tenant_id = 'acme' OR sampler_address IN ('10.0.0.1', '10.0.0.3')) AND sampler_address = '10.0.0.1'"

	tot := c.rows(t, "acme", TotalsSQL(w, dev))
	if len(tot) != 1 || Num(tot[0]["bytes_total"]) != 30000 || Num(tot[0]["packets_total"]) != 300 ||
		Num(tot[0]["flows"]) != 66 || Num(tot[0]["sources"]) != 2 || Num(tot[0]["rate_reported"]) != 0 {
		t.Fatalf("device totals = %v, want 30000 B, 300 packets, 66 flows, 2 sources, 0 rate-reported (globex's 7777 B never summed)", tot)
	}
	if got := SamplingOf(Num(tot[0]["flows"]), Num(tot[0]["rate_reported"])); got != SamplingNotReported {
		t.Errorf("sampling basis %q, want not_reported", got)
	}
	ifc := dev + " AND " + Link{Exporter: "10.0.0.1", IfIndex: 12}.IfCond(DirBoth)
	if it := c.rows(t, "acme", TotalsSQL(w, ifc)); Num(it[0]["bytes_total"]) != 30000 || Num(it[0]["flows"]) != 66 {
		t.Errorf("interface 12 (in or out) totals = %v, want every record of the device", it)
	}
	if it := c.rows(t, "acme", TotalsSQL(w, dev+" AND "+Link{Exporter: "10.0.0.1", IfIndex: 20}.IfCond(DirBoth))); Num(it[0]["bytes_total"]) != 24000 {
		t.Errorf("interface 20 totals = %v, want 24000", it)
	}

	talkers := c.rows(t, "acme", TalkersSQL(w, dev, 8))
	if len(talkers) != 2 || Str(talkers[0]["a"]) != "192.0.2.10" || Str(talkers[0]["b"]) != "198.51.100.1" ||
		Num(talkers[0]["bytes_total"]) != 24000 || Num(talkers[1]["bytes_total"]) != 6000 {
		t.Fatalf("talkers = %v, want the two acme pairs, heaviest first", talkers)
	}
	for _, r := range talkers {
		if Str(r["a"]) == "10.8.8.8" || Str(r["b"]) == "10.9.9.9" {
			t.Fatalf("TENANT LEAK: globex's conversation in acme's talkers: %v", r)
		}
	}
	svc := c.rows(t, "acme", ServicesSQL(w, dev, 8))
	if len(svc) != 2 || Num(svc[0]["port"]) != 443 || Num(svc[0]["bytes_total"]) != 24000 || Num(svc[1]["port"]) != 50000 {
		t.Fatalf("services = %v", svc)
	}

	// Correlix's own monitoring traffic (here: 203.0.113.5) is left out exactly.
	plat := dev + " AND NOT (src_addr IN ('203.0.113.5') OR dst_addr IN ('203.0.113.5'))"
	if pt := c.rows(t, "acme", TotalsSQL(w, plat)); Num(pt[0]["bytes_total"]) != 24000 || Num(pt[0]["flows"]) != 60 || Num(pt[0]["sources"]) != 1 {
		t.Errorf("platform-excluded totals = %v, want 24000 B, 60 flows, 1 source", pt)
	}

	// The reported 1:100 rate scales; the record counts as rate-reported.
	if r := c.rows(t, "acme", TotalsSQL(w, " AND sampler_address = '10.0.0.3'")); Num(r[0]["bytes_total"]) != 1000 || Num(r[0]["rate_reported"]) != 1 {
		t.Errorf("rate-reported exporter totals = %v", r)
	}
}

func TestIntegrationMoversStepChangeExact(t *testing.T) {
	c := chFromEnv(t)
	t0 := testT0()
	loadCorpus(t, c, t0)
	w := Window{From: t0, To: t0.Add(time.Hour), Explicit: true}
	l := Link{Exporter: "10.0.0.1", IfIndex: 12}
	scope := " AND (tenant_id = 'acme')"

	tot := c.rows(t, "acme", MoverTotalsSQL(l, DirBoth, w, scope))
	if len(tot) != 1 || Num(tot[0]["cur_b"]) != 30000 || Num(tot[0]["prev_b"]) != 6000 || Num(tot[0]["fl"]) != 66 {
		t.Fatalf("totals = %v, want cur 30000, prev 6000, 66 records", tot)
	}
	talkers := BuildMovers(ParseKeyBytes(c.rows(t, "acme", MoversSQL(l, DirIn, w, ByTalker, scope, 10))), true, 10)
	byKey := map[string]Mover{}
	for _, m := range talkers {
		byKey[m.Key] = m
	}
	step := byKey["192.0.2.10"]
	if step.Status != MoverUp || step.Change == nil || *step.Change != 3 || step.Bytes != 24000 || *step.PrevBytes != 6000 {
		t.Fatalf("talker step change = %+v (all %+v)", step, talkers)
	}
	if _, leaked := byKey["10.9.9.9"]; leaked {
		t.Fatal("TENANT LEAK: globex's host is a mover on acme's link")
	}
	ports := BuildMovers(ParseKeyBytes(c.rows(t, "acme", MoversSQL(l, DirBoth, w, ByPort, scope, 10))), true, 10)
	pk := map[string]Mover{}
	for _, m := range ports {
		pk[m.Key] = m
	}
	if p := pk["6/443"]; p.Status != MoverUp || p.Bytes != 24000 || *p.PrevBytes != 6000 {
		t.Errorf("6/443 = %+v", p)
	}
	if p := pk["17/53"]; p.Status != MoverNew || p.Bytes != 6000 || *p.PrevBytes != 0 {
		t.Errorf("17/53 = %+v", p)
	}
	if ports[0].Key != "6/443" {
		t.Errorf("largest change first: %+v", ports)
	}
	// App movers return address pairs for Go-side resolution.
	pairs := c.rows(t, "acme", MoversSQL(l, DirBoth, w, ByApp, scope, 10))
	if len(pairs) != 2 {
		t.Fatalf("app pairs = %v", pairs)
	}
}
