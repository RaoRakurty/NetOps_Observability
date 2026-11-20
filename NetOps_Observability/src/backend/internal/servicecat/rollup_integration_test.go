// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build integration

package servicecat

// rollup_integration_test.go — RollupInsertSQL against a REAL ClickHouse (the
// pinned 24.8 image), the §3a case only a server can prove: ClickHouse resolves
// a SELECT alias inside WHERE ahead of the column, so the rollup's tenant
// predicate must read the COLUMN. With `'acme' AS tenant_id` it read the
// constant and the rollup counted every untagged flow the row policy let
// through (tracker 370 lead, proven on the lab 2026-11-20).
//
// Same throwaway server and env as internal/flowquery's integration tests
// (CH_TEST_URL / CH_TEST_USER / CH_TEST_PASSWORD; backend-ci.yml job
// clickhouse-integration). It drops and recreates netops.flows and
// netops.svc_flow_rollup_1m.

import (
	"context"
	"encoding/json"
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

type chT struct{ base, user, pass string }

func chFromEnv(t *testing.T) chT {
	t.Helper()
	u := os.Getenv("CH_TEST_URL")
	if u == "" {
		t.Skip("CH_TEST_URL not set: this test needs a throwaway ClickHouse (see internal/flowquery's integration test)")
	}
	return chT{base: strings.TrimRight(u, "/"), user: os.Getenv("CH_TEST_USER"), pass: os.Getenv("CH_TEST_PASSWORD")}
}

func (c chT) exec(t *testing.T, scope, sql string) []byte {
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

// schemaFor returns init.sql's CREATE TABLE and CREATE ROW POLICY statements
// for the named tables, verbatim (so the test cannot drift from what ships).
func schemaFor(t *testing.T, tables ...string) []string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(here), "..", "..", "..", "..", "deployment", "docker", "clickhouse", "init.sql"))
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

func TestRollupCountsOnlyTheTenantsOwnFlows(t *testing.T) {
	c := chFromEnv(t)
	c.exec(t, "", "CREATE DATABASE IF NOT EXISTS netops")
	for _, tb := range []string{"flows", "svc_flow_rollup_1m"} {
		c.exec(t, "", "DROP ROW POLICY IF EXISTS tenant_iso_"+tb+" ON netops."+tb)
		c.exec(t, "", "DROP TABLE IF EXISTS netops."+tb)
	}
	for _, st := range schemaFor(t, "flows", "svc_flow_rollup_1m") {
		c.exec(t, "", st)
	}
	t0 := time.Now().UTC().Truncate(time.Minute).Add(-10 * time.Minute)
	type rec struct{ tenant, exporter, src string }
	corpus := []rec{
		{"acme", "10.1.0.1", "192.0.2.1"}, // acme's own stamped flow
		{"", "10.1.0.1", "192.0.2.2"},     // untagged, from acme's device → acme claims it
		{"", "10.9.9.9", "192.0.2.3"},     // untagged, from ANOTHER owner's device → never acme's
		{"globex", "10.2.0.1", "192.0.2.4"},
	}
	var b strings.Builder
	b.WriteString("INSERT INTO netops.flows (ts, sampler_address, src_addr, dst_addr, src_port, dst_port, proto, bytes, packets, sampling_rate, flow_type, tenant_id) FORMAT JSONEachRow\n")
	for i, r := range corpus {
		line, err := json.Marshal(map[string]any{
			"ts": t0.Add(time.Duration(i) * time.Second).Format("2006-01-02 15:04:05.000"), "sampler_address": r.exporter,
			"src_addr": r.src, "dst_addr": "198.51.100.1", "src_port": 40000 + i, "dst_port": 443, "proto": 6,
			"bytes": 100, "packets": 1, "sampling_rate": 1, "flow_type": "ipfix", "tenant_id": r.tenant,
		})
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	c.exec(t, "", b.String())

	// The worker's own inputs: acme's app-layer bound names only acme's device.
	addr := " AND (src_addr IN ('10.1.0.1') OR dst_addr IN ('10.1.0.1') OR sampler_address IN ('10.1.0.1'))"
	sql, n := RollupInsertSQL("acme", []SelectorSet{{TenantID: "acme", ServiceID: "11111111-2222-4333-8444-555555555555", Version: 1,
		Spec: map[string]any{"ports": []any{443.0}}}}, t0, t0, addr, "live")
	if n != 1 {
		t.Fatalf("want one select, got %d", n)
	}
	c.exec(t, "acme", sql) // the worker runs the INSERT at the owning tenant's scope

	var out struct {
		Data []struct {
			Flows string `json:"f"`
		} `json:"data"`
	}
	if err := json.Unmarshal(c.exec(t, "__all__", "SELECT toString(sum(flows)) AS f FROM netops.svc_flow_rollup_1m WHERE tenant_id = 'acme' FORMAT JSON"), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Data) != 1 || out.Data[0].Flows != "2" {
		t.Fatalf("acme's rollup counted %v flows, want 2 (its stamped flow + its own device's untagged flow, never another owner's untagged flow)", out.Data)
	}
}
