// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package changesignals

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/changeledger"
)

func row(tenant, source, kind, entity, attrs string, at time.Time) map[string]any {
	ts := at.UTC().Format("2006-01-02T15:04:05.000Z")
	return map[string]any{"tenant_id_s": tenant, "signal_id_s": "aaaaaaaa-0000-0000-0000-000000000001",
		"ts_s": ts, "ingest_ts_s": ts, "source_s": source, "kind_s": kind, "entity_type_s": "device", "entity_id_s": entity,
		"site_s": "", "metric_name_s": "device_config_change", "attrs_s": attrs}
}

// Attributes are read field by field, and a broken blob loses only who and where,
// never the fact, and says so.
func TestFromRow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	r := row("acme", "trap", changeledger.KindDeviceConfigChange, "edge-1",
		`{"user":"alice","source":"unknown","destination":"running","line":7,"authenticated":false}`, now)
	in, err := FromRow(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if in.User != "alice" || in.Origin != "" || in.Destination != "running" || in.Line != "" ||
		in.Authenticated == nil || *in.Authenticated || !in.At.Equal(now) || in.Tenant != "acme" {
		t.Fatalf("adapted: %+v", in)
	}
	warned := 0
	r["attrs_s"] = `{not json`
	in, err = FromRow(r, func(string, map[string]any) { warned++ })
	if err != nil || in.User != "" || in.Entity != "edge-1" || warned != 1 {
		t.Fatalf("a broken blob lost the change or was silent: %+v %v warned=%d", in, err, warned)
	}
	r["ts_s"] = "yesterday"
	if _, err = FromRow(r, nil); err == nil {
		t.Fatal("a row with no readable time was accepted")
	}

	c := row("acme", "cloud", changeledger.KindCloudChange, "sg-1",
		`{"request_id":"evt-1","event_source":"ec2.amazonaws.com","provider":"aws","actor":"arn:aws:sts::123456789012:assumed-role/deployer/x","app":"shop"}`, now)
	c["metric_name_s"] = "AuthorizeSecurityGroupIngress"
	c["entity_type_s"] = "cloud_resource"
	if in, err = FromRow(c, nil); err != nil {
		t.Fatal(err)
	}
	if in.RequestID != "evt-1" || in.EventName != "AuthorizeSecurityGroupIngress" || in.ChangeClass != "security_policy_change" ||
		in.App != "shop" || strings.Contains(in.Actor, "arn:") {
		t.Fatalf("cloud adapted: %+v", in)
	}
}

// The lanes are named, Versa's lane is absent, and a cursor that is not a signal
// id is refused rather than quoted.
func TestSQL(t *testing.T) {
	now := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	sql, err := SQL(changeledger.SignalPage{Since: now.Add(-time.Hour), Until: now, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"source IN ('trap','syslog')", "kind = 'device_config_change'",
		"kind IN ('cloud_change','cloud_audit','security_policy_change')", "GROUP BY tenant_id, signal_id", "LIMIT 500", "FORMAT JSON"} {
		if !strings.Contains(sql, want) {
			t.Errorf("SQL lacks %q:\n%s", want, sql)
		}
	}
	if strings.Contains(sql, "controller_policy_change") || strings.Contains(sql, "HAVING") {
		t.Errorf("unexpected clause:\n%s", sql)
	}
	id := "aaaaaaaa-0000-0000-0000-000000000000"
	sql, err = SQL(changeledger.SignalPage{Since: now.Add(-time.Hour), Until: now, Limit: 1, AfterAt: now, AfterID: id})
	if err != nil || !strings.Contains(sql, "HAVING") || !strings.Contains(sql, id) {
		t.Fatalf("keyset: %v\n%s", err, sql)
	}
	if _, err = SQL(changeledger.SignalPage{AfterAt: now, AfterID: "x' OR 1=1 --"}); err == nil {
		t.Fatal("a hostile cursor was quoted into SQL")
	}
}

func chExec(t *testing.T, base, sql string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/", strings.NewReader(sql))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clickhouse %d: %s\n%s", resp.StatusCode, body, sql)
	}
	return string(body)
}

// The SQL against a REAL ClickHouse, when CH_TEST_URL names a throwaway server.
// ClickHouse's alias and aggregate rules have broken this exact read shape before
// (a shadowing alias made /api/cloud/changes answer 0), and a string-level test
// cannot see that.
func TestSQLOnRealClickHouse(t *testing.T) {
	base := os.Getenv("CH_TEST_URL")
	if base == "" {
		t.Skip("CH_TEST_URL not set")
	}
	chExec(t, base, `CREATE DATABASE IF NOT EXISTS netops`)
	if strings.TrimSpace(chExec(t, base, `EXISTS TABLE netops.corr_signals`)) != "0" {
		t.Fatal("netops.corr_signals already exists: this test owns the table, so point CH_TEST_URL at a throwaway server")
	}
	t.Cleanup(func() { chExec(t, base, `DROP TABLE IF EXISTS netops.corr_signals`) })
	chExec(t, base, `CREATE TABLE netops.corr_signals (
		tenant_id LowCardinality(String), signal_id UUID, ts DateTime64(3), ingest_ts DateTime64(3),
		source Enum8('syslog'=6,'trap'=8,'cloud'=9,'controller'=11), kind LowCardinality(String),
		entity_type Enum8('device'=1,'cloud_resource'=9), entity_id String, site LowCardinality(String),
		metric_name LowCardinality(String), attrs String
	) ENGINE = MergeTree ORDER BY (tenant_id, ts)`)
	start := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Millisecond)
	lit := func(d time.Duration) string { return start.Add(d).Format("2006-01-02 15:04:05.000") }
	ins := func(tenant, id string, at time.Duration, source, kind, etype, entity string) string {
		return fmt.Sprintf(`('%s','%s','%s','%s','%s','%s','%s','%s','','evt','{"user":"u"}')`, tenant, id, lit(at), lit(at), source, kind, etype, entity)
	}
	id := func(n int) string { return fmt.Sprintf("aaaaaaaa-0000-0000-0000-%012d", n) }
	chExec(t, base, `INSERT INTO netops.corr_signals VALUES `+strings.Join([]string{
		ins("acme", id(1), 0, "trap", "device_config_change", "device", "dev-a"),
		// A re-emission of signal 2 later: one row, at its earliest time.
		ins("acme", id(2), time.Second, "cloud", "cloud_audit", "cloud_resource", "sg-1"),
		ins("acme", id(2), time.Minute, "cloud", "cloud_audit", "cloud_resource", "sg-1"),
		ins("globex", id(3), 2*time.Second, "syslog", "device_config_change", "device", "dev-b"),
		// Same event time as signal 3: the keyset's tie-break must not skip it.
		ins("globex", id(4), 2*time.Second, "cloud", "security_policy_change", "cloud_resource", "sg-2"),
		// Out of the bridge's lanes.
		ins("acme", id(5), 0, "controller", "controller_policy_change", "device", "dev-a"),
		ins("acme", id(6), 0, "trap", "device_alarm", "device", "dev-a"),
		ins("acme", id(7), 0, "cloud", "cloud_health", "cloud_resource", "sg-1"),
	}, ","))

	// Paged one row at a time, so the keyset is exercised at every step, ties
	// included.
	page := changeledger.SignalPage{Since: start.Add(-time.Minute), Until: start.Add(time.Hour), Limit: 1}
	var got []string
	for i := 0; i < 10; i++ {
		sql, err := SQL(page)
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			Data []map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(chExec(t, base, sql)), &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Data) == 0 {
			break
		}
		r, err := FromRow(out.Data[0], nil)
		if err != nil {
			t.Fatalf("%v: %v", out.Data[0], err)
		}
		got = append(got, r.Tenant+"/"+r.SignalID)
		if r.SignalID == id(2) && !r.At.Equal(start.Add(time.Second)) {
			t.Errorf("a re-emitted signal read at %s, want its earliest %s", r.At, start.Add(time.Second))
		}
		if r.SignalID == id(1) && r.User != "u" {
			t.Errorf("attrs lost: %+v", r)
		}
		page.AfterAt, page.AfterID = r.At, r.SignalID
	}
	want := []string{"acme/" + id(1), "acme/" + id(2), "globex/" + id(3), "globex/" + id(4)}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("paged read:\n got %v\nwant %v", got, want)
	}
}
