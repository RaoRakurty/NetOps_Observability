// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// corr_undetermined_live_shape_test.go — the missing test class for the #80
// undetermined-frequency read, written after the endpoint was found returning
// 502 on EVERY call since it shipped (2026-06-30).
//
// What the corpus already had, and why it could not see this: corr_undetermined_test.go
// is pure (splitGapToken / clusterUndetermined) and never touches SQL, and the
// route guards only assert the endpoint is tenant-scoped. Nothing executed the
// statement, so a query ClickHouse REFUSES TO ANALYZE looked exactly like a
// healthy one from the inside:
//
//	Code: 386. DB::Exception: There is no supertype for types String, DateTime
//	because some of them are String/FixedString/Enum and some of them are not.
//	(NO_COMMON_TYPE)
//
// This file closes it from the other side. It is in the DEFAULT build, strictly
// READ-ONLY, and it executes the SQL the production builder actually emits
// against whatever ClickHouse is reachable — which on a developer box or the
// deploy host is the live stack.
//
// GUARD (so CI without a stack stays green): the test enables ITSELF by probing —
// docker on PATH → a running container whose name contains "clickhouse" →
// SELECT 1 answered → netops.corr_current present. Any link missing is a
// clean t.Skip, never a failure. No env switch: an enable-gate that CI could
// export would only ever REMOVE coverage here.
//
// SHIP-SAFETY (scripts/CLAUDE.md §16.5 applied to a test that touches a live
// database): every statement is screened SELECT-only, with no write/DDL verb,
// before it is handed to the server, and carries a per-query budget, so a
// mistake costs a failed test and never a mutated or overloaded production table.

import (
	"context"
	"encoding/json"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/cloud"
)

// undetLiveTimeout bounds one docker exec round trip.
const undetLiveTimeout = 90 * time.Second

// undetProbeTag stamps system.query_log.log_comment for every read this file
// issues, so a scale-ladder rung can tell a test probe apart from the endpoint's
// production traffic (which carries "api:/api/correlations/undetermined-frequency").
const undetProbeTag = "probe-undetfreq"

// undetWriteVerb is the ship-safety screen: any of these anywhere in a statement
// disqualifies it from being sent to a live server by this file.
var undetWriteVerb = regexp.MustCompile(`(?i)\b(INSERT|ALTER|DROP|CREATE|TRUNCATE|DELETE|UPDATE|ATTACH|DETACH|RENAME|OPTIMIZE|SYSTEM|GRANT|REVOKE)\b`)

func undetMustBeReadOnly(t *testing.T, sql string) {
	t.Helper()
	trimmed := strings.TrimSpace(sql)
	if !strings.HasPrefix(strings.ToUpper(trimmed), "SELECT") {
		t.Fatalf("live-shape test may only run SELECTs, got:\n%s", sql)
	}
	if m := undetWriteVerb.FindString(trimmed); m != "" {
		t.Fatalf("live-shape test refuses a statement carrying %q:\n%s", m, sql)
	}
}

// undetRunLiveCH executes one statement through the container's clickhouse-client.
func undetRunLiveCH(container, sql string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), undetLiveTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "exec", container, "clickhouse-client", "--query", sql)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", &undetLiveErr{msg: msg}
	}
	return string(out), nil
}

type undetLiveErr struct{ msg string }

func (e *undetLiveErr) Error() string { return e.msg }

// undetLiveContainer finds a reachable ClickHouse holding the table this feed
// reads, or skips. It probes rather than trusting configuration, so the check
// runs by default where a stack exists and is silent where one does not.
func undetLiveContainer(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not on PATH — no live ClickHouse to check the undetermined-frequency shape against")
	}
	ctx, cancel := context.WithTimeout(context.Background(), undetLiveTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "ps", "--filter", "status=running", "--format", "{{.Names}}").Output()
	if err != nil {
		t.Skipf("docker ps failed (%v) — skipping live shape check", err)
	}
	for _, name := range strings.Split(string(out), "\n") {
		name = strings.TrimSpace(name)
		if name == "" || !strings.Contains(strings.ToLower(name), "clickhouse") {
			continue
		}
		got, err := undetRunLiveCH(name, `SELECT count() AS n FROM system.tables
 WHERE database = 'netops' AND name = 'corr_current' FORMAT TSV`)
		if err == nil && strings.TrimSpace(got) == "1" {
			return name
		}
	}
	t.Skip("no running ClickHouse container with netops.corr_current — skipping live shape check")
	return ""
}

// undetLiveSQL appends the settings the Go client sends as URL parameters plus
// the probe tag. SETTINGS must precede FORMAT, so the clause is spliced in
// rather than appended.
//
// max_execution_time is the PRODUCTION api budget (chWorkerBudget, 20 s), not a
// generous test value: a shape check that gave itself longer than the endpoint
// gets would call a read "working" that the API cancels. max_bytes_to_read is
// this file's own ship-safety ceiling — the API sends no byte cap, so a shape
// regression that turns this into a full-table scan fails the test instead of
// loading the production server.
func undetLiveSQL(sql string, executionSeconds int) string {
	probe := "tenant_scope = '__all__', max_execution_time = " +
		strconv.Itoa(executionSeconds) +
		", log_comment = '" + undetProbeTag + "'"
	// The production builder now carries its OWN SETTINGS clause (tracker 201's
	// scan cap). Two SETTINGS clauses is a syntax error and, worse, dropping the
	// builder's would test a statement the API never sends — so the probe
	// settings are MERGED into the existing clause when there is one. The
	// builder's max_bytes_to_read is deliberately left in place: this check must
	// exercise the cap the endpoint actually runs under.
	if i := strings.Index(sql, "\n SETTINGS "); i >= 0 {
		return sql[:i+len("\n SETTINGS ")] + probe + ", " + sql[i+len("\n SETTINGS "):]
	}
	settings := "\n SETTINGS " + probe + ", max_bytes_to_read = 20000000000"
	if i := strings.LastIndex(sql, "\n FORMAT JSON"); i >= 0 {
		return sql[:i] + settings + sql[i:]
	}
	return sql + settings
}

// undetAPIBudgetSeconds is chWorkerBudget, the execution cap the API actually
// sends on this read.
const undetAPIBudgetSeconds = 20

// undetRunAtAPIBudget runs the statement at the production budget. A TIMEOUT is
// a DIFFERENT fact from the fault this file exists to catch: an analysis error
// (386/43/184) is raised before execution starts, so a statement that times out
// was ACCEPTED — its shape is fine, it is merely too slow. Rather than fail the
// shape check on a loaded host (flake) or hide the cost (silence), the timeout is
// reported loudly and the shape is then confirmed at a relaxed cap.
func undetRunAtAPIBudget(t *testing.T, container, sql string) (string, error) {
	t.Helper()
	start := time.Now()
	out, err := undetRunLiveCH(container, undetLiveSQL(sql, undetAPIBudgetSeconds))
	if err == nil {
		return out, nil
	}
	msg := err.Error()
	if !strings.Contains(msg, "TIMEOUT_EXCEEDED") && !strings.Contains(msg, "Code: 159") {
		return "", err
	}
	t.Logf("WARNING: the undetermined-frequency read did NOT fit its production %d s budget on this host "+
		"(gave up after %s). The statement is accepted — this is COST, not shape — but under this load the "+
		"endpoint answers the panel a 502 instead of a ranking. Re-checking the shape at a relaxed cap.",
		undetAPIBudgetSeconds, time.Since(start).Round(time.Second))
	return undetRunLiveCH(container, undetLiveSQL(sql, 90))
}

// TestUndeterminedFrequencySQLIsAcceptedLive executes the production builder's
// output against a live server and pins its result-column contract to the row
// scan in handleUndeterminedFrequency. Read-only.
func TestUndeterminedFrequencySQLIsAcceptedLive(t *testing.T) {
	container := undetLiveContainer(t)
	sql := undeterminedFrequencySQL("604800")
	undetMustBeReadOnly(t, sql)
	out, err := undetRunAtAPIBudget(t, container, sql)
	if err != nil {
		t.Fatalf("ClickHouse REFUSED the undetermined-frequency read — the endpoint answers 502 for every caller:\n%v\n\nSQL:\n%s", err, sql)
	}
	var resp struct {
		Meta []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"meta"`
	}
	if jerr := json.Unmarshal([]byte(out), &resp); jerr != nil {
		t.Fatalf("decode live response: %v", jerr)
	}
	got := map[string]string{}
	for _, m := range resp.Meta {
		got[m.Name] = m.Type
	}
	// The row scan reads exactly these keys; a rename on either side must fail here.
	for _, col := range []string{"correlation_id_s", "window_start_iso", "evidence_missing", "affected", "signal_count"} {
		if _, ok := got[col]; !ok {
			t.Errorf("result column %q is missing — the row scan in handleUndeterminedFrequency reads it; got %v", col, got)
		}
	}
	// The projection must not hand back the typed column names: those are the
	// shadowing aliases that broke the predicate.
	for _, col := range []string{"correlation_id", "window_start"} {
		if _, ok := got[col]; ok {
			t.Errorf("result column %q shadows the typed column it is derived from — that is the 386 bug", col)
		}
	}
}

// TestUndeterminedFrequencyShadowingAliasStillFailsLive is the mutant, run against
// the real server: reverting the aliases to the column names must be REJECTED.
// It proves the rule that motivates the fix is still this server's behaviour —
// so the fix can never be "simplified" back on the belief that it was cosmetic.
func TestUndeterminedFrequencyShadowingAliasStillFailsLive(t *testing.T) {
	container := undetLiveContainer(t)
	mutant := strings.NewReplacer(
		"AS correlation_id_s", "AS correlation_id",
		"AS window_start_iso", "AS window_start",
	).Replace(undeterminedFrequencySQL("604800"))
	undetMustBeReadOnly(t, mutant)
	if _, err := undetRunLiveCH(container, undetLiveSQL(mutant, undetAPIBudgetSeconds)); err == nil {
		t.Fatal("the shadowing projection was ACCEPTED — ClickHouse alias resolution changed; re-derive the fix instead of trusting this test")
	} else if !strings.Contains(err.Error(), "386") && !strings.Contains(err.Error(), "NO_COMMON_TYPE") {
		t.Fatalf("expected the shadowing projection to fail with 386/NO_COMMON_TYPE, got: %v", err)
	}
}

// TestCloudReadsWithShadowedAliasesAreAcceptedLive covers the two OTHER queries
// the alias-shadowing audit found broken in exactly the same way — both live,
// both refused by the server since they shipped, neither with a test that ever
// executed it:
//
//   - cloudSeamTelemetrySQL: `argMax(kind, ts) AS kind` was substituted into
//     its own WHERE → Code 184 ILLEGAL_AGGREGATION.
//   - cloud.CostsSQL: `toString(day) AS day` was substituted into the day range
//     → Code 386 NO_COMMON_TYPE (String vs Date).
//
// Both are fixed by table-qualifying the predicate (alias resolution does not
// touch a qualified name), which keeps the projected names — the served wire
// fields — exactly as they were. Read-only, same self-enabling guard.
func TestCloudReadsWithShadowedAliasesAreAcceptedLive(t *testing.T) {
	container := undetLiveContainer(t)
	cases := []struct{ name, sql string }{
		{"cloud seam telemetry", cloudSeamTelemetrySQL(24, 5, "__all__")},
		{"cloud costs", cloud.CostsSQL("2026-08-01", "2026-08-31", "", 5, "__all__")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			undetMustBeReadOnly(t, tc.sql)
			tagged := strings.Replace(tc.sql, "tenant_scope = '__all__'",
				"tenant_scope = '__all__', log_comment = '"+undetProbeTag+"'", 1)
			if _, err := undetRunLiveCH(container, tagged); err != nil {
				t.Fatalf("ClickHouse REFUSED the %s read — the endpoint answers 502 for every caller:\n%v\n\nSQL:\n%s", tc.name, err, tc.sql)
			}
		})
	}
}
