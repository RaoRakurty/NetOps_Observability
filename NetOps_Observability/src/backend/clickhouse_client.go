package main

// clickhouse_client.go — the main package's adapter onto the chhttp seam.
//
// chhttp owns transport and failure classification and knows nothing about this
// process's environment. This file is the (deliberately thin) bridge: it
// resolves credentials from env and hands chhttp a configured client.
//
// The three helpers below keep their original signatures on purpose. Rewiring
// the plumbing beneath a dozen call sites is a bounded change; changing their
// shapes would ripple through unrelated modules and violate the one-bounded-
// context rule (CLAUDE.md §7).

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"netops/backend/chhttp"
)

// chDDLBudget bounds a DDL/converge statement. Longer than a read budget: a
// CREATE or ALTER on a populated table legitimately takes longer than a SELECT.
const chDDLBudget = 10 * time.Second

// chWorkerBudget bounds a cross-tenant background worker statement, which scans
// more than any single-tenant read and is not blocking a user.
const chWorkerBudget = 20 * time.Second

// chClientFor builds a client for an explicit endpoint. Credentials come from
// the environment; the endpoint is a parameter because converge paths address
// ClickHouse before the process-wide default is meaningful.
func chClientFor(base string) *chhttp.Client {
	return &chhttp.Client{
		Base:     base,
		User:     envOr("CLICKHOUSE_USER", "netops"),
		Password: os.Getenv("CLICKHOUSE_PASSWORD"),
		HTTP:     backendHTTPClient(chDDLBudget + 2*time.Second),
	}
}

// chStatementHead renders the first 80 characters of a statement on one line,
// so a converge failure names the statement that failed instead of a bare
// boolean. Preserved from the original chExecErr.
func chStatementHead(sql string) string {
	head := sql
	if len(head) > 80 {
		head = head[:80] + "…"
	}
	return strings.Join(strings.Fields(head), " ")
}

// chExecErr runs one DDL statement, returning a diagnosable description of the
// failure ("" = ok). Now classified: the returned text names the ClickHouse
// exception code, and chExecErrTyped exposes the typed error for callers that
// need to distinguish transient pressure from a permanent schema fault.
func chExecErr(base, sql string) string {
	if err := chExecErrTyped(context.Background(), base, sql); err != nil {
		return chStatementHead(sql) + ": " + err.Error()
	}
	return ""
}

// chExecErrTyped is chExecErr with the classification preserved. Prefer this in
// any path that retries — chhttp.Retryable(err) is the difference between
// backing off a TOO_MANY_PARTS and hot-looping a schema bug.
func chExecErrTyped(ctx context.Context, base, sql string) error {
	_, err := chClientFor(base).Exec(ctx, chhttp.Request{
		SQL: sql,
		Op:  "exec",
		// Converge/DDL runs as the trusted internal writer: the statement must
		// not itself be filtered by a row policy.
		Scope:  "__all__",
		Budget: chDDLBudget,
	})
	return err
}

// chExec runs one DDL statement, reporting only whether it worked.
func chExec(base, sql string) bool {
	return chExecErr(base, sql) == ""
}

// chExecAll runs statements in order, collecting failures. Converge steps are
// independent, so one failure must not abandon the rest.
func chExecAll(base string, stmts []string) []string {
	var errs []string
	for _, s := range stmts {
		if msg := chExecErr(base, s); msg != "" {
			errs = append(errs, msg)
		}
	}
	return errs
}

// chInsertJSON inserts rows as JSONEachRow.
//
// Two defects fixed in passing. (1) The previous implementation took a ctx and
// then discarded it (`_ = ctx`), so an insert could outlive the request that
// asked for it — cancellation stopped at the door. (2) It set no insert
// tolerance at all, which is F-56: one unexpected key 400s the entire batch.
func chInsertJSON(ctx context.Context, table string, rows []map[string]any) error {
	base := envOr("CLICKHOUSE_URL", "")
	if base == "" {
		return errors.New("CLICKHOUSE_URL not configured")
	}
	if len(rows) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("INSERT INTO " + table + " FORMAT JSONEachRow\n")
	for _, r := range rows {
		line, err := json.Marshal(r)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	_, err := chClientFor(base).Exec(ctx, chhttp.Request{
		SQL:      b.String(),
		Op:       "insert " + table,
		Scope:    "__all__",
		Settings: chInsertTolerance(),
		Budget:   chDDLBudget,
	})
	return err
}

// chInsertTolerance is the insert-hardening settings block F-56 found absent
// from every write site. A producer that learns a new field must not 400 an
// entire batch of otherwise-valid rows; the unknown field is dropped and the
// insert proceeds. Deliberately NOT applied to reads, where a silently skipped
// field would corrupt an answer rather than protect one.
//
// This mirrors collectors.chInsertSettings EXACTLY, including what it refuses:
//
//	input_format_allow_errors_num/ratio are DELIBERATELY NOT SET. They make
//	ClickHouse silently discard malformed ROWS, trading a loud batch failure for
//	precisely the invisible partial loss this audit exists to eliminate.
//
// Tolerating an unknown COLUMN is safe (the data is intact, the schema lags).
// Tolerating a bad ROW is not (the data is gone and nothing says so). The two
// look like the same kind of leniency and are opposites.
func chInsertTolerance() map[string]string {
	return map[string]string{
		"input_format_skip_unknown_fields": "1",
		"date_time_input_format":           "best_effort",
	}
}
