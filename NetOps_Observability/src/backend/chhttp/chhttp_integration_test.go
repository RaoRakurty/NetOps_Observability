//go:build integration

package chhttp

// chhttp_integration_test.go — verification against a REAL ClickHouse, pinned to
// the digest this repository deploys (clickhouse/clickhouse-server:24.8-alpine,
// server 24.8.14.39).
//
// Build-tagged so the default `go test ./...` stays hermetic. Run it with:
//
//	docker run -d --rm --name chdrill \
//	  -e CLICKHOUSE_USER=drill -e CLICKHOUSE_PASSWORD=drillpw \
//	  -p 18123:8123 --tmpfs /var/lib/clickhouse:rw,size=512m \
//	  clickhouse/clickhouse-server:24.8-alpine@sha256:b002e56ed5c16e224c312527f6fcba7e77216fec5d7a88a7828f59efc614feb5
//	CH_TEST_URL=http://localhost:18123 go test -tags=integration ./chhttp/
//
// WHY THIS EXISTS SEPARATELY FROM chhttp_test.go: the httptest suite proves how
// this CLIENT behaves when handed a given response. It cannot prove that
// ClickHouse actually SENDS those responses. Every constant in this package —
// exception codes, header names, the wait_end_of_query behaviour — is an
// assumption about the server until something asks the server.
//
// This file is deliberately NOT a claim about ClickHouse transaction semantics.
// It verifies wire-level error reporting only.

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func liveClient(t *testing.T) *Client {
	t.Helper()
	base := os.Getenv("CH_TEST_URL")
	if base == "" {
		t.Skip("CH_TEST_URL not set — see the header of this file for the docker line")
	}
	return &Client{
		Base: base, User: envOrDefault("CH_TEST_USER", "drill"),
		Password: envOrDefault("CH_TEST_PASSWORD", "drillpw"),
		HTTP:     &http.Client{Timeout: 30 * time.Second},
	}
}

func envOrDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// TestLiveServerVersionIsThePinnedOne fails loudly if the drill runs against a
// server other than the deployed major. Every code constant below is
// version-specific, so testing against 25.x would prove the wrong thing.
func TestLiveServerVersionIsThePinnedOne(t *testing.T) {
	c := liveClient(t)
	body, err := c.Exec(context.Background(), Request{SQL: "SELECT version()", Op: "version", Scope: "__all__"})
	if err != nil {
		t.Fatalf("version query failed: %v", err)
	}
	got := strings.TrimSpace(string(body))
	if !strings.HasPrefix(got, "24.8") {
		t.Fatalf("server is %s, expected the deployed 24.8.x — the exception codes "+
			"asserted below are pinned to that major", got)
	}
	t.Logf("verified against ClickHouse %s", got)
}

// TestLiveExceptionCodesMatchOurConstants is the test that stops this package
// from drifting into folklore. Each case asserts the code we CLASSIFY ON is the
// code the pinned server actually returns.
func TestLiveExceptionCodesMatchOurConstants(t *testing.T) {
	c := liveClient(t)
	cases := []struct {
		name     string
		sql      string
		wantCode int
		wantPerm bool // expected to be classified permanent (not retryable)
	}{
		{"unknown database", "SELECT 1 FROM nope_db.nope_tbl", codeUnknownDatabase, true},
		{"unknown table", "SELECT 1 FROM system.nope_tbl", codeUnknownTable, true},
		{"unknown column", "SELECT no_such_col FROM system.one", 47, false}, // UNKNOWN_IDENTIFIER
		{"unknown setting", "SELECT 1 SETTINGS totally_not_a_setting = 1", codeUnknownSetting, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.Exec(context.Background(), Request{SQL: tc.sql, Op: "probe", Scope: "__all__"})
			if err == nil {
				t.Fatal("expected the server to reject this statement")
			}
			var e *Error
			if !asChErr(err, &e) {
				t.Fatalf("expected *chhttp.Error, got %T", err)
			}
			t.Logf("HTTP %d, code %d, class %q, queryID %q", e.Status, e.Code, e.Classification, e.QueryID)
			if tc.wantCode != 0 && e.Code != tc.wantCode {
				t.Errorf("exception code = %d, want %d — the constant in chhttp.go is wrong "+
					"for this server version", e.Code, tc.wantCode)
			}
			if e.Outcome != OutcomeRejected {
				t.Errorf("Outcome = %v, want rejected: the server positively refused", e.Outcome)
			}
			if tc.wantPerm && e.Retryable {
				t.Errorf("%s classified retryable — retrying a schema fault loops forever", tc.name)
			}
		})
	}
}

// TestLiveAuthFailureIsPermanent — measured HTTP 403 + code 516.
func TestLiveAuthFailureIsPermanent(t *testing.T) {
	c := liveClient(t)
	bad := &Client{Base: c.Base, User: c.User, Password: "definitely-wrong", HTTP: c.HTTP}
	_, err := bad.Exec(context.Background(), Request{SQL: "SELECT 1", Op: "probe", Scope: "__all__"})
	if err == nil {
		t.Fatal("a wrong password must not succeed")
	}
	var e *Error
	if !asChErr(err, &e) {
		t.Fatalf("got %T", err)
	}
	if e.Code != codeAuthFailed {
		t.Errorf("code = %d, want %d (AUTHENTICATION_FAILED)", e.Code, codeAuthFailed)
	}
	if e.Retryable {
		t.Error("an auth failure is permanent — retrying will not rotate the password back")
	}
	if e.Classification != "auth" {
		t.Errorf("classification = %q, want \"auth\"", e.Classification)
	}
	if strings.Contains(e.Error(), "definitely-wrong") {
		t.Error("SECURITY: the error text leaked the password")
	}
}

// TestLiveQueryIDIsCaptured — X-ClickHouse-Query-Id is the only handle that ties
// a failure to system.query_log, which is how an Unknown outcome is resolved
// after the fact. If ClickHouse stops sending it, this fails.
func TestLiveQueryIDIsCaptured(t *testing.T) {
	c := liveClient(t)
	_, err := c.Exec(context.Background(), Request{
		SQL: "SELECT 1 FROM nope_db.nope_tbl", Op: "probe", Scope: "__all__",
	})
	if err == nil {
		t.Fatal("expected rejection")
	}
	if id := QueryIDOf(err); id == "" {
		t.Error("no X-ClickHouse-Query-Id captured — an Unknown outcome would be unresolvable")
	} else {
		t.Logf("query id: %s", id)
	}
}

// TestLiveEmbeddedExceptionInA200IsCaught is the headline integration case, and
// the one that proves the httptest suite was testing something real.
//
// MEASURED on 24.8.14.39: with wait_end_of_query=0, a query that fails after the
// output buffer has flushed returns HTTP 200, NO exception header, and ~15 MB of
// body whose tail is the DB::Exception. Before bodyCarriesException, this client
// returned that to the caller as a successful read.
func TestLiveEmbeddedExceptionInA200IsCaught(t *testing.T) {
	c := liveClient(t)
	// throwIf in the SELECT list, far enough in that output has already flushed.
	sql := "SELECT number, repeat('x',300) AS pad, throwIf(number=50000,'late') AS t " +
		"FROM numbers(200000) FORMAT JSONEachRow"
	_, err := c.Exec(context.Background(), Request{
		SQL: sql, Op: "streamed failure", Scope: "__all__",
		NoWaitEndOfQuery: true, // reproduce the dangerous mode on purpose
		MaxBytes:         64 << 20,
		Budget:           30 * time.Second,
		Settings:         map[string]string{"buffer_size": "1024", "max_block_size": "1000"},
	})
	if err == nil {
		t.Fatal("a 200 response whose body ends in a DB::Exception was reported as SUCCESS. " +
			"This is the exact silent-corruption case the package exists to prevent.")
	}
	var e *Error
	if !asChErr(err, &e) {
		t.Fatalf("got %T", err)
	}
	if e.Status != http.StatusOK {
		t.Logf("note: server returned HTTP %d rather than the measured 200 — "+
			"still correctly failed, but the streaming case may not have reproduced", e.Status)
	}
	t.Logf("caught: HTTP %d, code %d, class %q", e.Status, e.Code, e.Classification)
}

// TestLiveWaitEndOfQueryConvertsItToAProperError documents WHY the default is on.
// Same failing query, only the flag differing.
func TestLiveWaitEndOfQueryConvertsItToAProperError(t *testing.T) {
	c := liveClient(t)
	sql := "SELECT number, repeat('x',300) AS pad, throwIf(number=50000,'late') AS t " +
		"FROM numbers(200000) FORMAT JSONEachRow"
	_, err := c.Exec(context.Background(), Request{
		SQL: sql, Op: "buffered failure", Scope: "__all__",
		MaxBytes: 64 << 20, Budget: 30 * time.Second,
		Settings: map[string]string{"buffer_size": "1024", "max_block_size": "1000"},
	})
	if err == nil {
		t.Fatal("expected failure")
	}
	var e *Error
	if !asChErr(err, &e) {
		t.Fatalf("got %T", err)
	}
	if e.Status == http.StatusOK {
		t.Errorf("with wait_end_of_query=1 the server should have sent a real error status, got 200")
	}
	t.Logf("wait_end_of_query=1 → HTTP %d, code %d (vs the 200 the streaming mode returns)",
		e.Status, e.Code)
}

// TestLiveInsertAndReadback — the happy path against a real table, so the whole
// file is not made of failures.
func TestLiveInsertAndReadback(t *testing.T) {
	c := liveClient(t)
	ctx := context.Background()
	ddl := []string{
		"CREATE DATABASE IF NOT EXISTS chdrill",
		"DROP TABLE IF EXISTS chdrill.probe",
		"CREATE TABLE chdrill.probe (id UInt64, tenant String, ts DateTime64(3)) " +
			"ENGINE = MergeTree ORDER BY (tenant, id)",
	}
	for _, s := range ddl {
		if _, err := c.Exec(ctx, Request{SQL: s, Op: "ddl", Scope: "__all__"}); err != nil {
			t.Fatalf("ddl %q: %v", s, err)
		}
	}
	ins := `INSERT INTO chdrill.probe FORMAT JSONEachRow
{"id":1,"tenant":"t-a","ts":1750000000000}
{"id":2,"tenant":"t-b","ts":1750000000001}`
	if _, err := c.Exec(ctx, Request{SQL: ins, Op: "insert probe", Scope: "__all__"}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	body, err := c.Exec(ctx, Request{SQL: "SELECT count() FROM chdrill.probe", Op: "count", Scope: "__all__"})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if got := strings.TrimSpace(string(body)); got != "2" {
		t.Errorf("count = %q, want 2", got)
	}
}

// TestLiveUnknownFieldOnInsertIsSkippedByDefault records a MEASURED fact that
// contradicts the story the F-56 fix was written around.
//
// The premise was: "without input_format_skip_unknown_fields a single unknown
// JSON key 400s the ENTIRE batch." Measured on 24.8.14.39:
//
//	SELECT name, value, changed FROM system.settings
//	WHERE name = 'input_format_skip_unknown_fields'
//	→ value=1, changed=0
//
// It is already the SERVER DEFAULT for JSONEachRow. So an unknown field is
// skipped whether or not we send the setting, and half of chInsertTolerance()
// is a no-op that documents intent rather than changing behaviour. The other
// half — date_time_input_format=best_effort, default 'basic' — is real.
//
// This test asserts the true behaviour so nobody re-derives the myth from the
// code comments. If a future ClickHouse flips the default, this fails and the
// tolerance block becomes load-bearing again.
func TestLiveUnknownFieldOnInsertIsSkippedByDefault(t *testing.T) {
	c := liveClient(t)
	ctx := context.Background()
	for _, s := range []string{
		"CREATE DATABASE IF NOT EXISTS chdrill",
		"DROP TABLE IF EXISTS chdrill.strict",
		"CREATE TABLE chdrill.strict (id UInt64) ENGINE = MergeTree ORDER BY id",
	} {
		if _, err := c.Exec(ctx, Request{SQL: s, Op: "ddl", Scope: "__all__"}); err != nil {
			t.Fatalf("ddl: %v", err)
		}
	}
	// No tolerance settings sent — this measures the SERVER DEFAULT.
	ins := "INSERT INTO chdrill.strict FORMAT JSONEachRow\n{\"id\":1,\"ghost\":\"boo\"}"
	if _, err := c.Exec(ctx, Request{SQL: ins, Op: "insert strict", Scope: "__all__"}); err != nil {
		t.Fatalf("unknown field was REJECTED without tolerance settings: %v\n"+
			"If this starts failing, the server default for "+
			"input_format_skip_unknown_fields has changed and chInsertTolerance() "+
			"is now load-bearing rather than declarative — update its comment.", err)
	}
	body, err := c.Exec(ctx, Request{SQL: "SELECT count() FROM chdrill.strict", Op: "count", Scope: "__all__"})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if got := strings.TrimSpace(string(body)); got != "1" {
		t.Errorf("count = %q, want 1 — the row with the unknown field did not land", got)
	}

	// And confirm WHY, from the server itself rather than from folklore.
	s, err := c.Exec(ctx, Request{
		SQL:   "SELECT value, changed FROM system.settings WHERE name = 'input_format_skip_unknown_fields' FORMAT TSV",
		Op:    "setting probe",
		Scope: "__all__",
	})
	if err != nil {
		t.Fatalf("setting probe: %v", err)
	}
	t.Logf("input_format_skip_unknown_fields (value, changed) = %s", strings.TrimSpace(string(s)))
	if !strings.HasPrefix(strings.TrimSpace(string(s)), "1") {
		t.Errorf("expected the server default to be 1; got %q", strings.TrimSpace(string(s)))
	}
}

// TestLiveInsertToleranceActuallyTolerates — the other half: WITH the repo's
// tolerance settings, the same unknown column must be dropped and the row land.
// This is what F-56's fix is supposed to buy.
func TestLiveInsertToleranceActuallyTolerates(t *testing.T) {
	c := liveClient(t)
	ctx := context.Background()
	for _, s := range []string{
		"CREATE DATABASE IF NOT EXISTS chdrill",
		"DROP TABLE IF EXISTS chdrill.tolerant",
		"CREATE TABLE chdrill.tolerant (id UInt64) ENGINE = MergeTree ORDER BY id",
	} {
		if _, err := c.Exec(ctx, Request{SQL: s, Op: "ddl", Scope: "__all__"}); err != nil {
			t.Fatalf("ddl: %v", err)
		}
	}
	ins := "INSERT INTO chdrill.tolerant FORMAT JSONEachRow\n{\"id\":7,\"ghost\":\"boo\"}"
	if _, err := c.Exec(ctx, Request{
		SQL: ins, Op: "insert tolerant", Scope: "__all__",
		Settings: map[string]string{
			"input_format_skip_unknown_fields": "1",
			"date_time_input_format":           "best_effort",
		},
	}); err != nil {
		t.Fatalf("tolerant insert should have succeeded: %v", err)
	}
	body, err := c.Exec(ctx, Request{SQL: "SELECT count() FROM chdrill.tolerant", Op: "count", Scope: "__all__"})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if got := strings.TrimSpace(string(body)); got != "1" {
		t.Errorf("count = %q, want 1 — the tolerated row did not land", got)
	}
}

// asChErr is errors.As specialised to *Error, kept local so the integration
// file has no dependency on the unit-test helpers.
func asChErr(err error, target **Error) bool { return errorsAs(err, target) }
