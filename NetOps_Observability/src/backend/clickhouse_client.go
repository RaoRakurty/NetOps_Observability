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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"netops/backend/appid"
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
// chInsertJSON inserts rows at an EXPLICIT tenant scope. The scope was
// hardcoded "__all__" until the 2026-07-27 audit: harmless for rejection
// purposes (ClickHouse row policies are FOR SELECT — they do not filter
// INSERTs), but it meant a per-tenant write announced itself as cross-tenant,
// so anything re-evaluated during the write ran without the row's policy
// context and a genuinely cross-tenant writer was indistinguishable from a
// scoped one. Callers pass the row set's own tenant; "__all__" is reserved for
// a deliberately mixed batch and is now a visible choice at the call site.
func chInsertJSON(ctx context.Context, table, scope string, rows []map[string]any) error {
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
		Scope:    scope,
		Settings: chInsertTolerance(),
		Budget:   chDDLBudget,
	})
	return err
}

// ---------------------------------------------------------------------------
// The shared READ path (Phase-2 Wave 0a consolidation, 2026-07-29).
//
// Every tenant-scoped or worker-scoped ClickHouse read in package main goes
// through the helpers below. They used to live in the files that first needed
// them (report_scheduler.go, correlations.go, flows.go, appid_fusion_store.go),
// which pinned those files in the root: a file cannot be extracted while it
// hosts package-wide plumbing. This file is the designated chhttp adapter and
// legitimately stays, so the plumbing lives here now.
// ---------------------------------------------------------------------------

// chQueryBudget is the wall-clock budget for one report ClickHouse read. The
// SERVER is told the same number (max_execution_time), so it aborts before the
// client does rather than being abandoned still running.
const chQueryBudget = 8 * time.Second

// chQuery runs a read-only query against ClickHouse over HTTP and returns the
// non-empty result lines. Errors yield nil so the caller emits a clean "no data"
// report rather than failing — but they are now COUNTED AND LOGGED
// (netops_ch_read_failures_total), because "ClickHouse is unreachable" and
// "there is genuinely no data" produced an identical empty report before.
//
// This is the shared read used by 14 report sections; the F-27 fixes are here
// rather than at the call sites.
func chQuery(sql string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), chQueryBudget)
	defer cancel()
	lines, err := chQueryCtx(ctx, sql)
	if err != nil {
		chReadFailures.Add(1)
		logWarn("reports", "clickhouse read failed — this report section will render as 'no data'", map[string]any{
			"err": err.Error(),
		})
		return nil
	}
	return lines
}

// chQueryCtx is chQuery with a caller-supplied context and a real error.
//
// F-27, three defects in the old five lines:
//  1. `http.NewRequest` (no context) — the request could not be cancelled at
//     all, so a caller giving up left the query running server-side.
//  2. `io.ReadAll(resp.Body)` with NO limit — response size is a function of
//     table size, in the process that also serves the API.
//  3. `b, _ :=` — the read error was discarded, so a truncated response parsed
//     as a short, plausible-looking result set.
func chQueryCtx(ctx context.Context, sql string) ([]string, error) {
	// #20 Phase 2: reports are a trusted internal reader — pass tenant_scope=__all__
	// so the flows/findings row policies don't reject the query (getSetting errors
	// on an unset custom setting). Report-level tenant scoping is handled upstream.
	//
	// Transport, execution guards, status classification and the anti-truncation
	// check all live in chhttp now; what remains here is this reader's policy.
	b, err := chClientFor(envOr("CLICKHOUSE_URL", "http://clickhouse:8123")).Exec(ctx, chhttp.Request{
		SQL:        sql,
		Op:         "query worker:reports",
		Scope:      "__all__",
		LogComment: "worker:reports", // #100 read-budget attribution
		Profile:    chWorkloadProfile("worker:reports"),
		Budget:     chQueryBudget,
		MaxBytes:   chMaxResponseBytes,
	})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

// chRows runs one tenant-scoped ClickHouse query and returns the parsed JSON
// rows — the composable sibling of proxyClickHouse for handlers that combine
// multiple result sets into one response. The scope is derived from the request
// principal (chTenantScope); chRowsScope is the request-free form background jobs
// (the auto-ticketing sweeper, #78 P3) use with an explicit scope.
func (s *server) chRows(r *http.Request, sql string) ([]map[string]any, error) {
	return s.chRowsScope(r.Context(), chTenantScope(r), sql, "api:"+r.URL.Path)
}

// chRowsScope runs one ClickHouse query at an explicit tenant_scope ("__all__"
// for cross-tenant background jobs, a tenant id for one tenant, "__none__" to
// see nothing). The row policies enforce isolation server-side regardless of the
// caller's SQL — same defense-in-depth as chRows. The optional trailing comment
// stamps system.query_log.log_comment for per-caller read-budget attribution
// (#100); callers that pass nothing are tagged as generic background work.
func (s *server) chRowsScope(ctx context.Context, scope, sql string, comment ...string) ([]map[string]any, error) {
	return chSelect(ctx, scope, sql, comment...)
}

// chSelect is the request-free, server-free form of the same tenant-scoped read —
// the one stores (which hold no *server) use. chRowsScope delegates to it, so there
// is exactly ONE ClickHouse read path carrying tenant_scope, log_comment and the
// #101 workload profile.
func chSelect(ctx context.Context, scope, sql string, comment ...string) ([]map[string]any, error) {
	tag := "worker:generic"
	if len(comment) > 0 && comment[0] != "" {
		tag = comment[0]
	}
	// F-27's execution guards are applied by chhttp for every caller now, rather
	// than by each site remembering to call chApplyGuards.
	body, err := chClientFor(envOr("CLICKHOUSE_URL", "http://clickhouse:8123")).Exec(ctx, chhttp.Request{
		SQL:        sql,
		Op:         "select " + tag,
		Scope:      scope,
		LogComment: tag,
		// #101 workload fairness: same profile routing as proxyClickHouse.
		Profile:  chWorkloadProfile(tag),
		Budget:   chWorkerBudget,
		MaxBytes: chMaxResponseBytes,
	})
	if err != nil {
		return nil, err
	}
	var out struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// chTenantScope derives the ClickHouse `tenant_scope` custom setting for the
// caller (#20 Phase 2). The DB row policies on flows/findings/tunnels enforce on
// it: '__all__' unlocks everything (platform owner); a tenant id restricts to that
// tenant's tagged rows plus untagged (the app-layer device matcher narrows the
// untagged set). A request without claims (shouldn't reach an authed handler)
// fails closed to a non-matching sentinel.
func chTenantScope(r *http.Request) string {
	claims, ok := userFrom(r.Context())
	if !ok {
		return "__none__"
	}
	tenant, cross := principalTenant(claims)
	if cross {
		return "__all__"
	}
	if tenant == "" {
		return "__none__"
	}
	return tenant
}

// proxyClickHouse runs sql against ClickHouse over its HTTP interface, injecting
// the caller's tenant_scope so the DB row policies enforce per-tenant isolation
// even if a handler's SQL filter is ever forgotten (defense in depth).
func proxyClickHouse(w http.ResponseWriter, r *http.Request, sql string) {
	// Streams via the chhttp seam: the result set is passed through to the client
	// rather than buffered, but the FAILURE path is now classified like every
	// other ClickHouse call.
	//
	// Two things this used to do wrong. It forwarded ClickHouse's status AND raw
	// body straight to the API caller, so a DB::Exception — table names, column
	// names, sometimes fragments of the query — was rendered to whoever hit the
	// endpoint. And a 500 from insert backpressure reached the SPA looking
	// exactly like a 500 from a schema bug.
	body, err := chClientFor(envOr("CLICKHOUSE_URL", "http://clickhouse:8123")).ExecStream(r.Context(), chhttp.Request{
		SQL:   sql,
		Op:    "api:" + r.URL.Path,
		Scope: chTenantScope(r),
		// #100 hardening: stamp the issuing endpoint into system.query_log.log_comment
		// so per-endpoint read budgets are enforceable operationally (see
		// scripts/ch-query-budget-check.sh) instead of reverse-engineered from
		// normalized query hashes during an incident.
		LogComment: "api:" + r.URL.Path,
		// #101 workload fairness: hot UI reads run under a stricter settings
		// profile than analytics/background work, so a regressed hot query fails
		// small and alone instead of competing with the whole platform.
		Profile: chWorkloadProfile("api:" + r.URL.Path),
		Budget:  chWorkerBudget,
	})
	if err != nil {
		// 503 for transient pressure (the client may usefully retry), 502 for a
		// permanent fault. The operator gets the detail; the caller does not.
		status := http.StatusBadGateway
		if chhttp.Retryable(err) {
			status = http.StatusServiceUnavailable
		}
		logError("clickhouse", "proxy query failed", map[string]any{
			"path": r.URL.Path, "error": err.Error(), "retryable": chhttp.Retryable(err),
		})
		writeError(w, status, errors.New("query backend unavailable"))
		return
	}
	defer func() { _ = body.Close() }()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, body)
}

// writeEmptyClickHouse emits an empty result set in the same envelope shape the
// ClickHouse HTTP JSON format uses, so the SPA's `.data` access is unaffected.
func writeEmptyClickHouse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
}

// chWorkerExec POSTs a statement (INSERT … FORMAT JSONEachRow or DDL) to ClickHouse as
// the worker (tenant_scope=__all__: the worker spans tenants; per-tenant isolation is
// enforced by the row policies on READ + the tenant_id stamped on every row).
func chWorkerExec(ctx context.Context, body string) error {
	_, err := chClientFor(envOr("CLICKHOUSE_URL", "http://clickhouse:8123")).Exec(ctx, chhttp.Request{
		SQL:      body,
		Op:       "worker exec",
		Scope:    "__all__",
		Settings: chInsertTolerance(),
		Budget:   chWorkerBudget,
	})
	return err
}

// chWorkerQuery POSTs a SELECT … FORMAT JSON and returns the data rows.
func chWorkerQuery(ctx context.Context, sql string) ([]map[string]any, error) {
	// F-27 (execution guards + a bounded body) is now structural: chhttp applies
	// max_execution_time and the response cap to every call, so this path cannot
	// drift from its sibling chWorkerExec the way it once did.
	body, err := chClientFor(envOr("CLICKHOUSE_URL", "http://clickhouse:8123")).Exec(ctx, chhttp.Request{
		SQL:        sql,
		Op:         "worker query",
		Scope:      "__all__",
		LogComment: "worker:cross-tenant", // #100 read-budget attribution
		Budget:     chWorkerBudget,
		MaxBytes:   chMaxResponseBytes,
	})
	if err != nil {
		return nil, err
	}
	var out struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// chWorker is the appid.CHWorker adapter over main's worker plumbing.
func chWorker() appid.CHWorker {
	return appid.CHWorker{Exec: chWorkerExec, Query: chWorkerQuery}
}

// jsonEachRow renders rows as a "FORMAT JSONEachRow" insert body — re-homed
// from the moved appid builders for its remaining main users (path baselines).
func jsonEachRow(table string, rows []map[string]any) (string, error) {
	var b bytes.Buffer
	b.WriteString("INSERT INTO " + table + " FORMAT JSONEachRow\n")
	enc := json.NewEncoder(&b)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

// chInsertTolerance is the insert-hardening settings block F-56 found absent
// from every write site. Deliberately NOT applied to reads, where a silently
// skipped field would corrupt an answer rather than protect one.
//
// MEASURED CORRECTION (2026-07-22, ClickHouse 24.8.14.39, the deployed pin):
// F-56's premise — "without these, one unknown JSON key 400s the ENTIRE batch"
// — is NOT true for JSONEachRow on this version.
//
//	SELECT value, changed FROM system.settings
//	WHERE name='input_format_skip_unknown_fields'  →  value=1, changed=0
//
// It is already the server default, so that half of this block is DECLARATIVE:
// it pins the behaviour against a future default flip and states the intent at
// the call site, but it does not change what the server does today.
// date_time_input_format is the half that genuinely does (default 'basic').
// chhttp_integration_test.go asserts both facts against a live server, and
// fails if either default moves.
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

// chJSONRows and chScalarInt are the JSONEachRow/scalar conveniences over
// chQuery (moved here from cloud_signals.go — CH plumbing, W2.2).
func chJSONRows[T any](sql string) []T {
	lines := chQuery(sql)
	out := make([]T, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row T
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		out = append(out, row)
	}
	return out
}

func chScalarInt(sql string) int {
	for _, line := range chQuery(sql) {
		if n, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
			return n
		}
	}
	return 0
}

// ── handlers ─────────────────────────────────────────────────────────────────

// appFilterSQL builds the (validated) app predicate for the signal tables.

// chScopedExec POSTs a statement at an explicit tenant scope (moved from the
// svc rollup worker — CH plumbing, W4.11).
func chScopedExec(ctx context.Context, scope, body string) error {
	_, err := chClientFor(envOr("CLICKHOUSE_URL", "http://clickhouse:8123")).Exec(ctx, chhttp.Request{
		SQL:        body,
		Op:         "rollup insert",
		Scope:      scope,
		LogComment: "worker:svc-rollup",
		Settings:   chInsertTolerance(),
		Budget:     svcRollupQueryTimeout,
	})
	return err
}

// sqlStringLiteral quotes an internally-sourced identifier (tenant id, uuid)
// for interpolation. Values come from our own stores, but escape regardless
// (SR-011 discipline).
