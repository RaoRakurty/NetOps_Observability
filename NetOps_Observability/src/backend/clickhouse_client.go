// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

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
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"netops/backend/appid"
	"netops/backend/chhttp"
	"netops/backend/internal/chschema"
)

// chDDLBudget bounds a DDL/converge statement. Longer than a read budget: a
// CREATE or ALTER on a populated table legitimately takes longer than a SELECT.
const chDDLBudget = 10 * time.Second

// chWorkerBudget bounds a cross-tenant background worker statement, which scans
// more than any single-tenant read and is not blocking a user.
const chWorkerBudget = 20 * time.Second

// chWorkerReadMemoryBytes is the EXPLICIT per-query server-side memory ceiling
// for a background worker read (log_comment `worker:*`).
//
// Why state it per query rather than lean on the server default (2026-08-29
// storm incident): the default profile's max_memory_usage is 2 GiB and the
// `background` settings profile is the same 2 GiB, so a worker read that grows
// with table size — the timeintel backfill's corr_objects fold — was allowed to
// climb to 1.8 GiB before ClickHouse refused it, on a box whose whole
// per-server budget is 4 GiB. One worker could therefore price out every
// interactive query beside it and still fail itself.
//
// The arithmetic, stated so it can be re-checked: server cap 4 GiB; at most two
// worker lanes run concurrently (the reconciler ticker and the backfill
// ticker), so 2 x 1 GiB = 2 GiB worst case, leaving 2 GiB for the hot UI lane
// (whose own profile caps it at 1 GiB). Measured headroom: the heaviest healthy
// worker read in 24 h of system.query_log peaked at 310 MiB
// (worker:corr-current-reconcile), and the repaired backfill at 447-484 MiB.
//
// A breach is LOUD by construction: ClickHouse returns MEMORY_LIMIT_EXCEEDED,
// chhttp classifies it, and every worker caller propagates the error instead of
// returning an empty result set (CLAUDE.md §10 — no silent failures).
const chWorkerReadMemoryBytes = 1 << 30 // 1 GiB

// chWorkerReadGuards returns the per-query containment settings for a read
// attributed to tag. Only `worker:*` reads are tightened: an interactive read
// already runs under the hot_ui / default profiles, and silently shrinking an
// operator-facing query's ceiling would trade one silent failure for another.
func chWorkerReadGuards(tag string) map[string]string {
	if !strings.HasPrefix(tag, "worker:") {
		return nil
	}
	return map[string]string{"max_memory_usage": strconv.Itoa(chWorkerReadMemoryBytes)}
}

// chMergeSettings overlays extra onto base without mutating either. Nil-safe on
// both sides; extra wins on a key collision so a caller can tighten (never
// loosen silently — a loosening caller has to say so at its own call site).
func chMergeSettings(base, extra map[string]string) map[string]string {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// chClientFor builds a client for an explicit endpoint. Credentials come from
// the environment; the endpoint is a parameter because converge paths address
// ClickHouse before the process-wide default is meaningful.
func chClientFor(base string) *chhttp.Client {
	return chClientForBudget(base, chDDLBudget)
}

// chClientForBudget is chClientFor with the transport timeout DERIVED from the
// statement's server-side budget.
//
// The inversion this fixes (2026-08-29 storm incident, second defect): every
// ClickHouse call shared one 12 s HTTP timeout (chDDLBudget + 2 s) while the
// worker lane asked ClickHouse for up to 20 s of execution. A slow worker read
// was therefore ALWAYS cut off by the Go client first — the caller logged
// "Client.Timeout exceeded" and the real, classified server answer
// (MEMORY_LIMIT_EXCEEDED, in the incident) arrived nowhere. The transport must
// outlive the budget it is transporting, or the whole classification apparatus
// in chhttp is unreachable for exactly the queries that need it.
func chClientForBudget(base string, budget time.Duration) *chhttp.Client {
	return &chhttp.Client{
		Base:     base,
		User:     envOr("CLICKHOUSE_USER", "netops"),
		Password: os.Getenv("CLICKHOUSE_PASSWORD"),
		HTTP:     backendHTTPClient(budget + 2*time.Second),
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
	body, err := chClientForBudget(envOr("CLICKHOUSE_URL", "http://clickhouse:8123"), chWorkerBudget).Exec(ctx, chhttp.Request{
		SQL:        sql,
		Op:         "select " + tag,
		Scope:      scope,
		LogComment: tag,
		// #101 workload fairness: same profile routing as proxyClickHouse.
		Profile: chWorkloadProfile(tag),
		// #100 containment: a worker read also carries an EXPLICIT memory
		// ceiling, so a read that grows with table size fails alone and loudly
		// instead of consuming the server budget on its way to the same error.
		Settings: chWorkerReadGuards(tag),
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
	return chTenantScopeFor(claims)
}

// chTenantScopeFor is the same derivation for a caller that already HOLDS the
// claims and has no request to read them from (the AI assistant's tool seams,
// background workers). It exists so there is exactly one rule for what a
// principal's ClickHouse scope is — a second hand-rolled derivation is how the
// two drift apart.
func chTenantScopeFor(claims jwtClaims) string {
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
	defer func() { _ = body.Close() }() // best-effort: nothing actionable on close failure
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, body) // best-effort: proxy stream; a failed copy means the client is gone
}

// writeEmptyClickHouse emits an empty result set in the same envelope shape the
// ClickHouse HTTP JSON format uses, so the SPA's `.data` access is unaffected.
func writeEmptyClickHouse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`)) // best-effort: status committed; a failed write means the client is gone
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
	return chWorkerQueryTuned(ctx, chWorkerRead{SQL: sql, Tag: "worker:cross-tenant"})
}

// chWorkerRead is one cross-tenant worker SELECT plus the bounds it needs.
// A struct rather than five positional arguments because every field here is a
// BOUND, and a bound that is easy to pass in the wrong slot is not a bound.
// Zero values fall back to the generic worker defaults.
type chWorkerRead struct {
	SQL string
	// Tag stamps system.query_log.log_comment AND selects the #101 workload
	// profile. Give each worker read its own — the storm incident cost a
	// query_log dig because two unrelated workers shared one tag.
	Tag string
	// Budget is the server-side max_execution_time; it also derives the
	// transport timeout, so the two can no longer invert.
	Budget time.Duration
	// MaxBytes bounds the response body read into this process. Raise it only
	// with the row-cap arithmetic written down at the call site.
	MaxBytes int64
	// Settings are extra ClickHouse settings, merged over chWorkerReadGuards.
	Settings map[string]string
}

// chWorkerQueryTuned is chWorkerQuery with per-call ATTRIBUTION, an explicit
// execution budget and extra server settings — for the one worker read whose
// cost is a function of a wide history column and therefore needs both a tighter
// read shape (see timeIntelBackfillSQL) and read-side bounds the generic worker
// lane has no business paying for.
//
// tag stamps system.query_log.log_comment (#100 read-budget attribution) AND
// selects the #101 workload profile, so a new worker read is visible in the
// budget survey under its own name instead of hiding inside `worker:cross-tenant`.
//
// The guards are NOT advisory: max_execution_time (from budget) and
// max_memory_usage (from chWorkerReadGuards, overridable via extra) are applied
// server-side by ClickHouse, and any breach comes back as a classified chhttp
// error — never as a short or empty result set.
func chWorkerQueryTuned(ctx context.Context, req chWorkerRead) ([]map[string]any, error) {
	budget := req.Budget
	if budget <= 0 {
		budget = chWorkerBudget
	}
	maxBytes := req.MaxBytes
	if maxBytes <= 0 {
		maxBytes = chMaxResponseBytes
	}
	// F-27 (execution guards + a bounded body) is now structural: chhttp applies
	// max_execution_time and the response cap to every call, so this path cannot
	// drift from its sibling chWorkerExec the way it once did.
	body, err := chClientForBudget(envOr("CLICKHOUSE_URL", "http://clickhouse:8123"), budget).Exec(ctx, chhttp.Request{
		SQL:        req.SQL,
		Op:         "worker query " + req.Tag,
		Scope:      "__all__",
		LogComment: req.Tag, // #100 read-budget attribution
		Profile:    chWorkloadProfile(req.Tag),
		Settings:   chMergeSettings(chWorkerReadGuards(req.Tag), req.Settings),
		Budget:     budget,
		MaxBytes:   maxBytes,
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

// ── corr repartition: the transport adapter for the corr_* daily
// re-partition migration (internal/chschema/corr_repartition.go).
//
// chschema owns the migration's LOGIC and every SQL string it emits, with no
// transport and no environment of its own; this section is the (deliberately thin)
// bridge onto the chhttp seam, exactly as clickhouse_client.go bridges the
// converge statements. Keeping the two apart is what lets the whole migration —
// gate, batching, resume, verification, swap ordering — be unit-tested against
// a fake ClickHouse with no server in the loop.
//
// WHEN IT RUNS: after ensureCHRowPolicies' converge list has fully succeeded,
// in the same background goroutine. Ordering matters twice over:
//
//   - the converge CREATEs must have run, or a fresh volume has no corr tables
//     to migrate (same F-58 rule as the retention ALTERs);
//   - the migration applies the merge budget, the strict row policy and the
//     retention TTL to the shadow table ITSELF before swapping it in, so the
//     swapped-in table is fully converged the moment it becomes live and does
//     not have to wait for the next boot.
//
// It is best-effort and never fatal: a failure leaves the live table exactly as
// it was (monthly partitions, which work — just less efficiently) and says so.

// Statement budgets. All bounded (CLAUDE.md §9) — but bounded is not the whole
// story, as the 2026-08-29 incident showed:
//
// chClientFor hands back a client whose http.Client.Timeout is chDDLBudget+2s =
// 12 SECONDS. A Request's Budget only sets the SERVER's max_execution_time, so
// asking for 10 minutes bought a 10-minute server budget behind a 12-second
// client. The copy's client call failed at 12 s with
//
//	clickhouse repartition: transport: Post "https://clickhouse:8443?..."
//
// while the INSERT ... SELECT kept running server-side for minutes and had to be
// killed by hand. The rule that follows, and that chRepartitionSlack encodes:
// THE CLIENT MUST ALWAYS OUTLIVE THE SERVER-SIDE BOUND IT ASKED FOR. Otherwise
// "the call returned" and "the work stopped" are different facts, and only one
// of them is visible from here.
const (
	// chRepartitionBudget bounds one DDL / metadata statement (CREATE, DROP
	// PARTITION, EXCHANGE, KILL). Longer than an ordinary DDL budget: these run
	// against populated tables.
	chRepartitionBudget = 10 * time.Minute
	// chRepartitionQueryBudget bounds one metadata SELECT — counts and
	// system.* reads, none of which scan history.
	chRepartitionQueryBudget = 60 * time.Second
	// chRepartitionSlack is how much longer the HTTP client waits than the
	// server-side bound. The server is expected to end the statement first; the
	// client timeout is the backstop, not the mechanism.
	chRepartitionSlack = 30 * time.Second
)

// chRepartitionExec implements chschema.CHExec over the chhttp seam.
type chRepartitionExec struct {
	base string
}

// client builds a ClickHouse client whose HTTP timeout is derived from the
// server-side budget this call is about to ask for. chClientFor's default
// 12-second timeout is right for the converge DDL it was written for and wrong
// for every statement in this file.
func (e chRepartitionExec) client(budget time.Duration) *chhttp.Client {
	c := chClientFor(e.base)
	c.HTTP = backendHTTPClient(budget + chRepartitionSlack)
	return c
}

// Exec runs one migration statement.
//
// Scope is "__all__" because this is the trusted internal writer moving a
// tenant-partitioned table wholesale; the statements chschema emits ALSO carry
// an explicit `SETTINGS tenant_scope = '__all__'` so the copy cannot be reduced
// to zero rows by a policy if this seam is ever rewired (CLAUDE.md §3a).
func (e chRepartitionExec) Exec(ctx context.Context, sql string) error {
	_, err := e.client(chRepartitionBudget).Exec(ctx, chhttp.Request{
		SQL:        sql,
		Op:         "repartition",
		Scope:      "__all__",
		LogComment: "worker:corr-repartition",
		Budget:     chRepartitionBudget,
	})
	return err
}

// ExecLong runs ONE partition copy: an INSERT ... SELECT that is legitimately
// slower than any DDL here and must stay identifiable on the server after this
// call returns, however it returns.
//
//   - query_id is set explicitly (ClickHouse's HTTP interface takes it as a URL
//     parameter) so chschema can poll system.processes for it and KILL it. Left
//     unset, ClickHouse assigns a random id we would never learn on the failure
//     path — which is exactly why the 2026-08-29 orphan had to be found by hand.
//   - Budget becomes max_execution_time, so a copy nobody is waiting for still
//     dies on its own.
//   - the HTTP client is given Budget + slack, so the ordinary case is the client
//     WAITING for a long copy rather than abandoning it.
func (e chRepartitionExec) ExecLong(ctx context.Context, sql string, opt chschema.CHLongOpts) error {
	budget := opt.Budget
	if budget <= 0 {
		budget = chRepartitionBudget
	}
	req := chhttp.Request{
		SQL:        sql,
		Op:         "repartition copy",
		Scope:      "__all__",
		LogComment: "worker:corr-repartition",
		Budget:     budget,
	}
	if opt.QueryID != "" {
		req.Settings = map[string]string{"query_id": opt.QueryID}
	}
	_, err := e.client(budget).Exec(ctx, req)
	return err
}

// Query runs one migration SELECT. The statements chschema builds end in
// `FORMAT JSON`, so the response is ClickHouse's JSON envelope.
func (e chRepartitionExec) Query(ctx context.Context, sql string) ([]map[string]any, error) {
	body, err := e.client(chRepartitionQueryBudget).Exec(ctx, chhttp.Request{
		SQL:        sql,
		Op:         "repartition query",
		Scope:      "__all__",
		LogComment: "worker:corr-repartition",
		Budget:     chRepartitionQueryBudget,
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

// runCorrRepartition converges the corr_* history tables onto daily partitions.
// Called from ensureCHRowPolicies once the converge list has succeeded.
func runCorrRepartition(base string) {
	logf := func(format string, args ...any) { log.Printf(format, args...) }
	cfg := chschema.CorrRepartitionConfig(logf)
	// The whole migration shares one deadline. Generous — a forced run on a
	// multi-GiB table is a deliberate operator action — but bounded, so a stuck
	// ClickHouse cannot leave this goroutine running for the process's life.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()

	results := chschema.RunCorrRepartition(ctx, chRepartitionExec{base: base}, cfg,
		chschema.CorrRetentionConfig(), logf)

	// One summary line per non-trivial outcome. "already-daily" and "absent" are
	// the steady state on every boot after the first and would be pure noise; a
	// check-mode verdict already logged its own, fuller, actionable line.
	for _, r := range results {
		switch {
		case r.Status == chschema.CorrRepartitionAlready,
			r.Status == chschema.CorrRepartitionAbsent,
			chschema.CorrRepartitionIsCheck(r.Status):
			continue
		default:
			log.Printf("corr-repartition: netops.%s -> %s%s", r.Table, r.Status, detailSuffix(r.Detail))
		}
	}
}

func detailSuffix(detail string) string {
	if detail == "" {
		return ""
	}
	return " (" + detail + ")"
}
