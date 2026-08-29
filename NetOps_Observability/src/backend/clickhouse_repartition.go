package backend

// clickhouse_repartition.go — the transport adapter for the corr_* daily
// re-partition migration (internal/chschema/corr_repartition.go).
//
// chschema owns the migration's LOGIC and every SQL string it emits, with no
// transport and no environment of its own; this file is the (deliberately thin)
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

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"netops/backend/chhttp"
	"netops/backend/internal/chschema"
)

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
