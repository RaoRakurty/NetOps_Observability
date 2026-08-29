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

// chRepartitionBudget bounds ONE migration statement. A per-partition copy is
// legitimately slower than a DDL: it is an INSERT ... SELECT over up to a day of
// one tenant's history. Bounded all the same (CLAUDE.md §9: all IO has a
// timeout) — a wedged copy must not hold the migration open forever.
const chRepartitionBudget = 10 * time.Minute

// chRepartitionExec implements chschema.CHExec over the chhttp seam.
type chRepartitionExec struct {
	base string
}

// Exec runs one migration statement.
//
// Scope is "__all__" because this is the trusted internal writer moving a
// tenant-partitioned table wholesale; the statements chschema emits ALSO carry
// an explicit `SETTINGS tenant_scope = '__all__'` so the copy cannot be reduced
// to zero rows by a policy if this seam is ever rewired (CLAUDE.md §3a).
func (e chRepartitionExec) Exec(ctx context.Context, sql string) error {
	_, err := chClientFor(e.base).Exec(ctx, chhttp.Request{
		SQL:        sql,
		Op:         "repartition",
		Scope:      "__all__",
		LogComment: "worker:corr-repartition",
		Budget:     chRepartitionBudget,
	})
	return err
}

// Query runs one migration SELECT. The statements chschema builds end in
// `FORMAT JSON`, so the response is ClickHouse's JSON envelope.
func (e chRepartitionExec) Query(ctx context.Context, sql string) ([]map[string]any, error) {
	body, err := chClientFor(e.base).Exec(ctx, chhttp.Request{
		SQL:        sql,
		Op:         "repartition query",
		Scope:      "__all__",
		LogComment: "worker:corr-repartition",
		Budget:     chRepartitionBudget,
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
	// the steady state on every boot after the first and would be pure noise.
	for _, r := range results {
		switch r.Status {
		case chschema.CorrRepartitionAlready, chschema.CorrRepartitionAbsent:
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
