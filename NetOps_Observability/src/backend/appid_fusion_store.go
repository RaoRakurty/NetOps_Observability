package main

import (
	"bytes"
	"context"
	"encoding/json"
	"netops/backend/appid"

	"netops/backend/chhttp"
)

// appid_fusion_store.go — #81 Fusion Layer Phase 4 persistence. A non-request-scoped
// ClickHouse client (the fusion worker runs in the background, not per-request) that
// batch-writes app_observations + app_identities and reads recent observations. Writes
// are idempotent (deterministic ids → ReplacingMergeTree dedups), so re-ingest/replay
// is safe. No new dependency — stdlib net/http over the CH HTTP interface, the same
// transport proxyClickHouse uses.

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
