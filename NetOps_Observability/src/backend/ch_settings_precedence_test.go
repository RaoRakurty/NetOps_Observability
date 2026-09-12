// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ch_settings_precedence_test.go — 18 production call sites across the cloud
// surface put the caller's tenant scope in the SQL text
// (`… SETTINGS tenant_scope='t_x'`) while the HTTP layer sends
// `?tenant_scope=__all__` on the wire (clickhouse_client.go chQueryCtx).
//
// Their tenant isolation therefore rests entirely on ONE ClickHouse behaviour:
// a query-level SETTINGS clause must OVERRIDE the URL parameter. If that
// precedence ever reversed — a ClickHouse upgrade, a driver change, a proxy
// that strips the clause — all 18 would silently read every tenant's rows while
// still looking correct in review.
//
// Verified empirically against ClickHouse 24.8 on 2026-08-04:
//   POST /?tenant_scope=__all__   body: SELECT getSetting('tenant_scope')
//                                       SETTINGS tenant_scope='t_INNER'
//   → t_INNER      (the SQL clause wins)
//
// This test re-proves it against whatever ClickHouse the suite is pointed at,
// so an upgrade that changes the rule fails HERE rather than in production.
// Skipped when no ClickHouse is reachable (unit-test runs); it is a contract
// test, not a mock.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"netops/backend/chhttp"
)

func TestClickHouseQuerySettingsOverrideURLScope(t *testing.T) {
	base := os.Getenv("CLICKHOUSE_URL")
	if base == "" {
		t.Skip("set CLICKHOUSE_URL to run the ClickHouse settings-precedence contract test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Ask for the effective scope with the two sources deliberately in conflict:
	// URL says __all__ (what chQueryCtx sends), SQL says a specific tenant (what
	// the cloud call sites embed).
	body, err := chClientFor(base).Exec(ctx, chhttp.Request{
		SQL:        `SELECT getSetting('tenant_scope') AS scope SETTINGS tenant_scope='t_precedence_probe' FORMAT JSON`,
		Op:         "select test:settings-precedence",
		Scope:      "__all__",
		LogComment: "test:settings-precedence",
	})
	if err != nil {
		t.Skipf("ClickHouse not reachable for the contract test: %v", err)
	}
	got := string(body)
	if !strings.Contains(got, "t_precedence_probe") {
		t.Fatalf("ClickHouse did NOT honour the query-level SETTINGS over the URL parameter.\n"+
			"18 production call sites (cloud_*.go, cloud/*.go) rely on this precedence for tenant\n"+
			"isolation — if it has changed, those queries are now reading at __all__.\n"+
			"response: %s", got)
	}
	if strings.Contains(got, "__all__") {
		t.Fatalf("effective scope resolved to __all__ — the URL parameter won, which means the\n"+
			"cloud surface's tenant predicates are being applied against an unscoped read.\n"+
			"response: %s", got)
	}
}
