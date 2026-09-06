// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_costs.go — the cloud cost read surface (Wave 5 #18 slice 2).
//
//   GET /api/cloud/costs?provider=&account=&service=&from=&to=&limit=
//
// Serves the normalized daily cost records the cloud poller ingests from the
// providers' OWN cost APIs (AWS Cost Explorer / Azure Cost Management) into
// ClickHouse netops.cloud_costs via the netops.cloudcosts bus topic. Every row
// is a figure the provider itself billed; when nothing landed (no billing
// access connected), the endpoint returns an empty list and the UI shows its
// honest empty state — we never synthesize a cost.
//
// Tenant isolation (§3a): every query carries the caller's tenant_scope
// SETTINGS clause, enforced by the STRICT tenant_iso_cloud_costs row policy in
// ClickHouse itself (billing data is per-tenant financial data — no
// untagged-shared clause). Bounded (#100): the read is day-range-pruned
// (partitioned by (tenant_id, month)) with a hard window ceiling and a LIMIT.
//
// This file also owns the table's boot-converge DDL (cloudCostsSchemaDDL,
// appended to chConvergeStmts) so existing deployments converge without
// manual SQL — init.sql carries the identical DDL for fresh installs.

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"netops/backend/cloud"
)

func (s *server) handleCloudCosts(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET"))
		return
	}
	q := r.URL.Query()
	provider := strings.TrimSpace(q.Get("provider"))
	if provider != "" && !cloud.CostProviderOK(provider) {
		writeError(w, http.StatusBadRequest, errors.New("invalid provider"))
		return
	}
	account := strings.TrimSpace(q.Get("account"))
	if account != "" && !cloud.CostAccountOK(account) {
		writeError(w, http.StatusBadRequest, errors.New("invalid account"))
		return
	}
	service := cloud.ClampCostService(q.Get("service"))
	from, to, err := cloud.CostWindow(q.Get("from"), q.Get("to"), time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	limit := cloud.ClampCostLimit(q.Get("limit"))
	rows := chJSONRows[cloud.CostRow](cloud.CostsSQL(
		from, to, cloud.CostFilterSQL(provider, account, service), limit,
		cloud.SafeScopeLiteral(chTenantScope(r))))
	if rows == nil {
		rows = []cloud.CostRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"costs": rows,
		"count": len(rows),
		// the HONORED window — the UI label never claims a range the data
		// doesn't cover (clamps are echoed, never silent).
		"from":      from,
		"to":        to,
		"truncated": len(rows) == limit,
	})
}
