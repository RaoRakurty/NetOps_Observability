// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package servicecat

// selector_sql.go — the selector-spec → ClickHouse flow-condition compiler
// (Phase-2 W4.8, extracted from package main's flows_services.go): shape-
// validated CIDR/port/protocol/ASN/domain predicates folded into an
// injection-safe WHERE clause, and the bounded per-service scan SQL. The
// handler and its tenant clause stay in main.

import (
	"strconv"
	"strings"
	"time"
)

func isCIDRToken(s string) bool {
	host, mask, hasMask := strings.Cut(s, "/")
	if hasMask {
		m, err := strconv.Atoi(mask)
		if err != nil || m < 0 || m > 32 {
			return false
		}
	}
	octets := strings.Split(host, ".")
	if len(octets) != 4 {
		return false
	}
	for _, o := range octets {
		n, err := strconv.Atoi(o)
		if err != nil || n < 0 || n > 255 || (len(o) > 1 && o[0] == '0') {
			return false
		}
	}
	return true
}

// intList extracts bounded ints from a JSON array value (numbers arrive float64).
func intList(v any, lo, hi int) []int {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]int, 0, len(arr))
	for _, e := range arr {
		var n int
		switch x := e.(type) {
		case float64:
			n = int(x)
		case string:
			p, err := strconv.Atoi(x)
			if err != nil {
				continue
			}
			n = p
		default:
			continue
		}
		if n >= lo && n <= hi {
			out = append(out, n)
		}
	}
	return out
}

func strList(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, ",")
}

// BuildSelectorCondition turns a selector spec into a ClickHouse boolean over the
// flows table. Pure + unit-tested. Returns ("", false) when the spec yields no
// safe predicate (so the caller marks the service unattributed rather than match
// everything).
func BuildSelectorCondition(spec map[string]any) (string, bool) {
	var ors []string
	if ports := intList(spec["ports"], 0, 65535); len(ports) > 0 {
		ors = append(ors, "dst_port IN ("+joinInts(ports)+")")
	}
	for _, c := range strList(spec["dst_prefixes"]) {
		if isCIDRToken(c) {
			ors = append(ors, "isIPAddressInRange(dst_addr, '"+c+"')")
		}
	}
	if protos := intList(spec["protocols"], 0, 255); len(protos) > 0 {
		// netops.flows column is `proto` (goflow2 field name) — `protocol` was a
		// latent UNKNOWN_IDENTIFIER (#69 P2 fix; svc_rollup_worker reuses this).
		ors = append(ors, "proto IN ("+joinInts(protos)+")")
	}
	if len(ors) == 0 {
		return "", false
	}
	return "(" + strings.Join(ors, " OR ") + ")", true
}

// FlowScanSQL renders the one-scan attribution query. tenantClause is
// the addrTenantClauseFor fragment (" AND (src_addr IN … OR dst_addr IN …)" for
// a scoped principal, "" for cross-tenant) — it bounds the scan because the
// hybrid flows row policy alone does not isolate untagged rows.
func FlowScanSQL(sel []string, sinceSec int, tenantClause string) string {
	return "SELECT " + strings.Join(sel, ", ") +
		" FROM netops.flows WHERE ts >= now() - INTERVAL " + strconv.Itoa(sinceSec) + " SECOND" +
		tenantClause + " FORMAT JSON"
}

// isUUIDToken mirrors main's SR-011 shape validator (duplicated test fixture —
// test files cannot cross packages).
func isUUIDToken(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			switch {
			case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			default:
				return false
			}
		}
	}
	return true
}

// ── rollup SQL (Phase-2 W4.11, from main's svc_rollup_worker.go) ─────────────

func SQLStringLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// RollupInsertSQL renders the single per-tenant attribution statement for
// minutes [from, to] (inclusive minute buckets, i.e. ts ∈ [from, to+1m)).
// Pure + unit-tested. Every branch stamps ONLY the given tenant and reads only
// rows the tenant may claim: its tagged rows, plus untagged rows bounded by
// addrClause ("" = tenant has no visible devices → tagged rows only).
func RollupInsertSQL(tenant string, sets []SelectorSet, from, to time.Time, addrClause, rolledBy string) (string, int) {
	tl := SQLStringLiteral(tenant)
	tenantPred := "tenant_id = " + tl
	if addrClause != "" {
		// addrClause arrives in addrTenantClauseFor's " AND (src_addr IN … OR …)"
		// form; embed it as the untagged-row bound.
		tenantPred = "(tenant_id = " + tl + " OR (tenant_id = ''" + addrClause + "))"
	}
	fromU := strconv.FormatInt(from.Unix(), 10)
	toU := strconv.FormatInt(to.Add(time.Minute).Unix(), 10)
	var selects []string
	for _, set := range sets {
		if !isUUIDToken(set.ServiceID) {
			continue // never interpolate a malformed id (store-sourced, but §3 zero-trust)
		}
		cond, ok := BuildSelectorCondition(set.Spec)
		if !ok {
			continue // no usable predicate → service stays unattributed (honest)
		}
		selects = append(selects,
			"SELECT "+tl+" AS tenant_id, toStartOfMinute(ts) AS minute, toUUID("+SQLStringLiteral(set.ServiceID)+") AS service_id, "+
				"toUInt32("+strconv.Itoa(set.Version)+") AS selector_version, '' AS seam_id, "+SQLStringLiteral(rolledBy)+" AS rolled_by, "+
				"toUInt64(sum(bytes * if(sampling_rate = 0, 1, sampling_rate))) AS bytes, "+
				"toUInt64(sum(packets * if(sampling_rate = 0, 1, sampling_rate))) AS packets, "+
				"toUInt64(count()) AS flows "+
				"FROM netops.flows WHERE ts >= toDateTime("+fromU+") AND ts < toDateTime("+toU+") AND "+
				tenantPred+" AND "+cond+" GROUP BY minute")
	}
	if len(selects) == 0 {
		return "", 0
	}
	return "INSERT INTO netops.svc_flow_rollup_1m (tenant_id, minute, service_id, selector_version, seam_id, rolled_by, bytes, packets, flows) " +
		strings.Join(selects, " UNION ALL "), len(selects)
}

// svcRollupWorker materializes the rollup. All IO is injectable for tests.
