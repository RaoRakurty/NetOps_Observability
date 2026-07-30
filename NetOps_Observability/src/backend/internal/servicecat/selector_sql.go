package servicecat

// selector_sql.go — the selector-spec → ClickHouse flow-condition compiler
// (Phase-2 W4.8, extracted from package main's flows_services.go): shape-
// validated CIDR/port/protocol/ASN/domain predicates folded into an
// injection-safe WHERE clause, and the bounded per-service scan SQL. The
// handler and its tenant clause stay in main.

import (
	"strconv"
	"strings"
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
