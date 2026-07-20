package main

// GET /api/flows/services (#69 P2) — flow traffic attributed per defined service.
// QUERY-TIME attribution (deliberate, safe): one ClickHouse scan with a sumIf per
// service from its latest selector. We do NOT add a materialized view over
// netops.flows — a prior MV-over-flows regression broke ingestion (the flows_hourly
// incident). The materialized svc_flow_rollup is an OPTIMIZATION follow-up; this
// read-time path never touches the ingestion hot path.
//
// Injection-safe: only ints (ports/protocols, bounded) and shape-validated CIDRs
// are interpolated; service names/ids are NEVER put in SQL.

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// isCIDRToken allows an IPv4 CIDR or bare IPv4 (e.g. 10.0.0.0/8, 192.168.1.1).
// Shape-validate, never quote-escape (SR-011).
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

// buildSelectorCondition turns a selector spec into a ClickHouse boolean over the
// flows table. Pure + unit-tested. Returns ("", false) when the spec yields no
// safe predicate (so the caller marks the service unattributed rather than match
// everything).
func buildSelectorCondition(spec map[string]any) (string, bool) {
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

// flowsServicesScanSQL renders the one-scan attribution query. tenantClause is
// the addrTenantClauseFor fragment (" AND (src_addr IN … OR dst_addr IN …)" for
// a scoped principal, "" for cross-tenant) — it bounds the scan because the
// hybrid flows row policy alone does not isolate untagged rows.
func flowsServicesScanSQL(sel []string, sinceSec int, tenantClause string) string {
	return "SELECT " + strings.Join(sel, ", ") +
		" FROM netops.flows WHERE ts >= now() - INTERVAL " + intToString(sinceSec) + " SECOND" +
		tenantClause + " FORMAT JSON"
}

type svcFlowRow struct {
	ServiceID   string  `json:"service_id"`
	Name        string  `json:"name"`
	Criticality string  `json:"criticality"`
	Attributed  bool    `json:"attributed"` // false = no usable selector yet
	Bytes       float64 `json:"bytes"`
	Flows       float64 `json:"flows"`
}

func (s *server) handleFlowsServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	if s.services == nil {
		writeError(w, http.StatusNotImplemented, errServiceStoreOff)
		return
	}
	tenant, cross := principalTenant(claims)
	ctx := r.Context()
	svcs, err := s.services.ListServices(ctx, tenant, cross, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	rows := make([]svcFlowRow, 0, len(svcs))
	conds := make([]string, 0, len(svcs))
	idx := make([]int, 0, len(svcs)) // rows index for each cond
	for _, sv := range svcs {
		row := svcFlowRow{ServiceID: sv.ServiceID, Name: sv.Name, Criticality: sv.Criticality}
		sels, e := s.services.ListSelectors(ctx, tenant, cross, sv.ServiceID)
		if e == nil && len(sels) > 0 {
			if cond, has := buildSelectorCondition(sels[0].Spec); has { // sels[0] = latest (version DESC)
				row.Attributed = true
				conds = append(conds, cond)
				idx = append(idx, len(rows))
			}
		}
		rows = append(rows, row)
	}

	// One scan: sumIf/countIf per attributed service over the window. The flows
	// row policy shares untagged rows to every tenant scope (hybrid model), so
	// the scan is bounded to the caller's device addresses; a principal with no
	// visible devices skips the scan entirely (all totals stay 0, default-closed).
	tenantClause, noAddrs := s.addrTenantClauseFor(claims, "src_addr", "dst_addr")
	if len(conds) > 0 && !noAddrs {
		since := durationQuery(r, "since", time.Hour)
		var sel []string
		for i, cond := range conds {
			sel = append(sel,
				fmt.Sprintf("sumIf(bytes*if(sampling_rate=0,1,sampling_rate), %s) AS b%d", cond, i),
				fmt.Sprintf("countIf(%s) AS f%d", cond, i))
		}
		sql := flowsServicesScanSQL(sel, int(since.Seconds()), tenantClause)
		res, e := s.chRows(r, sql)
		if e != nil {
			writeError(w, http.StatusBadGateway, e)
			return
		}
		if len(res) > 0 {
			m := res[0]
			for i, ri := range idx {
				rows[ri].Bytes = asFloat(m[fmt.Sprintf("b%d", i)])
				rows[ri].Flows = asFloat(m[fmt.Sprintf("f%d", i)])
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": rows, "count": len(rows)})
}
