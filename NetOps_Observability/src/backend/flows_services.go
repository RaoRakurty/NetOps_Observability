package backend

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
	"time"

	"netops/backend/internal/servicecat"
)

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
			if cond, has := servicecat.BuildSelectorCondition(sels[0].Spec); has { // sels[0] = latest (version DESC)
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
		sql := servicecat.FlowScanSQL(sel, int(since.Seconds()), tenantClause)
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
