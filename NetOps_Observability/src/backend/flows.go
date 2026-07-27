package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netops/backend/chhttp"
	"netops/backend/internal/chschema"
)

// isAlphaToken reports whether s is non-empty and contains only ASCII letters.
// Used to allowlist enum-like query parameters (e.g. severity) before they are
// interpolated into a ClickHouse string literal — quote-stripping is not enough
// because ClickHouse honors backslash escapes (SR-011).
func isAlphaToken(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// flows.go — ClickHouse-backed analytics endpoints.
//
// The full flow stream lands in ClickHouse via vector-router (table
// netops.flows). These handlers run a small set of pre-defined queries
// against it. Keeping the SQL on the server side prevents SQL injection
// from the SPA and makes it cheap to swap the implementation for a
// materialized view or a dedicated rollup table later.

func (s *server) handleFlowsTopTalkers(w http.ResponseWriter, r *http.Request) {
	limit, errLimit := intQuery(r, "limit", 20, 1, 500)
	if errLimit != nil {
		writeError(w, http.StatusBadRequest, errLimit)
		return
	}
	since := durationQuery(r, "since", time.Hour)

	tenantClause, empty := s.flowTenantClause(r)
	if empty {
		writeEmptyClickHouse(w)
		return
	}
	filter, err := flowFilterClause(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Bidirectional folding: a conversation A↔B is one row regardless of who
	// initiated, by grouping on the ordered address pair (least/greatest).
	srcExpr, dstExpr := "src_addr", "dst_addr"
	if strings.ToLower(strings.TrimSpace(r.URL.Query().Get("direction"))) == "bi" {
		srcExpr, dstExpr = "least(src_addr, dst_addr)", "greatest(src_addr, dst_addr)"
	}
	sql := `
SELECT ` + srcExpr + ` AS src,
       ` + dstExpr + ` AS dst,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate))   AS bytes_total,
       sum(packets * if(sampling_rate = 0, 1, sampling_rate)) AS packets_total,
       count() AS flows
  FROM netops.flows
 WHERE ts >= now() - INTERVAL ` + intToString(int(since.Seconds())) + ` SECOND` + tenantClause + flowTypeClause(r) + filter + `
 GROUP BY src, dst
 ORDER BY bytes_total DESC
 LIMIT ` + intToString(limit) + `
 FORMAT JSON`
	proxyClickHouse(w, r, sql)
}

// flowTopDim describes one allowlisted top-N grouping dimension: the SQL
// expression to GROUP BY (aliased `k`), and an optional column that must be
// > 0 to drop noise rows (e.g. port 0 / AS 0 / interface 0). The client never
// supplies SQL — only the map key (?by=), so this is injection-safe.
type flowTopDim struct {
	expr    string
	nonzero string
}

var flowTopDims = map[string]flowTopDim{
	"device":   {"sampler_address", ""},
	"in_if":    {"toString(in_if)", "in_if"},
	"out_if":   {"toString(out_if)", "out_if"},
	"src_addr": {"src_addr", ""},
	"dst_addr": {"dst_addr", ""},
	"src_as":   {"toString(src_as)", "src_as"},
	"dst_as":   {"toString(dst_as)", "dst_as"},
	"src_port": {"toString(src_port)", "src_port"},
	"dst_port": {"toString(dst_port)", "dst_port"},
	"proto":    {"toString(proto)", ""},
}

// handleFlowsTopN is the generic top-N-by-dimension endpoint backing the NetFlow
// dashboard's many "Top <thing>" panels (devices, interfaces, IPs, AS, ports,
// protocols). One parametrized route (?by=) instead of a handler per panel keeps
// the SQL server-side and the dimension set allowlisted. Returns rows of
// {k, bytes_total, packets_total, flows} ordered by bytes desc.
func (s *server) handleFlowsTopN(w http.ResponseWriter, r *http.Request) {
	dim, ok := flowTopDims[strings.ToLower(strings.TrimSpace(r.URL.Query().Get("by")))]
	if !ok {
		writeError(w, http.StatusBadRequest, errors.New("invalid 'by' dimension"))
		return
	}
	limit, errLimit := intQuery(r, "limit", 20, 1, 500)
	if errLimit != nil {
		writeError(w, http.StatusBadRequest, errLimit)
		return
	}
	since := durationQuery(r, "since", time.Hour)
	tenantClause, empty := s.flowTenantClause(r)
	if empty {
		writeEmptyClickHouse(w)
		return
	}
	filter, err := flowFilterClause(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	nz := ""
	if dim.nonzero != "" {
		nz = " AND " + dim.nonzero + " > 0"
	}
	sql := `
SELECT ` + dim.expr + ` AS k,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate))   AS bytes_total,
       sum(packets * if(sampling_rate = 0, 1, sampling_rate)) AS packets_total,
       count() AS flows
  FROM netops.flows
 WHERE ts >= now() - INTERVAL ` + intToString(int(since.Seconds())) + ` SECOND` + tenantClause + flowTypeClause(r) + filter + nz + `
 GROUP BY k
 ORDER BY bytes_total DESC
 LIMIT ` + intToString(limit) + `
 FORMAT JSON`
	proxyClickHouse(w, r, sql)
}

// handleFlowsFanout powers flow-based threat detection: per source address, the
// count of distinct destination hosts and distinct destination ports it touched
// in the window — the classic horizontal-scan (many hosts) / vertical-scan (many
// ports) signal. Pure IPFIX/NetFlow, no new collection. ?sort=hosts|ports picks
// the ordering column (server-side allowlist, injection-safe).
func (s *server) handleFlowsFanout(w http.ResponseWriter, r *http.Request) {
	limit, errLimit := intQuery(r, "limit", 15, 1, 200)
	if errLimit != nil {
		writeError(w, http.StatusBadRequest, errLimit)
		return
	}
	since := durationQuery(r, "since", time.Hour)
	tenantClause, empty := s.flowTenantClause(r)
	if empty {
		writeEmptyClickHouse(w)
		return
	}
	filter, err := flowFilterClause(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	order := "dst_count"
	if strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort"))) == "ports" {
		order = "port_count"
	}
	sql := `
SELECT src_addr AS k,
       uniqExact(dst_addr) AS dst_count,
       uniqExact(dst_port) AS port_count,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate)) AS bytes_total,
       count() AS flows
  FROM netops.flows
 WHERE ts >= now() - INTERVAL ` + intToString(int(since.Seconds())) + ` SECOND` + tenantClause + flowTypeClause(r) + filter + `
 GROUP BY k
 ORDER BY ` + order + ` DESC
 LIMIT ` + intToString(limit) + `
 FORMAT JSON`
	proxyClickHouse(w, r, sql)
}

// handleFlowsFlags breaks TCP traffic down by tcp_flags combination
// (tcpControlBits, IPFIX IE6 — captured by goflow2 into the netops.flows
// tcp_flags column). Returns one row per distinct flag combo with scaled
// byte/packet/flow totals; the UI decodes the bitmask into SYN/ACK/FIN/RST…
// names and derives scan/reset heuristics. proto=6 only — flags are
// meaningless for non-TCP flows.
func (s *server) handleFlowsFlags(w http.ResponseWriter, r *http.Request) {
	limit, errLimit := intQuery(r, "limit", 20, 1, 100)
	if errLimit != nil {
		writeError(w, http.StatusBadRequest, errLimit)
		return
	}
	since := durationQuery(r, "since", time.Hour)
	tenantClause, empty := s.flowTenantClause(r)
	if empty {
		writeEmptyClickHouse(w)
		return
	}
	filter, err := flowFilterClause(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sql := `
SELECT tcp_flags,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate))   AS bytes_total,
       sum(packets * if(sampling_rate = 0, 1, sampling_rate)) AS packets_total,
       count() AS flows
  FROM netops.flows
 WHERE ts >= now() - INTERVAL ` + intToString(int(since.Seconds())) + ` SECOND
   AND proto = 6` + tenantClause + flowTypeClause(r) + filter + `
 GROUP BY tcp_flags
 ORDER BY flows DESC
 LIMIT ` + intToString(limit) + `
 FORMAT JSON`
	proxyClickHouse(w, r, sql)
}

// geoDictReady probes the geoip_country ip_trie dictionary with a single
// dictGetOrDefault. The dictionary is created lazily at bootstrap even when the
// operator hasn't supplied the CSV (licensing forbids bundling GeoIP data), so
// existence says nothing — only a successful lookup proves it loads. The probe
// is one in-memory trie hit per request (sub-ms once loaded); deliberately
// stateless rather than cached so a freshly dropped CSV lights the panels up on
// their next refresh with no staleness window.
func (s *server) geoDictReady() bool {
	base := envOr("CLICKHOUSE_URL", "")
	if base == "" {
		return false
	}
	return chExec(base, `SELECT dictGetOrDefault('netops.geoip_country', 'country', tuple(IPv6StringToNum('192.0.2.1')), '')`)
}

// handleFlowsGeo aggregates flow traffic by country of the initiator
// (?dim=src, default) or responder (?dim=dst), resolved at query time through
// the geoip_country dictionary. Addresses the dataset doesn't cover (RFC 1918,
// CGNAT, unallocated) come back as country ” — kept in the result so the UI
// can report the public-traffic share honestly instead of hiding it. When the
// dictionary has no data yet the response is {"data":[],"geo_enabled":false}
// and the UI renders onboarding guidance instead of an empty chart.
func (s *server) handleFlowsGeo(w http.ResponseWriter, r *http.Request) {
	col := "src_addr"
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("dim"))) {
	case "", "src":
	case "dst":
		col = "dst_addr"
	default:
		writeError(w, http.StatusBadRequest, errors.New("invalid 'dim' (want src|dst)"))
		return
	}
	// Countries are bounded (~250), so the default limit returns the full
	// distribution and the UI can compute exact share stats client-side.
	limit, errLimit := intQuery(r, "limit", 300, 1, 500)
	if errLimit != nil {
		writeError(w, http.StatusBadRequest, errLimit)
		return
	}
	since := durationQuery(r, "since", time.Hour)
	tenantClause, empty := s.flowTenantClause(r)
	if empty {
		writeEmptyClickHouse(w)
		return
	}
	filter, err := flowFilterClause(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.geoDictReady() {
		writeJSON(w, http.StatusOK, map[string]any{"data": []any{}, "geo_enabled": false})
		return
	}
	sql := `
SELECT dictGetOrDefault('netops.geoip_country', 'country', tuple(IPv6StringToNum(` + col + `)), '') AS country,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate))   AS bytes_total,
       sum(packets * if(sampling_rate = 0, 1, sampling_rate)) AS packets_total,
       count() AS flows
  FROM netops.flows
 WHERE ts >= now() - INTERVAL ` + intToString(int(since.Seconds())) + ` SECOND
   AND IPv6StringToNumOrNull(` + col + `) IS NOT NULL` + tenantClause + flowTypeClause(r) + filter + `
 GROUP BY country
 ORDER BY bytes_total DESC
 LIMIT ` + intToString(limit) + `
 FORMAT JSON`
	proxyClickHouse(w, r, sql)
}

func (s *server) handleFlowsByProto(w http.ResponseWriter, r *http.Request) {
	since := durationQuery(r, "since", time.Hour)
	tenantClause, empty := s.flowTenantClause(r)
	if empty {
		writeEmptyClickHouse(w)
		return
	}
	filter, err := flowFilterClause(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sql := `
SELECT proto,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate))   AS bytes_total,
       sum(packets * if(sampling_rate = 0, 1, sampling_rate)) AS packets_total,
       count() AS flows
  FROM netops.flows
 WHERE ts >= now() - INTERVAL ` + intToString(int(since.Seconds())) + ` SECOND` + tenantClause + flowTypeClause(r) + filter + `
 GROUP BY proto
 ORDER BY bytes_total DESC
 FORMAT JSON`
	proxyClickHouse(w, r, sql)
}

// handleFlowsByType breaks traffic down by flow-protocol family
// (netflow / ipfix / sflow) using the flow_type column the vector-router VRL
// derives from goflow2's `type`. Lets the UI prove all three flow sources are
// actually arriving, not just "flows".
func (s *server) handleFlowsByType(w http.ResponseWriter, r *http.Request) {
	since := durationQuery(r, "since", time.Hour)
	tenantClause, empty := s.flowTenantClause(r)
	if empty {
		writeEmptyClickHouse(w)
		return
	}
	sql := `
SELECT flow_type,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate))   AS bytes_total,
       sum(packets * if(sampling_rate = 0, 1, sampling_rate)) AS packets_total,
       count() AS flows,
       uniqExact(sampler_address) AS exporters
  FROM netops.flows
 WHERE ts >= now() - INTERVAL ` + intToString(int(since.Seconds())) + ` SECOND` + tenantClause + `
 GROUP BY flow_type
 ORDER BY flows DESC
 FORMAT JSON`
	proxyClickHouse(w, r, sql)
}

func (s *server) handleFlowsTimeseries(w http.ResponseWriter, r *http.Request) {
	since := durationQuery(r, "since", time.Hour)
	step := durationQuery(r, "step", time.Minute)
	tenantClause, empty := s.flowTenantClause(r)
	if empty {
		writeEmptyClickHouse(w)
		return
	}
	filter, err := flowFilterClause(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sql := `
SELECT toStartOfInterval(ts, INTERVAL ` + intToString(int(step.Seconds())) + ` SECOND) AS bucket,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate))   AS bytes_total,
       sum(packets * if(sampling_rate = 0, 1, sampling_rate)) AS packets_total
  FROM netops.flows
 WHERE ts >= now() - INTERVAL ` + intToString(int(since.Seconds())) + ` SECOND` + tenantClause + flowTypeClause(r) + filter + `
 GROUP BY bucket
 ORDER BY bucket
 FORMAT JSON`
	proxyClickHouse(w, r, sql)
}

func (s *server) handleFindings(w http.ResponseWriter, r *http.Request) {
	limit, errLimit := intQuery(r, "limit", 100, 1, 1000)
	if errLimit != nil {
		writeError(w, http.StatusBadRequest, errLimit)
		return
	}
	sev := r.URL.Query().Get("severity")
	var conds []string
	if sev != "" {
		// SR-011: severity must be an allowlisted alphabetic token. Quote-stripping
		// alone is unsafe — ClickHouse honors backslash escapes, so a value ending
		// in `\` would escape the closing quote and break out of the string literal.
		// (The Python correlation service guards this exact case with .isalpha().)
		// Tenant isolation is independently enforced by ClickHouse row policies, but
		// we still must not let the query shape be attacker-controlled.
		if !isAlphaToken(sev) {
			writeError(w, http.StatusBadRequest, errors.New("invalid severity"))
			return
		}
		conds = append(conds, "severity = '"+sev+"'")
	}
	// Tenant isolation: a scoped principal only sees findings on devices it can
	// view (matched by the finding's `device` column against the device id/name).
	claims, _ := userFrom(r.Context())
	// Compliance (operator-visibility): deny if the operator scoped into a
	// restricted tenant; in the Global view exclude restricted tenants' devices.
	rt := s.restrictedTelemetry(claims)
	if rt.deny {
		writeEmptyClickHouse(w)
		return
	}
	if keys, cross := s.visibleDeviceKeys(claims); !cross {
		if len(keys) == 0 {
			writeEmptyClickHouse(w)
			return
		}
		conds = append(conds, "device IN ("+sqlInList(keys)+")")
	} else if len(rt.keys) > 0 {
		conds = append(conds, "device NOT IN ("+sqlInList(rt.keys)+")")
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ") + " "
	}
	sql := `
SELECT ` + chschema.ISO("ts") + ` AS ts, id, kind, severity, score, device,
       component, summary, description
  FROM netops.findings
` + where + `
 ORDER BY ts DESC
 LIMIT ` + intToString(limit) + `
 FORMAT JSON`
	proxyClickHouse(w, r, sql)
}

// isIPish reports whether s looks like an IPv4/IPv6 literal — digits, hex
// letters, dots and colons only. Used to allowlist address/device filter params
// before they are interpolated into a ClickHouse string literal (quote-escaping
// alone is not enough; ClickHouse honors backslash escapes — SR-011).
func isIPish(s string) bool {
	if s == "" || len(s) > 45 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F', c == '.', c == ':':
		default:
			return false
		}
	}
	return true
}

// flowFilterClause builds an injection-safe AND-fragment from the optional
// filter-bar params: src/dst address + exporter device (allowlisted via isIPish,
// then quote-escaped) and ingress/egress interface ids (parsed as integers). A
// malformed value is a 400 (returned error), never silently dropped.
func flowFilterClause(r *http.Request) (string, error) {
	q := r.URL.Query()
	var conds []string
	for _, f := range []struct{ param, col string }{
		{"src", "src_addr"}, {"dst", "dst_addr"}, {"device", "sampler_address"},
	} {
		v := strings.TrimSpace(q.Get(f.param))
		if v == "" {
			continue
		}
		if !isIPish(v) {
			return "", errors.New("invalid filter value for " + f.param)
		}
		conds = append(conds, f.col+" = '"+strings.ReplaceAll(v, "'", "''")+"'")
	}
	for _, f := range []struct{ param, col string }{
		{"in_if", "in_if"}, {"out_if", "out_if"},
	} {
		v := strings.TrimSpace(q.Get(f.param))
		if v == "" {
			continue
		}
		n, err := parseIntStrict(v)
		if err != nil || n < 0 {
			return "", errors.New("invalid filter value for " + f.param)
		}
		conds = append(conds, f.col+" = "+intToString(n))
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " AND " + strings.Join(conds, " AND "), nil
}

// flowTypeClause restricts flow rows to a single source family when ?type= is
// one of netflow|ipfix|sflow. The returned fragment uses only server-side
// literals (never the raw query value), so it is injection-safe; any other
// value yields no clause (= all sources).
func flowTypeClause(r *http.Request) string {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type"))) {
	case "netflow":
		return " AND flow_type = 'netflow'"
	case "ipfix":
		return " AND flow_type = 'ipfix'"
	case "sflow":
		return " AND flow_type = 'sflow'"
	default:
		return ""
	}
}

// flowTenantClause builds the SQL fragment that restricts flow rows to a scoped
// principal's devices (matched on src_addr/dst_addr). It returns ("", false) for
// cross-tenant principals (no restriction) and ("", true) when the principal has
// no visible device addresses (caller should short-circuit to an empty result).
func (s *server) flowTenantClause(r *http.Request) (clause string, empty bool) {
	claims, _ := userFrom(r.Context())
	return s.addrTenantClauseFor(claims, "src_addr", "dst_addr")
}

// addrTenantClauseFor is the claims-based core of flowTenantClause, shared with
// the AI DataSource (which has claims, not a request). The CH row policies share
// untagged telemetry rows to every tenant scope by design (hybrid model), so THIS
// app-layer narrowing is the isolation for untagged rows — a scoped principal
// reads only rows touching its own device addresses, and a principal with no
// devices reads nothing (default-closed).
func (s *server) addrTenantClauseFor(claims jwtClaims, srcCol, dstCol string) (clause string, empty bool) {
	addrs, cross := s.visibleDeviceAddrs(claims)
	// Compliance (operator-visibility): deny if the operator scoped into a
	// restricted tenant; in the Global view exclude restricted tenants' devices.
	if rt := s.restrictedTelemetry(claims); rt.deny {
		return "", true
	} else if cross {
		if len(rt.addrs) > 0 {
			in := sqlInList(rt.addrs)
			return " AND " + srcCol + " NOT IN (" + in + ") AND " + dstCol + " NOT IN (" + in + ")", false
		}
		return "", false
	}
	if len(addrs) == 0 {
		return "", true
	}
	in := sqlInList(addrs)
	return " AND (" + srcCol + " IN (" + in + ") OR " + dstCol + " IN (" + in + "))", false
}

// deviceTenantCondFor is the device-keyed sibling of addrTenantClauseFor for
// tables keyed by a device name column (findings). Same hybrid-model contract:
// scoped principal → only its own devices' rows; no devices → nothing.
func (s *server) deviceTenantCondFor(claims jwtClaims, col string) (cond string, empty bool) {
	keys, cross := s.visibleDeviceKeys(claims)
	if rt := s.restrictedTelemetry(claims); rt.deny {
		return "", true
	} else if cross {
		if len(rt.keys) > 0 {
			return col + " NOT IN (" + sqlInList(rt.keys) + ")", false
		}
		return "", false
	}
	if len(keys) == 0 {
		return "", true
	}
	return col + " IN (" + sqlInList(keys) + ")", false
}

// sqlInList renders values as a quoted, comma-separated SQL list with single
// quotes escaped. Inputs come from the device inventory (not the client), but we
// escape regardless to keep the query well-formed and injection-safe.
func sqlInList(vals []string) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, "'"+strings.ReplaceAll(v, "'", "''")+"'")
	}
	return strings.Join(parts, ", ")
}

// writeEmptyClickHouse emits an empty result set in the same envelope shape the
// ClickHouse HTTP JSON format uses, so the SPA's `.data` access is unaffected.
func writeEmptyClickHouse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
}

// handleTunnels returns the latest sample for each overlay tunnel (IPsec /
// SD-WAN / GRE) the collectors have reported, newest first. "LIMIT 1 BY id"
// collapses the time series to the current state per tunnel. Optional
// ?status=up|down filters; ?limit caps the rows. Empty until a collector
// populates netops.tunnels — the view renders whatever real data arrives.
func (s *server) handleTunnels(w http.ResponseWriter, r *http.Request) {
	limit, errLimit := intQuery(r, "limit", 200, 1, 2000)
	if errLimit != nil {
		writeError(w, http.StatusBadRequest, errLimit)
		return
	}
	var conds []string
	if st := r.URL.Query().Get("status"); st == "up" || st == "down" {
		conds = append(conds, "status = '"+st+"'")
	}
	// Tenant isolation: a scoped principal only sees tunnels terminating on a
	// device it can view (local or remote endpoint).
	claims, _ := userFrom(r.Context())
	if keys, cross := s.visibleDeviceKeys(claims); !cross {
		if len(keys) == 0 {
			writeEmptyClickHouse(w)
			return
		}
		in := sqlInList(keys)
		conds = append(conds, "(local_device IN ("+in+") OR remote_device IN ("+in+"))")
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ") + " "
	}
	sql := `
SELECT id, type, local_device, local_addr, remote_device, remote_addr,
       status, latency_ms, jitter_ms, loss_pct, qoe, uptime_s,
       ` + chschema.ISO("ts") + ` AS ts
  FROM netops.tunnels
` + where + `
 ORDER BY ts DESC
 LIMIT 1 BY id
 LIMIT ` + intToString(limit) + `
 FORMAT JSON`
	proxyClickHouse(w, r, sql)
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
	defer func() { _ = body.Close() }()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, body)
}

// intQuery parses a bounded integer query parameter.
//
// F-71 (High): this used to FAIL OPEN — a malformed or out-of-range value
// silently returned the DEFAULT. Measured on /api/flows/top: limit=500 gave 500
// rows, limit=501 gave 20, limit=5000 gave 20, limit=abc gave 20, and never an
// error. A client paginating by doubling collapses to the default at step 4 and
// renders a fraction of the traffic as the whole picture. Silently returning
// FEWER results than were asked for is indistinguishable, at the client, from
// "that is all the data there is" — which is why this class is invisible.
//
// Out-of-range and unparseable now FAIL CLOSED with a message naming the key
// and its bounds. An ABSENT parameter still takes the default: that is the
// documented contract and every caller relies on it.
func intQuery(r *http.Request, key string, def, min, max int) (int, error) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def, nil
	}
	n, err := parseIntStrict(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", key, min, max)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("%s must be between %d and %d (got %d)", key, min, max, n)
	}
	return n, nil
}

func durationQuery(r *http.Request, key string, def time.Duration) time.Duration {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 || d > 30*24*time.Hour {
		return def
	}
	return d
}

// parseIntStrict parses a decimal integer and rejects ANY trailing garbage.
//
// It previously used fmt.Sscanf("%d"), which is not strict despite the name:
// Sscanf stops at the first character that does not fit the verb and reports
// success for what it consumed. So "1e3" parsed as 1, "100x" as 100, and
// "5 OR 1=1" as 5 — each silently becoming a DIFFERENT number than the caller
// sent, with no error. Combined with intQuery that produced `?limit=1e3`
// returning a single row. strconv.Atoi consumes the whole string or fails.
func parseIntStrict(s string) (int, error) {
	return strconv.Atoi(s)
}

func intToString(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// fmtSscanf is a tiny wrapper around fmt.Sscanf so we can keep the
// import block narrow. It's defined here so flows.go doesn't pull in
// the fmt package twice (main.go already imports it).
var fmtSscanf = func(s, format string, a ...any) (int, error) {
	return fmtSscanfImpl(s, format, a...)
}
