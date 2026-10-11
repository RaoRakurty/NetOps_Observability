// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/chschema"
	"netops/backend/models"
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
	s.proxyClickHouse(w, r, sql)
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
	// service_port is the LIKELY service end of a conversation, "<proto>/<port>":
	// the lower of the two ports, since a client speaks from an ephemeral (high)
	// port to the service's (low) one. It folds a conversation's two directions —
	// request (dst_port = service) and reply (src_port = service) — into one row.
	// A heuristic, and labelled as one wherever it is shown; never an app name.
	"service_port": {"concat(toString(proto), '/', toString(least(src_port, dst_port)))", "least(src_port, dst_port)"},
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
	s.proxyClickHouse(w, r, sql)
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
	s.proxyClickHouse(w, r, sql)
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
	s.proxyClickHouse(w, r, sql)
}

// handleFlowsCoverage says what the flows in the window CAN show, so every
// Explore Flows tab explains an empty panel instead of claiming "no flow
// records" (owner report 2026-10-10: AS, Geo, Flags, Applications were empty
// while 29k flows/hour arrived). One scan, the SAME tenant clause and
// flow-type filter as the tabs it explains, so it can never count rows a tab
// could not show.
func (s *server) handleFlowsCoverage(w http.ResponseWriter, r *http.Request) {
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
	priv := func(col string) string {
		return "(isIPAddressInRange(" + col + ", '10.0.0.0/8') OR isIPAddressInRange(" + col + ", '172.16.0.0/12')" +
			" OR isIPAddressInRange(" + col + ", '192.168.0.0/16') OR isIPAddressInRange(" + col + ", '100.64.0.0/10')" +
			" OR isIPAddressInRange(" + col + ", '127.0.0.0/8') OR isIPAddressInRange(" + col + ", '169.254.0.0/16')" +
			" OR isIPAddressInRange(" + col + ", 'fc00::/7') OR isIPAddressInRange(" + col + ", 'fe80::/10'))"
	}
	sql := `
SELECT count()                                       AS flows,
       countIf(proto = 6)                            AS tcp_flows,
       countIf(proto = 6 AND tcp_flags > 0)          AS tcp_flows_with_flags,
       countIf(src_as > 0 OR dst_as > 0)             AS flows_with_as,
       countIf(` + priv("src_addr") + ` AND ` + priv("dst_addr") + `) AS private_only_flows,
       uniqExact(sampler_address)                    AS exporters
  FROM netops.flows
 WHERE ts >= now() - INTERVAL ` + intToString(int(since.Seconds())) + ` SECOND` + tenantClause + flowTypeClause(r) + filter + `
 FORMAT JSON`
	s.proxyClickHouse(w, r, sql)
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
	s.proxyClickHouse(w, r, sql)
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
	s.proxyClickHouse(w, r, sql)
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
	s.proxyClickHouse(w, r, sql)
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
	s.proxyClickHouse(w, r, sql)
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
	// Alias-shadowing guard (tracker 200, the 1c402b5c/dda24f37 class): the
	// projection aliases the ISO conversion back onto `ts` because `ts` is the
	// served wire field — renaming it would change the API. ClickHouse resolves
	// a SELECT alias INSIDE the WHERE/ORDER BY of the same query, so ORDER BY
	// must name a TABLE-QUALIFIED column (alias resolution does not touch a
	// qualified name) or it sorts the ISO String instead of the DateTime. Latent
	// today (RFC 3339 text happens to sort like the instant); the next range
	// predicate on `ts` would be code 386 NO_COMMON_TYPE.
	sql := `
SELECT ` + chschema.ISO("f.ts") + ` AS ts, id, kind, severity, score, device,
       component, summary, description
  FROM netops.findings AS f
` + where + `
 ORDER BY f.ts DESC
 LIMIT ` + intToString(limit) + `
 FORMAT JSON`
	s.proxyClickHouse(w, r, sql)
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
// principal's devices. It returns ("", false) for cross-tenant principals (no
// restriction) and ("", true) when the principal has no visible device
// addresses (caller should short-circuit to an empty result).
func (s *server) flowTenantClause(r *http.Request) (clause string, empty bool) {
	claims, _ := userFrom(r.Context())
	return s.flowTenantClauseFor(claims)
}

// flowTenantClauseFor is the netops.flows form of addrTenantClauseFor. A flow
// record belongs to the tenant whose device EXPORTED it, not only to the tenant
// whose device is one of its two endpoints: a router reports the traffic it
// forwards, and almost none of that traffic is to or from the router's own
// management address. Matching endpoints alone hid every transit flow from the
// very tenant whose router saw it. So a scoped principal reads a flow when its
// exporter (sampler_address) OR either endpoint is one of its own devices.
// Shared/global devices are not in a scoped principal's address set, so a
// shared exporter grants nothing (strict isolation is unchanged).
func (s *server) flowTenantClauseFor(claims jwtClaims) (clause string, empty bool) {
	return s.addrTenantClauseCols(claims, "src_addr", "dst_addr", "sampler_address")
}

// addrTenantClauseFor is the claims-based core for tables keyed by two endpoint
// addresses, shared with the AI DataSource (which has claims, not a request).
// The CH row policies share untagged telemetry rows to every tenant scope by
// design (hybrid model), so THIS app-layer narrowing is the isolation for
// untagged rows — a scoped principal reads only rows touching its own device
// addresses, and a principal with no devices reads nothing (default-closed).
// For netops.flows use flowTenantClauseFor, which also matches the exporter.
func (s *server) addrTenantClauseFor(claims jwtClaims, srcCol, dstCol string) (clause string, empty bool) {
	return s.addrTenantClauseCols(claims, srcCol, dstCol, "")
}

// addrTenantClauseCols matches the principal's device addresses against the
// endpoint columns and, when exporterCol is set, the exporter column too.
func (s *server) addrTenantClauseCols(claims jwtClaims, srcCol, dstCol, exporterCol string) (clause string, empty bool) {
	addrs, cross := s.visibleDeviceAddrs(claims)
	// Compliance (operator-visibility): deny if the operator scoped into a
	// restricted tenant; in the Global view exclude restricted tenants' devices
	// — as endpoints, and as the exporter that saw the traffic.
	if rt := s.restrictedTelemetry(claims); rt.deny {
		return "", true
	} else if cross {
		if len(rt.addrs) > 0 {
			in := sqlInList(rt.addrs)
			c := " AND " + srcCol + " NOT IN (" + in + ") AND " + dstCol + " NOT IN (" + in + ")"
			if exporterCol != "" {
				c += " AND " + exporterCol + " NOT IN (" + in + ")"
			}
			return c, false
		}
		return "", false
	}
	if len(addrs) == 0 {
		return "", true
	}
	in := sqlInList(addrs)
	c := " AND (" + srcCol + " IN (" + in + ") OR " + dstCol + " IN (" + in + ")"
	if exporterCol != "" {
		c += " OR " + exporterCol + " IN (" + in + ")"
	}
	return c + ")", false
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

// deviceTenantPairCondFor is the TWO-ENDPOINT form of deviceTenantCondFor, for a
// table whose row names a device at EACH END (netops.tunnels: local_device /
// remote_device). A tunnel is an edge, not a row owned by one device, so the
// scoped clause is an OR across the two columns and the exclusion is an AND
// across them — a restricted tenant's device at EITHER end hides the row.
//
// It exists because the single-column sibling could not express that shape, and
// the tunnel handler hand-rolled its own clause instead of asking a chokepoint.
// That hand-rolled copy is how the operator-visibility restriction, added later
// INSIDE the chokepoints, never reached the tunnel QoE surface. One shape per
// table layout, all of them here, is what stops the next one drifting.
//
// Same hybrid-model contract as its siblings: a scoped principal with no visible
// devices reads nothing (default-closed), and the operator scoped INTO a
// restricted tenant reads nothing at all.
func (s *server) deviceTenantPairCondFor(claims jwtClaims, localCol, remoteCol string) (cond string, empty bool) {
	keys, cross := s.visibleDeviceKeys(claims)
	if rt := s.restrictedTelemetry(claims); rt.deny {
		return "", true
	} else if cross {
		if len(rt.keys) > 0 {
			in := sqlInList(rt.keys)
			return localCol + " NOT IN (" + in + ") AND " + remoteCol + " NOT IN (" + in + ")", false
		}
		return "", false
	}
	if len(keys) == 0 {
		return "", true
	}
	in := sqlInList(keys)
	return "(" + localCol + " IN (" + in + ") OR " + remoteCol + " IN (" + in + "))", false
}

// sqlInList renders values as a quoted, comma-separated ClickHouse list.
//
// BOTH the quote and the backslash are escaped. ClickHouse reads backslash
// escapes inside a string literal, so doubling only the quote left a value that
// ENDS in `\` able to escape its own closing quote — the literal then ran on
// into the next element, and the element after that parsed as SQL. Inputs here
// include device names, which a device reports about itself (SNMP sysName), so
// they are treated as untrusted (§3) regardless of which caller builds the list.
func sqlInList(vals []string) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, chStringLiteral(v))
	}
	return strings.Join(parts, ", ")
}

// chLiteralEscaper escapes a value for a single-quoted ClickHouse string
// literal: backslash first-class, then the quote.
var chLiteralEscaper = strings.NewReplacer(`\`, `\\`, `'`, `\'`)

// chStringLiteral renders one value as a safe single-quoted ClickHouse literal.
func chStringLiteral(v string) string { return "'" + chLiteralEscaper.Replace(v) + "'" }

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
	// device it can view (local or remote endpoint). This asks the package's
	// device-keyed chokepoint rather than building the clause here, so the
	// operator-visibility restriction reaches this surface like it reaches
	// flows and findings. A tunnel row carries the customer's overlay: its two
	// endpoint device names, both endpoint addresses, and the measured latency,
	// jitter, loss and QoE of the link between them.
	claims, _ := userFrom(r.Context())
	cond, empty := s.deviceTenantPairCondFor(claims, "local_device", "remote_device")
	if empty {
		writeEmptyClickHouse(w)
		return
	}
	if cond != "" {
		conds = append(conds, cond)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ") + " "
	}
	// SD-WAN tunnels (tracker 349): a Viptela/IOS XE SD-WAN tunnel is not an
	// IF-MIB/TUNNEL-MIB interface, so the interface-based discovery behind
	// netops.tunnels never sees it (owner report 2026-10-10: "vEdge tunnels are
	// not showing"). They come from the SD-WAN overlay facts — never written to
	// netops.tunnels, whose seam rule would turn every session into a VPN seam
	// suggestion — and are merged here, for the caller's visible devices only.
	sdwanRows := sdwanTunnelRows(s.sdwanOverlay.Load(), s.visibleDevicesFor(claims), r.URL.Query().Get("status"), limit, time.Now())
	// `ts` is the wire field, so the ORDER BY is TABLE-QUALIFIED rather than
	// renamed, and the fold sorts the DateTime column, never the ISO String.
	sql := `
SELECT id, type, local_device, local_addr, remote_device, remote_addr,
       status, latency_ms, jitter_ms, loss_pct, qoe, uptime_s,
       ` + chschema.ISO("t.ts") + ` AS ts
  FROM netops.tunnels AS t
` + where + `
 ORDER BY t.ts DESC
 LIMIT 1 BY id
 LIMIT ` + intToString(limit) + `
 FORMAT JSON`
	if len(sdwanRows) == 0 {
		s.proxyClickHouse(w, r, sql) // unchanged path: no SD-WAN tunnels visible
		return
	}
	rows, err := s.chRows(r, sql)
	if err != nil {
		writeError(w, http.StatusBadGateway, errors.New("tunnel inventory is unavailable"))
		return
	}
	for _, sr := range sdwanRows {
		if len(rows) >= limit {
			break
		}
		rows = append(rows, sr)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows, "rows": len(rows)})
}

// sdwanTunnelRows lists the SD-WAN tunnels of the caller's visible devices as
// tunnel rows: one per (device, remote edge, local colour, remote colour). The
// remote device is named only when it resolves to a device of the SAME tenant
// (the overlay inference is tenant-partitioned); otherwise the row carries the
// remote system-ip. Latency/jitter/loss are not read over SNMP and stay 0.
func sdwanTunnelRows(snap *sdwanOverlaySnapshot, visible []models.Device, status string, limit int, now time.Time) []map[string]any {
	if snap == nil || len(snap.devFacts) == 0 || limit <= 0 {
		return nil
	}
	tenantOf := make(map[string]string, len(visible))
	nameOf := make(map[string]string, len(visible))
	ids := make([]string, 0, len(visible))
	for _, d := range visible {
		tenantOf[d.ID] = normTenant(d.TenantID)
		nameOf[d.ID] = firstNonEmpty(d.Name, d.ID)
		ids = append(ids, d.ID)
	}
	sort.Strings(ids)
	ts := snap.at.UTC().Format(time.RFC3339)
	var out []map[string]any
	for _, dev := range ids {
		f, ok := snap.devFacts[dev]
		if !ok {
			continue
		}
		owners := snap.res.SystemIPs[tenantOf[dev]]
		for _, p := range f.Peers {
			remote := p.SystemIP
			if owner, ok := owners[p.SystemIP]; ok {
				if n, visibleToo := nameOf[owner]; visibleToo {
					remote = n
				}
			}
			remoteAddr := ""
			if len(p.TLOCAddrs) > 0 {
				remoteAddr = p.TLOCAddrs[0]
			}
			for _, cp := range p.ColorPairs {
				st := "down"
				if cp.Up > 0 {
					st = "up"
				}
				if (status == "up" || status == "down") && st != status {
					continue
				}
				out = append(out, map[string]any{
					"id":            "sdwan|" + dev + "|" + p.SystemIP + "|" + cp.LocalColor + "|" + cp.RemoteColor,
					"type":          "sdwan",
					"local_device":  nameOf[dev],
					"local_addr":    cp.LocalColor,
					"remote_device": remote,
					"remote_addr":   firstNonEmpty(remoteAddr, cp.RemoteColor),
					"status":        st,
					// Path quality is not read over SNMP for an SD-WAN tunnel:
					// "measured": false makes the view show "—", never a 0 ms
					// that reads like a perfect link.
					"latency_ms": 0, "jitter_ms": 0, "loss_pct": 0, "qoe": 0, "uptime_s": 0,
					"measured": false,
					"ts":       ts,
				})
				if len(out) >= limit {
					return out
				}
			}
		}
	}
	return out
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
