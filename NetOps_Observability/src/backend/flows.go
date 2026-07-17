package main

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// flows.go — ClickHouse-backed analytics endpoints.
//
// The full flow stream lands in ClickHouse via vector-router (table
// netops.flows). These handlers run a small set of pre-defined queries
// against it. Keeping the SQL on the server side prevents SQL injection
// from the SPA and makes it cheap to swap the implementation for a
// materialized view or a dedicated rollup table later.

// Timezone note for the WHERE clauses below: `ts >= now() - INTERVAL n
// SECOND` is instant-based — ClickHouse DateTime values are epoch seconds
// internally, so the comparison is timezone-safe regardless of server TZ.
// Timezone only matters when a timestamp is RENDERED (toString/formatting)
// or BUCKETED (toStartOfInterval/toYYYYMMDD) — those must be explicit; see
// chTsUTC and handleFlowsTimeseries.
func (s *server) handleFlowsTopTalkers(w http.ResponseWriter, r *http.Request) {
	limit := intQuery(r, "limit", 20, 1, 500)
	since := durationQuery(r, "since", time.Hour)

	sql := `
SELECT src_addr AS src,
       dst_addr AS dst,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate))   AS bytes_total,
       sum(packets * if(sampling_rate = 0, 1, sampling_rate)) AS packets_total,
       count() AS flows
  FROM netops.flows
 WHERE ts >= now() - INTERVAL ` + intToString(int(since.Seconds())) + ` SECOND
 GROUP BY src, dst
 ORDER BY bytes_total DESC
 LIMIT ` + intToString(limit) + `
 FORMAT JSON`
	proxyClickHouse(w, sql)
}

func (s *server) handleFlowsByProto(w http.ResponseWriter, r *http.Request) {
	since := durationQuery(r, "since", time.Hour)
	sql := `
SELECT proto,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate))   AS bytes_total,
       sum(packets * if(sampling_rate = 0, 1, sampling_rate)) AS packets_total,
       count() AS flows
  FROM netops.flows
 WHERE ts >= now() - INTERVAL ` + intToString(int(since.Seconds())) + ` SECOND
 GROUP BY proto
 ORDER BY bytes_total DESC
 FORMAT JSON`
	proxyClickHouse(w, sql)
}

func (s *server) handleFlowsTimeseries(w http.ResponseWriter, r *http.Request) {
	since := durationQuery(r, "since", time.Hour)
	step := durationQuery(r, "step", time.Minute)
	// bucket is epoch milliseconds (UTC by construction): a zoneless
	// "YYYY-MM-DD HH:MM:SS" string in the server timezone was previously
	// returned here, which JS Date / ECharts re-interpret as viewer-LOCAL
	// time — shifting the whole chart by the viewer's UTC offset. The
	// bucketing itself is pinned to UTC so day/hour edges are stable.
	sql := `
SELECT toUnixTimestamp(toStartOfInterval(ts, INTERVAL ` + intToString(int(step.Seconds())) + ` SECOND, 'UTC')) * 1000 AS bucket,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate))   AS bytes_total,
       sum(packets * if(sampling_rate = 0, 1, sampling_rate)) AS packets_total
  FROM netops.flows
 WHERE ts >= now() - INTERVAL ` + intToString(int(since.Seconds())) + ` SECOND
 GROUP BY bucket
 ORDER BY bucket
 FORMAT JSON`
	proxyClickHouse(w, sql)
}

func (s *server) handleFindings(w http.ResponseWriter, r *http.Request) {
	limit := intQuery(r, "limit", 100, 1, 1000)
	sev := r.URL.Query().Get("severity")
	where := ""
	if sev != "" {
		where = " WHERE severity = '" + strings.ReplaceAll(sev, "'", "") + "' "
	}
	sql := `
SELECT ` + chTsUTC("ts") + ` AS ts, id, kind, severity, score, device,
       component, summary, description
  FROM netops.findings
` + where + `
 ORDER BY ts DESC
 LIMIT ` + intToString(limit) + `
 FORMAT JSON`
	proxyClickHouse(w, sql)
}

// chTsUTC renders a ClickHouse DateTime/DateTime64 column as an RFC 3339 UTC
// string with an explicit "Z" suffix (e.g. "2026-07-17T12:34:56.789Z").
// A bare toString(ts) yields "YYYY-MM-DD HH:MM:SS[.fff]" in the ClickHouse
// SERVER timezone with no offset marker — which JS `new Date()` then parses
// as viewer-local time, silently shifting every rendered timestamp.
// Every query that returns a timestamp column to the SPA must use this.
func chTsUTC(col string) string {
	return `concat(replaceOne(toString(` + col + `, 'UTC'), ' ', 'T'), 'Z')`
}

// handleTunnels returns the latest sample for each overlay tunnel (IPsec /
// SD-WAN / GRE) the collectors have reported, newest first. "LIMIT 1 BY id"
// collapses the time series to the current state per tunnel. Optional
// ?status=up|down filters; ?limit caps the rows. Empty until a collector
// populates netops.tunnels — the view renders whatever real data arrives.
func (s *server) handleTunnels(w http.ResponseWriter, r *http.Request) {
	limit := intQuery(r, "limit", 200, 1, 2000)
	where := ""
	if st := r.URL.Query().Get("status"); st == "up" || st == "down" {
		where = " WHERE status = '" + st + "' "
	}
	sql := `
SELECT id, type, local_device, local_addr, remote_device, remote_addr,
       status, latency_ms, jitter_ms, loss_pct, qoe, uptime_s,
       ` + chTsUTC("ts") + ` AS ts
  FROM netops.tunnels
` + where + `
 ORDER BY ts DESC
 LIMIT 1 BY id
 LIMIT ` + intToString(limit) + `
 FORMAT JSON`
	proxyClickHouse(w, sql)
}

// proxyClickHouse runs sql against ClickHouse over its HTTP interface.
func proxyClickHouse(w http.ResponseWriter, sql string) {
	base := envOr("CLICKHOUSE_URL", "http://clickhouse:8123")
	u, err := url.Parse(base)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	user := envOr("CLICKHOUSE_USER", "netops")
	pass := envOr("CLICKHOUSE_PASSWORD", "")

	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader([]byte(sql)))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	req.SetBasicAuth(user, pass)
	req.Header.Set("Content-Type", "text/plain")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func intQuery(r *http.Request, key string, def, min, max int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := parseIntStrict(v)
	if err != nil || n < min || n > max {
		return def
	}
	return n
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

func parseIntStrict(s string) (int, error) {
	var n int
	_, err := fmtSscanf(s, "%d", &n)
	return n, err
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
