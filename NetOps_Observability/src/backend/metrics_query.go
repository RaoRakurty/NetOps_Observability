package main

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Native metrics querying: a thin pass-through to a Prometheus-compatible
// time-series backend so the UI can render charts itself instead of iframing
// Prometheus. VictoriaMetrics and Prometheus share the /api/v1 query API.
//
// METRICS_URL selects the upstream. It defaults to VictoriaMetrics (the deployed
// stack target — Telegraf/SNMP/gnmic remote_write all land there); a Prometheus
// URL also works for the raw query API but cannot enforce tenant scoping (see
// below).
//
// ---- tenant scoping (#3) ----------------------------------------------------
//
// The query API is otherwise a raw pass-through: without scoping ANY
// authenticated tenant user could query ANY device's metrics via PromQL. We
// enforce the same per-tenant device boundary the flows/logs/findings handlers
// use, but at the time-series layer.
//
// We do NOT parse or rewrite the user's PromQL (that needs a full parser and is
// trivially evaded). Instead we use VictoriaMetrics' server-side `extra_filters[]`
// query arg: VM injects each extra_filters[] value as an additional label matcher
// into EVERY series selector of the query, server-side, before evaluation.
// Multiple extra_filters[] entries are OR-combined; matchers within one entry are
// AND-combined. This is the clean, parser-free enforcement point.
//
// Device-identifying labels differ by producer, and a given series carries only
// ONE of them:
//   - `device`   = device id   — Go collectors (poller.go, snmpmetrics.go)
//   - `hostname` = sysName      — Telegraf SNMP edge poller (telegraf.conf)
//   - `source`   = target name  — gnmic gNMI sidecar (gnmi_* metrics)
// So we emit three OR-combined extra_filters[] entries (device id set, name set,
// name set) — a `device`-tagged series matches the first, a `hostname`/`source`-
// tagged series matches the others. A series that carries NONE of these labels
// (e.g. self-observability / stack metrics with no device) is excluded for a
// scoped tenant, which is the correct fail-closed default.
//
// LIMITATION: extra_filters[] is a VictoriaMetrics extension; Prometheus does NOT
// support it. If METRICS_URL points at Prometheus we cannot scope safely, so a
// scoped (non-cross-tenant) caller is refused rather than served unscoped data
// (fail closed). The platform owner (cross-tenant) is unaffected on any backend.

// metricsScopeFilters builds the VictoriaMetrics `extra_filters[]` values that
// constrain a query to a scoped principal's visible devices. It is a pure
// function (no IO) so the rewriting logic is unit-testable.
//
//   - cross == true (platform owner): returns nil — no restriction.
//   - scoped with visible devices: returns OR-combined matchers on the three
//     device-identifying labels (device id set, hostname name set, source name
//     set), regex-escaping every value.
//   - scoped with NO visible devices: returns a single matcher that can never
//     match (an impossible label value), so the result set is empty.
//
// metricsExcludeFilter builds ONE VictoriaMetrics extra_filters[] entry that
// EXCLUDES the given device ids/names (operator-visibility for restricted tenants).
// All matchers are AND'd within the single filter so a restricted device's series
// is dropped regardless of which label identifies it (device id, or hostname/source
// name) — OR'd separate filters would let a series slip through on an absent label.
func metricsExcludeFilter(ids, names []string) string {
	var parts []string
	if idRe := regexAlternation(ids); idRe != "" {
		parts = append(parts, `device!~"`+idRe+`"`)
	}
	if nameRe := regexAlternation(names); nameRe != "" {
		parts = append(parts, `hostname!~"`+nameRe+`"`, `source!~"`+nameRe+`"`)
	}
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func metricsScopeFilters(ids, names []string, cross bool) []string {
	if cross {
		return nil
	}
	if len(ids) == 0 && len(names) == 0 {
		// Empty namespace: match nothing. A label value that cannot exist on any
		// real series guarantees an empty result without 400-ing the query.
		return []string{`{device="__netops_no_visible_device__"}`}
	}
	var filters []string
	if idRe := regexAlternation(ids); idRe != "" {
		filters = append(filters, `{device=~"`+idRe+`"}`)
	}
	if nameRe := regexAlternation(names); nameRe != "" {
		// hostname (Telegraf) and source (gnmic) both carry the device name.
		filters = append(filters, `{hostname=~"`+nameRe+`"}`)
		filters = append(filters, `{source=~"`+nameRe+`"}`)
	}
	return filters
}

// regexAlternation renders values as an anchored RE2 alternation suitable for a
// `label=~"..."` matcher (e.g. ["a","b.c"] -> `a|b\.c`). Each value is regex-
// quoted so metacharacters in device ids/names are treated literally. VM anchors
// =~ matchers at both ends, so the alternation matches the full label value.
// Returns "" for an empty input.
func regexAlternation(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, regexp.QuoteMeta(v))
	}
	return strings.Join(parts, "|")
}

// metricsUpstreamIsVictoria reports whether the configured METRICS_URL is a
// VictoriaMetrics backend (the only one that honours extra_filters[]). We key off
// the HOST component only — a VM cluster's select path legitimately contains
// "/prometheus", so matching the whole URL would misfire. Defaulting to VM (the
// deployed stack target) is correct; an explicit Prometheus host/port triggers
// fail-closed scoping.
func metricsUpstreamIsVictoria(base string) bool {
	host := strings.ToLower(base)
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		host = strings.ToLower(u.Host) // host[:port], excludes the path
	}
	if strings.Contains(host, "prometheus") || strings.HasSuffix(host, ":9090") {
		return false
	}
	return true // victoria / vmselect / default
}

func (s *server) proxyMetrics(w http.ResponseWriter, r *http.Request, path string, allowed ...string) {
	base := envOr("METRICS_URL", "http://victoria:8428")
	u, err := url.Parse(base + path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Forward only the query params this endpoint expects.
	q := url.Values{}
	for _, key := range allowed {
		for _, v := range r.URL.Query()[key] {
			if v != "" {
				q.Add(key, v)
			}
		}
	}

	// Tenant isolation: inject server-side extra_filters[] so a scoped principal
	// can only read its own devices' series. The platform owner (cross) is
	// unrestricted EXCEPT for the operator-visibility compliance rule below.
	claims, _ := userFrom(r.Context())
	ids, names, cross := s.visibleDeviceMetricLabels(claims)
	rt := s.restrictedTelemetry(claims)
	var scopeFilters []string
	switch {
	case rt.deny:
		// Operator scoped into a restricted tenant → match nothing.
		scopeFilters = []string{`{device="__netops_no_visible_device__"}`}
	case !cross:
		// Scoped tenant → only its own devices' series.
		scopeFilters = metricsScopeFilters(ids, names, cross)
	case len(rt.ids) > 0 || len(rt.names) > 0:
		// Operator Global view → exclude restricted tenants' devices.
		if f := metricsExcludeFilter(rt.ids, rt.names); f != "" {
			scopeFilters = []string{f}
		}
	}
	if len(scopeFilters) > 0 {
		if !metricsUpstreamIsVictoria(base) {
			// Fail closed: the upstream can't enforce label scoping, so we must
			// not serve filtered/excluded series unscoped.
			writeError(w, http.StatusNotImplemented,
				errors.New("metrics scoping requires a VictoriaMetrics backend"))
			return
		}
		// Drop any client-supplied extra_filters[]/extra_label so a caller can't
		// pre-load the arg and dodge our scoping (we own these args).
		q.Del("extra_filters[]")
		q.Del("extra_label")
		for _, f := range scopeFilters {
			q.Add("extra_filters[]", f)
		}
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u.String(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	client := backendHTTPClient(25 * time.Second)
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

// GET /api/metrics/query?query=<promql>&time=<unix>
func (s *server) handleMetricsQuery(w http.ResponseWriter, r *http.Request) {
	s.proxyMetrics(w, r, "/api/v1/query", "query", "time")
}

// GET /api/metrics/query_range?query=<promql>&start=&end=&step=
func (s *server) handleMetricsQueryRange(w http.ResponseWriter, r *http.Request) {
	s.proxyMetrics(w, r, "/api/v1/query_range", "query", "start", "end", "step")
}

// GET /api/metrics/names — list metric names for the query autocomplete.
//
// Scoping here is best-effort: VictoriaMetrics applies extra_filters[] to the
// label/.../values API too, so for a scoped tenant we constrain the returned
// __name__ set to metrics that exist on a visible device. This can still surface
// a metric NAME that also exists on an out-of-tenant device (names aren't
// secret), but never that device's series — the actual data path (/query,
// /query_range) is the hard boundary above. A no-device tenant gets an empty
// name list via the match-nothing filter.
func (s *server) handleMetricsNames(w http.ResponseWriter, r *http.Request) {
	s.proxyMetrics(w, r, "/api/v1/label/__name__/values", "match[]", "start", "end")
}
