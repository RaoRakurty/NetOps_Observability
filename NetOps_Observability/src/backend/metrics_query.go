// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"errors"
	"fmt"
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
// metricsExcludeFilters builds the VictoriaMetrics extra_filters[] that
// EXCLUDE the given device ids/names (operator-visibility for restricted
// tenants). extra_filters are OR'd, so the series are PARTITIONED by whether
// they carry a device label, and each partition gets exactly one filter:
//
//	{device!="", device!~"<ids>"}                        — labelled series: by device id
//	{device="",  hostname!~"<names>", source!~"<names>"} — device-less series: by name
//
// Every series falls in exactly one partition, so nothing slips through on an
// absent label. The partition also stops OVER-exclusion: a labelled series is
// judged by its device alone, so another device's series whose `source` holds
// a constant ("derived", "sdwan-system") that happens to equal a restricted
// device's name is no longer hidden (2026-10-11, the same defect class as the
// scope filter's name matchers).
//
// tenants are the restricted tenants themselves. Controller series carry the
// integration's tenant_id but a device label that need not be an inventory id
// (an unresolved system-ip), so excluding by device id alone let a restricted
// tenant's unresolved controller series into the Global view.
func metricsExcludeFilters(ids, names, tenants []string) []string {
	idRe, nameRe := regexAlternation(ids), regexAlternation(names)
	tenantRe := regexAlternation(normalizedTenants(tenants))
	if idRe == "" && nameRe == "" && tenantRe == "" {
		return nil
	}
	tenantClause := ""
	if tenantRe != "" {
		tenantClause = `,tenant_id!~"(?i)(` + tenantRe + `)"`
	}
	labelled := `{device!=""`
	if idRe != "" {
		labelled += `,device!~"` + idRe + `"`
	}
	unlabelled := `{device=""`
	if nameRe != "" {
		unlabelled += `,hostname!~"` + nameRe + `",source!~"` + nameRe + `"`
	}
	return []string{labelled + tenantClause + "}", unlabelled + tenantClause + "}"}
}

// normalizedTenants lower-cases and trims tenant ids, dropping empties: the
// form principalTenant and the controller tenant_id label share.
func normalizedTenants(tenants []string) []string {
	out := make([]string, 0, len(tenants))
	for _, t := range tenants {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// metricsTenantScoped binds every scope filter to the caller's tenant as well
// as its devices. A device label is not proof of ownership: controller series
// label an UNRESOLVED device by its native key (a system-ip), and a tenant may
// create a device with any id, so {device=~"10.255.255.40"} alone read another
// tenant's controller series once a tenant named a device 10.255.255.40 (F1,
// 2026-10-24). Series with no tenant_id (SNMP, gNMI, probes) still match on
// the empty alternative; the device filter keeps bounding them.
func metricsTenantScoped(filters []string, tenant string) []string {
	clause := `,tenant_id=~"(?i)(|` + regexAlternation(normalizedTenants([]string{tenant})) + `)"`
	out := make([]string, 0, len(filters))
	for _, f := range filters {
		if f == metricsNoVisibleDeviceFilter || !strings.HasSuffix(f, "}") {
			out = append(out, f)
			continue
		}
		out = append(out, strings.TrimSuffix(f, "}")+clause+"}")
	}
	return out
}

// metricsNoVisibleDeviceFilter is the match-nothing selector: a label value that
// cannot exist on any real series, so the query returns an empty result instead
// of 400-ing or, worse, running unfiltered.
const metricsNoVisibleDeviceFilter = `{device="__netops_no_visible_device__"}`

// metricsScopeFiltersFor is THE derivation of a caller's VictoriaMetrics
// boundary, and the reason every metrics lane is correct rather than every
// metrics lane happening to be correct.
//
// It folds BOTH rules into one answer — the tenant's visible device set AND the
// per-tenant operator-visibility restriction — the way addrTenantClauseFor does
// for the flows lane. That fold is the whole point. While each lane called the
// pure metricsScopeFilters itself, a lane got the device boundary and silently
// skipped the restriction, because the restriction lived in proxyMetrics and
// nowhere a lane would trip over it. Six lanes had drifted that way, and a lane
// added tomorrow would have started there too.
//
// The four answers:
//
//   - operator scoped INTO a restricted tenant → the match-nothing sentinel. Not
//     a 403: a refusal would confirm the tenant has series at all.
//   - scoped tenant → its own devices only, and the sentinel when it has none.
//     Never an unfiltered read.
//   - platform owner in the Global view while some tenant is restricted → that
//     tenant's devices excluded.
//   - unrestricted platform owner → nil, which every lane reads as "nothing to
//     restrict".
//
// metrics_scope_chokepoint_test.go fails the build if a lane builds its own
// filter set instead of calling this.
func (s *server) metricsScopeFiltersFor(c jwtClaims) []string {
	ids, names, cross := s.visibleDeviceMetricLabels(c)
	rt := s.restrictedTelemetry(c)
	switch {
	case rt.deny:
		return []string{metricsNoVisibleDeviceFilter}
	case !cross:
		tenant, _ := principalTenant(c)
		return metricsTenantScoped(metricsScopeFilters(ids, names, cross), tenant)
	case len(rt.ids) > 0 || len(rt.names) > 0 || len(rt.tenants) > 0:
		if f := metricsExcludeFilters(rt.ids, rt.names, rt.tenants); len(f) > 0 {
			return f
		}
	}
	return nil
}

func metricsScopeFilters(ids, names []string, cross bool) []string {
	if cross {
		return nil
	}
	if len(ids) == 0 && len(names) == 0 {
		// Empty namespace: match nothing.
		return []string{metricsNoVisibleDeviceFilter}
	}
	var filters []string
	if idRe := regexAlternation(ids); idRe != "" {
		filters = append(filters, `{device=~"`+idRe+`"}`)
	}
	if nameRe := regexAlternation(names); nameRe != "" {
		// hostname (Telegraf) and a raw gnmic `source` tag carry the device
		// NAME on series that have no `device` label. The name matchers are
		// bound to exactly those series (device=""): a series that HAS a device
		// label is owned by that label alone. Without the binding these OR'd
		// filters admitted any series whose `source`/`hostname` happened to
		// equal one of the caller's device names — and collectors put
		// constants in `source` ("derived", "sdwan-system", "mpls-l3vpn"), so a
		// tenant that named a device after one read every tenant's series
		// (2026-10-11). Device names are set by the device owner (sysName).
		filters = append(filters, `{hostname=~"`+nameRe+`",device=""}`)
		filters = append(filters, `{source=~"`+nameRe+`",device=""}`)
	}
	return filters
}

// regexAlternation renders values as an anchored RE2 alternation ready to sit
// INSIDE a double-quoted PromQL label matcher, `label=~"..."`
// (e.g. ["a","b.c"] -> `a|b\\.c`). Two layers of quoting, both required:
//
//   - regexp.QuoteMeta makes metacharacters literal for RE2;
//   - promQLStringEscape then escapes for the PromQL string literal, where a
//     backslash starts an escape sequence. Without it VictoriaMetrics rejects
//     `"10\.0\.0\.1"` ("cannot parse extra_filters"), so a scoped tenant with
//     any dotted device id or name (an IP, an FQDN sysName) got NO metrics; and
//     a `"` in a device name (sysName is set by the device) closed the string
//     and let the name inject matchers into the caller's tenant scope.
//
// VM anchors =~ matchers at both ends, so the alternation matches the full
// label value. Returns "" for an empty input.
func regexAlternation(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, promQLStringEscape(regexp.QuoteMeta(v)))
	}
	return strings.Join(parts, "|")
}

// promQLStringEscape escapes s for a double-quoted PromQL string literal.
// Control characters are escaped too, so no value can end the literal or the
// selector line.
func promQLStringEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
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
	scopeFilters := s.metricsScopeFiltersFor(claims)
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
	_, _ = io.Copy(w, resp.Body) // best-effort: proxy stream; a failed copy means the client is gone
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
