// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_security.go — Wave 5 #16: security & provider-event read surfaces.
//
// Three tenant-scoped reads over the signals that ALREADY land in ClickHouse
// (nothing here ingests — the poller/correlation lanes own that):
//
//   GET /api/cloud/security         security-relevant rollups from the
//                                   log-fidelity lanes: WAF BLOCKs
//                                   (cloud_waf_log), LB-plane 5xx
//                                   (cloud_lb_log + normalized lb_5xx) and
//                                   DNS resolution failures (cloud_dns_log).
//   GET /api/cloud/provider-events  provider-declared incidents/maintenance
//                                   (kind=provider_event, AWS Health lane) —
//                                   one row per event, LATEST observation
//                                   (an update open→closed must win).
//   GET /api/cloud/seam-telemetry   the hybrid-seam gateway plane: latest
//                                   state per seam endpoint from the seam
//                                   transition/drop kinds (#105).
//
// Every query follows the cloud_signals.go contract: bounded window + LIMIT,
// named columns, and the caller's tenant scope in SETTINGS tenant_scope (the
// corr_signals FORCE row policy enforces on it) — §3a.

import (
	"fmt"
	"net/http"
	"strings"

	"netops/backend/internal/chschema"

	"netops/backend/cloud"
)

// securityLaneKinds maps each fidelity lane to the signal kinds that prove it.
// The lane vocabulary matches the ingestion matrix's source types so the UI's
// coverage note ("which lanes are flowing") joins 1:1.
var securityLaneKinds = map[string][]string{
	"waf": {"cloud_waf_log"},
	"lb":  {"cloud_lb_log", "lb_5xx"},
	"dns": {"cloud_dns_log"},
}

// securityKinds is the flat kind set /api/cloud/security reads.
func securityKinds() []string {
	out := make([]string, 0, 4)
	for _, lane := range []string{"waf", "lb", "dns"} {
		out = append(out, securityLaneKinds[lane]...)
	}
	return out
}

func securityLaneOf(kind string) string {
	for lane, kinds := range securityLaneKinds {
		for _, k := range kinds {
			if k == kind {
				return lane
			}
		}
	}
	return "other"
}

// seamTelemetryKinds are the hybrid-seam transition/drop/evidence kinds the
// seam lanes emit (cloud-ingest seam_aws/azure/gcp + the IPsec gateway feed).
var seamTelemetryKinds = []string{
	"cloud_vpn_tunnel_down", "cloud_vpn_tunnel_up",
	"cloud_bgp_session_down", "cloud_bgp_session_up", "cloud_bgp_flap",
	"cloud_route_count_drop", "cloud_physical_link_down", "cloud_link_error",
	"cloud_gateway_blackhole_drop", "cloud_gateway_no_route_drop",
	"cloud_nat_port_exhaustion", "cloud_state_unknown",
	"ipsec_tunnel_status", "ipsec_underlay_status",
}

func sqlKindList(kinds []string) string {
	return cloud.SQLList(kinds)
}

// ── SQL builders (pure; carry the caller's tenant scope) ─────────────────────

func cloudSecuritySQL(windowHours int, extra string, limit int, scope string) string {
	return fmt.Sprintf(`
SELECT `+chschema.ISO("ts")+`         AS ts_s,
       toString(signal_id)     AS signal_id_s,
       kind                    AS kind,
       toString(entity_type)   AS entity_type_s,
       entity_id               AS entity_id,
       toString(severity)      AS severity_s,
       metric_name             AS metric_name,
       value                   AS value,
       baseline                AS baseline,
       deviation               AS deviation,
       attrs                   AS attrs,
       observer_id             AS observer_id
  FROM netops.corr_signals
 WHERE source = 'cloud'
   AND kind IN (%s)
   AND ts > now() - INTERVAL %d HOUR%s
 ORDER BY ts DESC, signal_id DESC
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, sqlKindList(securityKinds()), windowHours, extra, limit, scope)
}

// cloudProviderEventsSQL — one row per provider event, LATEST observation.
// The poller re-emits an event when the provider updates it (status/last-update
// move), keyed by the same signal_id; the read must show the CURRENT state of
// the incident, so argMax(…, ts) picks the newest emission (the inverse of
// cloudChangesSQL, where the FIRST observation is the truth).
func cloudProviderEventsSQL(windowHours int, limit int, scope string) string {
	return fmt.Sprintf(`
SELECT `+chschema.ISO("max(ts)")+`            AS ts_s,
       toString(signal_id)             AS signal_id_s,
       any(kind)                       AS kind,
       toString(any(entity_type))      AS entity_type_s,
       argMax(entity_id, ts)           AS entity_id,
       toString(argMax(severity, ts))  AS severity_s,
       argMax(metric_name, ts)         AS metric_name,
       argMax(value, ts)               AS value,
       argMax(attrs, ts)               AS attrs,
       argMax(observer_id, ts)         AS observer_id
  FROM (
       SELECT signal_id, ts, kind, entity_type, entity_id, severity,
              metric_name, value, attrs, observer_id
         FROM netops.corr_signals
        WHERE source = 'cloud'
          AND kind IN ('provider_event')
          AND ts > now() - INTERVAL %d HOUR
  )
 GROUP BY signal_id
 ORDER BY ts_s DESC, signal_id_s DESC
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, windowHours, limit, scope)
}

// cloudSeamTelemetrySQL — the LATEST state per seam endpoint plus how many
// transitions the window saw. Grouped by the seam key (entity_id), newest
// state via argMax — a seam that flapped shows its CURRENT state, with the
// churn count as the evidence of instability.
// The WHERE columns are TABLE-QUALIFIED (s.kind, s.ts, s.source) for the reason
// ChangesSQL pushes its filter into a subquery: `argMax(kind, ts) AS kind` is an
// output alias that shadows the source column, ClickHouse substitutes it into
// the WHERE of the same query, and the server refused every call with
//
//	Code: 184. DB::Exception: Aggregate function argMax(kind, ts) AS kind is
//	found in WHERE in query. (ILLEGAL_AGGREGATION)
//
// Alias resolution does not touch a qualified name, so the filter binds the raw
// column and the projected names (the wire contract) stay as they are.
func cloudSeamTelemetrySQL(windowHours int, limit int, scope string) string {
	return fmt.Sprintf(`
SELECT entity_id                      AS entity_id,
       argMax(kind, ts)               AS kind,
       toString(argMax(severity, ts)) AS severity_s,
       `+chschema.ISO("max(ts)")+`           AS ts_s,
       count()                        AS events,
       argMax(value, ts)              AS value,
       argMax(attrs, ts)              AS attrs
  FROM netops.corr_signals AS s
 WHERE s.source = 'cloud'
   AND s.kind IN (%s)
   AND s.ts > now() - INTERVAL %d HOUR
 GROUP BY entity_id
 ORDER BY ts_s DESC, entity_id DESC
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, sqlKindList(seamTelemetryKinds), windowHours, limit, scope)
}

// ── wire shapes ──────────────────────────────────────────────────────────────

type cloudSecurityFinding struct {
	Time     string  `json:"time"`
	Lane     string  `json:"lane"` // waf | lb | dns
	Signal   string  `json:"signal"`
	App      string  `json:"app"`
	Resource string  `json:"resource"`
	Source   string  `json:"source"` // provider (aws|azure|gcp) or "cloud"
	Severity string  `json:"severity"`
	Count    float64 `json:"count"` // the rollup's event count / value
	Detail   string  `json:"detail"`
}

type cloudProviderEvent struct {
	Time     string `json:"time"`
	Provider string `json:"provider"`
	Service  string `json:"service"` // the provider service affected (EC2, …)
	Region   string `json:"region"`
	Category string `json:"category"` // issue | scheduledChange | accountNotification
	Status   string `json:"status"`   // open | upcoming | closed (provider's own)
	Summary  string `json:"summary"`
	Severity string `json:"severity"`
}

type cloudSeamTelemetryRow struct {
	SeamID        string `json:"seam_id"` // the seam endpoint key (vpn:…/dxbgp:…)
	State         string `json:"state"`   // up | down | degraded | unknown
	Kind          string `json:"kind"`    // the latest signal kind behind the state
	Severity      string `json:"severity"`
	LastSeen      string `json:"last_seen"`
	Events        int    `json:"events"` // transitions/evidence rows in the window
	Provider      string `json:"provider"`
	EvidenceClass string `json:"evidence_class"`
}

// chSeamGroupRow decodes one grouped seam-telemetry row.
type chSeamGroupRow struct {
	EntityID string  `json:"entity_id"`
	Kind     string  `json:"kind"`
	Severity string  `json:"severity_s"`
	TS       string  `json:"ts_s"`
	Events   int     `json:"events"`
	Value    float64 `json:"value"`
	Attrs    string  `json:"attrs"`
}

// seamStateOf maps the latest seam signal kind to the honest seam state.
// Default-closed: an unrecognised kind reads "unknown", never "up".
func seamStateOf(kind string, value float64) string {
	switch kind {
	case "cloud_vpn_tunnel_up", "cloud_bgp_session_up":
		return "up"
	case "cloud_vpn_tunnel_down", "cloud_bgp_session_down", "cloud_physical_link_down":
		return "down"
	case "cloud_bgp_flap", "cloud_route_count_drop", "cloud_link_error",
		"cloud_gateway_blackhole_drop", "cloud_gateway_no_route_drop",
		"cloud_nat_port_exhaustion", "cloud_vpn_packet_drop":
		return "degraded"
	case "ipsec_tunnel_status", "ipsec_underlay_status":
		// the gateway feed reports status as the value: 1 = up, 0 = down
		if value >= 1 {
			return "up"
		}
		return "down"
	default: // cloud_state_unknown and anything new
		return "unknown"
	}
}

// securityDetail renders the lane-specific substance of a finding from its
// bounded attrs — only fields the producer actually set; absence stays absent.
func securityDetail(kind string, a signalAttrs) string {
	var parts []string
	switch securityLaneOf(kind) {
	case "waf":
		if a.Rule != "" {
			parts = append(parts, "rule "+a.Rule)
		}
		if a.Action != "" {
			parts = append(parts, a.Action)
		}
		if a.Host != "" {
			parts = append(parts, "host "+a.Host)
		}
	case "lb":
		if a.ElbStatusCode != "" {
			parts = append(parts, "LB "+a.ElbStatusCode)
		}
		if a.Reason != "" {
			parts = append(parts, a.Reason)
		}
		if a.Domain != "" {
			parts = append(parts, a.Domain)
		}
	case "dns":
		if a.Rcode != "" {
			parts = append(parts, "rcode "+a.Rcode)
		}
		if a.QueryType != "" {
			parts = append(parts, a.QueryType)
		}
	}
	return strings.Join(parts, " · ")
}

// ── handlers ─────────────────────────────────────────────────────────────────

// handleCloudSecurity serves GET /api/cloud/security — the security-relevant
// rollups the log-fidelity lanes already ingest, tenant-scoped and bounded.
func (s *server) handleCloudSecurity(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	app, ok := requireCloudApp(w, r)
	if !ok {
		return
	}
	limit := cloud.ClampSignalLimit(r.URL.Query().Get("limit"))
	window, werr := s.tenantWindowHours(r)
	if werr != nil {
		writeError(w, http.StatusBadRequest, werr)
		return
	}
	inv := s.cloudResourceIndex(r)
	rows := chJSONRows[chSignalRow](cloudSecuritySQL(
		window, cloud.AppFilterSQL(app), limit, cloud.SafeScopeLiteral(chTenantScope(r))))
	laneCounts := map[string]int{"waf": 0, "lb": 0, "dns": 0}
	out := make([]cloudSecurityFinding, 0, len(rows))
	for _, row := range rows {
		a := cloud.ParseAttrs(row.Attrs)
		resID := cloud.ResourceOf(row, a)
		resName := resID
		appName := cloud.AppOf(row, a)
		if c, ok := lookupCloudResource(inv, resID); ok {
			if c.ResourceName != "" {
				resName = c.ResourceName
			}
			if appName == "" {
				appName = c.AppName
			}
		}
		if resName == resID {
			resName = cloud.ShortCloudName(resID)
		}
		lane := securityLaneOf(row.Kind)
		laneCounts[lane]++
		count := row.Value
		if count < 1 {
			count = 1 // a normalized single event (lb_5xx) is one event, never zero
		}
		out = append(out, cloudSecurityFinding{
			Time:     isoTS(row.TS),
			Lane:     lane,
			Signal:   row.Kind,
			App:      orDash(appName),
			Resource: resName,
			Source:   cloud.ProviderOf(a),
			Severity: cloud.HealthSeverity(row.Severity),
			Count:    count,
			Detail:   securityDetail(row.Kind, a),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": out, "count": len(out), "window_hours": window,
		"lane_counts": laneCounts,
	})
}

// handleCloudProviderEvents serves GET /api/cloud/provider-events — the
// provider's own incident/maintenance declarations (AWS Health lane; other
// providers join when their lanes exist — absence is honest, never inferred).
func (s *server) handleCloudProviderEvents(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	limit := cloud.ClampSignalLimit(r.URL.Query().Get("limit"))
	window, werr := s.tenantWindowHours(r)
	if werr != nil {
		writeError(w, http.StatusBadRequest, werr)
		return
	}
	rows := chJSONRows[chSignalRow](cloudProviderEventsSQL(
		window, limit, cloud.SafeScopeLiteral(chTenantScope(r))))
	out := make([]cloudProviderEvent, 0, len(rows))
	for _, row := range rows {
		a := cloud.ParseAttrs(row.Attrs)
		out = append(out, cloudProviderEvent{
			Time:     isoTS(row.TS),
			Provider: cloud.ProviderOf(a),
			Service:  orDash(a.Service),
			Region:   orDash(a.Region),
			Category: orDash(a.Category),
			Status:   orDash(a.Status),
			Summary:  strings.TrimSpace(a.Summary),
			Severity: cloud.HealthSeverity(row.Severity),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": out, "count": len(out), "window_hours": window,
	})
}

// handleCloudSeamTelemetry serves GET /api/cloud/seam-telemetry — the latest
// measured state per hybrid-seam endpoint (#105 lanes), honest about absence:
// zero rows means the seam lanes have not observed anything in the window
// (the UI renders "awaiting telemetry", never a green guess).
func (s *server) handleCloudSeamTelemetry(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	limit := cloud.ClampSignalLimit(r.URL.Query().Get("limit"))
	window, werr := s.tenantWindowHours(r)
	if werr != nil {
		writeError(w, http.StatusBadRequest, werr)
		return
	}
	rows := chJSONRows[chSeamGroupRow](cloudSeamTelemetrySQL(
		window, limit, cloud.SafeScopeLiteral(chTenantScope(r))))
	out := make([]cloudSeamTelemetryRow, 0, len(rows))
	for _, row := range rows {
		a := cloud.ParseAttrs(row.Attrs)
		out = append(out, cloudSeamTelemetryRow{
			SeamID:        row.EntityID,
			State:         seamStateOf(row.Kind, row.Value),
			Kind:          row.Kind,
			Severity:      cloud.HealthSeverity(row.Severity),
			LastSeen:      isoTS(row.TS),
			Events:        row.Events,
			Provider:      cloud.ProviderOf(a),
			EvidenceClass: a.EvidenceClass,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"seams": out, "count": len(out), "window_hours": window,
	})
}
