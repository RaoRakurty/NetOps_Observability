package main

// Unified event feed (#69 §5 / #53 Explorer half) — one spine, two consumers.
// The backing store IS netops.corr_signals (the same normalized-signal spine the
// correlation engine reads); there is no second event table. This handler is a
// read-only, tenant-scoped (row policy via chTenantScope), keyset-paginated view
// with server-rendered one-line titles + facet counts.
//
//   GET /api/events/feed?from=&to=&source=&kind=&severity=&entity_type=
//                        &entity=&site=&q=&class=&cursor=&limit=
//     → { items:[FeedItem], next_cursor, facets:{source,severity,kind} }
//
// class=changes restricts to discrete "what changed" events — the dedicated change
// sources (topology / sot_drift / alert) AND any "*_change" kind (BGP/IS-IS/OSPF
// adjacency, link state, LLDP/CDP neighbour), which arrive over syslog/trap rather
// than a change-specific source. The Front Page "What changed" panel is this same
// API pre-filtered.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netops/backend/appid"
)

// Allowlists for the enum columns — shape-validate, never quote-escape (SR-011).
var feedSources = map[string]bool{
	"flow": true, "probe": true, "metric": true, "alert": true,
	"topology": true, "syslog": true, "sot_drift": true, "trap": true,
}
var feedSeverities = map[string]bool{"info": true, "warn": true, "high": true, "crit": true}
var feedEntityTypes = map[string]bool{
	"device": true, "interface": true, "path": true, "segment": true,
	"site": true, "service": true, "prefix": true,
}

// sanitizeCHText keeps only characters valid in our device / path / kind / site
// identifiers, so an interpolated ClickHouse string literal can't be used for
// injection. Quotes/backslashes are dropped entirely (not escaped) per the house
// shape-validate rule. Bounded length.
func sanitizeCHText(v string) string {
	v = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == '_' || r == ':' || r == '-' || r == '/' || r == ' ' || r == '>':
			return r
		default:
			return -1
		}
	}, v)
	if len(v) > 128 {
		v = v[:128]
	}
	return v
}

// feedCursor is a keyset cursor over (ts DESC, signal_id DESC): "millis|signal_id".
func encodeFeedCursor(tsMillis int64, signalID string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d|%s", tsMillis, signalID)))
}
func decodeFeedCursor(s string) (millis int64, signalID string, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, "", false
	}
	ms, sid, found := strings.Cut(string(raw), "|")
	if !found {
		return 0, "", false
	}
	m, err := strconv.ParseInt(ms, 10, 64)
	if err != nil || !isUUIDToken(sid) {
		return 0, "", false
	}
	return m, sid, true
}

// feedTitle renders the operator-facing one-liner. Kept pure + small so it is
// unit-tested; the UI renders it as escaped text (LLM02-style: data, not markup).
func feedTitle(kind, entityID, source string) string {
	k := kindNoc(kind)
	ent := strings.TrimSpace(entityID)
	if ent == "" || ent == "unknown" {
		return k
	}
	// "X on/at <entity>" — "on" for events, "at" reads odd for paths; keep "on".
	return k + " — " + ent
}

// feedAppEntityTypes are the entity kinds whose entity_id is an address-like
// key the unified app-name resolver can speak to (#81 P3G): plain IPs, CIDR
// prefixes, and cloud resource ids. Device/interface/path/site entities are
// named by inventory, not by app identity — never resolved here.
var feedAppEntityTypes = map[string]bool{
	"ip": true, "address": true, "prefix": true, "cloud_resource": true,
}

// feedEntityApp resolves an app name for an IP/prefix/cloud-resource feed
// entity via the unified resolver ("" = unresolved or not an addressable
// entity — the title then stays EXACTLY as before; no "unknown" spam). A CIDR
// prefix resolves by its base address; a cloud resource id matches the cloud
// identity-map directly. Tenant-scoped default-closed like every resolve.
func (s *server) feedEntityApp(tenant string, cross bool, ov tenantOverrides, order []string, entityType, entityID string) string {
	if !feedAppEntityTypes[entityType] {
		return ""
	}
	key := strings.TrimSpace(entityID)
	if key == "" || key == "unknown" {
		return ""
	}
	if i := strings.IndexByte(key, '/'); i > 0 {
		key = key[:i] // prefix → its base address
	}
	sigs := s.keyAppSignals(tenant, cross, ov, key)
	if len(sigs) == 0 {
		return ""
	}
	v := appid.FuseWithPrecedence(sigs, order)
	if v.Tier == appid.Undetermined || v.App == "" || v.App == "unknown" {
		return ""
	}
	return v.App
}

// kindNoc is a compact humanizer for signal kinds (server side mirror of the UI's
// kindLabel for the common families; the UI re-labels for display, this is the
// stored title fallback).
func kindNoc(kind string) string {
	base := strings.TrimSuffix(kind, "_clear")
	switch base {
	case "bgp_adjacency_change", "bgp_state_anomaly":
		return "BGP neighbor change"
	case "ospf_adjacency_change":
		return "OSPF neighbor change"
	case "isis_adjacency_change":
		return "IS-IS neighbor change"
	case "link_state_change":
		return "Link up/down"
	case "lldp_neighbor_change":
		return "Neighbor change"
	case "stp_topology_change":
		return "Spanning-tree change"
	case "probe_loss":
		return "Packet loss"
	case "probe_rtt_anomaly", "probe_latency_departure":
		return "Response-time change"
	case "if_errors":
		return "Interface errors"
	case "if_util_high":
		return "High link utilization"
	case "device_resource_anomaly":
		return "Device CPU/memory change"
	case "flow_volume_anomaly":
		return "Traffic volume change"
	case "sot_drift":
		return "Inventory drift"
	case "topology_change":
		return "Topology change"
	}
	title := strings.ReplaceAll(base, "_", " ")
	if title == "" {
		return "Event"
	}
	return strings.ToUpper(title[:1]) + title[1:]
}

func (s *server) handleEventsFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	q := r.URL.Query()
	since := durationQuery(r, "from", 24*time.Hour)
	limit := intQuery(r, "limit", 100, 1, 500)

	conds := []string{"ts >= now() - INTERVAL " + intToString(int(since.Seconds())) + " SECOND"}
	if to := strings.TrimSpace(q.Get("to")); to != "" && isDatetimeToken(to) {
		conds = append(conds, "ts <= '"+to+"'")
	}
	// enum filters — allowlisted
	if v := strings.TrimSpace(q.Get("source")); v != "" {
		if !feedSources[v] {
			writeError(w, http.StatusBadRequest, errors.New("invalid source"))
			return
		}
		conds = append(conds, "source = '"+v+"'")
	}
	if v := strings.TrimSpace(q.Get("severity")); v != "" {
		if !feedSeverities[v] {
			writeError(w, http.StatusBadRequest, errors.New("invalid severity"))
			return
		}
		conds = append(conds, "severity = '"+v+"'")
	}
	if v := strings.TrimSpace(q.Get("entity_type")); v != "" {
		if !feedEntityTypes[v] {
			writeError(w, http.StatusBadRequest, errors.New("invalid entity_type"))
			return
		}
		conds = append(conds, "entity_type = '"+v+"'")
	}
	// class=changes → discrete "what changed" (Front Page panel 4). Match the
	// change-specific sources OR any "*_change" kind (adjacency / link / neighbour
	// changes arrive over syslog/trap, not a change-specific source).
	if strings.TrimSpace(q.Get("class")) == "changes" {
		conds = append(conds, "(source IN ('topology','sot_drift','alert') OR endsWith(kind, '_change'))")
	}
	// text filters — sanitized literals (quotes stripped, not escaped)
	if v := sanitizeCHText(q.Get("kind")); v != "" {
		conds = append(conds, "kind = '"+v+"'")
	}
	if v := sanitizeCHText(q.Get("entity")); v != "" {
		conds = append(conds, "entity_id = '"+v+"'")
	}
	if v := sanitizeCHText(q.Get("site")); v != "" {
		conds = append(conds, "site = '"+v+"'")
	}
	if v := sanitizeCHText(q.Get("q")); v != "" {
		lv := strings.ToLower(v)
		conds = append(conds, "(positionCaseInsensitive(entity_id, '"+v+"') > 0 OR positionCaseInsensitive(kind, '"+lv+"') > 0)")
	}
	where := strings.Join(conds, " AND ")

	// keyset cursor (ts DESC, signal_id DESC)
	itemConds := where
	if cur := strings.TrimSpace(q.Get("cursor")); cur != "" {
		if ms, sid, ok := decodeFeedCursor(cur); ok {
			ets := time.UnixMilli(ms).UTC().Format("2006-01-02 15:04:05.000")
			itemConds = where + " AND (ts < '" + ets + "' OR (ts = '" + ets + "' AND toString(signal_id) < '" + sid + "'))"
		}
	}

	itemSQL := `
SELECT toString(signal_id) AS signal_id,
       ` + chISO("ts") + ` AS ts_iso,
       toUnixTimestamp64Milli(ts) AS ts_ms,
       source, kind, severity, entity_type, entity_id, site,
       observer_type, modality_class, metric_name, value, deviation
  FROM netops.corr_signals
 WHERE ` + itemConds + `
 ORDER BY ts DESC, signal_id DESC
 LIMIT ` + intToString(limit) + `
 FORMAT JSON`
	rows, err := s.chRows(r, itemSQL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}

	// #81 P3G: name the app for address-like entities via the unified resolver
	// (cheap — the feed already runs on s.chRows, no passthrough conversion).
	tenant, cross := principalTenant(claims)
	ov := s.overridesFor(r.Context(), tenant, cross)
	order, _ := s.governance.attributionPrecedence(tenant)

	items := make([]map[string]any, 0, len(rows))
	var nextCursor string
	for _, row := range rows {
		kind := fmt.Sprintf("%v", row["kind"])
		entity := fmt.Sprintf("%v", row["entity_id"])
		src := fmt.Sprintf("%v", row["source"])
		// De-shadowed RFC 3339 alias (chISO) → wire name. Selecting it AS ts
		// would shadow the DateTime column the WHERE/ORDER BY cursor needs.
		if v, ok := row["ts_iso"]; ok {
			row["ts"] = v
			delete(row, "ts_iso")
		}
		title := feedTitle(kind, entity, src)
		etype := fmt.Sprintf("%v", row["entity_type"])
		if app := s.feedEntityApp(tenant, cross, ov, order, etype, entity); app != "" {
			row["entity_app"] = app
			title += " (" + app + ")" // resolved name appended; otherwise UNCHANGED
		}
		row["title"] = title
		row["correlation_id"] = nil // best-effort link is a follow-up (Explorer wiring)
		items = append(items, row)
	}
	// next_cursor only on a FULL page (house style, cloud_signals.go): a short
	// page IS the end of the window — never dangle a cursor that returns nothing.
	if n := len(rows); n == limit {
		last := rows[n-1]
		msStr := fmt.Sprintf("%v", last["ts_ms"])
		ms, _ := strconv.ParseInt(msStr, 10, 64)
		nextCursor = encodeFeedCursor(ms, fmt.Sprintf("%v", last["signal_id"]))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": nextCursor,
		// TRUE window total (cursor-independent, owner directive: DON'T HIDE) —
		// the real COUNT of matching events, never the capped page length.
		"total": s.feedTotal(r, where),
		"facets": map[string]any{
			"source":   s.feedFacet(r, where, "source"),
			"severity": s.feedFacet(r, where, "severity"),
			"kind":     s.feedFacet(r, where, "kind"),
		},
	})
}

// feedTotalSQL builds the true-window-count query. Pure so its bounded,
// filter-carrying shape is unit-testable.
func feedTotalSQL(where string) string {
	return `SELECT count() AS c FROM netops.corr_signals WHERE ` + where + ` FORMAT JSON`
}

// feedTotal returns the exact number of events matching the filtered window
// (cursor-independent). Tenant-scoped like every feed read (chRows). -1 when
// the count read fails — the UI treats it as "unknown", never as zero.
func (s *server) feedTotal(r *http.Request, where string) int64 {
	rows, err := s.chRows(r, feedTotalSQL(where))
	if err != nil || len(rows) == 0 {
		return -1
	}
	c, err := strconv.ParseInt(fmt.Sprintf("%v", rows[0]["c"]), 10, 64)
	if err != nil {
		return -1
	}
	return c
}

// feedFacet returns {value: count} for one dimension over the filtered window
// (cursor-independent). dim is a fixed column name (never user input).
func (s *server) feedFacet(r *http.Request, where, dim string) map[string]int64 {
	sql := `SELECT ` + dim + ` AS k, count() AS c
  FROM netops.corr_signals
 WHERE ` + where + `
 GROUP BY k ORDER BY c DESC LIMIT 25 FORMAT JSON`
	rows, err := s.chRows(r, sql)
	out := map[string]int64{}
	if err != nil {
		return out
	}
	for _, row := range rows {
		k := fmt.Sprintf("%v", row["k"])
		c, _ := strconv.ParseInt(fmt.Sprintf("%v", row["c"]), 10, 64)
		out[k] = c
	}
	return out
}
