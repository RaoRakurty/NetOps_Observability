package main

// cloud_signals.go — the REAL cloud health / change / evidence read surfaces
// behind App Observability's Health & Changes and Evidence tabs (#81 P3H).
//
//   GET /api/cloud/health?app=&limit=    — cloud health signals   (corr_signals)
//   GET /api/cloud/changes?app=&limit=   — cloud change events    (corr_signals)
//   GET /api/cloud/evidence?app=&limit=  — the evidence ledger of the cloud
//                                          correlation objects (corr_current +
//                                          corr_signals_archive)
//
// These replace the sample rows the UI used to render. Every row here is a signal
// that actually landed on the bus from a connected AWS / Azure account; when
// nothing landed, the endpoints return an empty list and the UI shows its honest
// empty state. We never synthesize a row, an app, or a resource.
//
// Honesty rules encoded below:
//   * Health STATE and SEVERITY are derived from the signal's own severity — not
//     from a threshold we invented.
//   * A change's TYPE is classified from the provider's own event name; an event
//     we cannot classify stays a plain config_change (a mutating management-plane
//     call IS a config change) and an empty event name stays "unknown".
//   * Evidence categories are limited to what the engine actually records:
//     "supporting" = the signal was attached to (grounded into) the correlation
//     object, and "missing" = an entry from the object's own evidence_missing
//     list. The engine records no contradicting/discriminating role today, so we
//     never claim one.
//   * Related symptoms are NOT invented: we only report what the engine attached.
//
// Tenant isolation (§3a): every query is scoped by the caller's principal via the
// tenant_scope SETTINGS clause, which the corr_signals / corr_signals_archive /
// corr_objects FORCE row policies enforce in the database itself.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"netops/backend/cloud"
)

// The signal-surface domain moved to cloud/signals.go (Phase-2 W2.2).
// Aliases + const aliases keep the handlers and overview source-compatible.
type (
	cloudHealthSignal = cloud.HealthSignal
	cloudChangeEvent  = cloud.ChangeEvent
	cloudEvidenceRow  = cloud.EvidenceRow
	cloudEvidenceRef  = cloud.EvidenceRef
	cloudRcaObject    = cloud.RcaObject
	chSignalRow       = cloud.SignalRow
	chObjectRow       = cloud.ObjectRow
	signalAttrs       = cloud.SignalAttrs
)

const (
	cloudSignalWindowHours    = cloud.SignalWindowHours
	cloudSignalWindowMaxHours = cloud.SignalWindowMaxHours
	cloudSignalDefaultLim     = cloud.SignalDefaultLim
	cloudSignalMaxLim         = cloud.SignalMaxLim
	cloudEvidenceMaxObjects   = cloud.EvidenceMaxObjects
)

var errBadSignalCursor = cloud.ErrBadCursorToken

func (s *server) tenantWindowHours(r *http.Request) (int, error) {
	if raw := strings.TrimSpace(r.URL.Query().Get("window_hours")); raw != "" {
		n, err := intQuery(r, "window_hours", 0, 1, cloudSignalWindowMaxHours)
		if err != nil {
			return 0, err
		}
		return n, nil
	}
	claims, _ := userFrom(r.Context())
	tenant, _ := principalTenant(claims)
	hours, _ := s.governance.rcaWindowHours(tenant)
	return hours, nil
}

func parseSignalPage(w http.ResponseWriter, r *http.Request) (q, curTS, curID string, ok bool) {
	q = cloud.ClampSignalQuery(r.URL.Query().Get("q"))
	if c := strings.TrimSpace(r.URL.Query().Get("cursor")); c != "" {
		var err error
		if curTS, curID, err = cloud.DecodeSignalCursor(c); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return "", "", "", false
		}
	}
	return q, curTS, curID, true
}

// cloudArchivedSignalCountSQL counts ALL grounded signals for the picked
// objects — the ledger's `count` header (the page itself stays LIMIT-bounded).
func requireCloudApp(w http.ResponseWriter, r *http.Request) (string, bool) {
	app := strings.TrimSpace(r.URL.Query().Get("app"))
	if app == "" {
		return "", true
	}
	if !isCloudAppToken(app) {
		writeError(w, http.StatusBadRequest, errors.New("invalid app"))
		return "", false
	}
	return app, true
}

// handleCloudHealth serves GET /api/cloud/health — the cloud health signals that
// actually landed (cloud_health / cloud_resource_health), newest first.
func (s *server) handleCloudHealth(w http.ResponseWriter, r *http.Request) {
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
	q, curTS, curID, ok := parseSignalPage(w, r)
	if !ok {
		return
	}
	format, ferr := exportFormat(r)
	if ferr != nil {
		writeError(w, http.StatusBadRequest, ferr)
		return
	}
	if format != "" {
		// An export means "everything in the filter", bounded — not one page.
		limit = clampExportLimit(r.URL.Query().Get("limit"))
	}
	// Resolve each signal's raw resource id → the clean resource NAME + its owning
	// app from the tenant-scoped inventory, exactly like handleCloudChanges. Health
	// signals are stamped on a raw provider id (an ARM path, an instance id); the
	// operator reads a name, not a path.
	inv := s.cloudResourceIndex(r)
	pred := cloud.AppFilterSQL(app) + cloud.SignalSearchSQL(q) + cloud.SignalCursorPredSQL(curTS, curID)
	rows := chJSONRows[chSignalRow](cloud.HealthSQL(window, pred, limit, cloud.SafeScopeLiteral(chTenantScope(r))))
	out := make([]cloudHealthSignal, 0, len(rows))
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
		if resName == resID { // not in inventory — fall back to the last path segment
			resName = cloud.ShortCloudName(resID)
		}
		// Metric / Current / Baseline apply ONLY to metric-anomaly signals. A
		// health-STATUS event (cloud_resource_health with no metric_name) has no
		// value or baseline — render "—", never a misleading "0".
		metric, current, baseline := "—", "—", "—"
		if row.MetricName != "" {
			metric = row.MetricName
			current = cloud.FmtSignalValue(row.Value)
			baseline = cloud.FmtBaseline(row.Baseline, row.Deviation)
		}
		out = append(out, cloudHealthSignal{
			Time:     isoTS(row.TS),
			App:      orDash(appName),
			Resource: resName,
			Signal:   row.Kind,
			State:    cloud.HealthState(row.Severity),
			Metric:   metric,
			Current:  current,
			Baseline: baseline,
			Severity: cloud.HealthSeverity(row.Severity),
			Source:   cloud.ProviderOf(a),
			// A state event's only substance (the provider's own reasonType).
			Reason: strings.TrimSpace(a.Reason),
		})
	}
	next := ""
	if len(rows) > 0 {
		last := rows[len(rows)-1]
		next = cloud.NextSignalCursor(last.TS, last.SignalID, len(rows), limit)
	}
	body := map[string]any{"signals": out, "count": len(out), "window_hours": window, "next_cursor": next}
	if format != "" {
		writeSignalExport(w, "health", format, healthExportHeader, healthExportRows(out), body)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// handleCloudChanges serves GET /api/cloud/changes — the provider-audited change
// events (CloudTrail / Activity Log) that landed as cloud_change / cloud_audit /
// security_policy_change. Apps come from the cloud inventory (resource → app),
// never from a guess: an unattributed resource's change shows app "—".
func (s *server) handleCloudChanges(w http.ResponseWriter, r *http.Request) {
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
	q, curTS, curID, ok := parseSignalPage(w, r)
	if !ok {
		return
	}
	format, ferr := exportFormat(r)
	if ferr != nil {
		writeError(w, http.StatusBadRequest, ferr)
		return
	}
	if format != "" {
		limit = clampExportLimit(r.URL.Query().Get("limit"))
	}

	// resource → (app, name, confidence) from the tenant-scoped cloud inventory,
	// keyed by every handle a signal can carry (id, ENI, IP).
	inv := s.cloudResourceIndex(r)

	filter := cloud.AppFilterSQL(app)
	if app != "" {
		// A change is stamped on a RESOURCE; the app link comes from the inventory.
		// Widen the app filter with every handle of that app's resources — a
		// change stamped on the ENI/IP belongs to the app too (empty ⇒ attrs-only).
		ids := make([]string, 0, len(inv))
		for id, c := range inv {
			if c.AppName == app || c.AppID == app {
				ids = append(ids, id)
			}
		}
		if list := cloud.SQLList(ids); list != "" {
			filter = fmt.Sprintf(
				" AND (entity_id IN (%s) OR JSONExtractString(attrs,'app') = '%s' OR JSONExtractString(attrs,'app_id') = '%s')",
				list, app, app)
		}
	}

	filter += cloud.SignalSearchSQL(q)
	rows := chJSONRows[chSignalRow](cloud.ChangesSQL(window, filter,
		cloud.ChangesCursorHavingSQL(curTS, curID), limit, cloud.SafeScopeLiteral(chTenantScope(r))))
	out := make([]cloudChangeEvent, 0, len(rows))
	for _, row := range rows {
		a := cloud.ParseAttrs(row.Attrs)
		resID := cloud.ResourceOf(row, a)
		appName := cloud.AppOf(row, a)
		resName := resID
		if c, ok := lookupCloudResource(inv, resID); ok {
			if appName == "" {
				appName = c.AppName
			}
			if c.ResourceName != "" {
				resName = c.ResourceName
			}
		}
		src := a.EventSource
		if src == "" {
			src = cloud.ProviderOf(a)
		}
		ref := enrichCloudRef(cloudEvidenceRef{
			Provider:   a.Provider,
			ResourceID: resID,
			Account:    a.Account,
			Region:     a.Region,
			LogRef:     a.RequestID, // CloudTrail eventID / Activity Log correlation id
			SignalID:   row.SignalID,
		}, inv)
		out = append(out, cloudChangeEvent{
			Time:       isoTS(row.TS),
			App:        orDash(appName),
			Resource:   resName,
			ChangeType: cloud.ChangeType(row.Kind, row.MetricName),
			Actor:      cloud.ShortActor(a.Actor),
			Source:     src,
			Confidence: cloud.ChangeConfidence(a.Actor, a.EventSource, a.RequestID),
			// The engine attaches signals to an object; it does not label a change
			// with the symptoms it "caused". We report none rather than invent one —
			// the Evidence tab shows what a change was actually grounded with.
			RelatedSymptoms: []string{},
			CloudRef:        ref,
		})
	}
	next := ""
	if len(rows) > 0 {
		last := rows[len(rows)-1]
		next = cloud.NextSignalCursor(last.TS, last.SignalID, len(rows), limit)
	}
	body := map[string]any{"changes": out, "count": len(out), "window_hours": window, "next_cursor": next}
	if format != "" {
		writeSignalExport(w, "changes", format, changeExportHeader, changeExportRows(out), body)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// handleCloudEvidence serves GET /api/cloud/evidence — the evidence ledger of the
// cloud correlation objects: every signal the engine GROUNDED into an object
// (used_in_verdict), plus the object's own evidence_missing entries (the honest
// gaps). Nothing else — a category the engine does not record is never claimed.
//
// Read shape follows the #100 contract: the hot projection corr_current FINAL with
// NAMED columns, and the archive prefiltered by the picked object ids + the time
// window so the join build side stays granule-pruned.
func (s *server) handleCloudEvidence(w http.ResponseWriter, r *http.Request) {
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
	q, curTS, curID, pok := parseSignalPage(w, r)
	if !pok {
		return
	}
	format, ferr := exportFormat(r)
	if ferr != nil {
		writeError(w, http.StatusBadRequest, ferr)
		return
	}
	if format != "" {
		limit = clampExportLimit(r.URL.Query().Get("limit"))
	}
	scope := cloud.SafeScopeLiteral(chTenantScope(r))

	appPred := ""
	if app != "" {
		appPred = fmt.Sprintf(" AND has(JSONExtract(affected,'apps','Array(String)'), '%s')", app)
	}
	objRows := chJSONRows[chObjectRow](cloud.EvidenceObjectsSQL(window, appPred, scope))
	objects := make([]cloudRcaObject, 0, len(objRows))
	byID := map[string]chObjectRow{}
	ids := make([]string, 0, len(objRows))
	for _, o := range objRows {
		byID[o.CorrelationID] = o
		ids = append(ids, o.CorrelationID)
		objects = append(objects, cloudRcaObject{
			CorrelationID: o.CorrelationID,
			VerdictTier:   o.VerdictTier,
			Confidence:    o.TopConfidence,
			TopHypothesis: o.TopHypothesis,
			SignalCount:   o.SignalCount,
			State:         o.State,
			WindowStart:   isoTS(o.WindowStart),
			Apps:          s.cloudAppsForObject(r, o.Affected),
		})
	}

	// Resolve provider-native ids (eni-…, i-…) to the resource/app they belong to,
	// from the tenant's DECLARED inventory. A NOC reads names; the raw handle is
	// preserved in cloud_ref for the console pivot.
	inventoryIdx := s.cloudResourceIndex(r)
	resourceNamer := namerFromIndex(inventoryIdx)

	evidence := make([]cloudEvidenceRow, 0, limit)
	totalGrounded := 0
	nextCursor := ""
	if list := cloud.SQLList(ids); list != "" {
		totalGrounded = chScalarInt(cloud.ArchivedSignalCountSQL(window, list, scope))
		extra := cloud.SignalSearchSQL(q) + cloud.SignalCursorPredSQL(curTS, curID)
		grounded := chJSONRows[chSignalRow](cloud.EvidenceSignalsSQL(window, list, extra, limit, scope))
		if len(grounded) > 0 {
			last := grounded[len(grounded)-1]
			nextCursor = cloud.NextSignalCursor(last.TS, last.SignalID, len(grounded), limit)
		}
		for _, row := range grounded {
			o := byID[row.CorrelationID]
			a := cloud.ParseAttrs(row.Attrs)
			ref := enrichCloudRef(cloudEvidenceRef{
				Provider:   a.Provider,
				ResourceID: firstNonEmptyStr(a.ResourceID, row.EntityID),
				Account:    a.Account,
				Region:     a.Region,
				LogRef:     a.RequestID, // CloudTrail eventID / provider record id
				SignalID:   row.SignalID,
			}, inventoryIdx)
			evidence = append(evidence, cloudEvidenceRow{
				Time:       isoTS(row.TS),
				Category:   "grounded", // attached to the investigation by the engine
				SignalType: row.Kind,
				App:        orDash(cloud.EvidenceApp(row, a, resourceNamer)),
				Resource:   cloud.EvidenceResource(row, a, resourceNamer),
				Source:     cloud.ProviderOf(a),
				Confidence: cloud.VerdictConfidence(o.VerdictTier),
				Reason: cloud.EvidenceReason(row.Kind, row.MetricName, row.EntityID, row.Severity,
					o.TopHypothesis, o.VerdictTier, resourceNamer),
				Grounded:    true,
				RcaGroup:    row.CorrelationID,
				EvidenceRef: row.SignalID,
				CloudRef:    ref,
			})
		}
	}

	// The engine's OWN gaps — the only "missing" evidence we are entitled to show.
	// They are object-level (not ts-ordered), so they ride the FIRST page only; a
	// cursor-following page would otherwise repeat every gap row.
	gaps := 0
	if curTS != "" {
		objRows = nil
	}
	for _, o := range objRows {
		apps := affectedApps(o.Affected)
		appName := "—"
		if len(apps) > 0 {
			appName = apps[0]
		}
		for _, gap := range missingEvidence(o.EvidenceMissing) {
			// A search narrows the ledger; a gap row only qualifies when the
			// term matches what the operator would read on it.
			if q != "" && !strings.Contains(strings.ToLower(gap+" "+appName), strings.ToLower(q)) {
				continue
			}
			gaps++
			evidence = append(evidence, cloudEvidenceRow{
				Time:        isoTS(o.WindowStart),
				Category:    "missing",
				SignalType:  "gap",
				App:         appName,
				Resource:    "—",
				Source:      "correlation engine",
				Confidence:  "unknown",
				Reason:      gap,
				Grounded:    false,
				RcaGroup:    o.CorrelationID,
				EvidenceRef: "—",
			})
		}
	}

	// count = the TRUE ledger size (all grounded signals + gaps), not the page
	// length; `returned` is what this page carries (audit D-P2-13). The open-
	// object count is a dedicated COUNT so the Active tile can never be capped
	// by the 10-object evidence join (audit D-P1-7).
	openCount := chScalarInt(cloud.OpenObjectCountSQL(window, appPred, scope))
	body := map[string]any{
		"objects":           objects,
		"evidence":          evidence,
		"count":             totalGrounded + gaps,
		"returned":          len(evidence),
		"open_object_count": openCount,
		"objects_truncated": openCount > len(objects),
		"window_hours":      window,
		"next_cursor":       nextCursor,
	}
	if format != "" {
		writeSignalExport(w, "evidence", format, evidenceExportHeader, evidenceExportRows(evidence), body)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// cloudAppsForObject names the applications an object affects. The engine names
// apps when it can; when the probes only knew an IP, the DECLARED cloud
// inventory resolves that address to the workload living there — so the Service
// View's Apps column reads "correlix-app-host-01", never a bare 10.60.10.10.
func (s *server) cloudAppsForObject(r *http.Request, affectedRaw string) []string {
	if apps := affectedApps(affectedRaw); len(apps) > 0 {
		return apps
	}
	var a struct {
		Services []string `json:"services"`
		Paths    []string `json:"paths"`
	}
	if affectedRaw != "" {
		_ = json.Unmarshal([]byte(affectedRaw), &a)
	}
	targets := append(append([]string{}, a.Services...), a.Paths...)
	if len(targets) == 0 {
		return []string{}
	}
	res, _, _, err := s.cloudResources(r)
	if err != nil {
		return []string{}
	}
	if names := cloudAppNamesFor(res, targets); len(names) > 0 {
		return names
	}
	return []string{}
}

// affectedApps pulls the app blast radius out of an object's affected JSON.
func affectedApps(raw string) []string {
	var a struct {
		Apps []string `json:"apps"`
	}
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &a)
	}
	if a.Apps == nil {
		return []string{}
	}
	return a.Apps
}

// missingEvidence decodes the object's evidence_missing JSON array (engine-authored).
func missingEvidence(raw string) []string {
	var out []string
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	if out == nil {
		return []string{}
	}
	return out
}

// isoTS turns ClickHouse's "2006-01-02 15:04:05[.000]" into an ISO-8601 UTC stamp
// the browser can parse. A stamp we cannot read passes through untouched.
func isoTS(ts string) string {
	t := strings.TrimSpace(ts)
	if t == "" {
		return ""
	}
	if !strings.Contains(t, " ") {
		return t
	}
	return strings.Replace(t, " ", "T", 1) + "Z"
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
