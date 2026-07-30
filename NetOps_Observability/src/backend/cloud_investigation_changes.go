package backend

// cloud_investigation_changes.go — the REAL change→incident correlation read
// (Wave 4 #12 slice 3): for ONE cloud investigation, the provider change events
// (cloud_change / cloud_audit / security_policy_change signals that actually
// landed) recorded around the investigation's onset ON its affected resources
// and apps.
//
//   GET /api/cloud/investigations/{id}/changes
//
// Honesty rules:
//   * The window is anchored on the object's OWN window_start (onset): changes
//     from 6h before onset up to now — a change outside that window is not
//     claimed as related, and nothing inside it is claimed as CAUSAL, only as
//     "recorded in the window" with its time relative to onset.
//   * Scope is the object's OWN blast radius (affected.cloud_resources +
//     affected.apps, engine-authored). No affected resources recorded ⇒ an
//     honest empty answer with that basis — we never fall back to "all changes
//     everywhere" and pass them off as correlated.
//   * Rows are the same wire shape the Changes tab uses (cloudChangeEvent), so
//     actor/type/console pivots stay consistent.
//
// Tenant isolation (§3a): the object lookup AND the signal read carry the
// caller's tenant_scope SETTINGS clause (ClickHouse FORCE row policies); a
// cross-tenant id resolves no object → 404, never a hint the id exists.
// Bounded (#100): both queries are LIMIT-bounded; the signal read is granule-
// prunable (kind + absolute now()-interval guard + onset-anchored window).

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/chschema"

	"netops/backend/cloud"
)

const (
	// Lead window: how far before onset a change is still surfaced. A deploy
	// typically precedes impact by minutes-to-hours; 6h is the bound, not a
	// claim of causality.
	investigationChangeLookbackHours = 6
	// Hard absolute guard so the read stays granule-pruned even for an old
	// object (same ceiling as the signal surfaces' 7-day max window).
	investigationChangeMaxAgeHours = 7 * 24
	investigationChangeLimit       = 50
)

// affectedCloudResources decodes the engine-authored affected.cloud_resources
// bucket (see engine.py affected()). Empty when the engine recorded none.
func affectedCloudResources(raw string) []string {
	var a struct {
		CloudResources []string `json:"cloud_resources"`
	}
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &a)
	}
	if a.CloudResources == nil {
		return []string{}
	}
	return a.CloudResources
}

// investigationScopeSQL builds the affected-scope predicate: the change must be
// stamped on one of the object's own resources or apps (identity fields only —
// never a fuzzy match). Returns "" when the object recorded no scope at all;
// the handler then answers honestly instead of querying unscoped.
func investigationScopeSQL(resources, apps []string) string {
	preds := make([]string, 0, 2)
	if list := cloud.SQLList(resources); list != "" {
		preds = append(preds,
			fmt.Sprintf("entity_id IN (%[1]s) OR JSONExtractString(attrs,'resource_id') IN (%[1]s)", list))
	}
	if list := cloud.SQLList(apps); list != "" {
		preds = append(preds,
			fmt.Sprintf("JSONExtractString(attrs,'app') IN (%[1]s) OR JSONExtractString(attrs,'app_id') IN (%[1]s)", list))
	}
	if len(preds) == 0 {
		return ""
	}
	return " AND (" + strings.Join(preds, " OR ") + ")"
}

// investigationObjectSQL loads ONE correlation object by id (tenant-scoped;
// invisible cross-tenant → no row → 404 upstream). id is pre-validated as a
// UUID token by the handler.
func investigationObjectSQL(id, scope string) string {
	return fmt.Sprintf(`
SELECT toString(correlation_id)  AS cid,
       toString(verdict_tier)    AS verdict_tier_s,
       top_confidence            AS top_confidence,
       top_hypothesis            AS top_hypothesis,
       signal_count              AS signal_count,
       toString(state)           AS state_s,
       `+chschema.ISO("window_start")+` AS window_start_s,
       affected                  AS affected,
       evidence_missing          AS evidence_missing
  FROM netops.corr_current FINAL
 WHERE correlation_id = '%s'
 LIMIT 1
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, id, scope)
}

// investigationChangesSQL reads the change signals in the onset-anchored window
// on the object's affected scope. onsetLit is a server-formatted UTC literal
// ("2006-01-02 15:04:05"), never caller input.
func investigationChangesSQL(onsetLit, scopePred string, limit int, scope string) string {
	return fmt.Sprintf(`
SELECT `+chschema.ISO("min(ts)")+`       AS ts_s,
       toString(signal_id)        AS signal_id_s,
       any(kind)                  AS kind,
       toString(any(entity_type)) AS entity_type_s,
       any(entity_id)             AS entity_id,
       toString(any(severity))    AS severity_s,
       any(metric_name)           AS metric_name,
       any(value)                 AS value,
       any(attrs)                 AS attrs,
       any(observer_id)           AS observer_id
  FROM (
       SELECT signal_id, ts, kind, entity_type, entity_id, severity,
              metric_name, value, attrs, observer_id
         FROM netops.corr_signals
        WHERE source = 'cloud'
          AND kind IN ('cloud_change','cloud_audit','security_policy_change')
          AND ts > now() - INTERVAL %d HOUR
          AND ts >= toDateTime('%s','UTC') - INTERVAL %d HOUR
          AND ts <= now()%s
  )
 GROUP BY signal_id
 ORDER BY ts_s DESC, signal_id_s DESC
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`,
		investigationChangeMaxAgeHours, onsetLit, investigationChangeLookbackHours,
		scopePred, limit, scope)
}

// offsetFromOnset is the PURE relative-time fact the card renders ("14m before
// onset"): change time minus onset, in seconds (negative = before onset).
func offsetFromOnset(changeTS, onset time.Time) int64 {
	return int64(changeTS.Sub(onset) / time.Second)
}

// investigationChangeRow is one change with its onset-relative offset.
type investigationChangeRow struct {
	cloudChangeEvent
	OffsetSeconds int64 `json:"offset_seconds"`
}

// handleCloudInvestigationChanges serves
// GET /api/cloud/investigations/{id}/changes.
func (s *server) handleCloudInvestigationChanges(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET"))
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/cloud/investigations/")
	id, tail, found := strings.Cut(rest, "/")
	if !found || tail != "changes" || !isUUIDToken(id) {
		writeError(w, http.StatusNotFound, errNotFound)
		return
	}
	scope := cloud.SafeScopeLiteral(chTenantScope(r))

	objs := chJSONRows[chObjectRow](investigationObjectSQL(id, scope))
	if len(objs) == 0 {
		// unknown OR another tenant's — indistinguishable on purpose (§3a.1)
		writeError(w, http.StatusNotFound, errNotFound)
		return
	}
	obj := objs[0]
	onset, err := time.Parse(time.RFC3339, obj.WindowStart)
	if err != nil {
		// an object without a readable onset cannot anchor an honest window
		writeJSON(w, http.StatusOK, map[string]any{
			"changes": []investigationChangeRow{}, "count": 0,
			"onset": "", "basis": "onset_unknown",
			"lookback_hours": investigationChangeLookbackHours,
		})
		return
	}

	apps := affectedApps(obj.Affected)
	resources := affectedCloudResources(obj.Affected)
	scopePred := investigationScopeSQL(resources, apps)
	if scopePred == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"changes": []investigationChangeRow{}, "count": 0,
			"onset": obj.WindowStart, "basis": "no_affected_resources",
			"lookback_hours": investigationChangeLookbackHours,
		})
		return
	}

	onsetLit := onset.UTC().Format("2006-01-02 15:04:05")
	rows := chJSONRows[chSignalRow](investigationChangesSQL(
		onsetLit, scopePred, investigationChangeLimit, scope))

	inv := s.cloudResourceIndex(r)
	out := make([]investigationChangeRow, 0, len(rows))
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
		off := int64(0)
		if ts, terr := time.Parse(time.RFC3339, row.TS); terr == nil {
			off = offsetFromOnset(ts, onset)
		}
		out = append(out, investigationChangeRow{
			cloudChangeEvent: cloudChangeEvent{
				Time:            isoTS(row.TS),
				App:             orDash(appName),
				Resource:        resName,
				ChangeType:      cloud.ChangeType(row.Kind, row.MetricName),
				Actor:           cloud.ShortActor(a.Actor),
				Source:          src,
				Confidence:      cloud.ChangeConfidence(a.Actor, a.EventSource, a.RequestID),
				RelatedSymptoms: []string{},
				CloudRef: enrichCloudRef(cloudEvidenceRef{
					Provider:   a.Provider,
					ResourceID: resID,
					Account:    a.Account,
					Region:     a.Region,
					LogRef:     a.RequestID,
					SignalID:   row.SignalID,
				}, inv),
			},
			OffsetSeconds: off,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"changes":        out,
		"count":          len(out),
		"onset":          obj.WindowStart,
		"basis":          "affected_scope",
		"lookback_hours": investigationChangeLookbackHours,
	})
}
