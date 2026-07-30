package backend

// svc_health.go — #69 P2: GET /api/health/score?scope=service&service_id=…
//
// The per-service score is the SAME explainable contract as global/site
// (aggregateHealthScore in health_score.go): per-signal-class badness,
// weighted blend with the anti-averaging floor, per-contribution points, and
// the coverage-honesty rule — fewer than 2 live signal classes returns
// INSUFFICIENT_TELEMETRY, never a hollow number.
//
// Signal classes resolvable to a SERVICE today (each best-effort/independent):
//   - path_health  — ONLY the service's bound probes/paths (service_bindings
//     kind probe|path; ref matched against the probe destination host). No
//     bindings → class honestly not live.
//   - flow_health  — the service's attributed traffic from svc_flow_rollup_1m
//     (latest-selector-version-wins read). Liveness = rollup rows exist in the
//     window; badness = a conservative collapse detector (recent 15-minute
//     volume vs the trailing 24h per-15m norm — only a near-total stop
//     registers; ordinary diurnal swing does not).
//   - correlation  — trusted RCA objects (same gates as the global class)
//     whose affected sets name this service id or one of its bound seams.
// availability/device_health are NOT resolvable to a service (no device
// bindings exist in the model) and are omitted rather than faked.
//
// TENANT ISOLATION (§3a): service_id resolves through the RLS-scoped store —
// a cross-tenant id is invisible and returns 404 (never revealing it exists).
// The rollup read is additionally pinned to the service row's own tenant_id,
// and the ClickHouse row policies scope both reads server-side.

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/chschema"

	"netops/backend/internal/healthscore"
)

// serviceHealthWindow is the flow_health lookback (norm window + liveness gate).
const serviceHealthWindow = 24 * time.Hour

// isSeamToken allowlists a seam/binding ref before SQL interpolation
// (SR-011: shape-validate, never quote-escape).
func isSeamToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == ':':
		default:
			return false
		}
	}
	return true
}

// serveServiceHealthScore handles scope=service (dispatched by handleHealthScore).
func (s *server) serveServiceHealthScore(w http.ResponseWriter, r *http.Request, claims jwtClaims) {
	if s.services == nil {
		writeError(w, http.StatusNotImplemented, errServiceStoreOff)
		return
	}
	serviceID := strings.TrimSpace(r.URL.Query().Get("service_id"))
	if serviceID == "" {
		serviceID = strings.TrimSpace(r.URL.Query().Get("id")) // scope=site uses ?id= — accept both
	}
	if !isUUIDToken(serviceID) {
		writeError(w, http.StatusBadRequest, errors.New("service_id must be a UUID"))
		return
	}
	tenant, cross := principalTenant(claims)
	svc, found, err := s.services.GetService(r.Context(), tenant, cross, serviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !found {
		// Cross-tenant or unknown id — same honest 404 (RLS hides the row).
		writeError(w, http.StatusNotFound, errNotFound)
		return
	}
	bindings, err := s.services.ListBindings(r.Context(), tenant, cross, serviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	pathAllow := map[string]bool{}
	var seams []string
	for _, b := range bindings {
		switch b.Kind {
		case "probe", "path":
			pathAllow[b.Ref] = true
			pathAllow[hostOnly(b.Ref)] = true
		case "seam":
			if isSeamToken(b.Ref) {
				seams = append(seams, b.Ref)
			}
		}
	}

	classes := []healthscore.ClassResult{
		s.fetchPathHealthClassFiltered(r.Context(), pathAllow),
		s.fetchServiceFlowClass(r, svc),
		s.fetchServiceCorrelationClass(r, serviceID, seams),
	}
	resp := healthscore.Aggregate("service", serviceID, classes, time.Now().UTC().Format(time.RFC3339))
	writeJSON(w, http.StatusOK, resp)
}

// serviceFlowBadness is the PURE collapse detector (unit-tested): given the
// summed bytes of the most recent 15 minutes and of the rest of the window,
// return the flow_health badness. Only a near-total stop against a meaningful
// norm registers (recent < 25% of the per-15m norm ramps 0→1); a service whose
// traffic only just started (no norm) is live at badness 0.
func serviceFlowBadness(recentBytes, olderBytes float64, olderMinutes float64) float64 {
	if olderMinutes < 60 || olderBytes <= 0 {
		return 0 // not enough history for a norm — liveness only, no verdict
	}
	norm15 := olderBytes / olderMinutes * 15
	if norm15 <= 0 {
		return 0
	}
	ratio := recentBytes / norm15
	return healthscore.HingeN(1-ratio, 0.75, 1.0)
}

// fetchServiceFlowClass reads the service's attributed rollup minutes
// (latest-selector-version-wins) and scores traffic collapse. Best-effort: a
// ClickHouse error or an empty rollup drops the class (not live), it never
// errors the score.
func (s *server) fetchServiceFlowClass(r *http.Request, svc Service) healthscore.ClassResult {
	res := healthscore.ClassResult{Class: "flow_health"}
	now := time.Now().UTC()
	rows, err := s.chRows(r, svcRollupLatestVersionSQL(svc.TenantID, svc.ServiceID, now.Add(-serviceHealthWindow)))
	if err != nil {
		// The rollup did not ANSWER. The class still drops out (a health score
		// must never be invented from a failed read), but "we could not ask" and
		// "this service has no attributed traffic" are different facts and no
		// longer share a branch — the first one is now visible (§10).
		logWarn("svc.health", "flow-health class dropped: the rollup did not answer",
			map[string]any{"service": svc.ServiceID, "tenant": svc.TenantID, "err": err.Error()})
		return res
	}
	if len(rows) == 0 {
		return res // answered: rollup dark for this service → class not live (honest)
	}
	recentCut := float64(now.Add(-15 * time.Minute).Unix())
	var recent, older float64
	oldest := float64(now.Unix())
	for _, row := range rows {
		ts := asFloat(row["minute_ts"])
		b := asFloat(row["bytes"])
		if ts >= recentCut {
			recent += b
		} else {
			older += b
		}
		if ts < oldest {
			oldest = ts
		}
	}
	res.Live = true
	olderMinutes := (recentCut - oldest) / 60
	if b := serviceFlowBadness(recent, older, olderMinutes); b > 0 {
		res.Badness = b
		res.Contribs = append(res.Contribs, healthscore.Contribution{
			SignalClass: "flow_health", Entity: svc.Name, Badness: b,
			Reason: "Attributed traffic for " + svc.Name + " collapsed vs its 24h norm",
		})
	}
	return res
}

// fetchServiceCorrelationClass: the global correlation gates (trusted tier,
// ≥2 planes, not debug/low-authority) PLUS a service filter — the object's
// affected set must name this service id or a bound seam. Tenant scoping rides
// the corr_current row policy (chRows). Unlike the global class it does NOT
// decorate edge grounding (that join reads corr_edges per object; the verdict-
// tier + plane gates already bound trust here and the read stays one narrow
// keyed scan — #100 bounded-IO discipline).
func (s *server) fetchServiceCorrelationClass(r *http.Request, serviceID string, seams []string) healthscore.ClassResult {
	res := healthscore.ClassResult{Class: "correlation"}
	match := []string{"positionCaseInsensitive(c.affected, '" + serviceID + "') > 0"}
	for _, seam := range seams { // isSeamToken-validated by the caller
		match = append(match, "positionCaseInsensitive(c.affected, '"+seam+"') > 0")
	}
	sql := `
SELECT toString(c.correlation_id) AS id, c.top_hypothesis AS hyp, c.top_confidence AS conf,
       c.verdict_tier AS tier, ` + chschema.ISO("c.created_at") + ` AS created_at,
       c.plane_count AS planes,
       c.debug_excluded > 0 AS debug_excluded,
       c.low_authority > 0 AS low_authority
  FROM netops.corr_current AS c FINAL
 WHERE c.state = 'open' AND c.verdict_tier IN ('confirmed','suspected')
   AND c.top_hypothesis != 'undetermined'
   AND (` + strings.Join(match, " OR ") + `)
 ORDER BY c.created_at DESC
 LIMIT 50 FORMAT JSON`
	rows, err := s.chRows(r, sql)
	if err != nil {
		return res // engine/CH down → class not live
	}
	res.Live = true
	for _, row := range rows {
		if truthy(row["debug_excluded"]) || truthy(row["low_authority"]) {
			continue
		}
		if asFloat(row["planes"]) < 2 {
			continue // single-plane → not strong enough (same rule as global)
		}
		conf := asFloat(row["conf"])
		if conf > res.Badness {
			res.Badness = conf
		}
		hyp, _ := row["hyp"].(string)
		created, _ := row["created_at"].(string)
		res.Contribs = append(res.Contribs, healthscore.Contribution{
			SignalClass: "correlation", Entity: hyp, Badness: conf,
			Reason: "Trusted RCA affecting this service: " + hyp + " (" + asString(row["tier"]) + ")", Timestamp: created,
		})
	}
	return res
}
