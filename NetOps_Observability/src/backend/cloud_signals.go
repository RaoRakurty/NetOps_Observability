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
	"strconv"
	"strings"
)

const (
	// Bounded read window for the cloud signal surfaces. The UI shows "what is
	// happening now", and an unbounded scan of corr_signals is exactly the read
	// pattern the #100 incident was about.
	cloudSignalWindowHours = 24
	// Caller-selectable ceiling (Wave 2 #5 real time-range): 7 days. Still a
	// bounded, granule-prunable window + LIMIT, so it stays inside the #100
	// read contract; anything above clamps here, never widens silently.
	cloudSignalWindowMaxHours = 7 * 24
	cloudSignalDefaultLim     = 200
	cloudSignalMaxLim         = 1000
	// Cloud RCA objects considered by the evidence ledger (bounded join build side).
	cloudEvidenceMaxObjects = 10
)

// ── pure helpers (unit-tested in cloud_signals_test.go) ──────────────────────

// clampSignalLimit bounds a caller-supplied limit; junk or 0 → the default.
func clampSignalLimit(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return cloudSignalDefaultLim
	}
	if n > cloudSignalMaxLim {
		return cloudSignalMaxLim
	}
	return n
}

// clampWindowHours bounds the caller-supplied ?window_hours= read window
// (Wave 2 #5): junk/absent/0 → the 24h default the surfaces always had;
// anything above the 7-day ceiling clamps to it. The handler reports the
// HONORED value back in window_hours so the UI label never claims a range
// the data doesn't cover.
func clampWindowHours(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return cloudSignalWindowHours
	}
	if n > cloudSignalWindowMaxHours {
		return cloudSignalWindowMaxHours
	}
	return n
}

// safeScopeLiteral is the caller's tenant_scope, guarded before it is embedded in
// a SQL literal. Claims-derived ids are opaque tokens; anything else fails closed
// to the non-matching sentinel rather than reaching the DB.
func safeScopeLiteral(scope string) string {
	if scope == "" {
		return "__none__"
	}
	for _, c := range scope {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '-' || c == '.'
		if !ok {
			return "__none__"
		}
	}
	return scope
}

// cloudHealthState maps a signal severity onto the UI's health state. A cloud
// health signal only EXISTS because the provider reported a problem, so even
// "info" is a reported event — it renders "degraded", never "healthy" (audit
// D-P2-11: a problems-only table must not contain a "healthy" row).
func cloudHealthState(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "crit":
		return "down"
	case "high", "warn", "info":
		return "degraded"
	default:
		return "unknown"
	}
}

// cloudHealthSeverity maps the engine severity onto the table's severity chip.
func cloudHealthSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "crit":
		return "critical"
	case "high", "warn":
		return "warning"
	default:
		return "info"
	}
}

// cloudChangeType classifies a provider event name into the change taxonomy the
// UI renders. Classification is on the provider's OWN event name — never guessed
// from timing. An unclassifiable-but-present event is a config_change (every
// mutating management-plane call is, by definition, a config change); an absent
// event name stays "unknown".
func cloudChangeType(kind, event string) string {
	if kind == "security_policy_change" {
		return "security_policy_change"
	}
	e := strings.TrimSpace(event)
	if e == "" {
		return "unknown"
	}
	l := strings.ToLower(e)
	switch {
	case strings.Contains(l, "securitygroup"), strings.Contains(l, "networkacl"),
		strings.Contains(l, "bucketpolicy"), strings.Contains(l, "publicaccessblock"),
		strings.HasPrefix(l, "authorize"), strings.HasPrefix(l, "revoke"),
		strings.Contains(l, "firewallpolicy"), strings.Contains(l, "nsg"):
		return "security_policy_change"
	case strings.Contains(l, "certificate"):
		return "cert_change"
	case strings.Contains(l, "resourcerecordset"), strings.Contains(l, "hostedzone"),
		strings.Contains(l, "dnszone"):
		return "dns_change"
	case strings.Contains(l, "route"), strings.Contains(l, "address"),
		strings.Contains(l, "gateway"), strings.Contains(l, "vif_state"),
		strings.Contains(l, "connection_state"), strings.Contains(l, "peering"):
		return "route_change"
	case strings.Contains(l, "rolepolicy"), strings.Contains(l, "attachrole"),
		strings.HasPrefix(l, "createuser"), strings.HasPrefix(l, "createrole"),
		strings.Contains(l, "accesskey"):
		return "iam_change"
	case strings.Contains(l, "instances"), strings.Contains(l, "scalinggroup"),
		strings.Contains(l, "desiredcapacity"), strings.Contains(l, "capacity"):
		return "scale_change"
	case strings.Contains(l, "deployment"), strings.Contains(l, "functioncode"),
		strings.Contains(l, "updateservice"), strings.Contains(l, "deploy"):
		return "deploy"
	default:
		return "config_change"
	}
}

// shortActor renders the acting principal without the account number — the role /
// user path is what an operator needs; the raw account id is noise (and PII-ish
// provenance we do not need to echo back). Non-ARN actors pass through, bounded.
func shortActor(actor string) string {
	a := strings.TrimSpace(actor)
	if a == "" {
		return "—"
	}
	if strings.HasPrefix(a, "arn:") {
		parts := strings.Split(a, ":")
		if len(parts) >= 6 && parts[2] != "" && parts[5] != "" {
			a = parts[2] + ":" + parts[5]
		}
	}
	if len(a) > 96 {
		a = a[:96]
	}
	return a
}

// cloudChangeConfidence: a change event is a record the provider itself emitted.
// With full provenance (an actor and the emitting service / request id) we OBSERVED
// the change — "confirmed". Without it, the record is real but thinly sourced.
func cloudChangeConfidence(actor, eventSource, requestID string) string {
	if strings.TrimSpace(actor) != "" && (strings.TrimSpace(eventSource) != "" || strings.TrimSpace(requestID) != "") {
		return "confirmed"
	}
	return "strong"
}

// verdictConfidence maps the engine's verdict tier onto the UI confidence ladder.
// "undetermined" is honestly unknown — never silently promoted.
func verdictConfidence(tier string) string {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "confirmed":
		return "confirmed"
	case "suspected":
		return "suspected"
	default:
		return "unknown"
	}
}

// fmtSignalValue renders a signal's measurement. A zero baseline/deviation means
// the engine computed none — that reads "—", never a fabricated "0".
func fmtSignalValue(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

func fmtBaseline(baseline, deviation float64) string {
	if baseline == 0 && deviation == 0 {
		return "—"
	}
	return strconv.FormatFloat(baseline, 'g', -1, 64)
}

// cloudEvidencePhrase renders a signal kind as an OPERATOR sentence — what the
// platform observed, in the words a NOC engineer uses. Schema kinds
// (cloud_flow_log, probe_loss, …) are implementation detail and never surface.
func cloudEvidencePhrase(kind, metric string) string {
	switch kind {
	case "cloud_flow_log":
		return "Traffic was rejected by a cloud security rule"
	case "cloud_health":
		return "The application reported itself unhealthy"
	case "cloud_resource_health", "cloud_resource_anomaly":
		return "The cloud provider reported a resource problem"
	case "cloud_change":
		return "A cloud configuration change was made"
	case "cloud_audit":
		return "A cloud administrative action was recorded"
	case "security_policy_change":
		return "A security policy was changed"
	case "probe_loss", "synthetic_icmp_loss":
		return "Active checks lost packets to this target"
	case "probe_rtt_anomaly":
		return "Active checks measured unusual response times"
	case "synthetic_http_fail", "synthetic_http_5xx", "synthetic_http_4xx":
		return "An application check returned a failing HTTP response"
	case "synthetic_dns_fail":
		return "An application check could not resolve the service name"
	case "synthetic_tls_fail", "synthetic_cert_expired", "synthetic_cert_expiring":
		return "An application check hit a TLS/certificate problem"
	case "synthetic_timeout":
		return "An application check timed out"
	case "lb_5xx", "lb_target_unhealthy":
		return "The load balancer reported failing backends"
	case "flow_volume_anomaly":
		return "Real traffic volume changed sharply"
	case "ipsec_tunnel_status":
		return "The VPN tunnel changed state"
	case "ipsec_underlay_status":
		return "The internet path underneath the VPN changed state"
	}
	// Unmapped kind: humanize rather than leak the raw token.
	h := strings.ReplaceAll(kind, "_", " ")
	if metric != "" {
		h += " (" + strings.ReplaceAll(metric, "_", " ") + ")"
	}
	if h == "" {
		return "An observation was recorded"
	}
	return strings.ToUpper(h[:1]) + h[1:]
}

// evidenceReason is the one-line, OPERATOR-readable reason a signal is in the
// ledger. Machine identifiers (eni-…, i-…, arn:…) mean nothing to a NOC — they
// are resolved to the resource/application they belong to, with the raw id kept
// only as a parenthetical for the engineer who needs to click through.
func evidenceReason(kind, metric, entity, severity, hypothesis, tier string, name func(string) string) string {
	what := cloudEvidencePhrase(kind, metric)

	on := ""
	if entity != "" {
		label := entity
		if name != nil {
			if n := name(entity); n != "" && n != entity {
				label = n + " (" + entity + ")"
			}
		}
		on = " on " + label
	}

	sev := map[string]string{
		"crit": "critical", "high": "major", "warn": "minor", "info": "informational",
	}[strings.ToLower(severity)]
	if sev == "" {
		sev = strings.ToLower(severity)
	}

	verdict := map[string]string{
		"confirmed":    "confirming",
		"suspected":    "supporting the suspected",
		"undetermined": "attached to the unresolved",
	}[strings.ToLower(tier)]
	if verdict == "" {
		verdict = "attached to the"
	}

	return fmt.Sprintf("%s%s — %s evidence, %s %s.",
		what, on, sev, verdict, signatureNocTitle(hypothesis))
}

// ── wire types ───────────────────────────────────────────────────────────────

type cloudHealthSignal struct {
	Time     string `json:"time"`
	App      string `json:"app"`
	Resource string `json:"resource"`
	Signal   string `json:"signal"`
	State    string `json:"state"`
	Metric   string `json:"metric"`
	Current  string `json:"current"`
	Baseline string `json:"baseline"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
	// WHY the provider declared this state — Azure Resource Health's reasonType
	// ("Customer Initiated" / "Platform Initiated"), the equivalent elsewhere.
	// A health STATE event carries no metric/value/baseline, so this is the only
	// substance it has: without it the row rendered an empty triplet. Empty when
	// the provider declared no reason — the UI then says so, never invents one.
	Reason string `json:"reason,omitempty"`
}

type cloudChangeEvent struct {
	Time            string   `json:"time"`
	App             string   `json:"app"`
	Resource        string   `json:"resource"`
	ChangeType      string   `json:"change_type"`
	Actor           string   `json:"actor"`
	Source          string   `json:"source"`
	Confidence      string   `json:"confidence"`
	RelatedSymptoms []string `json:"related_symptoms"`
	// CloudRef carries the provider-native identity + console deep-links —
	// a change row's pivot to the CloudTrail event / Activity Log record.
	CloudRef cloudEvidenceRef `json:"cloud_ref"`
}

type cloudEvidenceRow struct {
	Time       string `json:"time"`
	Category   string `json:"category"`
	SignalType string `json:"signal_type"`
	App        string `json:"app"`
	Resource   string `json:"resource"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
	Reason     string `json:"reason"`
	// Grounded = the engine attached this signal to the investigation (archive
	// membership — a fact we hold). Whether it fed the VERDICT specifically is
	// not recorded per-signal, so the API no longer claims it (audit D-P2-13).
	Grounded    bool   `json:"grounded"`
	RcaGroup    string `json:"rca_group"`
	EvidenceRef string `json:"evidence_ref"`
	// CloudRef is the PROVIDER-native identity of what this evidence is about —
	// the id an engineer pastes into the AWS/Azure console (eni-…, i-…, vm name,
	// account/region). The operator text names the resource; this keeps the raw
	// handle one click away instead of in the sentence.
	CloudRef cloudEvidenceRef `json:"cloud_ref"`
}

// cloudEvidenceRef — provider-native identifiers for console pivot / support case.
type cloudEvidenceRef struct {
	Provider   string `json:"provider,omitempty"`    // aws | azure
	ResourceID string `json:"resource_id,omitempty"` // i-… / eni-… / VM id
	Account    string `json:"account,omitempty"`     // account id / subscription
	Region     string `json:"region,omitempty"`
	// LogRef is the provider's own record id where this evidence came from —
	// CloudTrail eventID, VPC flow-log record, Azure activity-log correlation id.
	LogRef string `json:"log_ref,omitempty"`
	// SignalID is our internal evidence id (the platform's own audit handle).
	SignalID string `json:"signal_id,omitempty"`
	// ConsoleURL / LogURL are server-built provider console deep-links (the
	// resource, and the provider's own log record). Empty when unresolvable —
	// a URL is never guessed. See cloud_console.go.
	ConsoleURL string `json:"console_url,omitempty"`
	LogURL     string `json:"log_url,omitempty"`
}

type cloudRcaObject struct {
	CorrelationID string   `json:"correlation_id"`
	VerdictTier   string   `json:"verdict_tier"`
	Confidence    float64  `json:"confidence"`
	TopHypothesis string   `json:"top_hypothesis"`
	SignalCount   int      `json:"signal_count"`
	State         string   `json:"state"`
	WindowStart   string   `json:"window_start"`
	Apps          []string `json:"apps"`
}

// chSignalRow is one corr_signals / corr_signals_archive row as JSONEachRow.
type chSignalRow struct {
	CorrelationID string  `json:"cid"`
	SignalID      string  `json:"signal_id_s"`
	TS            string  `json:"ts_s"`
	Kind          string  `json:"kind"`
	EntityType    string  `json:"entity_type_s"`
	EntityID      string  `json:"entity_id"`
	Severity      string  `json:"severity_s"`
	MetricName    string  `json:"metric_name"`
	Value         float64 `json:"value"`
	Baseline      float64 `json:"baseline"`
	Deviation     float64 `json:"deviation"`
	Attrs         string  `json:"attrs"`
	ObserverID    string  `json:"observer_id"`
}

// chObjectRow is one corr_current row as JSONEachRow.
type chObjectRow struct {
	CorrelationID   string  `json:"cid"`
	VerdictTier     string  `json:"verdict_tier_s"`
	TopConfidence   float64 `json:"top_confidence"`
	TopHypothesis   string  `json:"top_hypothesis"`
	SignalCount     int     `json:"signal_count"`
	State           string  `json:"state_s"`
	WindowStart     string  `json:"window_start_s"`
	Affected        string  `json:"affected"`
	EvidenceMissing string  `json:"evidence_missing"`
}

// signalAttrs is the bounded attrs JSON the cloud producers emit.
type signalAttrs struct {
	App         string `json:"app"`
	AppID       string `json:"app_id"`
	ResourceID  string `json:"resource_id"`
	Account     string `json:"account"`
	Region      string `json:"region"`
	Provider    string `json:"provider"`
	Host        string `json:"host"`
	Actor       string `json:"actor"`
	EventSource string `json:"event_source"`
	RequestID   string `json:"request_id"`
	// Provider-declared cause of a health STATE event (Azure Resource Health
	// reasonType, emitted by cloud-ingest/azure.py poll_resource_health).
	Reason string `json:"reason"`
}

func parseAttrs(raw string) signalAttrs {
	var a signalAttrs
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &a) // best-effort: attrs is bounded, schema-checked upstream
	}
	return a
}

// chJSONRows runs sql (which must end in FORMAT JSONEachRow) and decodes each line.
func chJSONRows[T any](sql string) []T {
	lines := chQuery(sql)
	out := make([]T, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row T
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		out = append(out, row)
	}
	return out
}

// sqlList renders a bounded []string as a SQL literal list. Callers pass only
// values they have already validated (correlation ids, inventory resource ids).
func sqlList(vals []string) string {
	q := make([]string, 0, len(vals))
	for _, v := range vals {
		if v == "" || strings.ContainsAny(v, "'\\\n\t") {
			continue
		}
		q = append(q, "'"+v+"'")
	}
	return strings.Join(q, ",")
}

// appOf resolves the app a cloud signal belongs to, from its own attrs (the
// producer stamps app/app_id) or its entity when the entity IS the app. "" when
// unattributed — a first-class answer, never a guess.
func appOf(row chSignalRow, a signalAttrs) string {
	if a.App != "" {
		return a.App
	}
	if a.AppID != "" {
		return a.AppID
	}
	if row.EntityType == "app" {
		return row.EntityID
	}
	return ""
}

// cloudEvidenceApp names the APPLICATION this evidence concerns. When the signal
// only knows a machine id (an ENI, an instance), the declared inventory resolves
// it to the workload that owns it — an operator reads workloads, not handles.
func cloudEvidenceApp(row chSignalRow, a signalAttrs, name func(string) string) string {
	if app := appOf(row, a); app != "" {
		return app
	}
	if name == nil {
		return ""
	}
	for _, id := range []string{a.ResourceID, row.EntityID, a.Host} {
		if id == "" {
			continue
		}
		if n := name(id); n != "" {
			return n
		}
	}
	return ""
}

// cloudEvidenceResource renders the resource as "name (raw-id)" — the operator
// sees what it is; the engineer keeps the id to paste into the cloud console.
func cloudEvidenceResource(row chSignalRow, a signalAttrs, name func(string) string) string {
	raw := resourceOf(row, a)
	if raw == "—" || raw == "" || name == nil {
		return raw
	}
	if n := name(raw); n != "" && n != raw {
		return n + " (" + raw + ")"
	}
	return raw
}

// resourceOf resolves the resource a signal was measured on.
func resourceOf(row chSignalRow, a signalAttrs) string {
	if a.ResourceID != "" {
		return a.ResourceID
	}
	if row.EntityType == "cloud_resource" {
		return row.EntityID
	}
	if a.Host != "" {
		return a.Host
	}
	return "—"
}

// shortCloudName reduces a raw provider id (ARM path, GCP resource path, ARN) to
// its last path segment — the human-readable resource name — when the inventory
// doesn't resolve it. "/subscriptions/…/virtualMachines/correlix-app-host-01"
// → "correlix-app-host-01". A bare id (no "/") is returned unchanged.
func shortCloudName(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

func providerOf(a signalAttrs) string {
	if a.Provider != "" {
		return a.Provider
	}
	return "cloud"
}

// ── SQL builders (pure — every one carries the caller's tenant_scope) ─────────
// The scope literal is not decoration: the corr_signals / corr_signals_archive /
// corr_objects row policies read it via getSetting('tenant_scope'), so a query
// without it fails and a query with the wrong one cannot see another tenant's rows.
// Bounded by construction: a time window, a LIMIT, and named columns only.

func cloudHealthSQL(windowHours int, appFilter string, limit int, scope string) string {
	return fmt.Sprintf(`
SELECT toString(ts)            AS ts_s,
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
   AND kind IN ('cloud_health','cloud_resource_health')
   AND ts > now() - INTERVAL %d HOUR%s
 ORDER BY ts DESC
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, windowHours, appFilter, limit, scope)
}

// cloudChangesSQL — ONE ROW PER CHANGE. The ingester re-emits the same provider
// event on every poll cycle (same signal_id), so a raw SELECT counted a single
// security-group edit 19 times (audit 2026-07-13, P0-3: "Recent Cloud Changes"
// read 33 for 2 real events). The evidence store is append-only by design, so
// the READ must collapse the re-emissions: one row per signal_id, keeping the
// earliest observation of it (when the change actually happened).
func cloudChangesSQL(windowHours int, appFilter string, limit int, scope string) string {
	// The filter runs in a subquery: an output alias that shadows a source column
	// (any(kind) AS kind) is substituted into WHERE by ClickHouse and throws
	// ILLEGAL_AGGREGATION — the exact bug that made this endpoint answer 0.
	return fmt.Sprintf(`
SELECT toString(min(ts))          AS ts_s,
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
          AND ts > now() - INTERVAL %d HOUR%s
  )
 GROUP BY signal_id
 ORDER BY ts_s DESC
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, windowHours, appFilter, limit, scope)
}

func cloudEvidenceObjectsSQL(windowHours int, appPred, scope string) string {
	return fmt.Sprintf(`
WITH cloud_objs AS (
     SELECT DISTINCT archived_for
       FROM netops.corr_signals_archive
      WHERE source = 'cloud' AND ts > now() - INTERVAL %d HOUR
)
SELECT toString(correlation_id)  AS cid,
       toString(verdict_tier)    AS verdict_tier_s,
       top_confidence            AS top_confidence,
       top_hypothesis            AS top_hypothesis,
       signal_count              AS signal_count,
       toString(state)           AS state_s,
       toString(window_start)    AS window_start_s,
       affected                  AS affected,
       evidence_missing          AS evidence_missing
  FROM netops.corr_current FINAL
 WHERE correlation_id IN (SELECT archived_for FROM cloud_objs)
   AND state = 'open'%s
 ORDER BY window_start DESC
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, windowHours, appPred, cloudEvidenceMaxObjects, scope)
}

func cloudEvidenceSignalsSQL(windowHours int, idList string, limit int, scope string) string {
	return fmt.Sprintf(`
SELECT toString(archived_for)   AS cid,
       toString(signal_id)      AS signal_id_s,
       toString(ts)             AS ts_s,
       kind                     AS kind,
       toString(entity_type)    AS entity_type_s,
       entity_id                AS entity_id,
       toString(severity)       AS severity_s,
       metric_name              AS metric_name,
       value                    AS value,
       attrs                    AS attrs
  FROM netops.corr_signals_archive
 WHERE source = 'cloud'
   AND ts > now() - INTERVAL %d HOUR
   AND archived_for IN (%s)
 ORDER BY ts DESC
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, windowHours, idList, limit, scope)
}

// cloudOpenObjectCountSQL counts ALL open cloud objects — the Active-RCA tile
// must be a real COUNT, never the length of the LIMIT-bounded list above
// (audit D-P1-7: 10 open rendered as 2).
func cloudOpenObjectCountSQL(windowHours int, appPred, scope string) string {
	return fmt.Sprintf(`
WITH cloud_objs AS (
     SELECT DISTINCT archived_for
       FROM netops.corr_signals_archive
      WHERE source = 'cloud' AND ts > now() - INTERVAL %d HOUR
)
SELECT count()
  FROM netops.corr_current FINAL
 WHERE correlation_id IN (SELECT archived_for FROM cloud_objs)
   AND state = 'open'%s
 SETTINGS tenant_scope = '%s'
 FORMAT TSV`, windowHours, appPred, scope)
}

// cloudArchivedSignalCountSQL counts ALL grounded signals for the picked
// objects — the ledger's `count` header (the page itself stays LIMIT-bounded).
func cloudArchivedSignalCountSQL(windowHours int, idList, scope string) string {
	return fmt.Sprintf(`
SELECT count()
  FROM netops.corr_signals_archive
 WHERE source = 'cloud'
   AND ts > now() - INTERVAL %d HOUR
   AND archived_for IN (%s)
 SETTINGS tenant_scope = '%s'
 FORMAT TSV`, windowHours, idList, scope)
}

// chScalarInt runs a single-value TSV query and returns the integer (0 on any
// failure — counts degrade to "0 known", never an invented number).
func chScalarInt(sql string) int {
	for _, line := range chQuery(sql) {
		if n, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
			return n
		}
	}
	return 0
}

// ── handlers ─────────────────────────────────────────────────────────────────

// appFilterSQL builds the (validated) app predicate for the signal tables.
func appFilterSQL(app string) string {
	if app == "" {
		return ""
	}
	return fmt.Sprintf(
		" AND (entity_id = '%[1]s' OR JSONExtractString(attrs,'app') = '%[1]s' OR JSONExtractString(attrs,'app_id') = '%[1]s')", app)
}

// requireCloudApp reads + validates the optional ?app= filter.
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
	limit := clampSignalLimit(r.URL.Query().Get("limit"))
	window := clampWindowHours(r.URL.Query().Get("window_hours"))
	// Resolve each signal's raw resource id → the clean resource NAME + its owning
	// app from the tenant-scoped inventory, exactly like handleCloudChanges. Health
	// signals are stamped on a raw provider id (an ARM path, an instance id); the
	// operator reads a name, not a path.
	inv := s.cloudResourceIndex(r)
	rows := chJSONRows[chSignalRow](cloudHealthSQL(window, appFilterSQL(app), limit, safeScopeLiteral(chTenantScope(r))))
	out := make([]cloudHealthSignal, 0, len(rows))
	for _, row := range rows {
		a := parseAttrs(row.Attrs)
		resID := resourceOf(row, a)
		resName := resID
		appName := appOf(row, a)
		if c, ok := lookupCloudResource(inv, resID); ok {
			if c.ResourceName != "" {
				resName = c.ResourceName
			}
			if appName == "" {
				appName = c.AppName
			}
		}
		if resName == resID { // not in inventory — fall back to the last path segment
			resName = shortCloudName(resID)
		}
		// Metric / Current / Baseline apply ONLY to metric-anomaly signals. A
		// health-STATUS event (cloud_resource_health with no metric_name) has no
		// value or baseline — render "—", never a misleading "0".
		metric, current, baseline := "—", "—", "—"
		if row.MetricName != "" {
			metric = row.MetricName
			current = fmtSignalValue(row.Value)
			baseline = fmtBaseline(row.Baseline, row.Deviation)
		}
		out = append(out, cloudHealthSignal{
			Time:     isoTS(row.TS),
			App:      orDash(appName),
			Resource: resName,
			Signal:   row.Kind,
			State:    cloudHealthState(row.Severity),
			Metric:   metric,
			Current:  current,
			Baseline: baseline,
			Severity: cloudHealthSeverity(row.Severity),
			Source:   providerOf(a),
			// A state event's only substance (the provider's own reasonType).
			Reason: strings.TrimSpace(a.Reason),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"signals": out, "count": len(out), "window_hours": window})
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
	limit := clampSignalLimit(r.URL.Query().Get("limit"))
	window := clampWindowHours(r.URL.Query().Get("window_hours"))

	// resource → (app, name, confidence) from the tenant-scoped cloud inventory,
	// keyed by every handle a signal can carry (id, ENI, IP).
	inv := s.cloudResourceIndex(r)

	filter := appFilterSQL(app)
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
		if list := sqlList(ids); list != "" {
			filter = fmt.Sprintf(
				" AND (entity_id IN (%s) OR JSONExtractString(attrs,'app') = '%s' OR JSONExtractString(attrs,'app_id') = '%s')",
				list, app, app)
		}
	}

	rows := chJSONRows[chSignalRow](cloudChangesSQL(window, filter, limit, safeScopeLiteral(chTenantScope(r))))
	out := make([]cloudChangeEvent, 0, len(rows))
	for _, row := range rows {
		a := parseAttrs(row.Attrs)
		resID := resourceOf(row, a)
		appName := appOf(row, a)
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
			src = providerOf(a)
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
			ChangeType: cloudChangeType(row.Kind, row.MetricName),
			Actor:      shortActor(a.Actor),
			Source:     src,
			Confidence: cloudChangeConfidence(a.Actor, a.EventSource, a.RequestID),
			// The engine attaches signals to an object; it does not label a change
			// with the symptoms it "caused". We report none rather than invent one —
			// the Evidence tab shows what a change was actually grounded with.
			RelatedSymptoms: []string{},
			CloudRef:        ref,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": out, "count": len(out), "window_hours": window})
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
	limit := clampSignalLimit(r.URL.Query().Get("limit"))
	window := clampWindowHours(r.URL.Query().Get("window_hours"))
	scope := safeScopeLiteral(chTenantScope(r))

	appPred := ""
	if app != "" {
		appPred = fmt.Sprintf(" AND has(JSONExtract(affected,'apps','Array(String)'), '%s')", app)
	}
	objRows := chJSONRows[chObjectRow](cloudEvidenceObjectsSQL(window, appPred, scope))
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
	if list := sqlList(ids); list != "" {
		totalGrounded = chScalarInt(cloudArchivedSignalCountSQL(window, list, scope))
		for _, row := range chJSONRows[chSignalRow](cloudEvidenceSignalsSQL(window, list, limit, scope)) {
			o := byID[row.CorrelationID]
			a := parseAttrs(row.Attrs)
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
				App:        orDash(cloudEvidenceApp(row, a, resourceNamer)),
				Resource:   cloudEvidenceResource(row, a, resourceNamer),
				Source:     providerOf(a),
				Confidence: verdictConfidence(o.VerdictTier),
				Reason: evidenceReason(row.Kind, row.MetricName, row.EntityID, row.Severity,
					o.TopHypothesis, o.VerdictTier, resourceNamer),
				Grounded:    true,
				RcaGroup:    row.CorrelationID,
				EvidenceRef: row.SignalID,
				CloudRef:    ref,
			})
		}
	}

	// The engine's OWN gaps — the only "missing" evidence we are entitled to show.
	gaps := 0
	for _, o := range objRows {
		apps := affectedApps(o.Affected)
		appName := "—"
		if len(apps) > 0 {
			appName = apps[0]
		}
		for _, gap := range missingEvidence(o.EvidenceMissing) {
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
	openCount := chScalarInt(cloudOpenObjectCountSQL(window, appPred, scope))
	writeJSON(w, http.StatusOK, map[string]any{
		"objects":           objects,
		"evidence":          evidence,
		"count":             totalGrounded + gaps,
		"returned":          len(evidence),
		"open_object_count": openCount,
		"objects_truncated": openCount > len(objects),
		"window_hours":      window,
	})
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
