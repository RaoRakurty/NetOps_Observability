// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloud

// signals.go — the cloud signal-surface domain (Phase-2 W2.2, extracted from
// package main's cloud_signals.go): bounded-window clamps, the keyset cursor
// codec with its shape-validated ts/id tokens (SR-011: allowlist, never
// quote-escape), the corr_signals/corr_current SQL builders, the classifier
// vocabulary (health state/severity, change type/confidence, verdict
// confidence), evidence phrasing, and the ClickHouse row/attr projections.
// Handlers, the per-tenant window resolver (governance) and the CH transport
// stay in main; scope literals are still validated here before interpolation.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"netops/backend/internal/chschema"
	"netops/backend/internal/noclabel"
)

const (
	// Bounded read window for the cloud signal surfaces. The UI shows "what is
	// happening now", and an unbounded scan of corr_signals is exactly the read
	// pattern the #100 incident was about.
	SignalWindowHours = 24
	// Caller-selectable ceiling (Wave 2 #5 real time-range): 7 days. Still a
	// bounded, granule-prunable window + LIMIT, so it stays inside the #100
	// read contract; anything above clamps here, never widens silently.
	SignalWindowMaxHours = 7 * 24
	SignalDefaultLim     = 200
	SignalMaxLim         = 1000
	// Cloud RCA objects considered by the evidence ledger (bounded join build side).
	EvidenceMaxObjects = 10
)

// ── pure helpers (unit-tested in cloud_signals_test.go) ──────────────────────

// ClampSignalLimit bounds a caller-supplied limit; junk or 0 → the default.
func ClampSignalLimit(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return SignalDefaultLim
	}
	if n > SignalMaxLim {
		return SignalMaxLim
	}
	return n
}

// ClampWindowHours bounds the caller-supplied ?window_hours= read window
// (Wave 2 #5): junk/absent/0 → the 24h default the surfaces always had;
// anything above the 7-day ceiling clamps to it. The handler reports the
// HONORED value back in window_hours so the UI label never claims a range
// the data doesn't cover.
func ClampWindowHours(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return SignalWindowHours
	}
	if n > SignalWindowMaxHours {
		return SignalWindowMaxHours
	}
	return n
}

// tenantWindowHours resolves the read window for a tenant-scoped cloud signal
// surface (Wave 4 #11 slice 2): an explicit, valid ?window_hours= wins (clamped
// exactly as before); absent/junk falls back to the TENANT's governed default
// (/api/settings/rca-window) instead of the fixed 24h. The handler still
// reports the honored value, so the UI label never claims a range the data
// doesn't cover. Platform-global engine tuning is untouched — this only shapes
// per-tenant reads.
// It FAILS CLOSED on a malformed or out-of-range value (the F-71/F-74 rule):
// `?window_hours=abc` and `?window_hours=99999` used to fall through to the
// tenant default, so a caller asking for a 90-day window silently received 24
// hours behind a 200 and read it as the whole window. The caller is now told.
// SafeScopeLiteral is the caller's tenant_scope, guarded before it is embedded in
// a SQL literal. Claims-derived ids are opaque tokens; anything else fails closed
// to the non-matching sentinel rather than reaching the DB.
func SafeScopeLiteral(scope string) string {
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

// ── #10 scale-out: free-text search + keyset cursor for the signal surfaces ──

// SignalQueryMaxLen bounds the caller's free-text ?q= term (it is embedded,
// escaped, in a CH string literal — a bounded needle, never a pattern).
const SignalQueryMaxLen = 128

// cursorVersion tags the opaque page-cursor wire format.
const cursorVersion = "s1"

var ErrBadCursorToken = errors.New("invalid cursor")

// escapeCH escapes a value for embedding inside a single-quoted
// ClickHouse string literal (backslash first, then the quote).
// EscapeCH escapes a ClickHouse single-quoted string literal.
func EscapeCH(s string) string {
	return strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s)
}

// ClampSignalQuery normalizes the free-text search term: trimmed, control
// characters stripped, length-capped. Empty means "no search".
func ClampSignalQuery(raw string) string {
	raw = strings.TrimSpace(raw)
	var b strings.Builder
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	q := b.String()
	if len(q) > SignalQueryMaxLen {
		q = q[:SignalQueryMaxLen]
	}
	return strings.TrimSpace(q)
}

// SignalSearchSQL is the server-side free-text predicate: one case-insensitive
// needle across the fields the operator can actually see in the table. The
// needle is escaped and the fragment stays inside the bounded, scoped query.
func SignalSearchSQL(q string) string {
	if q == "" {
		return ""
	}
	return fmt.Sprintf(
		" AND positionCaseInsensitive(concat(entity_id, ' ', kind, ' ', metric_name, ' ', attrs), '%s') > 0",
		EscapeCH(q))
}

// EncodeSignalCursor packs the keyset position (last row's ts + signal id in
// the newest-first order) into an opaque page token.
func EncodeSignalCursor(ts, id string) string {
	return base64.URLEncoding.EncodeToString([]byte(cursorVersion + "|" + ts + "|" + id))
}

// DecodeSignalCursor unpacks + validates a caller-supplied cursor. Both fields
// are charset-checked BEFORE they may reach a SQL literal; anything off fails
// closed (handler → 400), mirroring the resources surface's cloud.ErrBadCursor.
func DecodeSignalCursor(raw string) (ts, id string, err error) {
	b, err := base64.URLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return "", "", ErrBadCursorToken
	}
	parts := strings.SplitN(string(b), "|", 3)
	if len(parts) != 3 || parts[0] != cursorVersion {
		return "", "", ErrBadCursorToken
	}
	ts, id = parts[1], parts[2]
	if ts == "" || len(ts) > 40 || !tsLiteralOK(ts) || id == "" || len(id) > 80 || !idTokenOK(id) {
		return "", "", ErrBadCursorToken
	}
	return ts, id, nil
}

// tsLiteralOK admits only characters a ClickHouse datetime rendering contains.
func tsLiteralOK(s string) bool {
	for _, c := range s {
		ok := c >= '0' && c <= '9' || c == '-' || c == ':' || c == ' ' || c == '.' ||
			c == 'T' || c == 'Z' || c == '+'
		if !ok {
			return false
		}
	}
	return true
}

// idTokenOK admits opaque signal-id tokens (uuid/hash charset) — the same
// closed-charset idea as SafeScopeLiteral.
func idTokenOK(s string) bool {
	for _, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '-' || c == '.' || c == ':'
		if !ok {
			return false
		}
	}
	return true
}

// SignalCursorPredSQL is the keyset WHERE fragment for the flat ts-ordered
// reads (health, evidence): strictly older than the cursor position, with the
// signal id as the total-order tie-breaker.
func SignalCursorPredSQL(ts, id string) string {
	if ts == "" {
		return ""
	}
	return fmt.Sprintf(
		" AND (ts < parseDateTime64BestEffort('%[1]s') OR (ts = parseDateTime64BestEffort('%[1]s') AND toString(signal_id) < '%[2]s'))",
		ts, id)
}

// ChangesCursorHavingSQL is the same keyset for the change rollup, applied
// AFTER the one-row-per-signal_id collapse (min(ts) is the row's time).
func ChangesCursorHavingSQL(ts, id string) string {
	if ts == "" {
		return ""
	}
	return fmt.Sprintf(
		"HAVING min(ts) < parseDateTime64BestEffort('%[1]s') OR (min(ts) = parseDateTime64BestEffort('%[1]s') AND toString(signal_id) < '%[2]s')\n ",
		ts, id)
}

// parseSignalPage reads the shared ?q= / ?cursor= params for the signal
// surfaces. A malformed cursor fails the request (400), never a silent
// first-page reset — the caller would misread the result as "no more rows".
// NextSignalCursor emits the follow-page token: only when the page came back
// full (len == limit) is there plausibly more to read.
func NextSignalCursor(ts, id string, got, limit int) string {
	if got == 0 || got < limit || ts == "" || id == "" {
		return ""
	}
	return EncodeSignalCursor(ts, id)
}

// HealthState maps a signal severity onto the UI's health state. A cloud
// health signal only EXISTS because the provider reported a problem, so even
// "info" is a reported event — it renders "degraded", never "healthy" (audit
// D-P2-11: a problems-only table must not contain a "healthy" row).
func HealthState(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "crit":
		return "down"
	case "high", "warn", "info":
		return "degraded"
	default:
		return "unknown"
	}
}

// HealthSeverity maps the engine severity onto the table's severity chip.
func HealthSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "crit":
		return "critical"
	case "high", "warn":
		return "warning"
	default:
		return "info"
	}
}

// ChangeType classifies a provider event name into the change taxonomy the
// UI renders. Classification is on the provider's OWN event name — never guessed
// from timing. An unclassifiable-but-present event is a config_change (every
// mutating management-plane call is, by definition, a config change); an absent
// event name stays "unknown".
func ChangeType(kind, event string) string {
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

// ShortActor renders the acting principal without the account number — the role /
// user path is what an operator needs; the raw account id is noise (and PII-ish
// provenance we do not need to echo back). Non-ARN actors pass through, bounded.
func ShortActor(actor string) string {
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

// ChangeConfidence: a change event is a record the provider itself emitted.
// With full provenance (an actor and the emitting service / request id) we OBSERVED
// the change — "confirmed". Without it, the record is real but thinly sourced.
func ChangeConfidence(actor, eventSource, requestID string) string {
	if strings.TrimSpace(actor) != "" && (strings.TrimSpace(eventSource) != "" || strings.TrimSpace(requestID) != "") {
		return "confirmed"
	}
	return "strong"
}

// VerdictConfidence maps the engine's verdict tier onto the UI confidence ladder.
// "undetermined" is honestly unknown — never silently promoted.
func VerdictConfidence(tier string) string {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "confirmed":
		return "confirmed"
	case "suspected":
		return "suspected"
	default:
		return "unknown"
	}
}

// FmtSignalValue renders a signal's measurement. A zero baseline/deviation means
// the engine computed none — that reads "—", never a fabricated "0".
func FmtSignalValue(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

func FmtBaseline(baseline, deviation float64) string {
	if baseline == 0 && deviation == 0 {
		return "—"
	}
	return strconv.FormatFloat(baseline, 'g', -1, 64)
}

// EvidencePhrase renders a signal kind as an OPERATOR sentence — what the
// platform observed, in the words a NOC engineer uses. Schema kinds
// (cloud_flow_log, probe_loss, …) are implementation detail and never surface.
func EvidencePhrase(kind, metric string) string {
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

// EvidenceReason is the one-line, OPERATOR-readable reason a signal is in the
// ledger. Machine identifiers (eni-…, i-…, arn:…) mean nothing to a NOC — they
// are resolved to the resource/application they belong to, with the raw id kept
// only as a parenthetical for the engineer who needs to click through.
func EvidenceReason(kind, metric, entity, severity, hypothesis, tier string, name func(string) string) string {
	what := EvidencePhrase(kind, metric)

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
		what, on, sev, verdict, noclabel.SignatureTitle(hypothesis))
}

// ── wire types ───────────────────────────────────────────────────────────────

type HealthSignal struct {
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

type ChangeEvent struct {
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
	CloudRef EvidenceRef `json:"cloud_ref"`
}

type EvidenceRow struct {
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
	CloudRef EvidenceRef `json:"cloud_ref"`
}

// EvidenceRef — provider-native identifiers for console pivot / support case.
type EvidenceRef struct {
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

type RcaObject struct {
	CorrelationID string   `json:"correlation_id"`
	VerdictTier   string   `json:"verdict_tier"`
	Confidence    float64  `json:"confidence"`
	TopHypothesis string   `json:"top_hypothesis"`
	SignalCount   int      `json:"signal_count"`
	State         string   `json:"state"`
	WindowStart   string   `json:"window_start"`
	Apps          []string `json:"apps"`
}

// SignalRow is one corr_signals / corr_signals_archive row as JSONEachRow.
type SignalRow struct {
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

// ObjectRow is one corr_current row as JSONEachRow.
type ObjectRow struct {
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

// SignalAttrs is the bounded attrs JSON the cloud producers emit.
type SignalAttrs struct {
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
	// Security-lane rollup facts (Wave 5 #16): only the producer that measured
	// them sets them — absence stays absence.
	Rule          string `json:"rule"`            // WAF rule that blocked
	Action        string `json:"action"`          // WAF action (BLOCK)
	Rcode         string `json:"rcode"`           // DNS response code
	QueryType     string `json:"query_type"`      // DNS query type
	ElbStatusCode string `json:"elb_status_code"` // LB-plane HTTP status
	Domain        string `json:"domain"`          // LB host header / domain
	// Provider incident/maintenance facts (kind=provider_event, AWS Health).
	Service       string `json:"service"`  // provider service affected (EC2, …)
	Category      string `json:"category"` // issue | scheduledChange | accountNotification
	Status        string `json:"status"`   // provider's own lifecycle status
	Summary       string `json:"summary"`  // bounded human description
	EvidenceClass string `json:"evidence_class"`
}

func ParseAttrs(raw string) SignalAttrs {
	var a SignalAttrs
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &a) // best-effort: attrs is bounded, schema-checked upstream
	}
	return a
}

// chJSONRows runs sql (which must end in FORMAT JSONEachRow) and decodes each line.
// SQLList renders a bounded []string as a SQL literal list. Callers pass only
// values they have already validated (correlation ids, inventory resource ids).
func SQLList(vals []string) string {
	q := make([]string, 0, len(vals))
	for _, v := range vals {
		if v == "" || strings.ContainsAny(v, "'\\\n\t") {
			continue
		}
		q = append(q, "'"+v+"'")
	}
	return strings.Join(q, ",")
}

// AppOf resolves the app a cloud signal belongs to, from its own attrs (the
// producer stamps app/app_id) or its entity when the entity IS the app. "" when
// unattributed — a first-class answer, never a guess.
func AppOf(row SignalRow, a SignalAttrs) string {
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

// EvidenceApp names the APPLICATION this evidence concerns. When the signal
// only knows a machine id (an ENI, an instance), the declared inventory resolves
// it to the workload that owns it — an operator reads workloads, not handles.
func EvidenceApp(row SignalRow, a SignalAttrs, name func(string) string) string {
	if app := AppOf(row, a); app != "" {
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

// EvidenceResource renders the resource as "name (raw-id)" — the operator
// sees what it is; the engineer keeps the id to paste into the cloud console.
func EvidenceResource(row SignalRow, a SignalAttrs, name func(string) string) string {
	raw := ResourceOf(row, a)
	if raw == "—" || raw == "" || name == nil {
		return raw
	}
	if n := name(raw); n != "" && n != raw {
		return n + " (" + raw + ")"
	}
	return raw
}

// ResourceOf resolves the resource a signal was measured on.
func ResourceOf(row SignalRow, a SignalAttrs) string {
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

// ShortCloudName reduces a raw provider id (ARM path, GCP resource path, ARN) to
// its last path segment — the human-readable resource name — when the inventory
// doesn't resolve it. "/subscriptions/…/virtualMachines/correlix-app-host-01"
// → "correlix-app-host-01". A bare id (no "/") is returned unchanged.
func ShortCloudName(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

func ProviderOf(a SignalAttrs) string {
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

func HealthSQL(windowHours int, appFilter string, limit int, scope string) string {
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
   AND kind IN ('cloud_health','cloud_resource_health')
   AND ts > now() - INTERVAL %d HOUR%s
 ORDER BY ts DESC, signal_id DESC
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, windowHours, appFilter, limit, scope)
}

// ChangesSQL — ONE ROW PER CHANGE. The ingester re-emits the same provider
// event on every poll cycle (same signal_id), so a raw SELECT counted a single
// security-group edit 19 times (audit 2026-07-13, P0-3: "Recent Cloud Changes"
// read 33 for 2 real events). The evidence store is append-only by design, so
// the READ must collapse the re-emissions: one row per signal_id, keeping the
// earliest observation of it (when the change actually happened).
func ChangesSQL(windowHours int, appFilter, having string, limit int, scope string) string {
	// The filter runs in a subquery: an output alias that shadows a source column
	// (any(kind) AS kind) is substituted into WHERE by ClickHouse and throws
	// ILLEGAL_AGGREGATION — the exact bug that made this endpoint answer 0.
	// `having` carries the keyset-cursor fragment (#10): it must run AFTER the
	// GROUP BY collapse because the row's time IS min(ts).
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
          AND ts > now() - INTERVAL %d HOUR%s
  )
 GROUP BY signal_id
 %sORDER BY ts_s DESC, signal_id_s DESC
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, windowHours, appFilter, having, limit, scope)
}

func EvidenceObjectsSQL(windowHours int, appPred, scope string) string {
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
       `+chschema.ISO("window_start")+` AS window_start_s,
       affected                  AS affected,
       evidence_missing          AS evidence_missing
  FROM netops.corr_current FINAL
 WHERE correlation_id IN (SELECT archived_for FROM cloud_objs)
   AND state = 'open'%s
 ORDER BY window_start DESC
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, windowHours, appPred, EvidenceMaxObjects, scope)
}

func EvidenceSignalsSQL(windowHours int, idList, extra string, limit int, scope string) string {
	// `extra` carries the optional free-text + keyset-cursor fragments (#10).
	return fmt.Sprintf(`
SELECT toString(archived_for)   AS cid,
       toString(signal_id)      AS signal_id_s,
       `+chschema.ISO("ts")+`          AS ts_s,
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
   AND archived_for IN (%s)%s
 ORDER BY ts DESC, signal_id DESC
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, windowHours, idList, extra, limit, scope)
}

// OpenObjectCountSQL counts ALL open cloud objects — the Active-RCA tile
// must be a real COUNT, never the length of the LIMIT-bounded list above
// (audit D-P1-7: 10 open rendered as 2).
func OpenObjectCountSQL(windowHours int, appPred, scope string) string {
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

func ArchivedSignalCountSQL(windowHours int, idList, scope string) string {
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
func AppFilterSQL(app string) string {
	if app == "" {
		return ""
	}
	return fmt.Sprintf(
		" AND (entity_id = '%[1]s' OR JSONExtractString(attrs,'app') = '%[1]s' OR JSONExtractString(attrs,'app_id') = '%[1]s')", app)
}

// requireCloudApp reads + validates the optional ?app= filter.
