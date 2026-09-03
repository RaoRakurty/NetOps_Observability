// Package alertwebhook is the DELIVERY layer for the vmalert evaluator.
//
// Until this package existed, vmalert ran with `-notifier.blackhole`: every
// rule in src/config/rules*.yaml was evaluated, the firing state was written
// back to VictoriaMetrics as the ALERTS series, and NOTHING was ever delivered
// to a human. A three-hour correlation-engine outage on 2026-09-02 went
// unnoticed with thirteen alerts standing firing the whole time. The store was
// honest; the notification path did not exist.
//
// This package closes that gap with the smallest surface that can: an
// Alertmanager-v2 receiver the vmalert notifier can POST to, which fans the
// alerts it accepts into the platform's existing notify.Dispatcher channels.
//
// Wire shape (verified against victoriametrics/vmalert:v1.101.0): the
// `-notifier.url` flag names an Alertmanager BASE url and the notifier appends
// `/api/v2/alerts`, so a flag of
//
//	-notifier.url=http://vmalert:<token>@api:8080/api/internal/vmalert
//
// produces `POST /api/internal/vmalert/api/v2/alerts`. vmalert posts the
// Alertmanager v2 API body — a BARE JSON ARRAY of alerts — while the classic
// webhook-receiver contract is a `{"alerts":[...]}` envelope. Both are
// accepted (the first non-whitespace byte decides), because a receiver that
// only understands one of them fails silently in exactly the way this whole
// change exists to end.
//
// Delivery-chain heartbeat: the rules carry an always-firing
// `AlertingHeartbeat` (HeartbeatAlertName) rule. It is NOT an alert and is
// never fanned out; its receipt is recorded as
// netops_alert_webhook_heartbeat_timestamp_seconds. The api is scraped by
// VictoriaMetrics (job netops-api, target api:8080), so that gauge lands in VM
// automatically and `time() - netops_alert_webhook_heartbeat_timestamp_seconds`
// becomes an assertion over the WHOLE chain — vmalert evaluated, the notifier
// posted, this receiver accepted — which no other signal in the stack makes.
// A dead notifier path is now itself alertable.
//
// Zero trust (CLAUDE.md §3): every request is authenticated against a shared
// secret before any state is touched, the body is bounded, the alert count per
// request is bounded, the dedup store is bounded, and the payload's labels are
// treated as untrusted input even though the rule files are server-controlled.
//
// Tenancy (CLAUDE.md §3a): this is platform-GLOBAL plumbing, not a tenant
// surface. It is not principal-scoped and it must never carry tenant data —
// see the tenantLabels refusal in dispatchAlert.
package alertwebhook

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/models"
	"netops/backend/notify"
)

// Environment contract. Declared here so there is exactly one spelling of each
// name and the compose plumbing can be checked against the package.
const (
	// EnvToken is the shared secret vmalert presents. EMPTY DISABLES the
	// receiver entirely (fail-closed): the route is not registered at all.
	// #nosec G101 -- this is the NAME of an environment variable, not a credential.
	EnvToken = "VMALERT_WEBHOOK_TOKEN"
	// EnvCooldown bounds repeat delivery of an identical alert.
	EnvCooldown = "VMALERT_WEBHOOK_COOLDOWN"
)

// Route constants. Path is the SUBTREE the mux registers (vmalert appends its
// own suffix); AlertsPath is the only request path this handler serves.
const (
	Path       = "/api/internal/vmalert/"
	AlertsPath = "/api/internal/vmalert/api/v2/alerts"
)

// HeartbeatAlertName is the always-firing delivery-chain probe rule. It is
// exported so the rule file and this code can be cross-checked by grep: if the
// rule is renamed without renaming this constant, the heartbeat gauge freezes
// and the chain alert fires — loudly wrong rather than silently absent.
const HeartbeatAlertName = "AlertingHeartbeat"

// DefaultCooldown is the suppression window for a repeated identical alert.
// vmalert re-posts every active alert on each notifier resend interval; without
// this the operator's phone repeats every rule, forever.
const DefaultCooldown = 30 * time.Minute

const (
	// maxBodyBytes bounds the request body. This route is JWT-EXEMPT (it
	// authenticates with its own shared secret), so it rides a HasPrefix escape
	// in withAuth and therefore does NOT get the pre-auth route-class body cap
	// — this MaxBytesReader is the only cap on it. §9 bounded IO.
	maxBodyBytes = 1 << 20
	// maxAlertsPerRequest bounds the fan-out one request can cause. vmalert
	// batches, but a batch is still a bounded batch.
	maxAlertsPerRequest = 500
	// maxDedupEntries hard-caps the cool-down store. A bounded store that stops
	// deduping under extreme cardinality is acceptable; one that grows forever
	// is a memory leak in the process that is supposed to report memory leaks.
	maxDedupEntries = 4096
)

// tenantLabels are the labels whose presence makes an incoming alert
// UNDELIVERABLE on this path (§3a). See dispatchAlert.
var tenantLabels = [...]string{"tenant", "tenant_id", "org"}

// validSeverities is notify's severity ladder (notify/servicenow.go
// severityRank). Anything else is not a severity this platform can route.
var validSeverities = map[string]bool{
	"info": true, "notice": true, "warning": true, "error": true, "critical": true,
}

// Dispatcher is the notification seam. Depending on the INTERFACE rather than
// on *notify.Dispatcher (§5: interfaces for all external dependencies) is what
// lets the tests assert the exact models.Alert produced without a delivery
// worker pool, and keeps this package from importing the server.
type Dispatcher interface {
	Dispatch(a models.Alert)
	DispatchResolve(a models.Alert)
}

// LogFunc is the injected structured logger (§10). level is one of
// "info"/"warn"/"error".
type LogFunc func(level, msg string, fields map[string]any)

// Deps is the injected dependency set. No globals, no singletons (§5).
type Deps struct {
	// Dispatcher receives the accepted alerts. Required.
	Dispatcher Dispatcher
	// Token is the shared secret. Required and non-empty: Handler refuses to
	// build without it rather than serving an unauthenticated fan-out.
	Token string
	// Cooldown suppresses a repeat of an identical alert. <=0 uses
	// DefaultCooldown.
	Cooldown time.Duration
	// Now is the injected clock, so the cool-down is testable without sleeping.
	// nil uses time.Now.
	Now func() time.Time
	// HostRoute is the HOST-MONITORING push destination (hostroute.go): the
	// phone channel the external watchdog already uses. nil = not configured,
	// which is COUNTED and warned about once, never an error per alert. This
	// route is deliberately independent of the product notification channels —
	// it is how the stack reports on ITSELF.
	HostRoute HostPusher
	// Metrics is the counter set surfaced on /metrics. nil is safe (every
	// method is nil-safe) but loses the observability §10 asks for.
	Metrics *Metrics
	// Log is the structured logger. nil discards.
	Log LogFunc
}

// ErrNoDispatcher / ErrNoToken are the two refusals Handler can make. Both are
// misconfiguration, and both are LOUD at construction rather than at the first
// undelivered alert.
var (
	ErrNoDispatcher = errors.New("alertwebhook: a Dispatcher is required")
	ErrNoToken      = errors.New("alertwebhook: " + EnvToken + " is required (an unauthenticated alert fan-out is never acceptable)")
)

// ParseCooldown parses the operator's cool-down setting. An invalid value logs
// a warning and yields the default: a typo in a duration must never take the
// process down, and must never silently become "no suppression at all".
func ParseCooldown(raw string, log LogFunc) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultCooldown
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		if log != nil {
			log("warn", "invalid "+EnvCooldown+" — using the default", map[string]any{
				"value": raw, "default": DefaultCooldown.String(),
			})
		}
		return DefaultCooldown
	}
	return d
}

// receiver holds the handler's injected deps plus the bounded dedup state.
type receiver struct {
	deps     Deps
	cooldown time.Duration
	now      func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time // fingerprint → time it was last delivered

	// Host-monitoring route state (hostroute.go). hostQ is the BOUNDED pending
	// queue; hostRunning says whether a drain goroutine currently owns it, so an
	// idle receiver holds none. hostOnce keeps "no topic configured" to a single
	// log line for the process's life.
	hostMu      sync.Mutex
	hostRunning bool
	hostQ       chan hostJob
	hostOnce    sync.Once
}

// Handler builds the Alertmanager-v2 receiver. It returns an error rather than
// a degraded handler when a dependency is missing, so a misconfigured stack
// fails at boot with a named cause instead of accepting alerts and dropping
// them (the exact failure mode this package exists to end).
func Handler(d Deps) (http.HandlerFunc, error) {
	if d.Dispatcher == nil {
		return nil, ErrNoDispatcher
	}
	if strings.TrimSpace(d.Token) == "" {
		return nil, ErrNoToken
	}
	r := &receiver{
		deps:     d,
		cooldown: d.Cooldown,
		now:      d.Now,
		seen:     make(map[string]time.Time),
	}
	if r.cooldown <= 0 {
		r.cooldown = DefaultCooldown
	}
	if r.now == nil {
		r.now = time.Now
	}
	if d.HostRoute != nil {
		r.hostQ = make(chan hostJob, hostQueueSize)
	}
	d.Metrics.setEnabled(true)
	d.Metrics.setHostRouteEnabled(d.HostRoute != nil)
	return r.serve, nil
}

// ── wire format ─────────────────────────────────────────────────────────────

// wireAlert is the subset of an Alertmanager v2 alert this receiver reads.
// Unknown fields (generatorURL, fingerprint, …) are ignored by design: a
// notifier is free to send more than we consume, and a receiver that rejects
// what it does not recognise breaks on the next upstream version.
type wireAlert struct {
	Status      string            `json:"status"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    string            `json:"startsAt"`
	EndsAt      string            `json:"endsAt"`
}

// wireEnvelope is the classic webhook-receiver body. Every other top-level
// field (groupKey, receiver, commonLabels, externalURL, version, …) is
// deliberately absent from this struct and therefore ignored.
type wireEnvelope struct {
	Alerts []wireAlert `json:"alerts"`
}

// ── HTTP ────────────────────────────────────────────────────────────────────

func (r *receiver) serve(w http.ResponseWriter, req *http.Request) {
	r.deps.Metrics.inc(&r.deps.Metrics.requests)

	// Order: method, then CREDENTIAL, then path. Authenticating before the path
	// check means an unauthenticated caller cannot probe which sub-paths of the
	// subtree exist; the 405 is first only because "wrong verb" is not a
	// credential decision and needs the Allow header to be useful.
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if !r.authorized(req) {
		r.deps.Metrics.inc(&r.deps.Metrics.unauthorized)
		// NEVER log the presented credential or the expected one — this log
		// line is shipped to OpenSearch and kept for the retention window.
		r.log("warn", "vmalert webhook rejected: bad or missing shared secret", map[string]any{
			"remote": req.RemoteAddr,
			"path":   req.URL.Path,
		})
		w.Header().Set("WWW-Authenticate", `Basic realm="vmalert", charset="UTF-8"`)
		writeErr(w, http.StatusUnauthorized, "invalid credential")
		return
	}
	if req.URL.Path != AlertsPath {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}

	alerts, err := readAlerts(w, req)
	if err != nil {
		r.deps.Metrics.inc(&r.deps.Metrics.malformed)
		r.log("warn", "vmalert webhook payload rejected", map[string]any{"error": err.Error()})
		writeErr(w, http.StatusBadRequest, "malformed payload")
		return
	}

	var received, dispatched, suppressed, dropped, heartbeats int
	for _, a := range alerts {
		received++
		switch res := r.handleAlert(a); res {
		case resultDispatched:
			dispatched++
		case resultSuppressed:
			suppressed++
		case resultDroppedTenant:
			dropped++
		case resultHeartbeat:
			heartbeats++
		}
	}
	r.deps.Metrics.add(&r.deps.Metrics.alertsReceived, int64(received))
	r.deps.Metrics.add(&r.deps.Metrics.dispatched, int64(dispatched))
	r.deps.Metrics.add(&r.deps.Metrics.suppressed, int64(suppressed))
	r.deps.Metrics.add(&r.deps.Metrics.droppedTenant, int64(dropped))

	// ALWAYS 200 once authenticated and parsed. vmalert retries a 5xx forever
	// and would turn a receiver-side bug into a self-inflicted request storm;
	// the per-alert outcome is reported in the body and in the metrics instead.
	writeJSON(w, http.StatusOK, map[string]any{
		"received":   received,
		"dispatched": dispatched,
		"suppressed": suppressed,
		"dropped":    dropped,
		"heartbeat":  heartbeats,
	})
}

// authorized checks the shared secret. Bearer OR Basic (any username, the token
// as password) — Basic is what makes credentials-in-URL work, which is how the
// compose default hands vmalert the secret without a file mount.
//
// Both forms are compared in constant time and BOTH are evaluated before the
// verdict is returned, so the answer carries no timing signal about which
// scheme was presented or how much of it matched.
func (r *receiver) authorized(req *http.Request) bool {
	want := []byte(r.deps.Token)

	var bearer string
	if h := req.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		bearer = strings.TrimSpace(h[7:])
	}
	var basic string
	if _, pw, ok := req.BasicAuth(); ok {
		basic = pw
	}

	okBearer := subtle.ConstantTimeCompare([]byte(bearer), want) == 1
	okBasic := subtle.ConstantTimeCompare([]byte(basic), want) == 1
	return okBearer || okBasic
}

// readAlerts reads a BOUNDED body and accepts either wire shape.
func readAlerts(w http.ResponseWriter, req *http.Request) ([]wireAlert, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimLeftFunc(string(body), func(rn rune) bool {
		return rn == ' ' || rn == '\t' || rn == '\n' || rn == '\r'
	})
	if trimmed == "" {
		return nil, errors.New("empty body")
	}
	var alerts []wireAlert
	switch trimmed[0] {
	case '[':
		// vmalert's own shape: the Alertmanager v2 API bare array.
		if err := json.Unmarshal([]byte(trimmed), &alerts); err != nil {
			return nil, err
		}
	case '{':
		// The classic webhook-receiver envelope.
		var env wireEnvelope
		if err := json.Unmarshal([]byte(trimmed), &env); err != nil {
			return nil, err
		}
		alerts = env.Alerts
	default:
		return nil, errors.New("body is neither a JSON array nor a JSON object")
	}
	if len(alerts) > maxAlertsPerRequest {
		alerts = alerts[:maxAlertsPerRequest]
	}
	return alerts, nil
}

// ── per-alert handling ──────────────────────────────────────────────────────

type result int

const (
	resultDispatched result = iota
	resultSuppressed
	resultDroppedTenant
	resultHeartbeat
)

func (r *receiver) handleAlert(a wireAlert) result {
	labels := map[string]string{}
	for k, v := range a.Labels {
		labels[k] = v
	}

	// §3a — REFUSE TO LAUNDER TENANT DATA.
	//
	// vmalert evaluates only the two server-controlled, checked-in rule files,
	// so a tenant label here is a BUG in a rule, not a legitimate scoping
	// signal. This endpoint fans out onto the platform-GLOBAL operator
	// channels, which are not principal-scoped and cannot be: forwarding an
	// alert that carries one tenant's identity onto every operator's phone is a
	// cross-tenant leak. Default-closed: drop, count, warn — never guess.
	for _, l := range tenantLabels {
		if strings.TrimSpace(labels[l]) != "" {
			r.log("warn", "vmalert alert dropped: tenant-scoped label on a platform-global path", map[string]any{
				"alertname": labels["alertname"],
				"label":     l,
			})
			return resultDroppedTenant
		}
	}

	name := strings.TrimSpace(labels["alertname"])

	// Delivery-chain heartbeat: recorded, never delivered. Paging an operator
	// every cool-down to say "the pager works" is how a pager gets muted.
	if name == HeartbeatAlertName {
		r.deps.Metrics.recordHeartbeat(r.now())
		return resultHeartbeat
	}

	// LAYER NORMALIZATION (§3a, and the whole point of this change).
	//
	// notify.PlatformScopeFilter wraps the GLOBAL paging channels and forwards
	// ONLY alerts whose `layer` label is in notify.PlatformLayers
	// {stack, host, clickhouse, platform} — default-closed, because a
	// CUSTOMER-network alert must page through the tenant-scoped RCA policy
	// lane instead. vmalert's rules, however, emit nine layers: bus,
	// clickhouse, correlation, host, ingest, metrics, platform, stack,
	// storage. Five of those are not in the allowlist, so without this
	// normalization every correlation/bus/ingest/storage/metrics alert —
	// including the CorrelationConsumerDead rule that would have caught the
	// 2026-09-02 outage — is silently dropped one step before delivery and the
	// gap this change closes stays open.
	//
	// Normalizing is SAFE precisely because of the two facts above: everything
	// vmalert can emit is platform self-health by construction (the rule files
	// are server-controlled), and anything carrying a tenant identity was
	// already refused. An already-platform layer is preserved UNCHANGED so
	// existing routing does not move; the original is kept as `rule_layer` so
	// no routing information is destroyed.
	if orig := labels["layer"]; !notify.PlatformLayers[orig] {
		if orig != "" {
			labels["rule_layer"] = orig
		}
		labels["layer"] = "platform"
	}

	if name == "" {
		name = "vmalert"
	}
	status := strings.ToLower(strings.TrimSpace(a.Status))
	fp := fingerprint(name, labels, status)

	// Dedup applies to both legs. firing and resolved hash differently by
	// construction (status is in the fingerprint), so a resolution is never
	// suppressed by its own trigger and is always delivered promptly.
	if !r.admit(fp) {
		return resultSuppressed
	}

	alert := models.Alert{
		ID:          fp,
		Rule:        name,
		Severity:    severityOf(labels["severity"]),
		Summary:     summaryOf(a.Annotations, name),
		Description: descriptionOf(a.Annotations),
		Labels:      labels,
		FiredAt:     r.parseTime(a.StartsAt),
	}
	if status == "resolved" {
		at := r.parseTime(a.EndsAt)
		alert.ResolvedAt = &at
		r.deps.Dispatcher.DispatchResolve(alert)
	} else {
		r.deps.Dispatcher.Dispatch(alert)
	}
	// TWO AUDIENCES, TWO ROUTES (hostroute.go). The product dispatcher above
	// carries this alert to whatever channels an operator configured; the host
	// route below carries it to the host-monitoring phone channel whether or
	// not anything was ever configured. Both legs are downstream of the SAME
	// tenant refusal and the SAME cool-down, so the second route adds a
	// destination, never a second buzz.
	r.pushHost(alert, labels, status)
	return resultDispatched
}

// admit reports whether fp may be delivered now, and records the delivery.
// The store is swept and hard-capped on every insert (§9 bounded queues).
func (r *receiver) admit(fp string) bool {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if last, ok := r.seen[fp]; ok && now.Sub(last) < r.cooldown {
		return false
	}
	// Sweep expired entries first — under normal operation this alone keeps the
	// map at the number of concurrently-firing alerts.
	for k, t := range r.seen {
		if now.Sub(t) >= r.cooldown {
			delete(r.seen, k)
		}
	}
	// Hard cap: evict the oldest live entry rather than growing without bound.
	for len(r.seen) >= maxDedupEntries {
		oldestKey, oldest := "", time.Time{}
		for k, t := range r.seen {
			if oldestKey == "" || t.Before(oldest) {
				oldestKey, oldest = k, t
			}
		}
		if oldestKey == "" {
			break
		}
		delete(r.seen, oldestKey)
	}
	r.seen[fp] = now
	return true
}

// fingerprint is the stable identity of an alert occurrence: the rule name, the
// full sorted label set, and the status. It is used both as the cool-down key
// and as models.Alert.ID, which is what destinations with resolution semantics
// key on (notify/pagerduty.go dedupFor) — so the same alert reopens the same
// incident instead of accumulating new ones.
func fingerprint(name string, labels map[string]string, status string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0})
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{'='})
		h.Write([]byte(labels[k]))
		h.Write([]byte{0})
	}
	h.Write([]byte(status))
	return hex.EncodeToString(h.Sum(nil))
}

// severityOf validates against notify's ladder. An absent or unknown severity
// becomes "warning": routing an alert the platform cannot rank is better than
// dropping it, and better than promoting it to critical.
func severityOf(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if validSeverities[s] {
		return s
	}
	return "warning"
}

func summaryOf(ann map[string]string, name string) string {
	if s := strings.TrimSpace(ann["summary"]); s != "" {
		return s
	}
	return name
}

func descriptionOf(ann map[string]string) string {
	desc := strings.TrimSpace(ann["description"])
	if rb := strings.TrimSpace(ann["runbook"]); rb != "" {
		if desc != "" {
			desc += "\n"
		}
		desc += "Runbook: " + rb
	}
	return desc
}

// parseTime accepts RFC3339 and falls back to the injected clock. An
// unparseable timestamp must not cost us the alert.
func (r *receiver) parseTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return r.now()
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil || t.IsZero() {
		return r.now()
	}
	return t
}

func (r *receiver) log(level, msg string, fields map[string]any) {
	if r.deps.Log != nil {
		r.deps.Log(level, msg, fields)
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body) // best-effort: status committed; a failed write means the client is gone
}

// writeErr never echoes the presented credential or any part of it.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
