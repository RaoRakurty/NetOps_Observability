package alertwebhook

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/models"
)

const testToken = "s3cr3t-shared-token"

// fakeDispatcher is the injected notification seam (§5): the tests assert the
// exact models.Alert the receiver produces, with no delivery worker pool.
type fakeDispatcher struct {
	mu       sync.Mutex
	fired    []models.Alert
	resolved []models.Alert
}

func (f *fakeDispatcher) Dispatch(a models.Alert) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fired = append(f.fired, a)
}

func (f *fakeDispatcher) DispatchResolve(a models.Alert) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved = append(f.resolved, a)
}

func (f *fakeDispatcher) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.fired), len(f.resolved)
}

// testClock is the injected clock — no time.Sleep anywhere in this file.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type rig struct {
	h     http.HandlerFunc
	disp  *fakeDispatcher
	clock *testClock
	mx    *Metrics
}

func newRig(t *testing.T, cooldown time.Duration) *rig {
	t.Helper()
	d := &fakeDispatcher{}
	c := &testClock{t: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}
	m := NewMetrics()
	h, err := Handler(Deps{
		Dispatcher: d,
		Token:      testToken,
		Cooldown:   cooldown,
		Now:        c.now,
		Metrics:    m,
	})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	return &rig{h: h, disp: d, clock: c, mx: m}
}

func (r *rig) post(t *testing.T, body string, auth func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, AlertsPath, strings.NewReader(body))
	if auth != nil {
		auth(req)
	}
	w := httptest.NewRecorder()
	r.h(w, req)
	return w
}

func bearer(req *http.Request)      { req.Header.Set("Authorization", "Bearer "+testToken) }
func basicAuth(req *http.Request)   { req.SetBasicAuth("vmalert", testToken) }
func wrongBearer(req *http.Request) { req.Header.Set("Authorization", "Bearer nope-nope-nope") }

// bareArray is vmalert's REAL wire shape: the Alertmanager v2 API body.
const bareArray = `[
 {"status":"firing",
  "labels":{"alertname":"CorrelationConsumerDead","severity":"critical","layer":"correlation","tier":"page"},
  "annotations":{"summary":"correlation consumer is dead","description":"no findings for 15m","runbook":"docs/runbooks/correlation.md"},
  "startsAt":"2026-09-02T11:45:00Z"}
]`

// envelope is the classic webhook-receiver body, with unknown top-level fields
// the receiver must accept and ignore.
const envelope = `{"version":"4","groupKey":"{}:{alertname=\"X\"}","receiver":"netops",
 "externalURL":"http://vmalert:8880","commonLabels":{"stack":"netops"},
 "alerts":[{"status":"firing",
   "labels":{"alertname":"ContainerDown","severity":"critical","layer":"stack"},
   "annotations":{"summary":"api is down"},
   "startsAt":"2026-09-02T11:00:00Z"}]}`

func TestAcceptsVmalertBareArray(t *testing.T) {
	r := newRig(t, time.Minute)
	w := r.post(t, bareArray, bearer)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	fired, resolved := r.disp.counts()
	if fired != 1 || resolved != 0 {
		t.Fatalf("fired/resolved = %d/%d, want 1/0", fired, resolved)
	}
	a := r.disp.fired[0]
	if a.Rule != "CorrelationConsumerDead" {
		t.Errorf("Rule = %q", a.Rule)
	}
	if a.Severity != "critical" {
		t.Errorf("Severity = %q", a.Severity)
	}
	if a.Summary != "correlation consumer is dead" {
		t.Errorf("Summary = %q", a.Summary)
	}
	if !strings.Contains(a.Description, "no findings for 15m") ||
		!strings.Contains(a.Description, "Runbook: docs/runbooks/correlation.md") {
		t.Errorf("Description = %q — must carry the description and the runbook", a.Description)
	}
	if a.ID == "" {
		t.Error("ID (fingerprint) must be set — it is the destination's dedup key")
	}
	want := time.Date(2026, 9, 2, 11, 45, 0, 0, time.UTC)
	if !a.FiredAt.Equal(want) {
		t.Errorf("FiredAt = %v, want %v", a.FiredAt, want)
	}
	// All labels pass through unchanged apart from the layer normalization.
	if a.Labels["tier"] != "page" {
		t.Errorf("tier label must pass through unchanged, got %q", a.Labels["tier"])
	}
}

func TestAcceptsWebhookEnvelopeAndIgnoresUnknownFields(t *testing.T) {
	r := newRig(t, time.Minute)
	w := r.post(t, envelope, bearer)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if fired, _ := r.disp.counts(); fired != 1 {
		t.Fatalf("fired = %d, want 1", fired)
	}
	if got := r.disp.fired[0].Rule; got != "ContainerDown" {
		t.Errorf("Rule = %q", got)
	}
}

func TestAuthAcceptsBearerAndBasicAndRefusesTheRest(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth func(*http.Request)
		want int
	}{
		{"bearer", bearer, http.StatusOK},
		{"basic", basicAuth, http.StatusOK},
		{"missing", nil, http.StatusUnauthorized},
		{"wrong bearer", wrongBearer, http.StatusUnauthorized},
		{"wrong basic", func(q *http.Request) { q.SetBasicAuth("vmalert", "wrong") }, http.StatusUnauthorized},
		{"empty basic password", func(q *http.Request) { q.SetBasicAuth("vmalert", "") }, http.StatusUnauthorized},
		{"garbage header", func(q *http.Request) { q.Header.Set("Authorization", "Basic !!!not-base64") }, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, time.Minute)
			w := r.post(t, bareArray, tc.auth)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, tc.want, w.Body.String())
			}
			if strings.Contains(w.Body.String(), testToken) {
				t.Fatal("the response body echoed the shared secret")
			}
			if tc.want == http.StatusUnauthorized {
				if fired, resolved := r.disp.counts(); fired != 0 || resolved != 0 {
					t.Fatal("an unauthenticated request reached the dispatcher")
				}
				if !strings.Contains(metricsText(r.mx), "netops_alert_webhook_unauthorized_total 1") {
					t.Error("the refusal was not counted")
				}
			}
		})
	}
}

// A password-only Basic header (no username) must still work: credentials-in-URL
// is the compose default and some clients send an empty user.
func TestBasicAuthAcceptsAnyUsername(t *testing.T) {
	r := newRig(t, time.Minute)
	raw := base64.StdEncoding.EncodeToString([]byte(":" + testToken))
	w := r.post(t, bareArray, func(q *http.Request) { q.Header.Set("Authorization", "Basic "+raw) })
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestNonPostIsRejectedWithAllow(t *testing.T) {
	r := newRig(t, time.Minute)
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(m, AlertsPath, nil)
		bearer(req)
		w := httptest.NewRecorder()
		r.h(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", m, w.Code)
		}
		if w.Header().Get("Allow") != http.MethodPost {
			t.Errorf("%s: Allow = %q, want POST", m, w.Header().Get("Allow"))
		}
	}
}

func TestWrongSubPathIs404(t *testing.T) {
	r := newRig(t, time.Minute)
	req := httptest.NewRequest(http.MethodPost, "/api/internal/vmalert/api/v1/alerts", strings.NewReader(bareArray))
	bearer(req)
	w := httptest.NewRecorder()
	r.h(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if fired, _ := r.disp.counts(); fired != 0 {
		t.Fatal("a request on an unknown sub-path reached the dispatcher")
	}
}

func TestOversizeBodyIsRejected(t *testing.T) {
	r := newRig(t, time.Minute)
	big := `[{"status":"firing","labels":{"alertname":"X","pad":"` +
		strings.Repeat("A", maxBodyBytes+1024) + `"}}]`
	w := r.post(t, big, bearer)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if fired, _ := r.disp.counts(); fired != 0 {
		t.Fatal("an oversize body reached the dispatcher")
	}
	if !strings.Contains(metricsText(r.mx), "netops_alert_webhook_malformed_total 1") {
		t.Error("the oversize body was not counted as malformed")
	}
}

func TestMalformedBodiesAreRejected(t *testing.T) {
	for _, body := range []string{"", "   ", "not json", `"a string"`, `[{"status":`} {
		r := newRig(t, time.Minute)
		if w := r.post(t, body, bearer); w.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, w.Code)
		}
	}
}

func TestCooldownSuppressesRepeatAndReleasesAfterTheWindow(t *testing.T) {
	r := newRig(t, 30*time.Minute)

	if w := r.post(t, bareArray, bearer); w.Code != http.StatusOK {
		t.Fatalf("first post: %d", w.Code)
	}
	if fired, _ := r.disp.counts(); fired != 1 {
		t.Fatalf("first post fired = %d, want 1", fired)
	}

	r.clock.advance(29 * time.Minute)
	if w := r.post(t, bareArray, bearer); w.Code != http.StatusOK {
		t.Fatalf("second post: %d", w.Code)
	}
	if fired, _ := r.disp.counts(); fired != 1 {
		t.Fatalf("a repeat inside the cool-down was delivered (fired = %d)", fired)
	}
	if !strings.Contains(metricsText(r.mx), "netops_alert_webhook_suppressed_total 1") {
		t.Error("the suppression was not counted")
	}

	r.clock.advance(2 * time.Minute) // now 31m since the first delivery
	if w := r.post(t, bareArray, bearer); w.Code != http.StatusOK {
		t.Fatalf("third post: %d", w.Code)
	}
	if fired, _ := r.disp.counts(); fired != 2 {
		t.Fatalf("a repeat AFTER the cool-down was suppressed (fired = %d, want 2)", fired)
	}
}

// A resolution has a different fingerprint by construction, so it is never
// suppressed by its own trigger's cool-down.
func TestResolveIsDeliveredImmediatelyAfterFiring(t *testing.T) {
	r := newRig(t, 30*time.Minute)
	if w := r.post(t, bareArray, bearer); w.Code != http.StatusOK {
		t.Fatalf("firing post: %d", w.Code)
	}
	resolved := `[{"status":"resolved",
	  "labels":{"alertname":"CorrelationConsumerDead","severity":"critical","layer":"correlation","tier":"page"},
	  "annotations":{"summary":"correlation consumer is dead"},
	  "startsAt":"2026-09-02T11:45:00Z","endsAt":"2026-09-02T12:05:00Z"}]`
	if w := r.post(t, resolved, bearer); w.Code != http.StatusOK {
		t.Fatalf("resolve post: %d", w.Code)
	}
	fired, res := r.disp.counts()
	if fired != 1 || res != 1 {
		t.Fatalf("fired/resolved = %d/%d, want 1/1", fired, res)
	}
	got := r.disp.resolved[0]
	if got.ResolvedAt == nil {
		t.Fatal("ResolvedAt must be set from endsAt")
	}
	want := time.Date(2026, 9, 2, 12, 5, 0, 0, time.UTC)
	if !got.ResolvedAt.Equal(want) {
		t.Errorf("ResolvedAt = %v, want %v", *got.ResolvedAt, want)
	}
}

// The PlatformScopeFilter problem: an already-platform layer is preserved so
// existing routing does not move; anything else is normalized to "platform"
// with the original kept under rule_layer. Without this every correlation /
// bus / ingest / storage / metrics alert is dropped one step before delivery.
func TestLayerNormalization(t *testing.T) {
	for _, tc := range []struct {
		in, wantLayer, wantRuleLayer string
	}{
		{"stack", "stack", ""},
		{"host", "host", ""},
		{"clickhouse", "clickhouse", ""},
		{"platform", "platform", ""},
		{"correlation", "platform", "correlation"},
		{"bus", "platform", "bus"},
		{"ingest", "platform", "ingest"},
		{"storage", "platform", "storage"},
		{"metrics", "platform", "metrics"},
		{"", "platform", ""},
	} {
		t.Run("layer="+tc.in, func(t *testing.T) {
			r := newRig(t, time.Minute)
			body := fmt.Sprintf(`[{"status":"firing","labels":{"alertname":"R","severity":"warning","layer":%q}}]`, tc.in)
			if w := r.post(t, body, bearer); w.Code != http.StatusOK {
				t.Fatalf("status = %d", w.Code)
			}
			if fired, _ := r.disp.counts(); fired != 1 {
				t.Fatalf("fired = %d, want 1", fired)
			}
			got := r.disp.fired[0].Labels
			if got["layer"] != tc.wantLayer {
				t.Errorf("layer = %q, want %q", got["layer"], tc.wantLayer)
			}
			if got["rule_layer"] != tc.wantRuleLayer {
				t.Errorf("rule_layer = %q, want %q", got["rule_layer"], tc.wantRuleLayer)
			}
		})
	}
}

// CLAUDE.md §3a isolation test for this feature: this path fans out onto the
// platform-GLOBAL operator channels, so an alert carrying a tenant identity is
// DROPPED, never dispatched, and counted.
func TestTenantLabelledAlertsAreDroppedNotDispatched(t *testing.T) {
	for _, label := range []string{"tenant", "tenant_id", "org"} {
		t.Run(label, func(t *testing.T) {
			r := newRig(t, time.Minute)
			body := fmt.Sprintf(
				`[{"status":"firing","labels":{"alertname":"Leaky","severity":"critical","layer":"stack",%q:"acme"}}]`,
				label)
			w := r.post(t, body, bearer)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (a drop is not a client error)", w.Code)
			}
			if fired, resolved := r.disp.counts(); fired != 0 || resolved != 0 {
				t.Fatalf("a tenant-labelled alert reached the GLOBAL channels (%d/%d) — cross-tenant leak",
					fired, resolved)
			}
			if !strings.Contains(metricsText(r.mx), "netops_alert_webhook_dropped_tenant_total 1") {
				t.Error("the drop was not counted")
			}
			var body2 map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body2); err != nil {
				t.Fatalf("response body: %v", err)
			}
			if body2["dropped"] != float64(1) {
				t.Errorf("response dropped = %v, want 1", body2["dropped"])
			}
		})
	}
	// A resolve leg carrying a tenant label is refused just as hard.
	r := newRig(t, time.Minute)
	body := `[{"status":"resolved","labels":{"alertname":"Leaky","layer":"stack","tenant":"acme"}}]`
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if _, resolved := r.disp.counts(); resolved != 0 {
		t.Fatal("a tenant-labelled RESOLVE reached the global channels")
	}
}

func TestHeartbeatIsRecordedButNeverDispatched(t *testing.T) {
	r := newRig(t, 30*time.Minute)
	if r.mx.HeartbeatAt() != 0 {
		t.Fatal("the heartbeat gauge must start at 0 (never seen)")
	}
	hb := fmt.Sprintf(
		`[{"status":"firing","labels":{"alertname":%q,"severity":"info","tier":"heartbeat"}}]`,
		HeartbeatAlertName)
	if w := r.post(t, hb, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if fired, resolved := r.disp.counts(); fired != 0 || resolved != 0 {
		t.Fatalf("the heartbeat was fanned out to the operator (%d/%d)", fired, resolved)
	}
	if got, want := r.mx.HeartbeatAt(), r.clock.now().Unix(); got != want {
		t.Fatalf("heartbeat gauge = %d, want %d", got, want)
	}
	txt := metricsText(r.mx)
	if !strings.Contains(txt, "netops_alert_webhook_heartbeat_total 1") {
		t.Error("the heartbeat counter did not move")
	}
	if !strings.Contains(txt, "# TYPE netops_alert_webhook_heartbeat_timestamp_seconds gauge") {
		t.Error("the heartbeat timestamp must be typed as a gauge")
	}
	if !strings.Contains(txt, "netops_alert_webhook_dispatched_total 0") {
		t.Error("the heartbeat must not count as a dispatch")
	}
	// The heartbeat repeats every evaluation — it must NEVER be suppressed by
	// the cool-down, or the freshness gauge would stall and read as an outage.
	r.clock.advance(30 * time.Second)
	if w := r.post(t, hb, bearer); w.Code != http.StatusOK {
		t.Fatalf("second heartbeat: %d", w.Code)
	}
	if got, want := r.mx.HeartbeatAt(), r.clock.now().Unix(); got != want {
		t.Fatalf("heartbeat gauge = %d, want %d (a repeat must still refresh it)", got, want)
	}
	if !strings.Contains(metricsText(r.mx), "netops_alert_webhook_suppressed_total 0") {
		t.Error("the heartbeat must not be dedup-counted as a normal alert")
	}

	// A NORMAL alert must not move the gauge.
	before := r.mx.HeartbeatAt()
	r.clock.advance(time.Minute)
	if w := r.post(t, bareArray, bearer); w.Code != http.StatusOK {
		t.Fatalf("normal alert: %d", w.Code)
	}
	if fired, _ := r.disp.counts(); fired != 1 {
		t.Fatalf("the normal alert was not dispatched (fired = %d)", fired)
	}
	if r.mx.HeartbeatAt() != before {
		t.Error("a normal alert moved the heartbeat gauge")
	}
}

func TestAlertsPerRequestAreBounded(t *testing.T) {
	r := newRig(t, time.Nanosecond) // no suppression: every alert is distinct anyway
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < maxAlertsPerRequest+50; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"status":"firing","labels":{"alertname":"R%d","layer":"stack"}}`, i)
	}
	sb.WriteString("]")
	if w := r.post(t, sb.String(), bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if fired, _ := r.disp.counts(); fired != maxAlertsPerRequest {
		t.Fatalf("fired = %d, want the per-request cap %d", fired, maxAlertsPerRequest)
	}
}

// §9: the cool-down store must never grow without bound.
func TestDedupStoreIsBounded(t *testing.T) {
	r := newRig(t, time.Hour) // long window: nothing expires during the test
	rec := handlerReceiver(t, r)
	for i := 0; i < maxDedupEntries+500; i++ {
		rec.admit(fmt.Sprintf("fingerprint-%d", i))
	}
	rec.mu.Lock()
	n := len(rec.seen)
	rec.mu.Unlock()
	if n > maxDedupEntries {
		t.Fatalf("dedup store holds %d entries, cap is %d", n, maxDedupEntries)
	}
	// And the sweep path: with everything expired the store collapses.
	r.clock.advance(2 * time.Hour)
	rec.admit("after-expiry")
	rec.mu.Lock()
	n = len(rec.seen)
	rec.mu.Unlock()
	if n != 1 {
		t.Fatalf("after the window expired the store holds %d entries, want 1", n)
	}
}

func TestHandlerRefusesToBuildWithoutTokenOrDispatcher(t *testing.T) {
	if _, err := Handler(Deps{Token: testToken}); !errors.Is(err, ErrNoDispatcher) {
		t.Errorf("no dispatcher: err = %v, want ErrNoDispatcher", err)
	}
	if _, err := Handler(Deps{Dispatcher: &fakeDispatcher{}}); !errors.Is(err, ErrNoToken) {
		t.Errorf("no token: err = %v, want ErrNoToken", err)
	}
	if _, err := Handler(Deps{Dispatcher: &fakeDispatcher{}, Token: "   "}); !errors.Is(err, ErrNoToken) {
		t.Errorf("blank token: err = %v, want ErrNoToken", err)
	}
}

func TestSeverityFallsBackToWarning(t *testing.T) {
	for raw, want := range map[string]string{
		"critical": "critical", "ERROR": "error", "warning": "warning",
		"notice": "notice", "info": "info",
		"": "warning", "page": "warning", "sev1": "warning",
	} {
		if got := severityOf(raw); got != want {
			t.Errorf("severityOf(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestParseCooldown(t *testing.T) {
	if got := ParseCooldown("45m", nil); got != 45*time.Minute {
		t.Errorf("45m → %v", got)
	}
	if got := ParseCooldown("", nil); got != DefaultCooldown {
		t.Errorf("empty → %v, want the default", got)
	}
	var warned int
	log := func(level, _ string, _ map[string]any) {
		if level == "warn" {
			warned++
		}
	}
	for _, bad := range []string{"banana", "-5m", "0"} {
		if got := ParseCooldown(bad, log); got != DefaultCooldown {
			t.Errorf("%q → %v, want the default", bad, got)
		}
	}
	if warned != 3 {
		t.Errorf("invalid values warned %d times, want 3 — a bad duration must be loud, not silent", warned)
	}
}

func TestMetricsAreNilSafe(t *testing.T) {
	var m *Metrics
	m.recordHeartbeat(time.Now())
	m.setEnabled(true)
	m.Write(&bytes.Buffer{})
	if m.HeartbeatAt() != 0 {
		t.Error("nil metrics must read 0")
	}
}

func TestEnabledGaugeIsSetByHandler(t *testing.T) {
	m := NewMetrics()
	if !strings.Contains(metricsText(m), "netops_alert_webhook_enabled 0") {
		t.Error("a receiver that was never built must report enabled 0")
	}
	if _, err := Handler(Deps{Dispatcher: &fakeDispatcher{}, Token: testToken, Metrics: m}); err != nil {
		t.Fatalf("Handler: %v", err)
	}
	if !strings.Contains(metricsText(m), "netops_alert_webhook_enabled 1") {
		t.Error("a built receiver must report enabled 1")
	}
}

// handlerReceiver reaches the receiver behind the returned HandlerFunc. The
// bounded-store guarantee is a property of the STORE, not of the HTTP surface,
// so the test drives it directly rather than through 12k requests.
func handlerReceiver(t *testing.T, r *rig) *receiver {
	t.Helper()
	rec := &receiver{
		deps:     Deps{Dispatcher: r.disp, Token: testToken, Metrics: r.mx},
		cooldown: time.Hour,
		now:      r.clock.now,
		seen:     make(map[string]time.Time),
	}
	return rec
}

func metricsText(m *Metrics) string {
	var b bytes.Buffer
	m.Write(&b)
	return b.String()
}
