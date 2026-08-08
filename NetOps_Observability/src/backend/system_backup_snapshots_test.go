package backend

// system_backup_snapshots_test.go — #150: the snapshot-policy control plane.
//
// Two halves, matching the surface's two risks:
//  1. the SM plumbing — the view must parse the real policy/explain shapes and
//     the update must perform the seq_no/primary_term dance (SM rejects a
//     token-less PUT — the apply-ism.sh bug class) and ride _start/_stop for
//     the enabled flip;
//  2. the §3a gate — platform-GLOBAL config behind requirePlatformAdmin: a
//     tenant admin holds full administration:admin, and a scope-blind gate here
//     would hand every tenant the platform's backup posture (the privilege
//     leak the gate rule exists to stop).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// smStub is a minimal OpenSearch SM endpoint double. It serves a mutable
// policy document and records what the client sent.
type smStub struct {
	policy      map[string]any
	enabled     bool
	putURL      atomic.Value // string: RawQuery of the last policy PUT
	putBody     atomic.Value // []byte
	startCalls  atomic.Int64
	stopCalls   atomic.Int64
	failGET     bool
	handlerHits atomic.Int64
}

func newSMStub() *smStub {
	return &smStub{
		enabled: true,
		policy: map[string]any{
			"enabled": true,
			"creation": map[string]any{
				"schedule": map[string]any{
					"cron": map[string]any{"expression": "30 1 * * *", "timezone": "UTC"},
				},
			},
			"deletion": map[string]any{
				"condition": map[string]any{"max_count": float64(14)},
			},
			"schema_version":    float64(19),
			"last_updated_time": float64(1786066432336),
		},
	}
}

func (st *smStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.handlerHits.Add(1)
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/_explain"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"policies": []map[string]any{{
					"name": "netops-daily",
					"creation": map[string]any{
						"trigger": map[string]any{"time": 1786152600000},
						"latest_execution": map[string]any{
							"status":     "SUCCESS",
							"start_time": 1786066252803,
							"end_time":   1786066432336,
						},
					},
					"enabled": st.enabled,
				}},
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/_sm/policies/netops-daily"):
			if st.failGET {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"_seq_no": 1573863, "_primary_term": 19, "sm_policy": st.policy,
			})
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/_sm/policies/netops-daily"):
			st.putURL.Store(r.URL.RawQuery)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			b, _ := json.Marshal(body)
			st.putBody.Store(b)
			// SM's real behaviour: a PUT without the concurrency token is a 400.
			if !strings.Contains(r.URL.RawQuery, "if_seq_no=") || !strings.Contains(r.URL.RawQuery, "if_primary_term=") {
				http.Error(w, "seq_no must be provided when updating", http.StatusBadRequest)
				return
			}
			st.policy = body
			_ = json.NewEncoder(w).Encode(map[string]any{"_id": "netops-daily"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/_start"):
			st.startCalls.Add(1)
			st.enabled = true
			if p, ok := st.policy["enabled"]; ok {
				_ = p
				st.policy["enabled"] = true
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"acknowledged": true})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/_stop"):
			st.stopCalls.Add(1)
			st.enabled = false
			st.policy["enabled"] = false
			_ = json.NewEncoder(w).Encode(map[string]any{"acknowledged": true})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestSnapshotPolicyViewParsesPolicyAndExplain(t *testing.T) {
	stub := newSMStub()
	os := stub.server(t)
	defer os.Close()
	t.Setenv("OPENSEARCH_URL", os.URL)

	_, s := newTestServerState(t)
	v := s.snapshotPolicyView(t.Context())

	if !v.Enabled {
		t.Error("enabled not parsed")
	}
	if v.ScheduleCron != "30 1 * * *" {
		t.Errorf("cron: %q", v.ScheduleCron)
	}
	if v.RetentionMaxCount != 14 {
		t.Errorf("retention: %d", v.RetentionMaxCount)
	}
	if v.RetentionMaxAgeDays != 0 {
		t.Errorf("no max_age in the policy must read as 0 (no age limit), got %d", v.RetentionMaxAgeDays)
	}
	if v.NextRun == "" {
		t.Error("next_run missing (explain trigger not parsed)")
	}
	if v.LastRun == nil || v.LastRun.Status != "SUCCESS" {
		t.Fatalf("last_run: %+v", v.LastRun)
	}
	if v.LastRun.DurationSeconds != 179 { // (1786066432336-1786066252803)/1000
		t.Errorf("duration: %d", v.LastRun.DurationSeconds)
	}
	if v.Detail != "" {
		t.Errorf("healthy read must carry no Detail, got %q", v.Detail)
	}
}

func TestSnapshotPolicyViewParsesMaxAge(t *testing.T) {
	for expr, want := range map[string]int{"30d": 30, "336h": 14, "weird": 0} {
		stub := newSMStub()
		cond := stub.policy["deletion"].(map[string]any)["condition"].(map[string]any)
		cond["max_age"] = expr
		os := stub.server(t)
		t.Setenv("OPENSEARCH_URL", os.URL)

		_, s := newTestServerState(t)
		if v := s.snapshotPolicyView(t.Context()); v.RetentionMaxAgeDays != want {
			t.Errorf("max_age %q: got %d, want %d", expr, v.RetentionMaxAgeDays, want)
		}
		os.Close()
	}
}

func TestSnapshotPolicyViewIsHonestWhenUnreadable(t *testing.T) {
	stub := newSMStub()
	stub.failGET = true
	os := stub.server(t)
	defer os.Close()
	t.Setenv("OPENSEARCH_URL", os.URL)

	_, s := newTestServerState(t)
	v := s.snapshotPolicyView(t.Context())
	if v.Detail == "" {
		t.Fatal("unreadable policy must set Detail — a blank panel reads as healthy")
	}
}

func TestSMApplyUpdateDoesTheSeqNoDanceAndStartStop(t *testing.T) {
	stub := newSMStub()
	os := stub.server(t)
	defer os.Close()
	t.Setenv("OPENSEARCH_URL", os.URL)

	_, s := newTestServerState(t)

	cron := "0 2 * * *"
	keep := 21
	age := 30
	off := false
	if err := s.smApplyUpdate(t.Context(), snapshotPolicyUpdate{
		ScheduleCron: &cron, RetentionMaxCount: &keep, RetentionMaxAgeDays: &age, Enabled: &off,
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	q, _ := stub.putURL.Load().(string)
	if !strings.Contains(q, "if_seq_no=1573863") || !strings.Contains(q, "if_primary_term=19") {
		t.Errorf("PUT missing concurrency token: %q", q)
	}
	body, _ := stub.putBody.Load().([]byte)
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("PUT body: %v", err)
	}
	if got := digMap(doc, "creation", "schedule", "cron", "expression"); got != "0 2 * * *" {
		t.Errorf("cron not applied: %v", got)
	}
	if got := digMap(doc, "deletion", "condition", "max_count"); got != float64(21) {
		t.Errorf("retention not applied: %v", got)
	}
	if got := digMap(doc, "deletion", "condition", "max_age"); got != "30d" {
		t.Errorf("max_age not applied as days: %v", got)
	}
	// Server-side bookkeeping fields must be stripped before the PUT — SM
	// rejects them on write.
	for _, k := range []string{"schema_version", "last_updated_time"} {
		if _, present := doc[k]; present {
			t.Errorf("PUT body still carries %s", k)
		}
	}
	if stub.stopCalls.Load() != 1 {
		t.Errorf("enabled=false must ride _stop exactly once, got %d", stub.stopCalls.Load())
	}
	if stub.startCalls.Load() != 0 {
		t.Errorf("_start must not fire on a disable")
	}
}

func TestSMApplyUpdateMaxAgeZeroClearsTheCondition(t *testing.T) {
	stub := newSMStub()
	cond := stub.policy["deletion"].(map[string]any)["condition"].(map[string]any)
	cond["max_age"] = "30d"
	os := stub.server(t)
	defer os.Close()
	t.Setenv("OPENSEARCH_URL", os.URL)

	_, s := newTestServerState(t)
	zero := 0
	if err := s.smApplyUpdate(t.Context(), snapshotPolicyUpdate{RetentionMaxAgeDays: &zero}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	body, _ := stub.putBody.Load().([]byte)
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("PUT body: %v", err)
	}
	if got := digMap(doc, "deletion", "condition", "max_age"); got != nil {
		t.Errorf("max_age=0 must remove the condition, PUT body still carries %v", got)
	}
	// The count condition must survive the round trip — 0 clears ONLY the age.
	if got := digMap(doc, "deletion", "condition", "max_count"); got != float64(14) {
		t.Errorf("max_count lost in the round trip: %v", got)
	}
}

func TestSystemBackupSnapshotsGate(t *testing.T) {
	stub := newSMStub()
	osrv := stub.server(t)
	defer osrv.Close()
	t.Setenv("OPENSEARCH_URL", osrv.URL)

	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// A tenant ADMIN — full administration:admin inside their tenant, which is
	// exactly the identity a scope-blind gate would wrongly admit (§3a.3).
	st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org G"})
	if st != 201 {
		t.Fatalf("create org: %d %s", st, b)
	}
	orgID := idOf(t, b)
	st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant G", "org_id": orgID})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenantID := idOf(t, b)
	if st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "snapadm", "password": "Passw0rd!2345", "role": "admin", "tenant_id": tenantID,
	}); st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	tenantAdmin := login(t, srv, "snapadm", "Passw0rd!2345").Token

	// Platform admin: full round trip.
	st, b = do(t, srv, "GET", "/api/system/backup/snapshots", admin, nil)
	if st != 200 {
		t.Fatalf("platform GET: %d %s", st, b)
	}
	var view SnapshotPolicyView
	if err := json.Unmarshal(b, &view); err != nil || view.ScheduleCron == "" {
		t.Fatalf("platform view: %v %s", err, b)
	}
	if st, b = do(t, srv, "PUT", "/api/system/backup/snapshots", admin, map[string]any{
		"retention_max_count": 21,
	}); st != 200 {
		t.Fatalf("platform PUT: %d %s", st, b)
	}

	// Tenant admin: refused on BOTH verbs, and the refusal happens before any
	// OpenSearch call (the hit counter pins the gate ahead of the plumbing).
	before := stub.handlerHits.Load()
	if st, _ = do(t, srv, "GET", "/api/system/backup/snapshots", tenantAdmin, nil); st != 403 {
		t.Errorf("tenant admin GET must 403, got %d", st)
	}
	if st, _ = do(t, srv, "PUT", "/api/system/backup/snapshots", tenantAdmin, map[string]any{
		"enabled": false,
	}); st != 403 {
		t.Errorf("tenant admin PUT must 403, got %d", st)
	}
	if got := stub.handlerHits.Load(); got != before {
		t.Errorf("refused requests still reached OpenSearch (%d -> %d hits)", before, got)
	}

	// Validation: garbage cron and out-of-range retention are 400s, and an
	// empty update is refused rather than silently acknowledged.
	for _, bad := range []map[string]any{
		{"schedule_cron": "not-a-cron"},
		{"retention_max_count": 0},
		{"retention_max_count": 400},
		{"retention_max_age_days": -1},
		{"retention_max_age_days": 4000},
		{},
	} {
		if st, _ = do(t, srv, "PUT", "/api/system/backup/snapshots", admin, bad); st != 400 {
			t.Errorf("bad update %v must 400, got %d", bad, st)
		}
	}
}
