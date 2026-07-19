package main

// verify_http_test.go — Active Verification isolation + gating (§3a rule 5):
// cross-tenant verify → 404, tenant opt-in flag respected, settings tenant-
// scoped with secrets write-only, per-tenant rate limit, auto-trigger cooldown
// dedupe. ClickHouse is faked with an httptest server that honors tenant_scope
// exactly like the row-policy + scope injection do in production.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/models"
)

const (
	caseA = "11111111-1111-1111-1111-111111111111"
	caseB = "22222222-2222-2222-2222-222222222222"
)

// fakeCH serves chSelect POSTs. A case row is visible only when the request's
// tenant_scope matches its tenant (or __all__) — the production isolation
// contract, reproduced faithfully.
func verifyFakeCH(t *testing.T, rows map[string]map[string]any) {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		sql := string(body)
		scope := r.URL.Query().Get("tenant_scope")
		var data []map[string]any
		if strings.Contains(sql, "verdict_tier = 'suspected'") {
			for id, row := range rows {
				if scope == row["tenant_id"] && row["verdict"] == "suspected" {
					data = append(data, map[string]any{"cid": id, "affected": row["affected"]})
				}
			}
		} else {
			for id, row := range rows {
				if strings.Contains(sql, id) && (scope == "__all__" || scope == row["tenant_id"]) {
					data = append(data, row)
				}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
}

type verifyFixture struct {
	tenantID string
	token    string
	admin    string // tenant-scoped admin token
}

// setupVerifyServer builds the shared harness plus the verification stores,
// two tenants (each with an operator + a tenant admin), and one discovered
// device per tenant.
func setupVerifyServer(t *testing.T) (*httptest.Server, *server, map[string]*verifyFixture) {
	t.Helper()
	srv, s := newTestServerState(t)
	dir := t.TempDir()
	s.verifyCfg = newVerifyConfigStore(filepath.Join(dir, "verify_config.json"), nil)
	s.verifyRuns = newVerifyRunStore(filepath.Join(dir, "verify_runs.json"))
	s.verifyLimiter = newTenantRateLimiter()

	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	fix := map[string]*verifyFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		op := "op-" + name
		if st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": op, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		}); st != 201 {
			t.Fatalf("create user %s: %d %s", op, st, b)
		}
		ta := "adm-" + name
		if st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": ta, "password": "Passw0rd!2345", "role": "admin", "tenant_id": tenantID,
		}); st != 201 {
			t.Fatalf("create admin %s: %d %s", ta, st, b)
		}
		fix[name] = &verifyFixture{
			tenantID: tenantID,
			token:    login(t, srv, op, "Passw0rd!2345").Token,
			admin:    login(t, srv, ta, "Passw0rd!2345").Token,
		}
		s.discovery.Upsert(models.Device{
			ID: "dev-" + name, Name: "edge-" + name, Address: "127.0.0.1",
			Vendor: "cisco", TenantID: tenantID, Source: "test", LastSeen: time.Now(),
		})
	}
	return srv, s, fix
}

func caseRow(tenant, device, verdict string) map[string]any {
	return map[string]any{
		"tenant_id": tenant,
		"state":     "open",
		"verdict":   verdict,
		"affected":  fmt.Sprintf(`{"devices":[%q],"paths":[]}`, device),
	}
}

func TestVerifyCrossTenantIsolation(t *testing.T) {
	t.Setenv("FEATURE_ACTIVE_VERIFICATION", "true")
	t.Setenv("BUS_BRIDGE_URL", "") // emit no-op in tests
	t.Setenv("VERIFY_CHECK_TIMEOUT_SEC", "1")
	t.Setenv("VERIFY_RUN_BUDGET_SEC", "10")
	srv, s, fix := setupVerifyServer(t)
	verifyFakeCH(t, map[string]map[string]any{
		caseA: caseRow(fix["A"].tenantID, "dev-A", "suspected"),
		caseB: caseRow(fix["B"].tenantID, "dev-B", "suspected"),
	})
	// tenant A opts in
	if _, err := s.verifyCfg.set(fix["A"].tenantID, verifySettingsPatch{Enabled: boolPtr(true)}); err != nil {
		t.Fatal(err)
	}

	// B cannot see or trigger A's case — 404, never 403 (id must not leak)
	if st, _ := do(t, srv, "GET", "/api/correlations/"+caseA+"/verify", fix["B"].token, nil); st != 404 {
		t.Fatalf("cross-tenant GET verify: want 404, got %d", st)
	}
	if st, _ := do(t, srv, "POST", "/api/correlations/"+caseA+"/verify", fix["B"].token, nil); st != 404 {
		t.Fatalf("cross-tenant POST verify: want 404, got %d", st)
	}

	// A can trigger its own case
	st, b := do(t, srv, "POST", "/api/correlations/"+caseA+"/verify", fix["A"].token, nil)
	if st != 202 {
		t.Fatalf("own-tenant POST verify: want 202, got %d %s", st, b)
	}
	var resp struct {
		RunID   string   `json:"run_id"`
		Devices []string `json:"devices"`
	}
	if err := json.Unmarshal(b, &resp); err != nil || resp.RunID == "" {
		t.Fatalf("bad verify response: %s", b)
	}
	if len(resp.Devices) != 1 || resp.Devices[0] != "dev-A" {
		t.Fatalf("must resolve only tenant A's device: %+v", resp.Devices)
	}

	// GET shows the run to A…
	if st, b = do(t, srv, "GET", "/api/correlations/"+caseA+"/verify", fix["A"].token, nil); st != 200 ||
		!strings.Contains(string(b), resp.RunID) {
		t.Fatalf("own-tenant GET verify: %d %s", st, b)
	}
	// …and still 404 to B.
	if st, _ = do(t, srv, "GET", "/api/correlations/"+caseA+"/verify", fix["B"].token, nil); st != 404 {
		t.Fatalf("cross-tenant GET after run: want 404, got %d", st)
	}
}

func TestVerifyTenantFlagRespectedAndFeatureGate(t *testing.T) {
	t.Setenv("BUS_BRIDGE_URL", "")
	srv, _, fix := setupVerifyServer(t)
	verifyFakeCH(t, map[string]map[string]any{
		caseA: caseRow(fix["A"].tenantID, "dev-A", "suspected"),
	})

	// Global feature OFF → the subresource does not exist (404, undisclosed).
	t.Setenv("FEATURE_ACTIVE_VERIFICATION", "")
	if st, _ := do(t, srv, "POST", "/api/correlations/"+caseA+"/verify", fix["A"].token, nil); st != 404 {
		t.Fatalf("feature off: want 404, got %d", st)
	}

	// Feature ON but tenant NOT opted in → 403 with guidance.
	t.Setenv("FEATURE_ACTIVE_VERIFICATION", "true")
	st, b := do(t, srv, "POST", "/api/correlations/"+caseA+"/verify", fix["A"].token, nil)
	if st != 403 || !strings.Contains(string(b), "not enabled") {
		t.Fatalf("tenant flag off: want 403, got %d %s", st, b)
	}
}

func TestVerifySettingsTenantScopedAndSecretsWriteOnly(t *testing.T) {
	t.Setenv("FEATURE_ACTIVE_VERIFICATION", "true")
	srv, s, fix := setupVerifyServer(t)

	// operator (non-admin) cannot write settings
	if st, _ := do(t, srv, "PUT", "/api/settings/verification", fix["A"].token,
		map[string]any{"enabled": true}); st != 403 {
		t.Fatalf("operator PUT settings: want 403, got %d", st)
	}
	// tenant A admin opts in + stores an SSH credential
	st, b := do(t, srv, "PUT", "/api/settings/verification", fix["A"].admin, map[string]any{
		"enabled": true, "ssh_user": "verify", "ssh_password": "s3cret-material",
	})
	if st != 200 {
		t.Fatalf("admin PUT settings: %d %s", st, b)
	}
	if strings.Contains(string(b), "s3cret-material") {
		t.Fatalf("settings response leaked secret material: %s", b)
	}
	var view struct {
		Enabled       bool `json:"enabled"`
		SSHConfigured bool `json:"ssh_configured"`
	}
	if err := json.Unmarshal(b, &view); err != nil || !view.Enabled || !view.SSHConfigured {
		t.Fatalf("bad settings view: %s", b)
	}
	// GET never returns secrets either
	if st, b = do(t, srv, "GET", "/api/settings/verification", fix["A"].admin, nil); st != 200 ||
		strings.Contains(string(b), "s3cret") {
		t.Fatalf("GET settings: %d %s", st, b)
	}
	// tenant B sees ITS OWN (unconfigured) view — A's opt-in is invisible
	if st, b = do(t, srv, "GET", "/api/settings/verification", fix["B"].admin, nil); st != 200 {
		t.Fatalf("B GET settings: %d %s", st, b)
	}
	var viewB struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(b, &viewB); err != nil || viewB.Enabled {
		t.Fatalf("tenant B must not inherit A's flag: %s", b)
	}
	// stored credential unseals for A's tenant only
	if cred := s.verifyCfg.sshCredFor(fix["A"].tenantID); cred == nil || cred.Password != "s3cret-material" {
		t.Fatal("stored credential must unseal for its own tenant")
	}
	if cred := s.verifyCfg.sshCredFor(fix["B"].tenantID); cred != nil {
		t.Fatal("tenant B must have no credential")
	}
}

func TestVerifyManualRateLimited(t *testing.T) {
	t.Setenv("FEATURE_ACTIVE_VERIFICATION", "true")
	t.Setenv("VERIFY_RATE_PER_MIN", "1")
	t.Setenv("BUS_BRIDGE_URL", "")
	t.Setenv("VERIFY_CHECK_TIMEOUT_SEC", "1")
	t.Setenv("VERIFY_RUN_BUDGET_SEC", "10")
	srv, s, fix := setupVerifyServer(t)
	verifyFakeCH(t, map[string]map[string]any{
		caseA: caseRow(fix["A"].tenantID, "dev-A", "suspected"),
	})
	if _, err := s.verifyCfg.set(fix["A"].tenantID, verifySettingsPatch{Enabled: boolPtr(true)}); err != nil {
		t.Fatal(err)
	}
	if st, b := do(t, srv, "POST", "/api/correlations/"+caseA+"/verify", fix["A"].token, nil); st != 202 {
		t.Fatalf("first verify: want 202, got %d %s", st, b)
	}
	if st, _ := do(t, srv, "POST", "/api/correlations/"+caseA+"/verify", fix["A"].token, nil); st != 429 {
		t.Fatalf("second verify inside the window: want 429, got %d", st)
	}
}

func TestVerifyTriggerCooldownDedupe(t *testing.T) {
	t.Setenv("FEATURE_ACTIVE_VERIFICATION", "true")
	t.Setenv("BUS_BRIDGE_URL", "")
	t.Setenv("VERIFY_CHECK_TIMEOUT_SEC", "1")
	t.Setenv("VERIFY_RUN_BUDGET_SEC", "10")
	_, s, fix := setupVerifyServer(t)
	verifyFakeCH(t, map[string]map[string]any{
		caseA: caseRow(fix["A"].tenantID, "dev-A", "suspected"),
	})
	if _, err := s.verifyCfg.set(fix["A"].tenantID, verifySettingsPatch{Enabled: boolPtr(true)}); err != nil {
		t.Fatal(err)
	}

	// A recent run exists → the tick must NOT launch another (cooldown dedupe).
	s.verifyRuns.put(verifyRunRecord{
		RunID: "recent", TenantID: fix["A"].tenantID, CorrelationID: caseA,
		Trigger: "auto", Actor: "system:verify", StartedAt: time.Now().UTC(),
		Status: "completed",
	})
	s.verifyTickOnce(t.Context())
	if rec, _ := s.verifyRuns.latest(fix["A"].tenantID, caseA); rec.RunID != "recent" {
		t.Fatalf("cooldown violated: new run %s launched", rec.RunID)
	}

	// Backdate the run beyond the cooldown → the tick launches a fresh one.
	s.verifyRuns.put(verifyRunRecord{
		RunID: "old", TenantID: fix["A"].tenantID, CorrelationID: caseA,
		Trigger: "auto", Actor: "system:verify",
		StartedAt: time.Now().UTC().Add(-2 * verifyCooldown()),
		Status:    "completed",
	})
	s.verifyTickOnce(t.Context())
	rec, ok := s.verifyRuns.latest(fix["A"].tenantID, caseA)
	if !ok || rec.RunID == "old" {
		t.Fatal("cooled-down case must get a fresh auto run")
	}
	if rec.Trigger != "auto" || rec.Actor != "system:verify" {
		t.Fatalf("auto run attribution: %+v", rec)
	}
}

func boolPtr(b bool) *bool { return &b }
