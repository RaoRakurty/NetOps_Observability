// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"netops/backend/internal/featureflags"
)

type memEnv struct {
	mu sync.Mutex
	m  map[string]string
}

func (e *memEnv) Lookup(k string) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.m[k]
	return v, ok
}

func (e *memEnv) Set(k, v string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.m[k] = v
	return nil
}

type memStore struct{ b []byte }

func (m *memStore) Load() ([]byte, error) {
	if m.b == nil {
		return nil, fmt.Errorf("absent: %w", os.ErrNotExist)
	}
	return m.b, nil
}
func (m *memStore) Save(b []byte) error { m.b = append([]byte(nil), b...); return nil }

// The spec table is the page's contract: every entry must be a flag the
// backend actually reads, none may be a CONTROL (a switch that could stop the
// boot or remove a protection), and none may be a flag another container
// reads (the api cannot apply it).
func TestFeatureSpecsAreReadAndSafe(t *testing.T) {
	forbidden := map[string]string{
		"FEATURE_SEALED_FIELDS":   "boot-fatal and turning it off stops encrypting",
		"AI_TOOLS_ALL_TENANTS":    "cross-tenant reach",
		"ENABLE_REPORT_SCHEDULER": "flag-gated log.Fatalf at start",
		"FEATURE_TRACEROUTE":      "read by the prober container",
		"FEATURE_DEM":             "read by the prober container too",
		"ENABLE_FLOW_CORRELATION": "read by the correlation engine",
	}
	src := readGoSources(t)
	seen := map[string]bool{}
	for _, sp := range featureSpecs() {
		if why, bad := forbidden[sp.Env]; bad {
			t.Errorf("%s must not be on the Features page: %s", sp.Env, why)
		}
		if seen[sp.Env] {
			t.Errorf("duplicate %s", sp.Env)
		}
		seen[sp.Env] = true
		if !strings.Contains(src, `"`+sp.Env+`"`) {
			t.Errorf("%s is on the page but no backend code reads it", sp.Env)
		}
		if sp.Label == "" || sp.Help == "" || sp.Group == "" {
			t.Errorf("%s needs a label, a group and one line of help", sp.Env)
		}
		if sp.Apply != featureflags.ApplyLive && sp.Apply != featureflags.ApplyRestart {
			t.Errorf("%s has no apply class", sp.Env)
		}
	}
}

// readGoSources concatenates the non-test Go files of the module.
func readGoSources(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	var walk func(dir string)
	walk = func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			p := dir + "/" + e.Name()
			switch {
			case e.IsDir():
				if e.Name() != "vendor" && e.Name() != "testdata" && !strings.HasPrefix(e.Name(), ".") {
					walk(p)
				}
			case strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") && e.Name() != "feature_flags.go":
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				b.Write(data)
			}
		}
	}
	walk(".")
	return b.String()
}

type featureFixture struct {
	t     *testing.T
	ts    *httptest.Server
	s     *server
	env   *memEnv
	admin string
}

func newFeatureFixture(t *testing.T) *featureFixture {
	t.Helper()
	ts, s := newTestServerState(t)
	env := &memEnv{m: map[string]string{"ENABLE_SNMP_COLLECTION": "true"}}
	s.features = featureflags.New(featureSpecs(), env, &memStore{})
	if err := s.features.Load(); err != nil {
		t.Fatal(err)
	}
	s.restart = &restartGate{ch: make(chan struct{}, 1)}
	return &featureFixture{t: t, ts: ts, s: s, env: env, admin: login(t, ts, "admin", "Passw0rd!2345").Token}
}

func (f *featureFixture) call(method, path, token string, body any) (int, []byte) {
	return do(f.t, f.ts, method, path, token, body)
}

func (f *featureFixture) row(env string) map[string]any {
	f.t.Helper()
	st, b := f.call("GET", "/api/platform/features", f.admin, nil)
	if st != 200 {
		f.t.Fatalf("GET = %d %s", st, b)
	}
	var out struct {
		Features []map[string]any `json:"features"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		f.t.Fatal(err)
	}
	for _, r := range out.Features {
		if r["env"] == env {
			return r
		}
	}
	f.t.Fatalf("%s not listed", env)
	return nil
}

// Tenant and org admins hold full administration rights inside their scope;
// feature switches are platform-global, so they are refused (§3a.3).
func TestFeaturesAreOwnerOnly(t *testing.T) {
	f := newFeatureFixture(t)
	if st, b := f.call("POST", "/api/orgs", f.admin, map[string]any{"name": "Acme Corp"}); st != 201 {
		t.Fatalf("create org: %d %s", st, b)
	}
	if st, _ := f.call("POST", "/api/tenants", f.admin, map[string]any{"name": "Acme Prod", "org_id": "acme-corp"}); st != 201 {
		t.Fatal("create tenant")
	}
	for _, u := range []map[string]any{
		{"username": "orgboss", "password": "Passw0rd!2345", "role": "org-admin", "tenant_id": "acme-prod"},
		{"username": "tadmin", "password": "Passw0rd!2345", "role": "super-admin", "tenant_id": "acme-prod"},
	} {
		if st, _ := f.call("POST", "/api/users", f.admin, u); st != 201 {
			t.Fatal("create user")
		}
	}
	for _, who := range []string{"orgboss", "tadmin"} {
		tok := login(t, f.ts, who, "Passw0rd!2345").Token
		if st, _ := f.call("GET", "/api/platform/features", tok, nil); st != 403 {
			t.Errorf("%s GET = %d, want 403", who, st)
		}
		if st, _ := f.call("PUT", "/api/platform/features", tok, map[string]any{"env": "FEATURE_PORT_DOM", "value": true}); st != 403 {
			t.Errorf("%s PUT = %d, want 403", who, st)
		}
		if st, _ := f.call("POST", "/api/platform/restart", tok, nil); st != 403 {
			t.Errorf("%s restart = %d, want 403", who, st)
		}
		if st, _ := f.call("GET", "/api/platform/features?as_tenant=acme-prod", tok, nil); st != 403 {
			t.Errorf("%s as_tenant GET = %d, want 403", who, st)
		}
	}
	if v, _ := f.env.Lookup("FEATURE_PORT_DOM"); v == "true" {
		t.Fatal("a refused caller changed a feature")
	}
}

func TestFeatureChangesLiveRestartAckAndAudit(t *testing.T) {
	f := newFeatureFixture(t)
	if r := f.row("ENABLE_SNMP_COLLECTION"); r["running"] != true || r["source"] != "install" {
		t.Fatalf("install value: %v", r)
	}
	// Live: in force immediately.
	if st, b := f.call("PUT", "/api/platform/features", f.admin, map[string]any{"env": "FEATURE_PORT_DOM", "value": true}); st != 200 {
		t.Fatalf("live PUT = %d %s", st, b)
	}
	if v, _ := f.env.Lookup("FEATURE_PORT_DOM"); v != "true" {
		t.Fatal("live flag not applied")
	}
	// Restart: desired, not running, and the page says so.
	if st, b := f.call("PUT", "/api/platform/features", f.admin, map[string]any{"env": "ENABLE_SNMP_COLLECTION", "value": false}); st != 200 {
		t.Fatalf("restart PUT = %d %s", st, b)
	}
	if r := f.row("ENABLE_SNMP_COLLECTION"); r["running"] != true || r["desired"] != false || r["restart_pending"] != true || r["source"] != "console" {
		t.Fatalf("restart-class change: %v", r)
	}
	// Risky: refused without the acknowledgement, accepted with it.
	if st, _ := f.call("PUT", "/api/platform/features", f.admin, map[string]any{"env": "FEATURE_DEVICE_SSH", "value": true}); st != 400 {
		t.Errorf("risky without ack = %d, want 400", st)
	}
	if st, _ := f.call("PUT", "/api/platform/features", f.admin, map[string]any{"env": "FEATURE_DEVICE_SSH", "value": true, "acknowledge": "FEATURE_DEVICE_SSH"}); st != 200 {
		t.Errorf("risky with ack = %d, want 200", st)
	}
	// Never on the page: a control, an unknown key, a malformed body.
	for _, body := range []map[string]any{
		{"env": "FEATURE_SEALED_FIELDS", "value": false},
		{"env": "NOT_A_FLAG", "value": true},
		{"env": "FEATURE_PORT_DOM"},
		{"env": "FEATURE_PORT_DOM", "value": "yes"},
		{"env": "FEATURE_PORT_DOM", "value": true, "extra": 1},
	} {
		if st, _ := f.call("PUT", "/api/platform/features", f.admin, body); st != 400 {
			t.Errorf("%v = %d, want 400", body, st)
		}
	}
	// Each accepted change wrote an audit row naming the flag, from and to.
	evs, err := f.s.audit.List("", true, auditQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]int{}
	for _, e := range evs {
		if e.Detail["action"] == "feature_flag_set" && e.Status == 200 {
			found[fmt.Sprint(e.Detail["flag"])]++
			if _, ok := e.Detail["from"]; !ok {
				t.Errorf("audit row lacks from/to: %v", e.Detail)
			}
		}
	}
	for _, flag := range []string{"FEATURE_PORT_DOM", "ENABLE_SNMP_COLLECTION", "FEATURE_DEVICE_SSH"} {
		if found[flag] != 1 {
			t.Errorf("audit rows for %s = %d, want 1 (%v)", flag, found[flag], found)
		}
	}
}

// Restart: refused when nothing supervises the process, then accepted once,
// then rate-limited; the request reaches Run's channel.
func TestPlatformRestartIsSupervisedAndRateLimited(t *testing.T) {
	f := newFeatureFixture(t)
	t.Setenv("CORRELIX_SUPERVISED", "")
	if st, _ := f.call("POST", "/api/platform/restart", f.admin, nil); st != 409 {
		t.Fatalf("unsupervised restart = %d, want 409", st)
	}
	t.Setenv("CORRELIX_SUPERVISED", "true")
	if st, _ := f.call("GET", "/api/platform/restart", f.admin, nil); st != 405 {
		t.Errorf("GET restart = %d, want 405", st)
	}
	if st, b := f.call("POST", "/api/platform/restart", f.admin, nil); st != 202 {
		t.Fatalf("restart = %d %s", st, b)
	}
	select {
	case <-f.s.restart.ch:
	default:
		t.Fatal("the restart request did not reach Run")
	}
	if st, _ := f.call("POST", "/api/platform/restart", f.admin, nil); st != 429 {
		t.Errorf("second restart within five minutes = %d, want 429", st)
	}
}
