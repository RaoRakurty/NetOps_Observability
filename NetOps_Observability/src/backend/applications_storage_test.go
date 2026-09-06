// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// applications_storage_test.go — tracker 245: the Applications registry must
// never acknowledge a write that lands nowhere durable, and the deployment must
// never end up on an ephemeral backend it did not explicitly ask for.
//
// These are INVARIANT tests, deliberately written so they fail if anyone
// restores the old behaviour:
//
//	unknown STORE_BACKEND        → must NOT select file or memory
//	file backend                 → applications must NOT fall back to memory
//	unsupported/unavailable      → must NOT read as an empty registry
//	memory                       → only by explicit selection, reported ephemeral
//
// The Postgres half (durability across a restart, RLS) lives in
// applications_pg_durability_test.go, gated on DATABASE_URL_TEST.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"netops/backend/alerts"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/registrystatus"
)

// useBackend flips the process-wide store backend for one test and restores the
// package default afterwards. Root-package tests never run in parallel, so the
// global is safe to move under a single test.
func useBackend(t *testing.T, kind string) {
	t.Helper()
	switch kind {
	case platformdb.KindMemory:
		platformdb.UseMemory()
	case platformdb.KindFile:
		platformdb.UseFile()
	default:
		t.Fatalf("useBackend: unsupported kind %q", kind)
	}
	t.Cleanup(func() { platformdb.UseFile() })
}

// TestApplicationStoreNeverFallsBackToMemory is the regression for the original
// bug: on the file backend the selector returned an in-memory store, so an
// application could be created, listed, and then silently lost on restart.
func TestApplicationStoreNeverFallsBackToMemory(t *testing.T) {
	useBackend(t, platformdb.KindFile)
	if st := newApplicationStore(); st != nil {
		t.Fatalf("file backend must leave the applications registry UNSUPPORTED (nil), got %T — "+
			"an implicit in-memory store is the tracker-245 data-loss bug", st)
	}
}

// TestApplicationStoreMemoryOnlyWhenExplicit: the ephemeral store exists, but
// only a deliberate STORE_BACKEND=memory reaches it.
func TestApplicationStoreMemoryOnlyWhenExplicit(t *testing.T) {
	useBackend(t, platformdb.KindMemory)
	if st := newApplicationStore(); st == nil {
		t.Fatal("explicit memory backend must provide the ephemeral applications store")
	}
	if platformdb.Kind() != platformdb.KindMemory {
		t.Fatalf("kind = %q, want memory", platformdb.Kind())
	}
	if registrystatus.PersistenceOf(platformdb.Kind()) != registrystatus.Ephemeral {
		t.Fatal("the memory backend must report itself as ephemeral")
	}
}

// TestInitStoreBackendRejectsUnknownValue: a typo must abort the boot, and must
// leave no backend selected behind it — never a quiet downgrade to file/memory.
func TestInitStoreBackendRejectsUnknownValue(t *testing.T) {
	for _, bad := range []string{"postgress", "sqlite", "postgres!", "FILE-ISH"} {
		t.Setenv("STORE_BACKEND", bad)
		before := platformdb.Kind()
		err := initStoreBackend()
		if err == nil {
			t.Fatalf("STORE_BACKEND=%q must be a configuration error, not a silent selection", bad)
		}
		if platformdb.Kind() != before {
			t.Fatalf("STORE_BACKEND=%q changed the active backend to %q — an invalid value must select nothing",
				bad, platformdb.Kind())
		}
	}
}

// TestInitStoreBackendPostgresNeedsDSN: the persistent backend fails closed. It
// must not come up on files or RAM because DATABASE_URL is missing.
func TestInitStoreBackendPostgresNeedsDSN(t *testing.T) {
	t.Setenv("STORE_BACKEND", "postgres")
	t.Setenv("DATABASE_URL", "")
	before := platformdb.Kind()
	if err := initStoreBackend(); err == nil {
		t.Fatal("STORE_BACKEND=postgres with no DATABASE_URL must fail the boot")
	}
	if platformdb.Kind() != before {
		t.Fatalf("a failed postgres selection switched the backend to %q — no failover is allowed",
			platformdb.Kind())
	}
}

// TestInitStoreBackendUnsetIsFile pins the documented binary-level contract:
// an UNSET variable is the historical compatibility backend, never a guess at
// postgres (an existing install that loses its configuration must keep reading
// the data it has, not serve an empty database). The PRODUCT default for a new
// install is postgres and is written explicitly by scripts/install.py —
// tests/test_store_backend_defaults.py holds that half.
func TestInitStoreBackendUnsetIsFile(t *testing.T) {
	t.Setenv("STORE_BACKEND", "")
	t.Cleanup(func() { platformdb.UseFile() })
	if err := initStoreBackend(); err != nil {
		t.Fatalf("unset STORE_BACKEND must select the file backend: %v", err)
	}
	if platformdb.Kind() != platformdb.KindFile {
		t.Fatalf("unset STORE_BACKEND selected %q, want file", platformdb.Kind())
	}
}

// TestApplicationsRefuseOnUnsupportedBackend: every method of the registry
// surface says so explicitly — no 200 with an empty list, no accepted write.
func TestApplicationsRefuseOnUnsupportedBackend(t *testing.T) {
	srv, s := newTestServerState(t)
	s.applications = nil // what the file backend now produces
	tok := adminToken(t, srv)

	const uuid = "11111111-2222-4333-8444-555555555555"
	cases := []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/applications", nil},
		{"POST", "/api/applications", map[string]any{"name": "Billing"}},
		{"GET", "/api/applications/" + uuid, nil},
		{"DELETE", "/api/applications/" + uuid, nil},
	}
	for _, c := range cases {
		st, body := do(t, srv, c.method, c.path, tok, c.body)
		if st != http.StatusNotImplemented {
			t.Fatalf("%s %s: status %d (%s) — an unsupported storage backend must be visible, "+
				"never an empty success", c.method, c.path, st, body)
		}
		var env struct{ Error, Code string }
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("%s %s: body %s: %v", c.method, c.path, body, err)
		}
		if env.Code != "APPLICATION_REGISTRY_BACKEND_UNSUPPORTED" {
			t.Fatalf("%s %s: code %q, want a stable machine-readable code", c.method, c.path, env.Code)
		}
		if env.Error == "" {
			t.Fatalf("%s %s: an operator-facing reason is required", c.method, c.path)
		}
	}
}

// TestRegistriesStatusReportsTheRealBackend: the endpoint the Registries page
// renders from must describe the ACTUAL selection, per registry.
func TestRegistriesStatusReportsTheRealBackend(t *testing.T) {
	get := func(t *testing.T) registrystatus.Report {
		t.Helper()
		srv, _ := newTestServerState(t)
		tok := adminToken(t, srv)
		st, body := do(t, srv, "GET", "/api/registries/status", tok, nil)
		if st != http.StatusOK {
			t.Fatalf("status: %d %s", st, body)
		}
		var rep registrystatus.Report
		if err := json.Unmarshal(body, &rep); err != nil {
			t.Fatalf("decode %s: %v", body, err)
		}
		return rep
	}
	find := func(t *testing.T, rep registrystatus.Report, id string) registrystatus.Status {
		t.Helper()
		for _, r := range rep.Registries {
			if r.Registry == id {
				return r
			}
		}
		t.Fatalf("registry %q missing from %+v", id, rep.Registries)
		return registrystatus.Status{}
	}

	t.Run("file backend: applications unsupported, never relabelled", func(t *testing.T) {
		useBackend(t, platformdb.KindFile)
		rep := get(t)
		if rep.ConfiguredBackend != platformdb.KindFile {
			t.Fatalf("configured_backend = %q", rep.ConfiguredBackend)
		}
		app := find(t, rep, applicationRegistry)
		if app.Available || app.Healthy {
			t.Fatalf("applications must not be available on the file backend: %+v", app)
		}
		if app.ActiveBackend != "" {
			t.Fatalf("no backend stores applications on file, got active_backend %q", app.ActiveBackend)
		}
		if app.ConfiguredBackend != platformdb.KindFile || app.Reason == "" {
			t.Fatalf("the configured backend and a reason must both be reported: %+v", app)
		}
	})

	t.Run("memory backend: explicit and reported ephemeral", func(t *testing.T) {
		useBackend(t, platformdb.KindMemory)
		rep := get(t)
		app := find(t, rep, applicationRegistry)
		if !app.Available || !app.Healthy {
			t.Fatalf("explicit memory must be available: %+v", app)
		}
		if app.ActiveBackend != platformdb.KindMemory || app.Persistence != registrystatus.Ephemeral {
			t.Fatalf("memory must be reported as an ephemeral active backend: %+v", app)
		}
		// The service catalog has no memory implementation — it must say so
		// rather than borrow the applications verdict.
		svc := find(t, rep, serviceRegistry)
		if svc.Available || svc.ActiveBackend != "" {
			t.Fatalf("service catalog is postgres-only and must report unsupported: %+v", svc)
		}
	})
}

// TestRegistriesStatusLeaksNoCredentials: the status surface reports a backend
// KIND, never a DSN. Guards CLAUDE.md §8 on a route an operator can read.
func TestRegistriesStatusLeaksNoCredentials(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://netops_app:sup3rs3cr3t@postgres:5432/netops")
	srv, _ := newTestServerState(t)
	tok := adminToken(t, srv)
	st, body := do(t, srv, "GET", "/api/registries/status", tok, nil)
	if st != http.StatusOK {
		t.Fatalf("status: %d %s", st, body)
	}
	for _, secret := range []string{"sup3rs3cr3t", "postgres://", "netops_app", os.Getenv("DATABASE_URL")} {
		if secret != "" && strings.Contains(string(body), secret) {
			t.Fatalf("registry status leaked %q: %s", secret, body)
		}
	}
}

// TestRegistryStorageMetricIsEmittedEveryScrape: a registry whose storage cannot
// serve must be ALERTABLE, not merely honest to whoever asks the API. The series
// is emitted on every scrape — including as a zero — so a vanished series still
// means a scrape failure rather than health.
func TestRegistryStorageMetricIsEmittedEveryScrape(t *testing.T) {
	useBackend(t, platformdb.KindFile)
	_, s := newTestServerState(t)
	s.alerts = alerts.NewEngine("", nil) // the exporter reads it; the harness leaves it nil
	w := httptest.NewRecorder()
	s.handlePromMetrics(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	text := w.Body.String()
	if !strings.Contains(text, "netops_registry_storage_available{registry=\"applications\"") {
		t.Fatalf("the applications storage gauge must be emitted on every scrape:\n%s", text)
	}
	// File backend cannot store applications → the gauge must read 0, and the
	// postgres-only siblings likewise.
	for _, want := range []string{
		`netops_registry_storage_available{registry="applications",configured_backend="file",persistence=""} 0`,
		`netops_registry_storage_available{registry="service_catalog",configured_backend="file",persistence=""} 0`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in /metrics", want)
		}
	}
}
