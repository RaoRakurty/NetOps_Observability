package tenant

import (
	"errors"
	"strings"
)

// tenant_router.go — the isolation-tier seam (Phase 4).
//
// Today every tenant shares one set of backends (one Postgres/OpenSearch/
// ClickHouse), isolated logically by tenant_id + the central Authorize() policy.
// This file is where a tenant graduates to stronger PHYSICAL isolation without an
// app rewrite: a Tenant carries an IsolationMode, and Router resolves a
// tenant to the storage handle it should use. Only "shared" is implemented; the
// dedicated modes are accepted and persisted so the data model + admin UI are
// ready, and BackendFor is the single place to extend when dedicated infra is
// provisioned (it converges with Phase 5 PG RLS / per-tenant DSNs).

// IsolationMode is how strongly a tenant's data is separated from others.
type IsolationMode = string

const (
	IsolationShared           IsolationMode = "shared"            // one backend, tenant_id-scoped (default; implemented)
	IsolationDedicatedSchema  IsolationMode = "dedicated_schema"  // per-tenant schema (planned)
	IsolationDedicatedDB      IsolationMode = "dedicated_db"      // per-tenant database (planned)
	IsolationDedicatedCluster IsolationMode = "dedicated_cluster" // per-tenant cluster (planned)
)

// NormalizeIsolationMode defaults blank → shared and rejects unknown values.
func NormalizeIsolationMode(m string) (IsolationMode, error) {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "", IsolationShared:
		return IsolationShared, nil
	case IsolationDedicatedSchema:
		return IsolationDedicatedSchema, nil
	case IsolationDedicatedDB:
		return IsolationDedicatedDB, nil
	case IsolationDedicatedCluster:
		return IsolationDedicatedCluster, nil
	default:
		return "", errors.New("invalid isolation_mode (shared|dedicated_schema|dedicated_db|dedicated_cluster)")
	}
}

// isolationImplemented reports whether a mode is actually provisioned today.
// Dedicated modes capture intent but currently fall back to shared at runtime.
//
//nolint:unused // guards the not-yet-implemented dedicated isolation modes; dedicated falls back to shared at runtime
//lint:ignore U1000 guards the not-yet-implemented dedicated isolation modes
func isolationImplemented(m IsolationMode) bool { return m == IsolationShared || m == "" }

// Backend identifies where a tenant's data physically lives. For shared
// mode all fields are empty (= the default backends); dedicated modes will
// populate the schema / DSN / cluster endpoint.
type Backend struct {
	Mode    IsolationMode
	Schema  string // dedicated_schema
	DSN     string // dedicated_db
	Cluster string // dedicated_cluster
}

// Router resolves a tenant to its storage backend.
type Router interface {
	BackendFor(t Tenant) Backend
}

// SharedRouter maps every tenant to the shared default backend — the only router
// wired today. A tenant flagged dedicated_* still resolves to shared until its
// infra is actually provisioned: the flag captures intent, this captures reality.
type SharedRouter struct{}

func (SharedRouter) BackendFor(_ Tenant) Backend {
	return Backend{Mode: IsolationShared}
}
