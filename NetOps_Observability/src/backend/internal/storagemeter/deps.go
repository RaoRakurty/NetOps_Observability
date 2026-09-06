package storagemeter

import (
	"context"
	"net/http"
	"time"
)

// ── the injected seams (§5 "interfaces for all external dependencies") ───────
//
// Every seam is a function value, not a client type: this package must never
// hold a credential, a URL or a TLS config. The integrator passes the SAME
// clients the rest of the api already uses (s.osDo, chWorkerQuery, s.vmInstant,
// the platformdb pool), so a transport, credential or timeout change lands in
// one place and this package cannot drift from it.

// OpenSearchGet performs one authenticated GET against the search cluster and
// decodes the JSON body into out. path is a cluster path ("/_cat/indices/…").
type OpenSearchGet func(ctx context.Context, path string, out any) error

// ClickHouseQuery runs one read-only SELECT and returns the decoded rows.
// The integrator binds the cross-tenant WORKER lane: `system.parts` is cluster
// metadata with no tenant column, so a row policy cannot scope it — the tenant
// narrowing happens in the SQL this package builds and again on the way out.
type ClickHouseQuery func(ctx context.Context, sql string) ([]map[string]any, error)

// VMSample is one VictoriaMetrics instant-query sample.
type VMSample struct {
	Labels map[string]string
	Value  float64
}

// VMQuery runs one instant PromQL query. Bound to the UNSCOPED query path on
// purpose, and called only on the platform path: `vm_data_size_bytes` is the
// engine's own self-metric and carries no tenant label, so a tenant-scoped
// query would return nothing — and "nothing" must never be rendered as zero
// bytes. A tenant asking for its share gets a nil and the reason instead.
type VMQuery func(ctx context.Context, promql string) ([]VMSample, error)

// PGSize reports the application database's on-disk size and the per-relation
// breakdown. ok=false with a reason means there is no application database to
// size on this installation (the file backend), which is a DIFFERENT statement
// from "the query failed" and reads differently to an operator.
type PGSize func(ctx context.Context) (total int64, relations []Component, ok bool, reason string, err error)

// DirSize reports the recursive apparent size of one directory as this process
// sees it, plus the per-child breakdown. The integrator binds a bounded
// filepath.WalkDir over the api's own data root — the ONE store this process
// can measure with a syscall rather than by asking a server.
type DirSize func(ctx context.Context, root string) (total int64, children []Component, err error)

// Principal is the already-authorized caller, reduced to the two facts this
// package needs to scope a reading. The package never sees the integrator's
// claims type (§3a: the tenant comes from the token, never from the request).
type Principal struct {
	// Subject is the authenticated subject, for the audit line.
	Subject string
	// Tenant is the caller's own tenant. Empty + !CrossTenant reads nothing.
	Tenant string
	// CrossTenant is true for a platform principal that may see every tenant.
	CrossTenant bool
}

// Gate authorizes one request and yields the caller. ok=false means the gate
// ALREADY wrote the refusal and the handler must return immediately.
type Gate func(w http.ResponseWriter, r *http.Request) (Principal, bool)

// Deps is everything this package needs, resolved ONCE by the integrator.
// A nil seam is not a crash and not a zero — it is a store that reports "not
// measured" with the reason "this installation wires no <x> client", which is
// the honest thing to say on a deployment that does not run that store.
type Deps struct {
	// Now is the clock. Required.
	Now func() time.Time
	// Log is the structured logger. Optional; nil discards.
	Log func(msg string, kv ...any)

	// Gate authorizes the HTTP surface. Required for the handler.
	Gate Gate

	// OpenSearch reads the search cluster. nil → not measured.
	OpenSearch OpenSearchGet
	// CatPattern renders the `_cat/indices` pattern a caller may enumerate.
	// Bound to oslog.TenantCatPattern so the measurement path names EXACTLY the
	// indices the log-search path already lets that caller see — a second
	// pattern derivation is a second thing that can silently be wrong (§3a.4).
	CatPattern func(tenant string, cross bool) string
	// IndexTenant extracts the tenant segment from an index name. Bound to the
	// same derivation ingest uses (oslog.IndexTenantSeg's inverse), so bytes
	// attribute to the tenant that actually owns the documents.
	IndexTenant func(index string) (tenant string, ok bool)

	// ClickHouse reads system.parts. nil → not measured.
	ClickHouse ClickHouseQuery
	// Database is the ClickHouse database whose parts are measured.
	Database string

	// Victoria reads VictoriaMetrics' own storage self-metrics. nil → not measured.
	Victoria VMQuery

	// Postgres sizes the application database. nil → not measured.
	Postgres PGSize

	// Dir measures a directory. nil → not measured.
	Dir DirSize
	// DataRoot is the api's own data directory as THIS process sees it.
	DataRoot string

	// SampleEvery is the background sampler's cadence. Zero → DefaultSampleEvery.
	SampleEvery time.Duration
	// ProbeTimeout bounds ONE store probe (§9: all IO has a timeout).
	ProbeTimeout time.Duration
}

// DefaultSampleEvery is the sampler cadence. Deliberately slow: a size is a
// slow-moving fact, `system.parts` and `_cat/indices` are not free, and the
// scrape must never pay for either (the /metrics handler formats a CACHE).
const DefaultSampleEvery = 15 * time.Minute

// DefaultProbeTimeout bounds one store probe.
const DefaultProbeTimeout = 20 * time.Second

func (d Deps) now() time.Time {
	if d.Now == nil {
		return time.Now().UTC()
	}
	return d.Now().UTC()
}

func (d Deps) logf(msg string, kv ...any) {
	if d.Log != nil {
		d.Log(msg, kv...)
	}
}

func (d Deps) probeTimeout() time.Duration {
	if d.ProbeTimeout <= 0 {
		return DefaultProbeTimeout
	}
	return d.ProbeTimeout
}

func (d Deps) sampleEvery() time.Duration {
	if d.SampleEvery <= 0 {
		return DefaultSampleEvery
	}
	return d.SampleEvery
}
