// Package storagemeter MEASURES bytes on disk, per store, and refuses to guess.
//
// WHY IT EXISTS (tracker 204, owner directive 2026-09-01). Every storage and
// retention-pricing number this platform has ever published was DERIVED: a
// row-rate multiplied by an assumed bytes-per-row, or a vendor's
// bytes-per-sample constant. `docs/scale/HOST_CEILING_2026-08-31.md` §5 says so
// in as many words — "storage/day is honestly n/a; no run instruments bytes on
// disk". A derived number presented as a measurement is the §10 failure this
// codebase does not tolerate, so the directive was: measure it, or say you did
// not.
//
// THE HONESTY RULE, inherited verbatim from internal/dataprotect: a number we
// did not measure is a NIL POINTER carrying a sibling sentence that says why.
// Never a fabricated zero, never a blank an operator reads as "fine". A failed
// probe and an unmeasurable store are different sentences, and both are
// different from zero bytes — which is itself a legitimate measurement.
//
// WHAT "MEASURED" MEANS HERE. One reading = (store, scope, bytes, source,
// sampled_at). `Source` names the exact query or syscall the number came from,
// so the claim is auditable without reading this package: `_cat/indices`
// store.size, `system.parts` bytes_on_disk, VictoriaMetrics' own
// `vm_data_size_bytes`, `pg_database_size()`, or a walk of the api's own /data.
// Anything a formula produced is NOT a reading and does not appear here.
//
// TENANCY (§3a). Two of the six stores are tenant-PARTITIONED at rest and are
// therefore measurable per tenant:
//
//   - OpenSearch — the index name carries the tenant segment
//     (netops-<signal>-<tenant>-<date>), so bytes attribute exactly. The
//     `untagged` indices are SHARED and are reported under their own scope
//     rather than folded into anybody's tenant total: attributing them would be
//     a derivation wearing a measurement's clothes.
//   - ClickHouse — every netops table is partitioned by (tenant_id, …), so
//     `system.parts.partition` carries the owning tenant and bytes attribute
//     exactly.
//
// The other four (VictoriaMetrics, PostgreSQL, the api's file store, Kafka) are
// NOT partitioned by tenant on disk. A tenant asking for its share of them gets
// a nil and the reason — not a pro-rata split, which would be a derivation.
//
// A SCOPED CALLER NEVER SEES ANOTHER TENANT'S BYTES: the OpenSearch pattern and
// the ClickHouse WHERE clause are both narrowed by the caller's own tenant
// BEFORE the query leaves this process, and the readings are filtered again on
// the way out. Volume is business intelligence — how much a competitor's tenant
// stores is exactly the kind of thing §3a exists to keep in its own lane.
//
// NOTHING HERE READS THE ENVIRONMENT. Every store client, path and clock is
// injected as a VALUE or an interface in Deps, resolved once by the integrator.
// That is what keeps the package offline-testable and keeps the credentials —
// which live inside the injected clients' URLs — out of this file entirely.
package storagemeter

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

// Store is the closed vocabulary of measurable stores. Closed on purpose: a
// reading whose store name is a free string cannot be alerted on, and the
// per-store "why not" sentences below are only correct for these six.
type Store string

const (
	StoreOpenSearch Store = "opensearch"
	StoreClickHouse Store = "clickhouse"
	StoreVictoria   Store = "victoriametrics"
	StorePostgres   Store = "postgres"
	StoreFiles      Store = "filestore"
	StoreKafka      Store = "kafka"
)

// Stores is the fixed enumeration, in report order (largest tier first). Used
// by the sampler, the metrics writer and the tests, so no one can add a store
// to one and forget the others.
var Stores = []Store{
	StoreOpenSearch, StoreClickHouse, StoreVictoria,
	StorePostgres, StoreFiles, StoreKafka,
}

// ScopePlatform is the scope of a reading that belongs to the installation as a
// whole rather than to any tenant. ScopeUntagged is the OpenSearch tenant
// segment ingest uses when a document carried no tenant claim: real bytes, real
// storage cost, and deliberately NOT attributed to a tenant.
const (
	ScopePlatform = "__platform__"
	ScopeUntagged = "untagged"
)

// Component is one addressable piece inside a store — an index, a table, a
// VictoriaMetrics part type, a top-level directory. Present so an operator can
// see WHERE the bytes are without a second round trip, and so the compression
// ratio (where the store reports both) is attached to the thing it describes.
type Component struct {
	// Name is the component's own identifier (index name, `db.table`, part type).
	Name string `json:"name"`
	// BytesOnDisk is what the store reports it occupies. Never negative.
	BytesOnDisk int64 `json:"bytes_on_disk"`
	// Rows is the row/document count, when the store reports one; nil when it
	// does not. A component with bytes but no rows is normal (a directory).
	Rows *int64 `json:"rows"`
	// UncompressedBytes is the pre-compression size, when the store reports it
	// (ClickHouse does; nobody else here does). nil is NOT zero.
	UncompressedBytes *int64 `json:"uncompressed_bytes"`
	// Period is the day or month this component covers, when the store's own
	// addressing carries one — the date suffix of a daily OpenSearch index, or
	// the date element of a ClickHouse partition key. Empty when the store does
	// not partition by time, which is a fact about the store and not a gap:
	// tracker 204 asks for bytes PER DAY, and this is the only way to answer it
	// with a measurement instead of a division.
	Period string `json:"period,omitempty"`
}

// CompressionRatio is uncompressed/on-disk for this component, or nil when the
// store does not report an uncompressed size. A MEASURED ratio, never the
// assumed constant the sizing model uses.
func (c Component) CompressionRatio() *float64 {
	if c.UncompressedBytes == nil || c.BytesOnDisk <= 0 || *c.UncompressedBytes <= 0 {
		return nil
	}
	r := float64(*c.UncompressedBytes) / float64(c.BytesOnDisk)
	return &r
}

// Reading is one store's bytes for one scope, measured or explicitly not.
//
// The three-state contract the frontend renders (dataProtection.model.ts
// `measured()`): BytesOnDisk non-nil = a measurement, and Detail says how it was
// taken; BytesOnDisk nil = NOT measured, and Detail says why. There is no third
// state and no zero-that-means-unknown.
type Reading struct {
	Store Store `json:"store"`
	// Scope is ScopePlatform, ScopeUntagged, or a tenant id.
	Scope string `json:"scope"`
	// BytesOnDisk is nil when this was NOT measured. Read Detail.
	BytesOnDisk *int64 `json:"bytes_on_disk"`
	// Detail is the sentence beside the number. Mandatory in BOTH states.
	Detail string `json:"detail"`
	// Source names the query/API/syscall the number came from, verbatim enough
	// that an operator can re-run it. Empty when nothing was measured.
	Source string `json:"source"`
	// SampledAt is when the probe ran (not when the response was rendered), so
	// a stale reading is visible as stale rather than as current.
	SampledAt time.Time `json:"sampled_at"`
	// Components is the breakdown, largest first, bounded by maxComponents.
	Components []Component `json:"components,omitempty"`
}

// Measured reports whether this reading carries a number.
func (r Reading) Measured() bool { return r.BytesOnDisk != nil }

// maxComponents bounds the breakdown carried on one reading (§9: bounded
// everything). An installation with thousands of daily indices must not turn
// one status call into a megabyte of JSON; the TOTAL is always exact, only the
// itemisation is truncated, and Detail says when it was.
const maxComponents = 50

// measured builds a measured reading. bytes is taken by value on purpose: the
// caller cannot accidentally share a pointer into a mutating accumulator.
func measured(store Store, scope string, bytes int64, source, detail string, at time.Time, comps []Component) Reading {
	b := bytes
	sort.SliceStable(comps, func(i, j int) bool { return comps[i].BytesOnDisk > comps[j].BytesOnDisk })
	truncated := 0
	if len(comps) > maxComponents {
		truncated = len(comps) - maxComponents
		comps = comps[:maxComponents]
	}
	if truncated > 0 {
		detail += " (breakdown truncated to the " + itoa(maxComponents) +
			" largest of " + itoa(maxComponents+truncated) + "; the total is exact)"
	}
	return Reading{
		Store: store, Scope: scope, BytesOnDisk: &b,
		Source: source, Detail: detail, SampledAt: at, Components: comps,
	}
}

// notMeasured builds an unmeasured reading. `why` must be a sentence an
// operator can act on — "the probe failed" is not one, "<store> refused the
// query: <status>" is.
func notMeasured(store Store, scope, why string, at time.Time) Reading {
	return Reading{Store: store, Scope: scope, Detail: "not measured — " + why, SampledAt: at}
}

// itoa is strconv.Itoa without the import churn in this file's hot path.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// probeReason turns a store error into the sentence that goes beside the nil.
// A cancelled context and a refused query read very differently to an operator,
// so they are never collapsed into one "unavailable".
func probeReason(store string, err error) string {
	switch {
	case err == nil:
		return store + " returned no rows and no error, which this probe cannot interpret as a size"
	case errors.Is(err, context.DeadlineExceeded):
		return store + " did not answer the size query inside the probe's deadline"
	case errors.Is(err, context.Canceled):
		return store + " size query was cancelled before it answered"
	default:
		msg := strings.TrimSpace(err.Error())
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		return store + " refused the size query: " + msg
	}
}
