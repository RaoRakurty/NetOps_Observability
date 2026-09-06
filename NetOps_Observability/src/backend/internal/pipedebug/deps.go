// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// deps.go — the injected collaborators the debug API runs over (§2/§5: this
// package holds no ambient authority; every store, socket and clock is handed
// to it explicitly, the secapi precedent).
//
// Nothing here reads the environment, dials a host or opens a file. Package
// backend builds the seams inside its DEBUG-ROUTES markers, which is also what
// makes this whole surface deletable: drop the markers and the package and the
// API loses the debug routes and nothing else.

import (
	"context"
	"net/http"
	"time"
)

// Principal is the authorized caller, reduced to what this package may act on.
// There is no "tenant from the body" field by construction (§3a rule 2).
type Principal struct {
	// Subject is the authenticated identity (audit only).
	Subject string
	// Tenant is the principal's resolved tenant ("" for an unscoped platform
	// owner).
	Tenant string
	// Cross is true when the principal reads across tenants (platform owner not
	// scoped into a tenant with the switcher).
	Cross bool
}

// PeekRequest is one bounded, read-only Kafka peek.
type PeekRequest struct {
	Topic  string
	Marker string
	// MaxSeconds bounds the ephemeral consumer's wall-clock life at the far end.
	MaxSeconds int
	// MaxRecords bounds how many matching records are returned.
	MaxRecords int
	// LookbackSeconds is how far back the consumer seeks before reading.
	LookbackSeconds int
	// ProbeSrc is the alternative needle for a kind whose record carries no
	// text marker (today: flow). It is an RFC 5737 documentation address, a
	// 512-value closed grammar the sidecar re-validates independently — it can
	// never be used to scan the bus for arbitrary content, and the API verifies
	// every returned record against the full fingerprint before believing it.
	ProbeSrc string
}

// PeekRecord is one matching record's address plus a bounded payload excerpt.
type PeekRecord struct {
	Topic     string `json:"topic"`
	Partition int    `json:"partition"`
	Offset    int64  `json:"offset"`
	Timestamp int64  `json:"timestamp_ms"`
	Excerpt   string `json:"excerpt"`
}

// PeekResult is the sidecar's answer.
type PeekResult struct {
	Records   []PeekRecord `json:"records"`
	Scanned   int          `json:"scanned"`
	ElapsedS  float64      `json:"elapsed_s"`
	Truncated bool         `json:"truncated"`
}

// LevelChange records what a runtime log-level request actually did. Honesty is
// the contract: Applied=false with a Reason is a valid, expected answer for a
// module that cannot be switched at runtime, and must never be reported as a
// success (design §4).
type LevelChange struct {
	Module   Module    `json:"module"`
	Applied  bool      `json:"applied"`
	Level    Level     `json:"level"`
	Previous Level     `json:"previous,omitempty"`
	RevertAt time.Time `json:"revert_at,omitempty"`
	Reason   string    `json:"reason,omitempty"`
}

// Deps is the injected seam set.
type Deps struct {
	// Authz authorizes the caller (requirePlatformAdmin in package backend),
	// writing the 401/403 itself and returning ok=false when it did.
	Authz func(w http.ResponseWriter, r *http.Request) (Principal, bool)

	// Search issues one OpenSearch request (package backend's env-configured,
	// credentialed client). The response body is this package's to close.
	Search func(method, path string, body any) (*http.Response, error)
	// OSIndexPattern resolves the readable index pattern for a signal and scope
	// (internal/oslog.TenantIndexPattern via package backend).
	OSIndexPattern func(signal, tenant string, cross bool) string

	// CHSelect runs a bounded SELECT with the caller's tenant_scope injected, so
	// the ClickHouse row policies enforce isolation under the handler's filter.
	CHSelect func(ctx context.Context, scope, sql string, comment ...string) ([]map[string]any, error)
	// CHScopeFor derives the ClickHouse tenant_scope for a principal
	// (chTenantScopeFor in package backend).
	CHScopeFor func(p Principal) string

	// VictoriaExport runs GET /api/v1/export for a selector over a window.
	VictoriaExport func(ctx context.Context, match string, start, end time.Time) ([]byte, error)

	// KafkaPeek proxies the bounded read-only peek to the correlation
	// container's debug sidecar (Go has no Kafka client by design). Nil, or an
	// error naming the missing configuration, is an expected NOT-OBSERVABLE
	// answer — never a fabricated one.
	KafkaPeek func(ctx context.Context, req PeekRequest) (PeekResult, error)

	// CorrHealth reads the correlation health snapshot (DLQ / quarantine
	// counters for the correlation stage's dead-letter check).
	CorrHealth func(ctx context.Context) (map[string]any, error)

	// SetAPILevel moves THIS process's log level for a bounded window, with the
	// auto-revert armed by the callee.
	SetAPILevel func(level Level, window time.Duration) LevelChange
	// CorrLogLevel moves the correlation service's level via its sidecar route.
	CorrLogLevel func(ctx context.Context, level Level, window time.Duration) (LevelChange, error)
	// VectorLogLevel moves Vector's level. Nil when the deployment has no way to
	// do it — which is the truthful answer today (Vector reads VECTOR_LOG at
	// process start and exposes no runtime level control), and the handler says
	// so rather than pretending.
	VectorLogLevel func(ctx context.Context, level Level, window time.Duration) (LevelChange, error)

	// InjectSyslog / InjectTrap send ONE synthetic record into the STACK's own
	// ingress. Never a device (design §5).
	InjectSyslog func(ctx context.Context, frame string) error
	InjectTrap   func(ctx context.Context, pdu []byte) error
	// InjectFlow sends ONE NetFlow v5 datagram to the stack's own goflow2
	// listener. There is deliberately NO InjectGNMI: a gNMI update originates
	// on the device, so the only way to mint one would be to configure a
	// router, and the absence of the seam is what makes that impossible rather
	// than merely discouraged.
	InjectFlow func(ctx context.Context, packet []byte) error

	// UIQueryRun runs the query the SPA ITSELF issues for a record (the
	// UIQueries contract) and reports what came back — stage 10. It takes the
	// *http.Request because the UI's log query resolves through logsScope, the
	// same tenant/visibility chokepoint the real handler uses: re-deriving that
	// scope from anything else would make this stage test a query the UI does
	// not send.
	UIQueryRun func(r *http.Request, kind Kind, marker string, spec PassiveSpec, tenant string) (UIProbe, error)

	// ParseFilter is the runtime parser decision-trace switch (internal/
	// parsetrace) exposed for the arm/disarm route and the /metrics gauges.
	// Nil = the build has no parser hook, which the route reports honestly.
	ParseFilter ParseSwitch

	// Ring is the API's bounded per-marker debug line buffer (stages 2 and 7).
	Ring *Ring

	// SessionRoot is the directory this API writes and serves session
	// directories from (design §3). Empty = sessions are not persisted here and
	// the session routes say so, which is the truthful answer for a build whose
	// data volume was never given a debug directory — never an empty list that
	// reads like "no trace was ever run".
	SessionRoot string

	// LevelReaders exposes the runtime log level of the modules whose switch
	// this process OWNS, for the read side of /api/debug/loglevel. A module
	// absent from the map is reported from the last change requested through
	// this api (or as unknown), never as "info" — guessing a module's level is
	// how a raised level goes unnoticed past its window.
	LevelReaders map[Module]LevelReader

	// Audit records an accepted debug action. Optional (nil = no sink); never
	// used to decide anything.
	Audit func(r *http.Request, tenant, action string, detail map[string]any)

	// WriteJSON / WriteError are package backend's response writers (they
	// marshal BEFORE committing the status, per audit F-21).
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)

	// Now is the clock seam (nil = wall clock).
	Now func() time.Time
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}
