// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package dataprotect is the platform's DATA PROTECTION domain: the backup
// intent store, the OpenSearch snapshot-policy control plane, the snapshot
// inventory + management surface, the restorability probe, the bounded async
// operation ring and the per-engine coverage table.
//
// WHY IT IS A PACKAGE (CLAUDE.md §2). It was four files in the flat root
// package; everything it needs from the platform — an OpenSearch caller, a
// clock, an audit sink, a platform-admin gate, a logger and a place to persist
// the operator's intent — is a NARROW seam, so the domain owes the root package
// nothing but those six interfaces. Nothing in here imports package backend,
// and nothing in here reads the process environment: every concrete value
// (repository name, file paths, probe cadence and kill switch) is injected as a
// VALUE in Deps, resolved once by the integrator.
//
// THE HONESTY RULE, which the whole surface obeys: a value we do not measure is
// a nil pointer, and it always ships with a sibling `*_detail` string saying WHY
// it is nil. Never a fabricated zero, never a blank an operator reads as "fine".
// This exists because of the 2026-08-27 incident, where a repository whose blob
// tree had been deleted still reported a policy, a schedule and a list of
// restore points — all of them unrestorable, for seven days, silently.
//
// ISOLATION (§3a rule 3): every route here is platform-GLOBAL plumbing behind
// the injected Gate (the integrator binds requirePlatformAdmin) and is audited
// on BOTH outcomes. No tenant data crosses this package, which is why there is
// deliberately no org-isolation test: a tenant admin must not reach it at all.
package dataprotect

import (
	"context"
	"net/http"
	"time"
)

// ── the injected seams (§5 "interfaces for all external dependencies") ───────

// Principal is the already-authorized caller. Deliberately minimal: this
// package never sees the integrator's claims type, and the only fact it needs
// is who to attribute an audited write to.
type Principal struct {
	// Subject is the authenticated subject (username/sub).
	Subject string
}

// Gate authorizes one request and yields the caller. ok=false means the gate
// ALREADY wrote the refusal (401/403) and the handler must return immediately.
// The integrator binds its platform-admin gate here.
type Gate func(w http.ResponseWriter, r *http.Request) (Principal, bool)

// StatusError is a non-2xx reply from the search cluster. The OpenSearch
// implementation returns it so a caller can tell "the repository is not
// registered" (404) apart from "the cluster is unreachable" — a distinction the
// backup-status view has to make and cannot make from a string.
type StatusError struct {
	// Status is the HTTP status the cluster returned.
	Status int
	// StatusText is the raw status line ("404 Not Found"), so a caller can
	// echo it verbatim the way the pre-extraction code did.
	StatusText string
	// Msg is the full, already-composed message (status line plus a bounded
	// slice of the body, which is where the 2026-08-27 NoSuchFileException text
	// lived).
	Msg string
}

func (e *StatusError) Error() string { return e.Msg }

// OpenSearch is the ONLY way this package reaches the search cluster. One
// method, with the timeout as a parameter: a policy read and a two-hour restore
// are the same call shape but emphatically not the same deadline (§9 all IO has
// a timeout, and the timeout has to be the operation's).
//
// A non-2xx reply MUST come back as a *StatusError. `out` may be nil, in which
// case the body is discarded.
type OpenSearch interface {
	Do(ctx context.Context, method, path string, body []byte, out any, timeout time.Duration) error
}

// Clock is the time source. RPO arithmetic, probe scheduling and operation
// timing all go through it, so a test needs no sleeps and no wall clock.
type Clock interface {
	Now() time.Time
}

// systemClock is the default Clock.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// AuditRecord is this package's own audit event. The integrator adapts it to
// the platform's audit type and fills the request envelope (method, path,
// remote) from r — which is why r travels with the record instead of the
// package re-deriving a client IP it has no business knowing how to derive.
type AuditRecord struct {
	// Actor is the authenticated subject the action is attributed to.
	Actor string
	// Status is the HTTP status the caller is about to receive.
	Status int
	// Decision is "allow" or "deny". BOTH are recorded: a refused
	// platform-global write that was never recorded is indistinguishable from
	// one that never happened.
	Decision string
	// Detail carries the action-specific context (action, snapshot, mode, …).
	Detail map[string]any
}

// Auditor records a platform-config event.
type Auditor interface {
	Record(r *http.Request, ev AuditRecord)
}

// Logger is the structured log seam (§10 no silent failures). `component` is
// this package's own subsystem label ("backup.ops", "backup.probe", …).
type Logger interface {
	Info(component, msg string, fields map[string]any)
	Warn(component, msg string, fields map[string]any)
	Error(component, msg string, fields map[string]any)
}

// nopLogger is the fallback when no Logger is injected. It is deliberately the
// ONLY silent path in the package, and it exists so a narrow unit harness does
// not have to build one.
type nopLogger struct{}

func (nopLogger) Info(string, string, map[string]any)  {}
func (nopLogger) Warn(string, string, map[string]any)  {}
func (nopLogger) Error(string, string, map[string]any) {}

// ConfigStore persists the platform's data-protection INTENT (a single global
// row). Get must be safe to call on an empty store and return the zero Config,
// which reads as "no intent recorded" — the shipped state of a fresh install.
type ConfigStore interface {
	Get() Config
	Put(Config) error
}

// DeviceConfigFacts is everything the coverage table needs to say about the
// in-product device config-backup module WITHOUT importing it. The env NAMES
// travel with the facts because the operator-facing reasons quote them: telling
// someone the cadence comes from CONFIG_BACKUP_INTERVAL is the difference
// between an actionable row and a shrug.
type DeviceConfigFacts struct {
	// Interval is the module's capture cadence.
	Interval time.Duration
	// KeepVersions is the per-device retention depth actually in force.
	KeepVersions int
	// FeatureFlagEnv / IntervalEnv / KeepVersionsEnv are the env var names the
	// reasons quote.
	FeatureFlagEnv  string
	IntervalEnv     string
	KeepVersionsEnv string
	// Versions / Failed / Pruned are process-lifetime counters; HasCounters is
	// false when the build exposes none, and the row then says so rather than
	// printing three zeros an operator would read as "nothing is wrong".
	Versions    int64
	Failed      int64
	Pruned      int64
	HasCounters bool
}

// DeviceConfigSource yields the config-backup module's coverage facts.
// ok=false means the module is OFF, which is a first-class answer
// (covered="not_applicable"), not a measurement failure.
type DeviceConfigSource interface {
	Facts() (DeviceConfigFacts, bool)
}

// ── Deps ────────────────────────────────────────────────────────────────────

// DefaultRepository is the one repository this platform registers. It is a
// VALUE in Deps rather than a request parameter for the same reason it was a
// constant before: a client-chosen repository name would be a path segment
// chosen by a browser.
const DefaultRepository = "netops-fs"

// DefaultProbeInterval is the minimum spacing between restorability probes.
const DefaultProbeInterval = 24 * time.Hour

// Deps are the module's injected collaborators and its resolved configuration
// (§1 every dependency explicit and injectable). Every interface field is
// REQUIRED unless its comment says otherwise; the concrete values below carry
// documented fallbacks so a narrow harness can leave them zero.
type Deps struct {
	// Search is the search-cluster caller. Required.
	Search OpenSearch
	// Clock is the time source. Optional (nil = the system clock).
	Clock Clock
	// Audit records platform-config events. Required.
	Audit Auditor
	// Authz is the platform-admin gate. Required.
	Authz Gate
	// Log is the structured logger. Optional (nil = silent, which only a unit
	// harness should ever choose).
	Log Logger
	// Config is the backup-intent store. Required.
	Config ConfigStore
	// WriteJSON is the platform's response writer. Required.
	WriteJSON func(w http.ResponseWriter, status int, body any)
	// Go starts a supervised goroutine. Optional (nil = a bare `go`; the
	// operation runner recovers its own panics either way).
	Go func(name string, fn func())
	// DeviceConfigs yields the config-backup module's coverage facts.
	// Optional: nil means the module is not built into this binary at all.
	DeviceConfigs DeviceConfigSource

	// Repository is the snapshot repository name. Optional (default
	// DefaultRepository).
	Repository string
	// OpsFile is where the operation history is persisted (SNAPSHOT_OPS_FILE).
	// Required in production; an empty path disables persistence.
	OpsFile string
	// VerifyFile is where probe verdicts are persisted (SNAPSHOT_VERIFY_FILE).
	// Required in production; an empty path disables persistence.
	VerifyFile string
	// BackupReportPath is the host bundle's report (BACKUP_REPORT). Named in
	// the coverage reasons, so an operator knows exactly which file was absent.
	BackupReportPath string
	// RestoreDrillReportPath is the restore-drill report (RESTORE_DRILL_REPORT).
	RestoreDrillReportPath string
	// BackupDrillReportPath is the BUNDLE restore drill's report
	// (BACKUP_DRILL_REPORT, written by scripts/backup-drill.sh). It is a
	// different artefact from RestoreDrillReportPath: restore-drill.sh proves
	// the LIVE stores' dump/restore mechanism with a canary, while
	// backup-drill.sh proves an actual BUNDLE ARTIFACT restores — which is the
	// thing an operator holds after losing the host. Both are read; neither is
	// inferred from the other.
	BackupDrillReportPath string
	// SecondaryRepository is an OPTIONAL second `fs` snapshot repository on a
	// separately-mounted path (OPENSEARCH_SNAPSHOT_REPO2). Empty = not
	// configured, which is the shipped default and is reported as such rather
	// than as a fault: an off-host repository is a deployment decision, and a
	// page that nags for one it cannot create is noise.
	SecondaryRepository string
	// ProbeEnabled is the restorability probe's kill switch
	// (SNAPSHOT_PROBE_ENABLED). Default ON in the integrator: a platform that
	// silently stops proving its backups is the failure this closes.
	ProbeEnabled bool
	// ProbeInterval is the minimum spacing between probes
	// (SNAPSHOT_PROBE_INTERVAL). Optional (<= 0 uses DefaultProbeInterval).
	ProbeInterval time.Duration
}

// normalize fills the documented fallbacks. It never invents an interface the
// caller did not supply, except for the two whose absence is genuinely benign
// (the clock and the logger).
func (d Deps) normalize() Deps {
	if d.Clock == nil {
		d.Clock = systemClock{}
	}
	if d.Log == nil {
		d.Log = nopLogger{}
	}
	if d.Repository == "" {
		d.Repository = DefaultRepository
	}
	if d.ProbeInterval <= 0 {
		d.ProbeInterval = DefaultProbeInterval
	}
	if d.Go == nil {
		d.Go = func(_ string, fn func()) { go fn() }
	}
	return d
}

// Service is the Data Protection module.
type Service struct {
	deps     Deps
	ops      opsRing
	verdicts verdictStore
	metrics  *Metrics
}

// New builds the module. The ops ring and the verdict store are VALUE fields
// whose zero value is usable, so the surface answers honestly rather than
// depending on a construction step someone can forget (§10).
func New(d Deps) *Service {
	d = d.normalize()
	s := &Service{deps: d}
	s.ops.path = d.OpsFile
	s.ops.log = d.Log
	s.ops.now = d.Clock.Now
	s.verdicts.path = d.VerifyFile
	s.verdicts.log = d.Log
	s.metrics = newMetrics(d.Repository, d.ProbeEnabled)
	return s
}

// Metrics is the module's Prometheus surface. Nil-safe: a server assembled
// without the module renders nothing rather than panicking in the exporter.
func (s *Service) Metrics() *Metrics {
	if s == nil {
		return nil
	}
	return s.metrics
}

// now is the module's clock.
func (s *Service) now() time.Time { return s.deps.Clock.Now() }

// repo is the configured repository name.
func (s *Service) repo() string { return s.deps.Repository }

// osDo is the one call into the search cluster.
func (s *Service) osDo(ctx context.Context, method, path string, body []byte, out any, timeout time.Duration) error {
	if s.deps.Search == nil {
		return jsonError("no OpenSearch client is configured on this server")
	}
	return s.deps.Search.Do(ctx, method, path, body, out, timeout)
}

// jsonError builds a plain, message-only error.
func jsonError(s string) error { return &simpleErr{s} }

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }
