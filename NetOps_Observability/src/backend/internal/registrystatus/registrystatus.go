// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package registrystatus answers one question honestly, per registry: WHICH
// storage backend is responsible for this registry's records right now, does it
// persist them, and can it serve?
//
// It exists because "the tenant has no applications" and "the Applications
// registry has nowhere durable to put an application" rendered identically
// (tracker 245): the selector fell back to an in-memory store, the API answered
// 200 with an empty list, the create succeeded, and the records vanished on the
// next restart. Three states that must never collapse into one:
//
//	available + healthy   — the configured backend owns the records and is up
//	available + unhealthy — the configured backend owns them but is unreachable
//	unavailable           — the configured backend cannot store them at all
//
// The package is pure: no env reads, no I/O, no globals. The caller supplies the
// configured backend and a liveness verdict; Evaluate maps them onto the report.
// That keeps the "no transparent failover" rule mechanically checkable — there
// is nowhere in here for a second backend to be substituted.
package registrystatus

// Backend kinds, mirrored from platformdb (this package stays dependency-free so
// it can be unit-tested without a store; the values are the STORE_BACKEND ones).
const (
	BackendPostgres = "postgres"
	BackendFile     = "file"
	BackendMemory   = "memory"
)

// Persistence characteristics.
const (
	Persistent = "persistent"
	Ephemeral  = "ephemeral"
)

// Reasons. Stable, machine-readable, and safe to render: never a DSN, a
// credential or a raw driver error.
const (
	ReasonUnsupported = "backend not supported for this registry"
	ReasonUnavailable = "database unavailable"
	ReasonEphemeral   = "ephemeral development backend — records do not survive a restart"
)

// Spec declares a registry and the backends that can actually store it. A
// backend absent from Backends is UNSUPPORTED for the registry — the registry is
// then reported unavailable, never quietly re-pointed at another backend.
type Spec struct {
	Registry string   // stable id, e.g. "applications"
	Label    string   // operator-facing name, e.g. "Application registry"
	Backends []string // backend kinds with a real implementation for this registry
}

// Supports reports whether this registry has a real implementation on `backend`.
func (s Spec) Supports(backend string) bool {
	for _, b := range s.Backends {
		if b == backend {
			return true
		}
	}
	return false
}

// Status is the per-registry report. ActiveBackend is deliberately EQUAL to
// ConfiguredBackend whenever the registry is supported — including while the
// backend is unhealthy. A configured-postgres registry never reports an active
// backend of file or memory, because it never writes to one.
type Status struct {
	Registry          string `json:"registry"`
	Label             string `json:"label"`
	ConfiguredBackend string `json:"configured_backend"`
	ActiveBackend     string `json:"active_backend"` // "" ⇒ nothing is storing this registry
	Persistence       string `json:"persistence"`    // "" ⇒ nothing is storing this registry
	Available         bool   `json:"available"`
	Healthy           bool   `json:"healthy"`
	Reason            string `json:"reason,omitempty"`
}

// PersistenceOf maps a backend kind to its durability characteristic. An unknown
// kind has no persistence claim to make — it returns "" rather than guessing
// "persistent", because over-claiming durability is the failure this package
// exists to prevent.
func PersistenceOf(backend string) string {
	switch backend {
	case BackendPostgres, BackendFile:
		return Persistent
	case BackendMemory:
		return Ephemeral
	default:
		return ""
	}
}

// Evaluate builds one registry's status.
//
//   - configured: the process-wide backend the operator selected.
//   - backendHealthy / healthReason: the liveness verdict for that backend.
//
// Health only ever downgrades a SUPPORTED registry; it can never promote an
// unsupported one, and it never changes which backend is active.
func Evaluate(spec Spec, configured string, backendHealthy bool, healthReason string) Status {
	st := Status{
		Registry:          spec.Registry,
		Label:             spec.Label,
		ConfiguredBackend: configured,
	}
	if !spec.Supports(configured) {
		// No implementation ⇒ no active backend, no persistence claim, no data.
		st.Reason = ReasonUnsupported
		return st
	}
	st.ActiveBackend = configured
	st.Persistence = PersistenceOf(configured)
	if !backendHealthy {
		if healthReason == "" {
			healthReason = ReasonUnavailable
		}
		st.Reason = healthReason
		return st // available:false, healthy:false — and STILL configured/active postgres
	}
	st.Available = true
	st.Healthy = true
	if st.Persistence == Ephemeral {
		st.Reason = ReasonEphemeral
	}
	return st
}

// Report is the endpoint payload: the process-wide backend plus one row per
// registry.
type Report struct {
	ConfiguredBackend string   `json:"configured_backend"`
	Persistence       string   `json:"persistence"`
	BackendHealthy    bool     `json:"backend_healthy"`
	Registries        []Status `json:"registries"`
}

// Build evaluates every spec against one backend verdict.
func Build(specs []Spec, configured string, backendHealthy bool, healthReason string) Report {
	rep := Report{
		ConfiguredBackend: configured,
		Persistence:       PersistenceOf(configured),
		BackendHealthy:    backendHealthy,
		Registries:        make([]Status, 0, len(specs)),
	}
	for _, sp := range specs {
		rep.Registries = append(rep.Registries, Evaluate(sp, configured, backendHealthy, healthReason))
	}
	return rep
}
