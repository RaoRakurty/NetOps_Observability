// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package plan compiles a VALIDATED CorrelixQueryAST into calls on a Scope and
// shapes the answer into a ResultSet with provenance (tracker 337 N-C4;
// design: docs/architecture/iris-nl-query-design.md §4).
//
// The planner never sees a principal, a tenant or a backend client. Everything
// it reads comes through Scope, which the ROOT implements bound to the
// authenticated request — so every read is scoped by the same chokepoints the
// UI's own pages use (VictoriaMetrics extra_filters, ClickHouse tenant_scope,
// Postgres RLS). An import guard test pins that this package cannot reach a
// backend any other way.
package plan

import (
	"context"
	"errors"
	"time"

	"netops/backend/internal/nlquery/mql"
)

// ErrNotFound is what Scope returns for an entity that is missing OR belongs
// to someone else — the two are indistinguishable by design.
var ErrNotFound = errors.New("not found")

// Scope is the planner's only window onto data.
type Scope interface {
	MetricRange(ctx context.Context, e mql.Expr, from, to time.Time, step time.Duration, maxSeries int) ([]Series, bool, error)
	MetricInstant(ctx context.Context, e mql.Expr, at time.Time, maxSeries int) ([]Sample, bool, error)
	Incidents(ctx context.Context, q IncidentQuery) ([]IncidentRow, bool, error)
	Incident(ctx context.Context, id string) (IncidentDetail, error)
	Changes(ctx context.Context, q ChangeQuery) ([]ChangeRow, bool, error)
	Devices(ctx context.Context, f DeviceFilter) ([]DeviceRef, error)
	Circuits(ctx context.Context, f CircuitFilter) ([]CircuitRef, error)
	Now() time.Time
}

// Series is one metric series; Labels are the backend's raw labels (the
// planner strips everything outside the catalog before it leaves).
type Series struct {
	Labels map[string]string
	Points []Point
}

// Point is one (unix seconds, value) sample.
type Point struct {
	T int64   `json:"t"`
	V float64 `json:"v"`
}

// Sample is one instant-query value.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// DeviceFilter selects devices the caller may see: by id, or by site.
type DeviceFilter struct {
	IDs   []string
	Sites []string
}

// DeviceRef is one visible device.
type DeviceRef struct{ ID, Name, Site string }

// CircuitFilter selects visible circuits.
type CircuitFilter struct {
	IDs       []string
	Sites     []string
	Devices   []string // device ids
	Providers []string // provider ids (alias table / seam owner)
}

// CircuitRef is one visible circuit; LocalDevice is the device NAME the
// circuit series carries in its local_device label.
type CircuitRef struct{ ID, LocalDevice, LocalIf, Site, Provider string }

// IncidentQuery is a typed incident read — no SQL crosses this boundary.
type IncidentQuery struct {
	From, To    time.Time
	States      []string // physical states
	Tiers       []string // physical verdict tiers
	SeamTypes   []string // physical seam types
	Owners      []string
	MinConf     float64
	Sites       []string // site ids (affected.sites)
	Devices     []string // device ids (affected.devices)
	Apps        []string
	Limit       int
	NewestFirst bool
}

// IncidentRow is one listed incident.
type IncidentRow struct {
	ID, DisplayID, Title, State, Tier, SeamType, Owner string
	Confidence                                         float64
	CreatedAt                                          time.Time
	Sites, Devices                                     []string
}

// IncidentDetail is the engine's conclusion for one incident (the N-B1 RCA
// contract, carried opaquely so this package need not import ai).
type IncidentDetail struct {
	Row    IncidentRow
	Detail any
}

// ChangeQuery is a typed change read.
type ChangeQuery struct {
	From, To    time.Time
	Types       []string // physical change types
	Actors      []string
	Objects     []string
	ObjectKinds []string
	Sites       []string
	Apps        []string
	Seams       []string
	Sources     []string
	ExcludeIDs  []string
	Limit       int
}

// ChangeRow is one recorded change.
type ChangeRow struct {
	ID, Type, Actor, Source, Object, ObjectKind, Site, App, Seam, Summary, Ticket string
	At                                                                            time.Time
	HasDiff                                                                       bool
}
