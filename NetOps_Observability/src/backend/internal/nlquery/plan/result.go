// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

import (
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/validate"
)

// ResultSet is the typed answer to one query. It carries ONLY catalog-level
// names: raw backend labels (including the circuit series' own `tenant`
// label) are stripped before a series leaves the planner.
type ResultSet struct {
	QueryID        string                `json:"query_id"`
	ASTHash        string                `json:"ast_hash"`
	CatalogVersion string                `json:"catalog_version"`
	Type           ast.QueryType         `json:"query_type"`
	Metric         string                `json:"metric,omitempty"`
	Unit           string                `json:"unit,omitempty"`
	Window         Window                `json:"window"`
	Compare        *Window               `json:"compare,omitempty"`
	Series         []OutSeries           `json:"series,omitempty"`
	Rows           []Row                 `json:"rows,omitempty"`
	Truncated      bool                  `json:"truncated"`
	Constraints    []validate.Constraint `json:"constraints_applied,omitempty"`
	Notes          []string              `json:"notes,omitempty"`
	Provenance     Provenance            `json:"provenance"`
	// Detail carries an incident_explain answer (the engine's RCA contract).
	Detail any `json:"detail,omitempty"`
}

// Window is the resolved time span.
type Window struct {
	From time.Time     `json:"from"`
	To   time.Time     `json:"to"`
	Step time.Duration `json:"step,omitempty"`
}

// OutSeries is one series keyed by catalog entity dimensions.
type OutSeries struct {
	Entity map[string]string `json:"entity"`
	Points []Point           `json:"points"`
}

// Row is one table row (catalog field → value).
type Row map[string]any

// Provenance says where the answer came from. Physical — the backend query
// text — is never serialized; /explain returns it to administrators only.
type Provenance struct {
	Source     string          `json:"source"`
	Entities   []ast.EntityRef `json:"entities,omitempty"`
	ExecutedAt time.Time       `json:"executed_at"`
	DurationMs int64           `json:"duration_ms"`
	Physical   []string        `json:"-"`
}
