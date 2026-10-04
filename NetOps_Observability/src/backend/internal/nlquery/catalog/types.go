// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package catalog is the Semantic Schema Catalog for the Iris NL query path
// (tracker 337 N-C1; design: docs/architecture/iris-nl-query-design.md §1).
//
// It says what an operator can ASK about — entity types, metrics, change and
// incident dimensions, and how they relate — in the operator's words (aliases)
// and in closed, validated names the query AST must use. It is DATA ONLY: the
// executable physical forms (MetricsQL templates, ClickHouse expressions) live
// in Go in the planner, keyed by the canonical names here, so editing the
// catalog can never inject query text.
//
// Nothing here is tenant data. Tenant-specific vocabulary (site nicknames,
// a workspace's own name for a provider) lives in the per-tenant alias table
// (N-C2), never in this file and never in a model's weights. The synonym
// groups below are PUBLIC vocabulary — the well-known names of carriers and
// SaaS applications ("AT&T" / "ATT", "Office 365" / "O365") — and a group
// never creates a tenant entity: it only lets the resolver find the caller's
// OWN entity by another of its common names (N-C2 catalog-synonym rung), and a
// provider group with a seed lets a carrier be NAMED before anyone aliased it.
package catalog

// Catalog is the whole embedded schema. SchemaVersion is the file format
// version; Version() is the content hash stamped into every query's provenance.
type Catalog struct {
	SchemaVersion int            `json:"schema_version"`
	Entities      []EntityType   `json:"entities"`
	Metrics       []Metric       `json:"metrics"`
	Dimensions    []Dimension    `json:"dimensions"`
	Relationships []Relationship `json:"relationships"`
	// Synonyms are public names for providers and applications (N-C2).
	Synonyms []SynonymGroup `json:"synonyms"`

	version   string
	byEntity  map[string]*EntityType
	byMetric  map[string]*Metric
	byDim     map[string]*Dimension // key: entity + "." + name
	aliases   map[string][]AliasHit // normalized alias → hits
	synByTerm map[string][]int      // entity + "\x1f" + normalized term → indexes into Synonyms
}

// SynonymGroup is one set of names that mean the same provider or
// application. Terms[0] is the display name. Seed, allowed only for a
// provider, is the canonical id the group stands for when the caller has no
// entity of their own by any of its names (provider seeding, N-C2): carriers
// are public, so naming one reveals nothing about any tenant. Applications are
// never seeded from here — the change ledger and incidents match an
// application by the value the WORKSPACE stores, so an application only
// resolves to an entity the caller's own data holds.
type SynonymGroup struct {
	Entity string   `json:"entity"`
	Seed   string   `json:"seed,omitempty"`
	Terms  []string `json:"terms"`
}

// EntityType is one queryable kind of object.
type EntityType struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IDPrefix    string   `json:"id_prefix"`
	IDPattern   string   `json:"id_pattern"`
	NameFields  []string `json:"name_fields"`
	Aliases     []string `json:"aliases"`
	// Resolver is how ids of this type are found and scoped — a closed set.
	Resolver    string     `json:"resolver"`
	MetricLabel []LabelMap `json:"metric_labels,omitempty"`
	Sensitivity string     `json:"sensitivity"`
}

// LabelMap says which metric label identifies this entity and from which of
// its fields the label value comes (e.g. device ← device_id|device_name).
type LabelMap struct {
	Label string `json:"label"`
	From  string `json:"from"`
}

// Metric is one measurable quantity, in operator terms.
type Metric struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Unit        string   `json:"unit"`
	Aliases     []string `json:"aliases"`
	EntityTypes []string `json:"entity_types"`
	Backend     string   `json:"backend"`
	// PhysicalMetrics are the raw series names the planner template reads.
	PhysicalMetrics []string `json:"physical_metrics"`
	// Labels maps an entity dimension to the physical label carrying it.
	Labels       map[string]string  `json:"labels"`
	Aggregations []string           `json:"aggregations"`
	DefaultAgg   string             `json:"default_agg"`
	Operators    []string           `json:"operators"`
	ValueEnum    map[string]float64 `json:"value_enum,omitempty"`
	// DefaultThreshold is what "high"/"unusual" means when no baseline applies.
	DefaultThreshold *float64 `json:"default_threshold,omitempty"`
	BaselineOK       bool     `json:"baseline_ok"`
	// FanoutHint is the expected series per entity (cost estimation).
	FanoutHint int `json:"fanout_hint"`
	// Scope is "device_scoped" or "gated:N-B5" (series a scoped tenant cannot
	// yet see; the validator refuses them for non-cross callers).
	Scope    string    `json:"scope"`
	Emitters []Emitter `json:"emitters"`
	Quality  []string  `json:"quality,omitempty"`
	Examples []string  `json:"examples,omitempty"`
}

// Emitter pins where a physical metric is produced: File (relative to the
// NetOps_Observability project root) must literally contain Contains. The
// drift test fails the build the day a metric is renamed or removed.
type Emitter struct {
	File     string `json:"file"`
	Contains string `json:"contains"`
}

// Dimension is a filterable/groupable field of a list-type entity (change,
// incident).
type Dimension struct {
	Entity      string      `json:"entity"`
	Name        string      `json:"name"`
	Type        string      `json:"type"` // enum | string | number | time
	Aliases     []string    `json:"aliases,omitempty"`
	Enum        []EnumValue `json:"enum,omitempty"`
	Operators   []string    `json:"operators,omitempty"`
	Filterable  bool        `json:"filterable"`
	Groupable   bool        `json:"groupable"`
	Display     bool        `json:"display"`
	Sensitivity string      `json:"sensitivity"`
}

// EnumValue is one allowed value; Physical lists the stored values it covers
// (a catalog-level class like "wan" maps to several stored change types).
type EnumValue struct {
	Value    string   `json:"value"`
	Aliases  []string `json:"aliases,omitempty"`
	Physical []string `json:"physical,omitempty"`
}

// Relationship is one allowed join between entity types.
type Relationship struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Via         string `json:"via"`
	Cardinality string `json:"cardinality"`
}

// AliasHit is one catalog object an operator word can mean.
type AliasHit struct {
	Kind string // entity | metric | dimension | enum
	Name string // canonical name (for enum: dimension.value)
	For  string // metric: entity types it applies to; dimension/enum: its entity
}
