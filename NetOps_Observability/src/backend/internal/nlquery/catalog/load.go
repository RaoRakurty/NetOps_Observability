// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package catalog

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

//go:embed catalog.v1.json
var embeddedV1 []byte

// Closed vocabularies. A catalog entry outside them is a load error, so a typo
// in the data file can never widen what the planner is asked to do.
var (
	resolvers    = set("site_store", "discovery", "label_pair", "wan_projection", "alias_table", "corr_current", "change_ledger")
	backends     = set("victoriametrics", "clickhouse", "postgres")
	scopes       = set("device_scoped", "gated:N-B5")
	aggregations = set("avg", "max", "min", "sum", "last", "p95", "count")
	operators    = set("eq", "ne", "in", "gt", "ge", "lt", "le", "between", "above_baseline", "increased_by")
	dimTypes     = set("enum", "string", "number", "time")
	vias         = set("sot_site", "label", "wan_circuit_local", "wan_circuit_remote", "alias_table", "seam_owner", "affected_json", "change_field")
	sensitivity  = set("operational", "personal", "restricted")
	nameRe       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
)

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Load parses and validates the embedded v1 catalog.
func Load() (*Catalog, error) { return Parse(embeddedV1) }

// MustLoad is Load for process start-up paths that already handle a panic as
// a boot failure; the server itself calls Load and disables the NL routes on
// error rather than aborting.
func MustLoad() *Catalog {
	c, err := Load()
	if err != nil {
		panic(err)
	}
	return c
}

// Parse decodes a catalog STRICTLY (unknown fields and trailing data are
// errors) and validates it.
func Parse(raw []byte) (*Catalog, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c Catalog
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("catalog: trailing data after the catalog object")
	}
	sum := sha256.Sum256(raw)
	c.version = "v" + fmt.Sprint(c.SchemaVersion) + "-" + hex.EncodeToString(sum[:6])
	if err := c.index(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Version is the content-derived version stamped into query provenance.
func (c *Catalog) Version() string { return c.version }

// NormalizeAlias is the one normalisation every alias lookup uses: lower-case,
// single spaces, hyphens and underscores as spaces.
func NormalizeAlias(s string) string {
	s = strings.ToLower(strings.NewReplacer("-", " ", "_", " ").Replace(s))
	return strings.Join(strings.Fields(s), " ")
}

func (c *Catalog) index() error {
	if c.SchemaVersion != 1 {
		return fmt.Errorf("catalog: schema_version %d is not supported", c.SchemaVersion)
	}
	c.byEntity = map[string]*EntityType{}
	c.byMetric = map[string]*Metric{}
	c.byDim = map[string]*Dimension{}
	c.aliases = map[string][]AliasHit{}

	for i := range c.Entities {
		e := &c.Entities[i]
		if !nameRe.MatchString(e.Name) || c.byEntity[e.Name] != nil {
			return fmt.Errorf("catalog: entity %q: invalid or duplicate name", e.Name)
		}
		if !resolvers[e.Resolver] || !sensitivity[e.Sensitivity] {
			return fmt.Errorf("catalog: entity %q: resolver/sensitivity outside the closed set", e.Name)
		}
		if _, err := regexp.Compile(e.IDPattern); err != nil || e.IDPattern == "" {
			return fmt.Errorf("catalog: entity %q: id_pattern does not compile", e.Name)
		}
		c.byEntity[e.Name] = e
		c.addAliases("entity", e.Name, e.Name, append([]string{e.Name}, e.Aliases...))
	}
	for i := range c.Metrics {
		m := &c.Metrics[i]
		if !nameRe.MatchString(m.Name) || c.byMetric[m.Name] != nil {
			return fmt.Errorf("catalog: metric %q: invalid or duplicate name", m.Name)
		}
		if !backends[m.Backend] || !scopes[m.Scope] {
			return fmt.Errorf("catalog: metric %q: backend/scope outside the closed set", m.Name)
		}
		if len(m.EntityTypes) == 0 || len(m.PhysicalMetrics) == 0 || len(m.Emitters) == 0 {
			return fmt.Errorf("catalog: metric %q: needs entity_types, physical_metrics and emitters", m.Name)
		}
		for _, et := range m.EntityTypes {
			if c.byEntity[et] == nil {
				return fmt.Errorf("catalog: metric %q: unknown entity type %q", m.Name, et)
			}
		}
		for _, a := range m.Aggregations {
			if !aggregations[a] {
				return fmt.Errorf("catalog: metric %q: aggregation %q outside the closed set", m.Name, a)
			}
		}
		if !contains(m.Aggregations, m.DefaultAgg) {
			return fmt.Errorf("catalog: metric %q: default_agg %q is not one of its aggregations", m.Name, m.DefaultAgg)
		}
		for _, o := range m.Operators {
			if !operators[o] {
				return fmt.Errorf("catalog: metric %q: operator %q outside the closed set", m.Name, o)
			}
		}
		if m.FanoutHint <= 0 {
			return fmt.Errorf("catalog: metric %q: fanout_hint must be positive", m.Name)
		}
		c.byMetric[m.Name] = m
		c.addAliases("metric", m.Name, strings.Join(m.EntityTypes, ","), append([]string{m.Name}, m.Aliases...))
	}
	for i := range c.Dimensions {
		d := &c.Dimensions[i]
		key := d.Entity + "." + d.Name
		if c.byEntity[d.Entity] == nil || !nameRe.MatchString(d.Name) || c.byDim[key] != nil {
			return fmt.Errorf("catalog: dimension %q: unknown entity, invalid or duplicate name", key)
		}
		if !dimTypes[d.Type] || !sensitivity[d.Sensitivity] {
			return fmt.Errorf("catalog: dimension %q: type/sensitivity outside the closed set", key)
		}
		if d.Type == "enum" && len(d.Enum) == 0 {
			return fmt.Errorf("catalog: dimension %q: enum with no values", key)
		}
		if d.Sensitivity == "restricted" && d.Filterable {
			return fmt.Errorf("catalog: dimension %q: a restricted dimension is display-only", key)
		}
		for _, o := range d.Operators {
			if !operators[o] {
				return fmt.Errorf("catalog: dimension %q: operator %q outside the closed set", key, o)
			}
		}
		c.byDim[key] = d
		c.addAliases("dimension", key, d.Entity, append([]string{d.Name}, d.Aliases...))
		for _, ev := range d.Enum {
			c.addAliases("enum", key+"="+ev.Value, d.Entity, append([]string{ev.Value}, ev.Aliases...))
		}
	}
	for _, r := range c.Relationships {
		if c.byEntity[r.From] == nil || c.byEntity[r.To] == nil || !vias[r.Via] {
			return fmt.Errorf("catalog: relationship %s→%s via %q is invalid", r.From, r.To, r.Via)
		}
	}
	return c.checkAliasCollisions()
}

func (c *Catalog) addAliases(kind, name, forWhat string, words []string) {
	for _, w := range words {
		n := NormalizeAlias(w)
		if n == "" {
			continue
		}
		hit := AliasHit{Kind: kind, Name: name, For: forWhat}
		dup := false
		for _, h := range c.aliases[n] {
			if h == hit {
				dup = true
			}
		}
		if !dup {
			c.aliases[n] = append(c.aliases[n], hit)
		}
	}
}

// checkAliasCollisions enforces the design's rule: one word may name two
// METRICS only when their entity types are disjoint (so the target type
// decides), and never two entity types.
func (c *Catalog) checkAliasCollisions() error {
	for word, hits := range c.aliases {
		var ents []string
		metricTypes := map[string]string{}
		for _, h := range hits {
			switch h.Kind {
			case "entity":
				ents = append(ents, h.Name)
			case "metric":
				for _, et := range strings.Split(h.For, ",") {
					if prev, ok := metricTypes[et]; ok && prev != h.Name {
						return fmt.Errorf("catalog: alias %q names metrics %q and %q for the same entity type %q", word, prev, h.Name, et)
					}
					metricTypes[et] = h.Name
				}
			}
		}
		if len(ents) > 1 {
			sort.Strings(ents)
			return fmt.Errorf("catalog: alias %q names entity types %v", word, ents)
		}
	}
	return nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ---- lookups ----------------------------------------------------------------

// Entity returns an entity type by canonical name.
func (c *Catalog) Entity(name string) (*EntityType, bool) { e, ok := c.byEntity[name]; return e, ok }

// Metric returns a metric by canonical name.
func (c *Catalog) Metric(name string) (*Metric, bool) { m, ok := c.byMetric[name]; return m, ok }

// Dimension returns an entity's dimension by canonical name.
func (c *Catalog) Dimension(entity, name string) (*Dimension, bool) {
	d, ok := c.byDim[entity+"."+name]
	return d, ok
}

// Lookup returns every catalog object an operator word can mean, in a stable
// order. It is the input to schema retrieval and to the grammar's slot filler.
func (c *Catalog) Lookup(word string) []AliasHit {
	hits := append([]AliasHit(nil), c.aliases[NormalizeAlias(word)]...)
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Kind != hits[j].Kind {
			return hits[i].Kind < hits[j].Kind
		}
		return hits[i].Name < hits[j].Name
	})
	return hits
}

// Aliases returns every normalized alias, sorted (the grammar's longest-match
// scanner and the suggestion engine both read it).
func (c *Catalog) Aliases() []string {
	out := make([]string, 0, len(c.aliases))
	for a := range c.aliases {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// Reachable reports whether `to` can be reached from `from` in at most two
// relationship hops (either direction), or is the same type.
func (c *Catalog) Reachable(from, to string) bool {
	if from == to {
		return true
	}
	adj := map[string]map[string]bool{}
	for _, r := range c.Relationships {
		if adj[r.From] == nil {
			adj[r.From] = map[string]bool{}
		}
		if adj[r.To] == nil {
			adj[r.To] = map[string]bool{}
		}
		adj[r.From][r.To], adj[r.To][r.From] = true, true
	}
	for mid := range adj[from] {
		if mid == to || adj[mid][to] {
			return true
		}
	}
	return false
}
