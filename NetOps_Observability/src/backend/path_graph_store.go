package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/pathgraph"
)

// path_graph_store.go — persistence seam for the Service Path Graph (frozen
// contract v1). Two backends, selected exactly like every other store:
//
//	memPathGraphStore  — the default dependency-free build (dev + tests). Tenant
//	                     isolation is enforced IN THE STORE (CLAUDE.md §3a.4): every
//	                     map is keyed by tenant and there is no unscoped "list all".
//	pgchPathGraphStore — STORE_BACKEND=postgres. Registries (Endpoint,
//	                     PathDefinition) in Postgres under the tenant_iso FORCE-RLS
//	                     policy via withTenant; the immutable observation/hop streams
//	                     in ClickHouse behind the strict tenant_scope row policy.
//
// The §1 rule that customer reads EXCLUDE data_class != 'live' is enforced HERE, in
// the store, on BOTH backends — not in a handler that a future endpoint might forget
// to call. A caller must ask for other classes explicitly, and only a platform
// (cross-tenant) principal is allowed to (see path_graph_api.go).

// ObservationFilter narrows an observation query. DataClasses is REQUIRED to be
// non-empty by the store: "which classes am I allowed to see" is never a default.
type ObservationFilter struct {
	PathID      string
	DstAddress  string
	Protocol    string
	VantageID   string
	Direction   string
	Status      string   // "" = any; e.g. StatusComplete for the seam-hint history query
	DataClasses []string // e.g. {"live"}; empty = the store refuses (fail closed)
	Limit       int
}

// liveOnly is the customer/default filter (§1).
func liveOnly() []string { return []string{pathgraph.DataClassLive} }

func (f ObservationFilter) allows(dataClass string) bool {
	for _, c := range f.DataClasses {
		if c == dataClass {
			return true
		}
	}
	return false
}

func (f ObservationFilter) matches(o pathgraph.PathObservation, d pathgraph.PathDefinition) bool {
	if !f.allows(o.DataClass) {
		return false
	}
	if f.PathID != "" && o.PathID != f.PathID {
		return false
	}
	if f.VantageID != "" && o.VantageID != f.VantageID {
		return false
	}
	if f.DstAddress != "" && !strings.EqualFold(d.DstAddress, f.DstAddress) {
		return false
	}
	if f.Protocol != "" && d.Protocol != f.Protocol {
		return false
	}
	if f.Direction != "" && d.Direction != f.Direction {
		return false
	}
	if f.Status != "" && o.Status != f.Status {
		return false
	}
	return true
}

// pathGraphStore is the storage contract. Every method takes the principal's
// (tenant, cross) — there is no unscoped accessor, by design.
type pathGraphStore interface {
	UpsertEndpoint(ctx context.Context, ep pathgraph.Endpoint) error
	ListEndpoints(ctx context.Context, tenant string, cross bool) ([]pathgraph.Endpoint, error)
	UpsertPathDefinition(ctx context.Context, pd pathgraph.PathDefinition) error
	ListPathDefinitions(ctx context.Context, tenant string, cross bool) ([]pathgraph.PathDefinition, error)
	// AppendObservation writes ONE immutable observation + its ordered hops. It never
	// updates an existing observation (§2.3) — a new run is a new row. The path
	// definition is passed alongside so the write can denormalize the path identity
	// (src/dst/protocol/port/direction/context) into the observation row — that is
	// what the read side filters on ("the latest live path to 10.60.10.10").
	AppendObservation(ctx context.Context, def pathgraph.PathDefinition, obs pathgraph.PathObservation, hops []pathgraph.PathHop) error
	// LatestObservation returns the newest observation matching the filter, with its
	// ordered hops and its path definition. "Current path" is this QUERY, never a
	// mutable row.
	LatestObservation(ctx context.Context, tenant string, cross bool, f ObservationFilter) (pathgraph.PathObservation, []pathgraph.PathHop, pathgraph.PathDefinition, bool, error)
	// ListObservations returns matching observations newest-first (route-change
	// history, §8).
	ListObservations(ctx context.Context, tenant string, cross bool, f ObservationFilter) ([]pathgraph.PathObservation, error)
	// PurgeRun deletes everything a scenario/run produced, keyed on (tenant,
	// scenario_id/run_id) ONLY (§1) — never on names, IP patterns or substrings.
	PurgeRun(ctx context.Context, tenant, scenarioID, runID string) error
}

var errPathScopeRequired = errors.New("path graph: a data_class filter is required (fail closed)")

// newPathGraphStore picks the backend, like newTopologyStore. Always non-nil.
func newPathGraphStore() pathGraphStore {
	if ps, ok := backend.(*pgStore); ok {
		return &pgchPathGraphStore{db: ps.db}
	}
	return newMemPathGraphStore()
}

// ── in-memory backend (default build, dev, tests) ────────────────────────────

type memPathGraphStore struct {
	mu sync.RWMutex
	// EVERY map is tenant-keyed. There is deliberately no flat collection to
	// accidentally range over: a cross-tenant read has to be spelled out.
	endpoints   map[string]map[string]pathgraph.Endpoint       // tenant → endpoint_id → ep
	definitions map[string]map[string]pathgraph.PathDefinition // tenant → path_id → def
	obs         map[string][]pathgraph.PathObservation         // tenant → observations (append-only)
	hops        map[string]map[string][]pathgraph.PathHop      // tenant → observation_id → ordered hops
}

func newMemPathGraphStore() *memPathGraphStore {
	return &memPathGraphStore{
		endpoints:   map[string]map[string]pathgraph.Endpoint{},
		definitions: map[string]map[string]pathgraph.PathDefinition{},
		obs:         map[string][]pathgraph.PathObservation{},
		hops:        map[string]map[string][]pathgraph.PathHop{},
	}
}

// tenantsFor is the ONLY place a cross-tenant read is expressible, and it demands
// the caller pass cross=true explicitly (the platform principal).
func (m *memPathGraphStore) tenantsFor(tenant string, cross bool) []string {
	if !cross {
		return []string{normTenant(tenant)}
	}
	seen := map[string]bool{}
	var out []string
	for t := range m.endpoints {
		seen[t] = true
	}
	for t := range m.definitions {
		seen[t] = true
	}
	for t := range m.obs {
		seen[t] = true
	}
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func (m *memPathGraphStore) UpsertEndpoint(_ context.Context, ep pathgraph.Endpoint) error {
	if err := ep.Validate(); err != nil {
		return err
	}
	t := normTenant(ep.TenantID)
	ep.TenantID = t
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.endpoints[t] == nil {
		m.endpoints[t] = map[string]pathgraph.Endpoint{}
	}
	m.endpoints[t][ep.EndpointID] = ep
	return nil
}

func (m *memPathGraphStore) ListEndpoints(_ context.Context, tenant string, cross bool) ([]pathgraph.Endpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []pathgraph.Endpoint{}
	for _, t := range m.tenantsFor(tenant, cross) {
		for _, ep := range m.endpoints[t] {
			out = append(out, ep)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EndpointID < out[j].EndpointID })
	return out, nil
}

func (m *memPathGraphStore) UpsertPathDefinition(_ context.Context, pd pathgraph.PathDefinition) error {
	if err := pd.Validate(); err != nil {
		return err
	}
	t := normTenant(pd.TenantID)
	pd.TenantID = t
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.definitions[t] == nil {
		m.definitions[t] = map[string]pathgraph.PathDefinition{}
	}
	m.definitions[t][pd.PathID] = pd
	return nil
}

func (m *memPathGraphStore) ListPathDefinitions(_ context.Context, tenant string, cross bool) ([]pathgraph.PathDefinition, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []pathgraph.PathDefinition{}
	for _, t := range m.tenantsFor(tenant, cross) {
		for _, pd := range m.definitions[t] {
			out = append(out, pd)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PathID < out[j].PathID })
	return out, nil
}

func (m *memPathGraphStore) AppendObservation(_ context.Context, _ pathgraph.PathDefinition, o pathgraph.PathObservation, hops []pathgraph.PathHop) error {
	if err := o.Validate(); err != nil {
		return err
	}
	for _, h := range hops {
		if err := h.Validate(); err != nil {
			return err
		}
		if normTenant(h.TenantID) != normTenant(o.TenantID) {
			// A hop that claims another tenant than its observation is a bug or an
			// attack; either way it never enters the store.
			return fmt.Errorf("hop %d tenant %q != observation tenant %q", h.HopIndex, h.TenantID, o.TenantID)
		}
	}
	t := normTenant(o.TenantID)
	o.TenantID = t
	m.mu.Lock()
	defer m.mu.Unlock()
	m.obs[t] = append(m.obs[t], o)
	if m.hops[t] == nil {
		m.hops[t] = map[string][]pathgraph.PathHop{}
	}
	ordered := make([]pathgraph.PathHop, len(hops))
	copy(ordered, hops)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].HopIndex < ordered[j].HopIndex })
	for i := range ordered {
		ordered[i].TenantID = t
	}
	m.hops[t][o.ObservationID] = ordered
	return nil
}

func (m *memPathGraphStore) LatestObservation(_ context.Context, tenant string, cross bool, f ObservationFilter) (pathgraph.PathObservation, []pathgraph.PathHop, pathgraph.PathDefinition, bool, error) {
	if len(f.DataClasses) == 0 {
		return pathgraph.PathObservation{}, nil, pathgraph.PathDefinition{}, false, errPathScopeRequired
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var best pathgraph.PathObservation
	var bestDef pathgraph.PathDefinition
	var bestTenant string
	found := false
	for _, t := range m.tenantsFor(tenant, cross) {
		for _, o := range m.obs[t] {
			def := m.definitions[t][o.PathID]
			if !f.matches(o, def) {
				continue
			}
			if !found || o.ObservedAt.After(best.ObservedAt) {
				best, bestDef, bestTenant, found = o, def, t, true
			}
		}
	}
	if !found {
		return pathgraph.PathObservation{}, nil, pathgraph.PathDefinition{}, false, nil
	}
	hops := append([]pathgraph.PathHop(nil), m.hops[bestTenant][best.ObservationID]...)
	return best, hops, bestDef, true, nil
}

func (m *memPathGraphStore) ListObservations(_ context.Context, tenant string, cross bool, f ObservationFilter) ([]pathgraph.PathObservation, error) {
	if len(f.DataClasses) == 0 {
		return nil, errPathScopeRequired
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []pathgraph.PathObservation{}
	for _, t := range m.tenantsFor(tenant, cross) {
		for _, o := range m.obs[t] {
			if f.matches(o, m.definitions[t][o.PathID]) {
				out = append(out, o)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ObservedAt.After(out[j].ObservedAt) })
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

// PurgeRun — cleanup on (tenant, scenario_id/run_id) ONLY (§1).
func (m *memPathGraphStore) PurgeRun(_ context.Context, tenant, scenarioID, runID string) error {
	if scenarioID == "" && runID == "" {
		return errors.New("purge requires a scenario_id or run_id (§1: never a name/IP pattern)")
	}
	t := normTenant(tenant)
	match := func(p pathgraph.Provenance) bool {
		if scenarioID != "" && p.ScenarioID != scenarioID {
			return false
		}
		if runID != "" && p.RunID != runID {
			return false
		}
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.obs[t][:0]
	for _, o := range m.obs[t] {
		if match(o.Provenance) {
			delete(m.hops[t], o.ObservationID)
			continue
		}
		kept = append(kept, o)
	}
	m.obs[t] = kept
	for id, ep := range m.endpoints[t] {
		if match(ep.Provenance) {
			delete(m.endpoints[t], id)
		}
	}
	for id, pd := range m.definitions[t] {
		if match(pd.Provenance) {
			delete(m.definitions[t], id)
		}
	}
	return nil
}

// ── Postgres (registries) + ClickHouse (streams) backend ─────────────────────

type pgchPathGraphStore struct {
	db *pgDB
}

func (s *pgchPathGraphStore) UpsertEndpoint(ctx context.Context, ep pathgraph.Endpoint) error {
	if err := ep.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	data, err := json.Marshal(ep)
	if err != nil {
		return err
	}
	// Written at platform scope: the writer (the ingester) spans tenants and each
	// row carries its own tenant_id, which the RLS WITH CHECK validates.
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO path_endpoints (tenant_id, endpoint_id, address, address_family, network_context, kind,
        resolved_entity_ref, resolution_method, confidence, valid_from, valid_to, evidence_ref,
        data_class, environment, scenario_id, run_id, producer_id, provenance_id, contract_version, data)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
ON CONFLICT (tenant_id, endpoint_id) DO UPDATE SET
        kind = EXCLUDED.kind,
        resolved_entity_ref = EXCLUDED.resolved_entity_ref,
        resolution_method = EXCLUDED.resolution_method,
        confidence = EXCLUDED.confidence,
        valid_to = EXCLUDED.valid_to,
        evidence_ref = EXCLUDED.evidence_ref,
        updated_at = now(),
        data = EXCLUDED.data`,
			normTenant(ep.TenantID), ep.EndpointID, ep.Address, ep.AddressFamily, ep.NetworkContext, ep.Kind,
			ep.ResolvedEntityRef, ep.ResolutionMethod, ep.Confidence, ep.ValidFrom, ep.ValidTo, ep.EvidenceRef,
			ep.DataClass, ep.Environment, ep.ScenarioID, ep.RunID, ep.ProducerID, ep.ProvenanceID,
			pathgraph.ContractVersion, data)
		return err
	})
}

func (s *pgchPathGraphStore) ListEndpoints(ctx context.Context, tenant string, cross bool) ([]pathgraph.Endpoint, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := []pathgraph.Endpoint{}
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT data FROM path_endpoints ORDER BY tenant_id, endpoint_id LIMIT 5000`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			var ep pathgraph.Endpoint
			if err := json.Unmarshal(raw, &ep); err != nil {
				return err
			}
			out = append(out, ep)
		}
		return rows.Err()
	})
	return out, err
}

func (s *pgchPathGraphStore) UpsertPathDefinition(ctx context.Context, pd pathgraph.PathDefinition) error {
	if err := pd.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	data, err := json.Marshal(pd)
	if err != nil {
		return err
	}
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO path_definitions (tenant_id, path_id, src_endpoint_ref, dst_endpoint_ref, src_address, dst_address,
        direction, protocol, dst_port, vantage_id, network_context,
        data_class, environment, scenario_id, run_id, producer_id, provenance_id, contract_version, data)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
ON CONFLICT (tenant_id, path_id) DO UPDATE SET last_seen = now(), data = EXCLUDED.data`,
			normTenant(pd.TenantID), pd.PathID, pd.SrcEndpointRef, pd.DstEndpointRef, pd.SrcAddress, pd.DstAddress,
			pd.Direction, pd.Protocol, pd.DstPort, pd.VantageID, pd.NetworkContext,
			pd.DataClass, pd.Environment, pd.ScenarioID, pd.RunID, pd.ProducerID, pd.ProvenanceID,
			pathgraph.ContractVersion, data)
		return err
	})
}

func (s *pgchPathGraphStore) ListPathDefinitions(ctx context.Context, tenant string, cross bool) ([]pathgraph.PathDefinition, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := []pathgraph.PathDefinition{}
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT data FROM path_definitions ORDER BY tenant_id, path_id LIMIT 5000`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			var pd pathgraph.PathDefinition
			if err := json.Unmarshal(raw, &pd); err != nil {
				return err
			}
			out = append(out, pd)
		}
		return rows.Err()
	})
	return out, err
}

// AppendObservation writes the immutable run to ClickHouse (observation + ordered
// hops) as JSONEachRow. Registries are upserted separately by the ingester. The
// definition's identity fields are denormalized into the row — the read side
// (LatestObservation / ListObservations) filters on dst_address/protocol/vantage,
// so an observation written without them is unreachable by every query.
func (s *pgchPathGraphStore) AppendObservation(ctx context.Context, def pathgraph.PathDefinition, o pathgraph.PathObservation, hops []pathgraph.PathHop) error {
	if err := o.Validate(); err != nil {
		return err
	}
	obsRow := map[string]any{
		"tenant_id": normTenant(o.TenantID), "observation_id": o.ObservationID, "path_id": o.PathID,
		"observed_at": chTime(o.ObservedAt), "method": o.Method, "vantage_id": o.VantageID,
		"status": o.Status, "hop_count": o.HopCount, "data_class": o.DataClass,
		"environment": o.Environment, "scenario_id": o.ScenarioID, "run_id": o.RunID,
		"producer_id": o.ProducerID, "provenance_id": o.ProvenanceID,
		"contract_version": pathgraph.ContractVersion,
		"src_address":      def.SrcAddress, "dst_address": def.DstAddress,
		"protocol": def.Protocol, "dst_port": def.DstPort,
		"direction": def.Direction, "network_context": def.NetworkContext,
	}
	if err := chInsertJSON(ctx, "netops.path_observations", []map[string]any{obsRow}); err != nil {
		return err
	}
	rows := make([]map[string]any, 0, len(hops))
	for _, h := range hops {
		if err := h.Validate(); err != nil {
			return err
		}
		if normTenant(h.TenantID) != normTenant(o.TenantID) {
			return fmt.Errorf("hop %d tenant %q != observation tenant %q", h.HopIndex, h.TenantID, o.TenantID)
		}
		rows = append(rows, map[string]any{
			"tenant_id": normTenant(h.TenantID), "observation_id": o.ObservationID, "hop_index": h.HopIndex,
			"state": h.State, "observed_address": h.ObservedAddress, "resolved_entity_ref": h.ResolvedEntityRef,
			"resolution_method": h.ResolutionMethod, "confidence": h.Confidence, "kind": h.Kind,
			"network_context": h.NetworkContext, "seam_id": h.SeamID, "rtt_ms": h.RTTms, "loss_pct": h.LossPct,
			"transformation": h.Transformation, "candidate_ref": h.CandidateRef, "evidence_ref": h.EvidenceRef,
			"observed_at": chTime(h.ObservedAt), "data_class": dataClassOrDefault(h.DataClass, o.DataClass),
		})
	}
	if len(rows) == 0 {
		return nil
	}
	return chInsertJSON(ctx, "netops.path_hops", rows)
}

func (s *pgchPathGraphStore) LatestObservation(ctx context.Context, tenant string, cross bool, f ObservationFilter) (pathgraph.PathObservation, []pathgraph.PathHop, pathgraph.PathDefinition, bool, error) {
	obs, err := s.ListObservations(ctx, tenant, cross, ObservationFilter{
		PathID: f.PathID, DstAddress: f.DstAddress, Protocol: f.Protocol, VantageID: f.VantageID,
		Direction: f.Direction, Status: f.Status, DataClasses: f.DataClasses, Limit: 1,
	})
	if err != nil || len(obs) == 0 {
		return pathgraph.PathObservation{}, nil, pathgraph.PathDefinition{}, false, err
	}
	o := obs[0]
	hops, err := s.hopsOf(ctx, tenant, cross, o.ObservationID)
	if err != nil {
		return pathgraph.PathObservation{}, nil, pathgraph.PathDefinition{}, false, err
	}
	def, _, err := s.pathDefinition(ctx, tenant, cross, o.PathID)
	if err != nil {
		return pathgraph.PathObservation{}, nil, pathgraph.PathDefinition{}, false, err
	}
	return o, hops, def, true, nil
}

func (s *pgchPathGraphStore) pathDefinition(ctx context.Context, tenant string, cross bool, pathID string) (pathgraph.PathDefinition, bool, error) {
	defs, err := s.ListPathDefinitions(ctx, tenant, cross)
	if err != nil {
		return pathgraph.PathDefinition{}, false, err
	}
	for _, d := range defs {
		if d.PathID == pathID {
			return d, true, nil
		}
	}
	return pathgraph.PathDefinition{}, false, nil
}

func (s *pgchPathGraphStore) ListObservations(ctx context.Context, tenant string, cross bool, f ObservationFilter) ([]pathgraph.PathObservation, error) {
	if len(f.DataClasses) == 0 {
		return nil, errPathScopeRequired
	}
	conds := []string{"data_class IN (" + chStringList(f.DataClasses) + ")"}
	if f.PathID != "" {
		if !isPathToken(f.PathID) {
			return nil, errors.New("invalid path_id")
		}
		conds = append(conds, "path_id = '"+f.PathID+"'")
	}
	if f.DstAddress != "" {
		if !isAddressToken(f.DstAddress) {
			return nil, errors.New("invalid dst address")
		}
		conds = append(conds, "dst_address = '"+f.DstAddress+"'")
	}
	if f.Protocol != "" {
		if !isPathToken(f.Protocol) {
			return nil, errors.New("invalid protocol")
		}
		conds = append(conds, "protocol = '"+f.Protocol+"'")
	}
	if f.VantageID != "" {
		if !isPathToken(f.VantageID) {
			return nil, errors.New("invalid vantage_id")
		}
		conds = append(conds, "vantage_id = '"+f.VantageID+"'")
	}
	if f.Status != "" {
		if !isPathToken(f.Status) {
			return nil, errors.New("invalid status")
		}
		conds = append(conds, "status = '"+f.Status+"'")
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	sql := `SELECT observation_id, path_id, ` + chISO("observed_at") + ` AS observed_at, method, vantage_id,
       status, hop_count, tenant_id, data_class, environment, scenario_id, run_id, producer_id, provenance_id
  FROM netops.path_observations FINAL
 WHERE ` + strings.Join(conds, " AND ") + `
 ORDER BY observed_at DESC
 LIMIT ` + intToString(limit) + `
 FORMAT JSON`
	rows, err := chSelect(ctx, chScopeFor(tenant, cross), sql, "api:/api/rca/path")
	if err != nil {
		return nil, err
	}
	out := make([]pathgraph.PathObservation, 0, len(rows))
	for _, r := range rows {
		out = append(out, pathgraph.PathObservation{
			ObservationID: str(r["observation_id"]), PathID: str(r["path_id"]),
			ObservedAt: parseCHTime(r["observed_at"]), Method: str(r["method"]),
			VantageID: str(r["vantage_id"]), Status: str(r["status"]), HopCount: asInt(r["hop_count"]),
			ContractVersion: pathgraph.ContractVersion,
			Provenance: pathgraph.Provenance{
				TenantID: str(r["tenant_id"]), DataClass: str(r["data_class"]), Environment: str(r["environment"]),
				ScenarioID: str(r["scenario_id"]), RunID: str(r["run_id"]), ProducerID: str(r["producer_id"]),
				ProvenanceID: str(r["provenance_id"]),
			},
		})
	}
	return out, nil
}

func (s *pgchPathGraphStore) hopsOf(ctx context.Context, tenant string, cross bool, observationID string) ([]pathgraph.PathHop, error) {
	if !isPathToken(observationID) {
		return nil, errors.New("invalid observation_id")
	}
	sql := `SELECT hop_index, state, observed_address, resolved_entity_ref, resolution_method, confidence,
       kind, network_context, seam_id, rtt_ms, loss_pct, transformation, candidate_ref, evidence_ref,
       ` + chISO("observed_at") + ` AS observed_at, tenant_id, data_class
  FROM netops.path_hops FINAL
 WHERE observation_id = '` + observationID + `'
 ORDER BY hop_index ASC
 LIMIT 128
 FORMAT JSON`
	rows, err := chSelect(ctx, chScopeFor(tenant, cross), sql, "api:/api/rca/path")
	if err != nil {
		return nil, err
	}
	out := make([]pathgraph.PathHop, 0, len(rows))
	for _, r := range rows {
		out = append(out, pathgraph.PathHop{
			ObservationID: observationID, HopIndex: asInt(r["hop_index"]), State: str(r["state"]),
			ObservedAddress: str(r["observed_address"]), ResolvedEntityRef: str(r["resolved_entity_ref"]),
			ResolutionMethod: str(r["resolution_method"]), Confidence: str(r["confidence"]),
			Kind: str(r["kind"]), NetworkContext: str(r["network_context"]), SeamID: str(r["seam_id"]),
			RTTms: asFloat(r["rtt_ms"]), LossPct: asFloat(r["loss_pct"]),
			Transformation: str(r["transformation"]), CandidateRef: str(r["candidate_ref"]),
			EvidenceRef: str(r["evidence_ref"]), ObservedAt: parseCHTime(r["observed_at"]),
			TenantID: str(r["tenant_id"]), DataClass: str(r["data_class"]),
		})
	}
	return out, nil
}

// PurgeRun — (tenant, scenario/run) keyed cleanup across both stores (§1).
func (s *pgchPathGraphStore) PurgeRun(ctx context.Context, tenant, scenarioID, runID string) error {
	if scenarioID == "" && runID == "" {
		return errors.New("purge requires a scenario_id or run_id (§1: never a name/IP pattern)")
	}
	if (scenarioID != "" && !isPathToken(scenarioID)) || (runID != "" && !isPathToken(runID)) {
		return errors.New("invalid scenario_id/run_id")
	}
	t := normTenant(tenant)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := s.db.withTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		for _, tbl := range []string{"path_endpoints", "path_definitions"} {
			if _, err := tx.Exec(ctx, "DELETE FROM "+tbl+
				" WHERE ($1 = '' OR scenario_id = $1) AND ($2 = '' OR run_id = $2)", scenarioID, runID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	// ClickHouse: a lightweight DELETE keyed on tenant + scenario/run, nothing else.
	where := "tenant_id = '" + t + "'"
	if scenarioID != "" {
		where += " AND scenario_id = '" + scenarioID + "'"
	}
	if runID != "" {
		where += " AND run_id = '" + runID + "'"
	}
	base := envOr("CLICKHOUSE_URL", "")
	if base == "" {
		return nil
	}
	if msg := chExecErr(base, "DELETE FROM netops.path_observations WHERE "+where); msg != "" {
		return errors.New(msg)
	}
	// path_hops carries no scenario/run of its own (it is a child of the run) — it is
	// purged by observation_id, resolved from the same keyed predicate.
	if msg := chExecErr(base, "DELETE FROM netops.path_hops WHERE tenant_id = '"+t+
		"' AND observation_id IN (SELECT observation_id FROM netops.path_observations WHERE "+where+")"); msg != "" {
		return errors.New(msg)
	}
	return nil
}

// ── ClickHouse helpers ───────────────────────────────────────────────────────

// chInsertJSON writes rows to a ClickHouse table as JSONEachRow. Table names come
// only from this file's constants — never from user input.
func chInsertJSON(ctx context.Context, table string, rows []map[string]any) error {
	base := envOr("CLICKHOUSE_URL", "")
	if base == "" {
		return errors.New("CLICKHOUSE_URL not configured")
	}
	var b strings.Builder
	b.WriteString("INSERT INTO " + table + " FORMAT JSONEachRow\n")
	for _, r := range rows {
		line, err := json.Marshal(r)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	_ = ctx // chExecErr uses its own bounded client + timeout
	if msg := chExecErr(base, b.String()); msg != "" {
		return errors.New(msg)
	}
	return nil
}

// chScopeFor maps a (tenant, cross) principal to the ClickHouse tenant_scope
// setting the row policies enforce on. Fails CLOSED: an empty, non-cross tenant
// sees '__none__' rather than everything.
func chScopeFor(tenant string, cross bool) string {
	if cross {
		return "__all__"
	}
	t := normTenant(tenant)
	if t == "" {
		return "__none__"
	}
	return t
}

func chTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05.000") }

func chStringList(vals []string) string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if isPathToken(v) {
			out = append(out, "'"+v+"'")
		}
	}
	if len(out) == 0 {
		return "''" // fail closed: an unrecognised class matches nothing
	}
	return strings.Join(out, ",")
}

// isPathToken allowlists an identifier before it is interpolated into ClickHouse
// SQL (SR-011 discipline: shape-validate, never quote-escape).
func isPathToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == ':'
		if !ok {
			return false
		}
	}
	return true
}

// isAddressToken allowlists an IPv4/IPv6 literal for the same purpose.
func isAddressToken(s string) bool {
	if s == "" || len(s) > 45 {
		return false
	}
	for _, c := range s {
		ok := c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '.' || c == ':'
		if !ok {
			return false
		}
	}
	return true
}

func asInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case string:
		i, err := strconv.Atoi(n)
		if err != nil {
			return 0
		}
		return i
	}
	return 0
}

func dataClassOrDefault(c, def string) string {
	if c == "" {
		return def
	}
	return c
}

var _ pathGraphStore = (*memPathGraphStore)(nil)
var _ pathGraphStore = (*pgchPathGraphStore)(nil)
