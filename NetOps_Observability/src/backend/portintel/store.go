package portintel

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// store.go — the tenant-scoped repository for Port Intelligence (#94 P5).
// Reads/writes the 0019 relational current-state tables. Same seam pattern as
// topologyGraphStore: in-memory store filters by tenant; pg store relies on the
// tenant_iso FORCE-RLS policy via the injected DB's WithTenant (CLAUDE.md §3a).
// The collector router (real hardware) is the writer via UpsertPort/
// UpsertTransceiver/…; the API handlers are the readers.
//
// The package does not know how the platform opens or scopes its database —
// package main adapts its pg plumbing to the DB seam at the composition root
// (the internal/vault Store idiom). Backend selection (pg vs in-memory) is
// wiring and stays in package main too.

// DB is the injected relational seam: run fn inside a transaction whose
// row-level security is scoped to tenant (or unscoped for a cross-tenant
// principal). Implemented by package main's pgDB adapter.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// PortRow is the flattened port + transceiver + health view the workbench table
// and detail drawer consume. Identity fields (serial/part) are RELATIONAL here,
// never TSDB labels (cardinality law).
type PortRow struct {
	TenantID    string `json:"-"`
	DeviceID    string `json:"device"`
	PortID      string `json:"port_id"`
	IfName      string `json:"port_name"`
	IfAlias     string `json:"if_alias"`
	AdminStatus string `json:"admin_status"`
	OperStatus  string `json:"oper_status"`
	SpeedBps    int64  `json:"speed_bps"`
	Role        string `json:"role"`
	Seam        string `json:"seam"`
	LagID       string `json:"lag_id,omitempty"`
	BreakoutGrp string `json:"breakout_group_id,omitempty"`
	// transceiver join
	FormFactor   string `json:"form_factor,omitempty"`
	MediaType    string `json:"media_type,omitempty"`
	VendorName   string `json:"vendor_name,omitempty"`
	PartNumber   string `json:"part_number,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	Supported    string `json:"supported_status,omitempty"`
	// health join
	HealthScore   int    `json:"health"`
	HealthState   string `json:"health_state"`
	DominantIssue string `json:"dominant_issue,omitempty"`
	MatchedSig    string `json:"matched_signature,omitempty"`
	LastChange    string `json:"last_change,omitempty"`
}

// PortFilter is the server-side filter set (owner spec — subset wired now).
type PortFilter struct {
	Device      string
	Seam        string
	Role        string
	MediaType   string
	FormFactor  string
	Supported   string
	OperStatus  string
	RCAAttached bool
	// paging
	Limit  int
	Offset int
}

// PathContext is the physical-layer resolution of one incident endpoint (#94
// P7): the port itself + its fiber path (panel/cassette/circuit A↔Z) + the
// discovered neighbor. RCA uses it to point an incident at the exact optic /
// strand / cross-connect instead of just "device X".
type PathContext struct {
	Port      *PortRow `json:"port,omitempty"`
	Resolved  bool     `json:"resolved"`
	Circuit   string   `json:"circuit_id,omitempty"`
	Provider  string   `json:"provider,omitempty"`
	PanelID   string   `json:"panel_id,omitempty"`
	Cassette  string   `json:"cassette_id,omitempty"`
	Polarity  string   `json:"polarity_method,omitempty"`
	FarDevice string   `json:"far_device_id,omitempty"`
	FarPort   string   `json:"far_port_id,omitempty"`
	Neighbor  string   `json:"lldp_remote_system_name,omitempty"`
}

// Store is the Port Intelligence repository seam (was package main's
// portStore). The collector router writes; the API handlers read.
type Store interface {
	ListPorts(ctx context.Context, tenant string, cross bool, f PortFilter) ([]PortRow, int, error)
	GetPort(ctx context.Context, tenant string, cross bool, deviceID, portID string) (*PortRow, bool, error)
	ResolvePath(ctx context.Context, tenant string, cross bool, deviceID, portID string) (*PathContext, error)
	UpsertPort(ctx context.Context, r PortRow) error
	UpsertHealth(ctx context.Context, tenant, deviceID, portID string, score int, state, dominant, sig string) error
	UpsertFiberPath(ctx context.Context, tenant string, fp FiberPath) error
	UpsertNeighbor(ctx context.Context, tenant, deviceID, portID, remoteSys, remotePort string) error
}

// FiberPath is the writer shape for fiber_path_inventory (subset used by the
// resolver; the full lossless record rides JSONB via the collector router).
type FiberPath struct {
	PathID   string
	ADevice  string
	APort    string
	ZDevice  string
	ZPort    string
	Circuit  string
	Provider string
	Polarity string
	PanelID  string
	Cassette string
}

// NewMemStore returns the in-memory reference implementation (used when no
// relational backend is configured, and by tests).
func NewMemStore() *MemStore {
	return &MemStore{ports: map[string]PortRow{}, paths: map[string]FiberPath{}, neighbors: map[string][2]string{}}
}

// NewPGStore returns the Postgres-backed implementation over the injected DB.
func NewPGStore(db DB) Store { return &pgPortStore{db: db} }

// matchPort is the shared predicate (both backends filter with it after the
// tenant scope is applied — pg by RLS + WHERE, mem in Go).
func matchPort(r PortRow, f PortFilter) bool {
	if f.Device != "" && !strings.EqualFold(r.DeviceID, f.Device) {
		return false
	}
	if f.Seam != "" && !strings.EqualFold(r.Seam, f.Seam) {
		return false
	}
	if f.Role != "" && !strings.EqualFold(r.Role, f.Role) {
		return false
	}
	if f.MediaType != "" && !strings.EqualFold(r.MediaType, f.MediaType) {
		return false
	}
	if f.FormFactor != "" && !strings.EqualFold(r.FormFactor, f.FormFactor) {
		return false
	}
	if f.Supported != "" && !strings.EqualFold(r.Supported, f.Supported) {
		return false
	}
	if f.OperStatus != "" && !strings.EqualFold(r.OperStatus, f.OperStatus) {
		return false
	}
	if f.RCAAttached && r.MatchedSig == "" {
		return false
	}
	return true
}

// ── in-memory backend ──────────────────────────────────────────────────────

type MemStore struct {
	mu        sync.RWMutex
	ports     map[string]PortRow   // key: tenant|device|port
	paths     map[string]FiberPath // key: tenant|pathid
	neighbors map[string][2]string // key: tenant|device|port → [remoteSys, remotePort]
}

func portKey(tenant, device, port string) string { return tenant + "|" + device + "|" + port }

func (m *MemStore) visible(tenant string, cross bool, r PortRow) bool {
	return cross || r.TenantID == tenant
}

func (m *MemStore) ListPorts(_ context.Context, tenant string, cross bool, f PortFilter) ([]PortRow, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var all []PortRow
	for _, r := range m.ports {
		if m.visible(tenant, cross, r) && matchPort(r, f) {
			all = append(all, r)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].DeviceID != all[j].DeviceID {
			return all[i].DeviceID < all[j].DeviceID
		}
		return all[i].IfName < all[j].IfName
	})
	total := len(all)
	lo := f.Offset
	if lo > total {
		lo = total
	}
	hi := total
	if f.Limit > 0 && lo+f.Limit < hi {
		hi = lo + f.Limit
	}
	return all[lo:hi], total, nil
}

func (m *MemStore) GetPort(_ context.Context, tenant string, cross bool, deviceID, portID string) (*PortRow, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.ports[portKey(tenantOrScan(m, tenant, cross, deviceID, portID), deviceID, portID)]
	if !ok {
		// cross reader: scan (tenant unknown in the key).
		for _, rr := range m.ports {
			if rr.DeviceID == deviceID && rr.PortID == portID && m.visible(tenant, cross, rr) {
				cp := rr
				return &cp, true, nil
			}
		}
		return nil, false, nil
	}
	if !m.visible(tenant, cross, r) {
		return nil, false, nil // foreign → 404, never reveal
	}
	cp := r
	return &cp, true, nil
}

// tenantOrScan returns the direct key tenant for a non-cross caller (fast path).
func tenantOrScan(_ *MemStore, tenant string, cross bool, _, _ string) string {
	if cross {
		return ""
	}
	return tenant
}

func (m *MemStore) UpsertPort(_ context.Context, r PortRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ports[portKey(r.TenantID, r.DeviceID, r.PortID)] = r
	return nil
}

func (m *MemStore) UpsertHealth(_ context.Context, tenant, deviceID, portID string, score int, state, dominant, sig string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := portKey(tenant, deviceID, portID)
	r := m.ports[k]
	r.TenantID, r.DeviceID, r.PortID = tenant, deviceID, portID
	r.HealthScore, r.HealthState, r.DominantIssue, r.MatchedSig = score, state, dominant, sig
	m.ports[k] = r
	return nil
}

func (m *MemStore) UpsertFiberPath(_ context.Context, tenant string, fp FiberPath) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.paths == nil {
		m.paths = map[string]FiberPath{}
	}
	m.paths[tenant+"|"+fp.PathID] = fp
	return nil
}

func (m *MemStore) UpsertNeighbor(_ context.Context, tenant, deviceID, portID, remoteSys, remotePort string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.neighbors == nil {
		m.neighbors = map[string][2]string{}
	}
	m.neighbors[portKey(tenant, deviceID, portID)] = [2]string{remoteSys, remotePort}
	return nil
}

func (m *MemStore) ResolvePath(_ context.Context, tenant string, cross bool, deviceID, portID string) (*PathContext, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	pc := &PathContext{}
	// Port (tenant-scoped).
	for _, r := range m.ports {
		if r.DeviceID == deviceID && r.PortID == portID && (cross || r.TenantID == tenant) {
			cp := r
			pc.Port = &cp
			break
		}
	}
	// Fiber path whose A or Z endpoint matches this port (tenant-scoped).
	for k, fp := range m.paths {
		if !cross && !strings.HasPrefix(k, tenant+"|") {
			continue
		}
		aMatch := fp.ADevice == deviceID && fp.APort == portID
		zMatch := fp.ZDevice == deviceID && fp.ZPort == portID
		if aMatch || zMatch {
			pc.Resolved = true
			pc.Circuit, pc.Provider, pc.PanelID, pc.Cassette, pc.Polarity = fp.Circuit, fp.Provider, fp.PanelID, fp.Cassette, fp.Polarity
			if aMatch {
				pc.FarDevice, pc.FarPort = fp.ZDevice, fp.ZPort
			} else {
				pc.FarDevice, pc.FarPort = fp.ADevice, fp.APort
			}
			break
		}
	}
	// Neighbor (tenant-scoped).
	if n, ok := m.neighbors[portKey(tenant, deviceID, portID)]; ok {
		pc.Neighbor = n[0]
		pc.Resolved = true
	} else if cross {
		for k, n := range m.neighbors {
			if strings.HasSuffix(k, "|"+deviceID+"|"+portID) {
				pc.Neighbor = n[0]
				pc.Resolved = true
				break
			}
		}
	}
	return pc, nil
}

// ── Postgres backend ─────────────────────────────────────────────────────────

type pgPortStore struct{ db DB }

func (s *pgPortStore) ListPorts(ctx context.Context, tenant string, cross bool, f PortFilter) ([]PortRow, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out []PortRow
	total := 0
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		// RLS scopes rows to the tenant; the LEFT JOINs bring in transceiver +
		// health. Filtering is applied in Go via matchPort for parity with mem.
		rows, err := tx.Query(ctx, `
			SELECT p.tenant_id, p.device_id, p.port_id, p.if_name, p.if_alias,
			       p.admin_status, p.oper_status, p.speed_bps, p.role, p.seam,
			       p.lag_id, p.breakout_group, coalesce(t.form_factor,''),
			       coalesce(t.media_type,''), coalesce(t.vendor_name,''),
			       coalesce(t.part_number,''), coalesce(t.serial_number,''),
			       coalesce(t.supported_status,''), coalesce(h.health_score,100),
			       coalesce(h.health_state,'ok'), coalesce(h.dominant_issue,''),
			       coalesce(h.matched_signature,'')
			  FROM port_inventory_current p
			  LEFT JOIN transceiver_inventory_current t
			         ON t.tenant_id=p.tenant_id AND t.device_id=p.device_id AND t.port_id=p.port_id
			  LEFT JOIN port_health_current h
			         ON h.tenant_id=p.tenant_id AND h.device_id=p.device_id AND h.port_id=p.port_id
			 ORDER BY p.device_id, p.if_name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r PortRow
			if err := rows.Scan(&r.TenantID, &r.DeviceID, &r.PortID, &r.IfName, &r.IfAlias,
				&r.AdminStatus, &r.OperStatus, &r.SpeedBps, &r.Role, &r.Seam,
				&r.LagID, &r.BreakoutGrp, &r.FormFactor, &r.MediaType, &r.VendorName,
				&r.PartNumber, &r.SerialNumber, &r.Supported, &r.HealthScore,
				&r.HealthState, &r.DominantIssue, &r.MatchedSig); err != nil {
				return err
			}
			if matchPort(r, f) {
				out = append(out, r)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	total = len(out)
	lo := f.Offset
	if lo > total {
		lo = total
	}
	hi := total
	if f.Limit > 0 && lo+f.Limit < hi {
		hi = lo + f.Limit
	}
	return out[lo:hi], total, nil
}

func (s *pgPortStore) GetPort(ctx context.Context, tenant string, cross bool, deviceID, portID string) (*PortRow, bool, error) {
	f := PortFilter{Device: deviceID}
	rows, _, err := s.ListPorts(ctx, tenant, cross, f)
	if err != nil {
		return nil, false, err
	}
	for i := range rows {
		if rows[i].PortID == portID {
			return &rows[i], true, nil
		}
	}
	return nil, false, nil
}

func (s *pgPortStore) UpsertPort(ctx context.Context, r PortRow) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	data, _ := json.Marshal(r)
	return s.db.WithTenant(ctx, r.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO port_inventory_current
			  (tenant_id, device_id, port_id, if_name, if_alias, admin_status,
			   oper_status, speed_bps, role, seam, lag_id, breakout_group, last_seen, data)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, now(), $13)
			ON CONFLICT (tenant_id, device_id, port_id) DO UPDATE SET
			  if_name=EXCLUDED.if_name, if_alias=EXCLUDED.if_alias,
			  admin_status=EXCLUDED.admin_status, oper_status=EXCLUDED.oper_status,
			  speed_bps=EXCLUDED.speed_bps, role=EXCLUDED.role, seam=EXCLUDED.seam,
			  lag_id=EXCLUDED.lag_id, breakout_group=EXCLUDED.breakout_group,
			  last_seen=now(), data=EXCLUDED.data`,
			r.TenantID, r.DeviceID, r.PortID, r.IfName, r.IfAlias, r.AdminStatus,
			r.OperStatus, r.SpeedBps, r.Role, r.Seam, r.LagID, r.BreakoutGrp, data)
		return err
	})
}

func (s *pgPortStore) ResolvePath(ctx context.Context, tenant string, cross bool, deviceID, portID string) (*PathContext, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pc := &PathContext{}
	if row, ok, err := s.GetPort(ctx, tenant, cross, deviceID, portID); err == nil && ok {
		pc.Port = row
	}
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		// Fiber path where this port is the A or Z endpoint (RLS-scoped).
		var aDev, aPort, zDev, zPort string
		e := tx.QueryRow(ctx, `
			SELECT circuit_id, provider, panel_id, cassette_id, polarity_method,
			       a_device_id, a_port_id, z_device_id, z_port_id
			  FROM fiber_path_inventory
			 WHERE (a_device_id=$1 AND a_port_id=$2) OR (z_device_id=$1 AND z_port_id=$2)
			 LIMIT 1`, deviceID, portID).Scan(&pc.Circuit, &pc.Provider, &pc.PanelID, &pc.Cassette,
			&pc.Polarity, &aDev, &aPort, &zDev, &zPort)
		if e == nil {
			pc.Resolved = true
			if aDev == deviceID && aPort == portID {
				pc.FarDevice, pc.FarPort = zDev, zPort
			} else {
				pc.FarDevice, pc.FarPort = aDev, aPort
			}
		}
		// Neighbor.
		var nsys string
		if e := tx.QueryRow(ctx, `SELECT remote_system_name FROM port_neighbor_current WHERE device_id=$1 AND port_id=$2 LIMIT 1`,
			deviceID, portID).Scan(&nsys); e == nil && nsys != "" {
			pc.Neighbor = nsys
			pc.Resolved = true
		}
		return nil
	})
	return pc, err
}

func (s *pgPortStore) UpsertFiberPath(ctx context.Context, tenant string, fp FiberPath) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO fiber_path_inventory
			  (tenant_id, path_id, a_device_id, a_port_id, z_device_id, z_port_id,
			   circuit_id, provider, polarity_method, panel_id, cassette_id, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, now())
			ON CONFLICT (tenant_id, path_id) DO UPDATE SET
			  a_device_id=EXCLUDED.a_device_id, a_port_id=EXCLUDED.a_port_id,
			  z_device_id=EXCLUDED.z_device_id, z_port_id=EXCLUDED.z_port_id,
			  circuit_id=EXCLUDED.circuit_id, provider=EXCLUDED.provider,
			  polarity_method=EXCLUDED.polarity_method, panel_id=EXCLUDED.panel_id,
			  cassette_id=EXCLUDED.cassette_id, updated_at=now()`,
			tenant, fp.PathID, fp.ADevice, fp.APort, fp.ZDevice, fp.ZPort,
			fp.Circuit, fp.Provider, fp.Polarity, fp.PanelID, fp.Cassette)
		return err
	})
}

func (s *pgPortStore) UpsertNeighbor(ctx context.Context, tenant, deviceID, portID, remoteSys, remotePort string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO port_neighbor_current
			  (tenant_id, device_id, port_id, remote_system_name, remote_port_id, last_seen)
			VALUES ($1,$2,$3,$4,$5, now())
			ON CONFLICT (tenant_id, device_id, port_id) DO UPDATE SET
			  remote_system_name=EXCLUDED.remote_system_name,
			  remote_port_id=EXCLUDED.remote_port_id, last_seen=now()`,
			tenant, deviceID, portID, remoteSys, remotePort)
		return err
	})
}

func (s *pgPortStore) UpsertHealth(ctx context.Context, tenant, deviceID, portID string, score int, state, dominant, sig string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO port_health_current
			  (tenant_id, device_id, port_id, health_score, health_state, dominant_issue, matched_signature, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7, now())
			ON CONFLICT (tenant_id, device_id, port_id) DO UPDATE SET
			  health_score=EXCLUDED.health_score, health_state=EXCLUDED.health_state,
			  dominant_issue=EXCLUDED.dominant_issue, matched_signature=EXCLUDED.matched_signature,
			  updated_at=now()`,
			tenant, deviceID, portID, score, state, dominant, sig)
		return err
	})
}
