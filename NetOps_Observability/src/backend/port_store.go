package main

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// port_store.go — the tenant-scoped repository for Port Intelligence (#94 P5).
// Reads/writes the 0019 relational current-state tables. Same seam pattern as
// topologyGraphStore: in-memory store filters by tenant; pg store relies on the
// tenant_iso FORCE-RLS policy via withTenant (CLAUDE.md §3a). The collector
// router (real hardware) is the writer via UpsertPort/UpsertTransceiver/…; the
// API handlers are the readers.

// PortRow is the flattened port + transceiver + health view the workbench table
// and detail drawer consume. Identity fields (serial/part) are RELATIONAL here,
// never TSDB labels (cardinality law).
type PortRow struct {
	TenantID     string `json:"-"`
	DeviceID     string `json:"device"`
	PortID       string `json:"port_id"`
	IfName       string `json:"port_name"`
	IfAlias      string `json:"if_alias"`
	AdminStatus  string `json:"admin_status"`
	OperStatus   string `json:"oper_status"`
	SpeedBps     int64  `json:"speed_bps"`
	Role         string `json:"role"`
	Seam         string `json:"seam"`
	LagID        string `json:"lag_id,omitempty"`
	BreakoutGrp  string `json:"breakout_group_id,omitempty"`
	// transceiver join
	FormFactor   string `json:"form_factor,omitempty"`
	MediaType    string `json:"media_type,omitempty"`
	VendorName   string `json:"vendor_name,omitempty"`
	PartNumber   string `json:"part_number,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	Supported    string `json:"supported_status,omitempty"`
	// health join
	HealthScore  int    `json:"health"`
	HealthState  string `json:"health_state"`
	DominantIssue string `json:"dominant_issue,omitempty"`
	MatchedSig   string `json:"matched_signature,omitempty"`
	LastChange   string `json:"last_change,omitempty"`
}

// PortFilter is the server-side filter set (owner spec — subset wired now).
type PortFilter struct {
	Device       string
	Seam         string
	Role         string
	MediaType    string
	FormFactor   string
	Supported    string
	OperStatus   string
	RCAAttached  bool
	// paging
	Limit  int
	Offset int
}

type portStore interface {
	ListPorts(ctx context.Context, tenant string, cross bool, f PortFilter) ([]PortRow, int, error)
	GetPort(ctx context.Context, tenant string, cross bool, deviceID, portID string) (*PortRow, bool, error)
	UpsertPort(ctx context.Context, r PortRow) error
	UpsertHealth(ctx context.Context, tenant, deviceID, portID string, score int, state, dominant, sig string) error
}

func newPortStore() portStore {
	if ps, ok := backend.(*pgStore); ok {
		return &pgPortStore{db: ps.db}
	}
	return &memPortStore{ports: map[string]PortRow{}}
}

// applyFilter is the shared predicate (both backends filter with it after the
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

type memPortStore struct {
	mu    sync.RWMutex
	ports map[string]PortRow // key: tenant|device|port
}

func portKey(tenant, device, port string) string { return tenant + "|" + device + "|" + port }

func (m *memPortStore) visible(tenant string, cross bool, r PortRow) bool {
	return cross || r.TenantID == tenant
}

func (m *memPortStore) ListPorts(_ context.Context, tenant string, cross bool, f PortFilter) ([]PortRow, int, error) {
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

func (m *memPortStore) GetPort(_ context.Context, tenant string, cross bool, deviceID, portID string) (*PortRow, bool, error) {
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
func tenantOrScan(_ *memPortStore, tenant string, cross bool, _, _ string) string {
	if cross {
		return ""
	}
	return tenant
}

func (m *memPortStore) UpsertPort(_ context.Context, r PortRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ports[portKey(r.TenantID, r.DeviceID, r.PortID)] = r
	return nil
}

func (m *memPortStore) UpsertHealth(_ context.Context, tenant, deviceID, portID string, score int, state, dominant, sig string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := portKey(tenant, deviceID, portID)
	r := m.ports[k]
	r.TenantID, r.DeviceID, r.PortID = tenant, deviceID, portID
	r.HealthScore, r.HealthState, r.DominantIssue, r.MatchedSig = score, state, dominant, sig
	m.ports[k] = r
	return nil
}

// ── Postgres backend ─────────────────────────────────────────────────────────

type pgPortStore struct{ db *pgDB }

func (s *pgPortStore) ListPorts(ctx context.Context, tenant string, cross bool, f PortFilter) ([]PortRow, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out []PortRow
	total := 0
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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
	return s.db.withTenant(ctx, r.TenantID, false, func(tx pgx.Tx) error {
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

func (s *pgPortStore) UpsertHealth(ctx context.Context, tenant, deviceID, portID string, score int, state, dominant, sig string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.db.withTenant(ctx, tenant, false, func(tx pgx.Tx) error {
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
