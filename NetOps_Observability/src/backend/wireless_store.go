package main

// wireless_store.go — persistence for the wireless canonical inventory
// (tracker #128 Phase 1, migration 0030). Two backends behind one interface
// (the nms_store.go convention): memWirelessStore for the file/dev backend +
// tests, pgWirelessStore for production. Isolation is enforced IN the store
// (§3a): every read is scoped by the caller's tenant — PG via the FORCE-RLS
// withTenant transaction, mem via tenant-keyed maps. There is no unscoped
// "list all".
//
// Writers are platform-side (vendor connectors, Phase 2); the HTTP surface
// (wireless_http.go) is read-only. Upserts preserve first_seen and advance
// last_seen (the topology_nodes honesty pattern); a row that stops being
// observed is marked stale by the reconciler, never silently deleted.

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/wireless"
)

type wirelessStore interface {
	UpsertController(ctx context.Context, c wireless.Controller) error
	ListControllers(ctx context.Context, tenant string, cross bool) ([]wireless.Controller, error)
	GetController(ctx context.Context, tenant string, cross bool, id string) (wireless.Controller, bool, error)

	UpsertAP(ctx context.Context, ap wireless.AccessPoint) error
	ListAPs(ctx context.Context, tenant string, cross bool) ([]wireless.AccessPoint, error)
	GetAP(ctx context.Context, tenant string, cross bool, id string) (wireless.AccessPoint, bool, error)

	UpsertWLAN(ctx context.Context, wl wireless.WLAN) error
	ListWLANs(ctx context.Context, tenant string, cross bool) ([]wireless.WLAN, error)

	UpsertBSSID(ctx context.Context, b wireless.BSSID) error
	ListBSSIDs(ctx context.Context, tenant string, cross bool) ([]wireless.BSSID, error)
}

// ── in-memory backend (file/dev + tests) ────────────────────────────────────

type memWirelessStore struct {
	mu          sync.RWMutex
	controllers map[string]map[string]wireless.Controller // tenant → id → row
	aps         map[string]map[string]wireless.AccessPoint
	wlans       map[string]map[string]wireless.WLAN
	bssids      map[string]map[string]wireless.BSSID
}

func newMemWirelessStore() *memWirelessStore {
	return &memWirelessStore{
		controllers: map[string]map[string]wireless.Controller{},
		aps:         map[string]map[string]wireless.AccessPoint{},
		wlans:       map[string]map[string]wireless.WLAN{},
		bssids:      map[string]map[string]wireless.BSSID{},
	}
}

// upsertTimes preserves first_seen across re-observation and stamps last_seen.
func upsertTimes(prevFirst time.Time, hadPrev bool) (first, last time.Time) {
	now := time.Now().UTC()
	if hadPrev && !prevFirst.IsZero() {
		return prevFirst, now
	}
	return now, now
}

func (m *memWirelessStore) UpsertController(_ context.Context, c wireless.Controller) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.controllers[c.TenantID]
	if t == nil {
		t = map[string]wireless.Controller{}
		m.controllers[c.TenantID] = t
	}
	prev, had := t[c.ControllerID]
	c.FirstSeen, c.LastSeen = upsertTimes(prev.FirstSeen, had)
	c.Stale = false
	t[c.ControllerID] = c
	return nil
}

func (m *memWirelessStore) ListControllers(_ context.Context, tenant string, cross bool) ([]wireless.Controller, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []wireless.Controller
	for tid, rows := range m.controllers {
		if !cross && tid != tenant {
			continue
		}
		for _, c := range rows {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ControllerID < out[j].ControllerID })
	return out, nil
}

func (m *memWirelessStore) GetController(_ context.Context, tenant string, cross bool, id string) (wireless.Controller, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for tid, rows := range m.controllers {
		if !cross && tid != tenant {
			continue
		}
		if c, ok := rows[id]; ok {
			return c, true, nil
		}
	}
	return wireless.Controller{}, false, nil
}

func (m *memWirelessStore) UpsertAP(_ context.Context, ap wireless.AccessPoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.aps[ap.TenantID]
	if t == nil {
		t = map[string]wireless.AccessPoint{}
		m.aps[ap.TenantID] = t
	}
	prev, had := t[ap.APID]
	ap.FirstSeen, ap.LastSeen = upsertTimes(prev.FirstSeen, had)
	ap.Stale = false
	t[ap.APID] = ap
	return nil
}

func (m *memWirelessStore) ListAPs(_ context.Context, tenant string, cross bool) ([]wireless.AccessPoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []wireless.AccessPoint
	for tid, rows := range m.aps {
		if !cross && tid != tenant {
			continue
		}
		for _, ap := range rows {
			out = append(out, ap)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].APID < out[j].APID })
	return out, nil
}

func (m *memWirelessStore) GetAP(_ context.Context, tenant string, cross bool, id string) (wireless.AccessPoint, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for tid, rows := range m.aps {
		if !cross && tid != tenant {
			continue
		}
		if ap, ok := rows[id]; ok {
			return ap, true, nil
		}
	}
	return wireless.AccessPoint{}, false, nil
}

func (m *memWirelessStore) UpsertWLAN(_ context.Context, wl wireless.WLAN) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.wlans[wl.TenantID]
	if t == nil {
		t = map[string]wireless.WLAN{}
		m.wlans[wl.TenantID] = t
	}
	prev, had := t[wl.WLANID]
	wl.FirstSeen, wl.LastSeen = upsertTimes(prev.FirstSeen, had)
	wl.Stale = false
	t[wl.WLANID] = wl
	return nil
}

func (m *memWirelessStore) ListWLANs(_ context.Context, tenant string, cross bool) ([]wireless.WLAN, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []wireless.WLAN
	for tid, rows := range m.wlans {
		if !cross && tid != tenant {
			continue
		}
		for _, wl := range rows {
			out = append(out, wl)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WLANID < out[j].WLANID })
	return out, nil
}

func (m *memWirelessStore) UpsertBSSID(_ context.Context, b wireless.BSSID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.bssids[b.TenantID]
	if t == nil {
		t = map[string]wireless.BSSID{}
		m.bssids[b.TenantID] = t
	}
	prev, had := t[b.BSSID]
	b.FirstSeen, b.LastSeen = upsertTimes(prev.FirstSeen, had)
	b.Stale = false
	t[b.BSSID] = b
	return nil
}

func (m *memWirelessStore) ListBSSIDs(_ context.Context, tenant string, cross bool) ([]wireless.BSSID, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []wireless.BSSID
	for tid, rows := range m.bssids {
		if !cross && tid != tenant {
			continue
		}
		for _, b := range rows {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BSSID < out[j].BSSID })
	return out, nil
}

// ── Postgres backend (tenant_iso FORCE-RLS via withTenant, migration 0030) ──

type pgWirelessStore struct{ db *pgDB }

func newPGWirelessStore(db *pgDB) *pgWirelessStore { return &pgWirelessStore{db: db} }

func jsonBlob(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil || b == nil {
		return []byte("{}")
	}
	return b
}

func (p *pgWirelessStore) UpsertController(ctx context.Context, c wireless.Controller) error {
	return p.db.withTenant(ctx, c.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO wireless_controllers (tenant_id, controller_id, name, vendor, model, os_version,
    kind, cluster_role, management_address, forwarding_default, visibility, data, last_seen, stale)
VALUES ($1,$2,$3,$4,$5,$6,COALESCE(NULLIF($7,''),'controller'),$8,$9,$10,$11,$12,now(),false)
ON CONFLICT (tenant_id, controller_id) DO UPDATE SET
    name=EXCLUDED.name, vendor=EXCLUDED.vendor, model=EXCLUDED.model,
    os_version=EXCLUDED.os_version, kind=EXCLUDED.kind, cluster_role=EXCLUDED.cluster_role,
    management_address=EXCLUDED.management_address, forwarding_default=EXCLUDED.forwarding_default,
    visibility=EXCLUDED.visibility, data=EXCLUDED.data, last_seen=now(), stale=false`,
			c.TenantID, c.ControllerID, c.Name, c.Vendor, c.Model, c.OSVersion,
			c.Kind, string(c.ClusterRole), c.ManagementAddress,
			fwdOrUnknown(c.ForwardingDefault), orPartial(c.Visibility), jsonBlob(c))
		if err != nil {
			return err
		}
		for _, mb := range c.Members {
			if _, err := tx.Exec(ctx, `
INSERT INTO wireless_controller_members (tenant_id, member_id, controller_id, name, serial,
    member_state, redundancy_role, ap_capacity, data, last_seen, stale)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),false)
ON CONFLICT (tenant_id, member_id) DO UPDATE SET
    controller_id=EXCLUDED.controller_id, name=EXCLUDED.name, serial=EXCLUDED.serial,
    member_state=EXCLUDED.member_state, redundancy_role=EXCLUDED.redundancy_role,
    ap_capacity=EXCLUDED.ap_capacity, data=EXCLUDED.data, last_seen=now(), stale=false`,
				c.TenantID, mb.MemberID, c.ControllerID, mb.Name, mb.Serial,
				mb.MemberState, mb.RedundancyRole, mb.APCapacity, jsonBlob(mb)); err != nil {
				return err
			}
		}
		return nil
	})
}

// fwdOrUnknown defaults an absent forwarding mode to the honest 'unknown'.
func fwdOrUnknown(f wireless.ForwardingMode) string {
	if f == "" {
		return string(wireless.ForwardUnknown)
	}
	return string(f)
}

func orPartial(v string) string {
	if v == "" {
		return "partial"
	}
	return v
}

func (p *pgWirelessStore) ListControllers(ctx context.Context, tenant string, cross bool) ([]wireless.Controller, error) {
	var out []wireless.Controller
	err := p.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, data, first_seen, last_seen, stale FROM wireless_controllers ORDER BY controller_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanWirelessRow[wireless.Controller](rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// scanWirelessRow rehydrates the lossless JSONB record and overlays the
// store-owned lifecycle columns (first/last_seen, stale) — the columns are the
// truth for lifecycle, the blob for everything else.
type wirelessLifecycle interface {
	wireless.Controller | wireless.AccessPoint | wireless.WLAN | wireless.BSSID
}

func scanWirelessRow[T wirelessLifecycle](rows pgx.Rows) (T, error) {
	var (
		zero      T
		tenantID  string
		blob      []byte
		first     time.Time
		last      time.Time
		staleFlag bool
	)
	if err := rows.Scan(&tenantID, &blob, &first, &last, &staleFlag); err != nil {
		return zero, err
	}
	var v T
	if err := json.Unmarshal(blob, &v); err != nil {
		return zero, err
	}
	switch p := any(&v).(type) {
	case *wireless.Controller:
		p.TenantID, p.FirstSeen, p.LastSeen, p.Stale = tenantID, first, last, staleFlag
	case *wireless.AccessPoint:
		p.TenantID, p.FirstSeen, p.LastSeen, p.Stale = tenantID, first, last, staleFlag
	case *wireless.WLAN:
		p.TenantID, p.FirstSeen, p.LastSeen, p.Stale = tenantID, first, last, staleFlag
	case *wireless.BSSID:
		p.TenantID, p.FirstSeen, p.LastSeen, p.Stale = tenantID, first, last, staleFlag
	}
	return v, nil
}

func (p *pgWirelessStore) GetController(ctx context.Context, tenant string, cross bool, id string) (wireless.Controller, bool, error) {
	var c wireless.Controller
	found := false
	err := p.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, data, first_seen, last_seen, stale FROM wireless_controllers WHERE controller_id = $1`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			if c, err = scanWirelessRow[wireless.Controller](rows); err != nil {
				return err
			}
			found = true
		}
		return rows.Err()
	})
	return c, found, err
}

func (p *pgWirelessStore) UpsertAP(ctx context.Context, ap wireless.AccessPoint) error {
	return p.db.withTenant(ctx, ap.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO access_points (tenant_id, ap_id, name, mac_base, serial, model, vendor,
    controller_ref, site_id, floor_ref, x, y, uplink_switch_ref, uplink_port_ref,
    poe_class, poe_draw_w, mgmt_address, mgmt_vlan, forwarding_mode, data, last_seen, stale)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,now(),false)
ON CONFLICT (tenant_id, ap_id) DO UPDATE SET
    name=EXCLUDED.name, mac_base=EXCLUDED.mac_base, serial=EXCLUDED.serial,
    model=EXCLUDED.model, vendor=EXCLUDED.vendor, controller_ref=EXCLUDED.controller_ref,
    site_id=EXCLUDED.site_id, floor_ref=EXCLUDED.floor_ref, x=EXCLUDED.x, y=EXCLUDED.y,
    uplink_switch_ref=EXCLUDED.uplink_switch_ref, uplink_port_ref=EXCLUDED.uplink_port_ref,
    poe_class=EXCLUDED.poe_class, poe_draw_w=EXCLUDED.poe_draw_w,
    mgmt_address=EXCLUDED.mgmt_address, mgmt_vlan=EXCLUDED.mgmt_vlan,
    forwarding_mode=EXCLUDED.forwarding_mode, data=EXCLUDED.data, last_seen=now(), stale=false`,
			ap.TenantID, ap.APID, ap.Name, ap.MACBase, ap.Serial, ap.Model, ap.Vendor,
			ap.ControllerRef, ap.SiteID, ap.FloorRef, ap.X, ap.Y,
			ap.UplinkSwitchRef, ap.UplinkPortRef, ap.PoEClass, ap.PoEDrawW,
			ap.MgmtAddress, ap.MgmtVLAN, fwdOrUnknown(ap.ForwardingMode), jsonBlob(ap))
		if err != nil {
			return err
		}
		for _, r := range ap.Radios {
			if _, err := tx.Exec(ctx, `
INSERT INTO ap_radios (tenant_id, radio_id, ap_id, slot, band, channel, channel_width_mhz,
    tx_power_dbm, tx_power_max_dbm, admin_state, oper_state, generation, mlo_capable, data, last_seen, stale)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,COALESCE(NULLIF($10,''),'unknown'),COALESCE(NULLIF($11,''),'unknown'),$12,$13,$14,now(),false)
ON CONFLICT (tenant_id, radio_id) DO UPDATE SET
    band=EXCLUDED.band, channel=EXCLUDED.channel, channel_width_mhz=EXCLUDED.channel_width_mhz,
    tx_power_dbm=EXCLUDED.tx_power_dbm, tx_power_max_dbm=EXCLUDED.tx_power_max_dbm,
    admin_state=EXCLUDED.admin_state, oper_state=EXCLUDED.oper_state,
    generation=EXCLUDED.generation, mlo_capable=EXCLUDED.mlo_capable,
    data=EXCLUDED.data, last_seen=now(), stale=false`,
				ap.TenantID, wireless.RadioID(ap.APID, r.Slot), ap.APID, r.Slot, r.Band,
				r.Channel, r.ChannelWidthMHz, r.TxPowerDBm, r.TxPowerMaxDBm,
				r.AdminState, r.OperState, r.Generation, r.MLOCapable, jsonBlob(r)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (p *pgWirelessStore) ListAPs(ctx context.Context, tenant string, cross bool) ([]wireless.AccessPoint, error) {
	var out []wireless.AccessPoint
	err := p.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, data, first_seen, last_seen, stale FROM access_points ORDER BY ap_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			ap, err := scanWirelessRow[wireless.AccessPoint](rows)
			if err != nil {
				return err
			}
			out = append(out, ap)
		}
		return rows.Err()
	})
	return out, err
}

func (p *pgWirelessStore) GetAP(ctx context.Context, tenant string, cross bool, id string) (wireless.AccessPoint, bool, error) {
	var ap wireless.AccessPoint
	found := false
	err := p.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, data, first_seen, last_seen, stale FROM access_points WHERE ap_id = $1`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			if ap, err = scanWirelessRow[wireless.AccessPoint](rows); err != nil {
				return err
			}
			found = true
		}
		return rows.Err()
	})
	return ap, found, err
}

func (p *pgWirelessStore) UpsertWLAN(ctx context.Context, wl wireless.WLAN) error {
	return p.db.withTenant(ctx, wl.TenantID, false, func(tx pgx.Tx) error {
		ssidRef := wl.SSIDRef
		if ssidRef == "" && wl.SSIDName != "" {
			ssidRef = wireless.SSIDID(wl.TenantID, wl.SSIDName)
		}
		if ssidRef != "" {
			if _, err := tx.Exec(ctx, `
INSERT INTO ssids (tenant_id, ssid_id, ssid_name, last_seen, stale)
VALUES ($1,$2,$3,now(),false)
ON CONFLICT (tenant_id, ssid_id) DO UPDATE SET ssid_name=EXCLUDED.ssid_name, last_seen=now(), stale=false`,
				wl.TenantID, ssidRef, wl.SSIDName); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `
INSERT INTO wlans (tenant_id, wlan_id, profile_name, ssid_ref, controller_ref,
    security_mode, auth_method, aaa_ref, vlan_or_pool, forwarding_mode, band_policy,
    mobility_domain_ref, enabled, data, last_seen, stale)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,now(),false)
ON CONFLICT (tenant_id, wlan_id) DO UPDATE SET
    profile_name=EXCLUDED.profile_name, ssid_ref=EXCLUDED.ssid_ref,
    controller_ref=EXCLUDED.controller_ref, security_mode=EXCLUDED.security_mode,
    auth_method=EXCLUDED.auth_method, aaa_ref=EXCLUDED.aaa_ref,
    vlan_or_pool=EXCLUDED.vlan_or_pool, forwarding_mode=EXCLUDED.forwarding_mode,
    band_policy=EXCLUDED.band_policy, mobility_domain_ref=EXCLUDED.mobility_domain_ref,
    enabled=EXCLUDED.enabled, data=EXCLUDED.data, last_seen=now(), stale=false`,
			wl.TenantID, wl.WLANID, wl.ProfileName, ssidRef, wl.ControllerRef,
			wl.SecurityMode, wl.AuthMethod, wl.AAARef, wl.VLANOrPool,
			fwdOrUnknown(wl.ForwardingMode), wl.BandPolicy, wl.MobilityDomainRef,
			wl.Enabled, jsonBlob(wl))
		return err
	})
}

func (p *pgWirelessStore) ListWLANs(ctx context.Context, tenant string, cross bool) ([]wireless.WLAN, error) {
	var out []wireless.WLAN
	err := p.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, data, first_seen, last_seen, stale FROM wlans ORDER BY wlan_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			wl, err := scanWirelessRow[wireless.WLAN](rows)
			if err != nil {
				return err
			}
			out = append(out, wl)
		}
		return rows.Err()
	})
	return out, err
}

func (p *pgWirelessStore) UpsertBSSID(ctx context.Context, b wireless.BSSID) error {
	return p.db.withTenant(ctx, b.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO bssids (tenant_id, bssid, radio_ref, wlan_ref, ap_ref, data, last_seen, stale)
VALUES ($1,$2,$3,$4,$5,$6,now(),false)
ON CONFLICT (tenant_id, bssid) DO UPDATE SET
    radio_ref=EXCLUDED.radio_ref, wlan_ref=EXCLUDED.wlan_ref, ap_ref=EXCLUDED.ap_ref,
    data=EXCLUDED.data, last_seen=now(), stale=false`,
			b.TenantID, b.BSSID, b.RadioRef, b.WLANRef, b.APRef, jsonBlob(b))
		return err
	})
}

func (p *pgWirelessStore) ListBSSIDs(ctx context.Context, tenant string, cross bool) ([]wireless.BSSID, error) {
	var out []wireless.BSSID
	err := p.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, data, first_seen, last_seen, stale FROM bssids ORDER BY bssid`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			b, err := scanWirelessRow[wireless.BSSID](rows)
			if err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}
