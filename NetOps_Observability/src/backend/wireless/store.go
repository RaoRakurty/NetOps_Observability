package wireless

// wireless_store.go — persistence for the wireless canonical inventory
// (tracker #128 Phase 1, migration 0030). Two backends behind one interface
// (the nms_store.go convention): memStore for the file/dev backend +
// tests, pgStore for production. Isolation is enforced IN the store
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
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

type Store interface {
	UpsertController(ctx context.Context, c Controller) error
	ListControllers(ctx context.Context, tenant string, cross bool) ([]Controller, error)
	GetController(ctx context.Context, tenant string, cross bool, id string) (Controller, bool, error)

	UpsertAP(ctx context.Context, ap AccessPoint) error
	ListAPs(ctx context.Context, tenant string, cross bool) ([]AccessPoint, error)
	GetAP(ctx context.Context, tenant string, cross bool, id string) (AccessPoint, bool, error)

	// UpsertRadios upserts radio rows independently of their AP (vendors report
	// radios on a separate stream; a radio poll must not clobber AP fields it
	// did not fetch). Reads overlay radios onto their AP by APID.
	UpsertRadios(ctx context.Context, tenant string, radios []Radio) error

	UpsertWLAN(ctx context.Context, wl WLAN) error
	ListWLANs(ctx context.Context, tenant string, cross bool) ([]WLAN, error)

	UpsertBSSID(ctx context.Context, b BSSID) error
	ListBSSIDs(ctx context.Context, tenant string, cross bool) ([]BSSID, error)
}

// ── in-memory backend (file/dev + tests) ────────────────────────────────────

type memStore struct {
	mu          sync.RWMutex
	controllers map[string]map[string]Controller // tenant → id → row
	aps         map[string]map[string]AccessPoint
	radios      map[string]map[string]Radio // tenant → radio_id → row (overlaid on APs at read)
	wlans       map[string]map[string]WLAN
	bssids      map[string]map[string]BSSID
}

func NewMemStore() *memStore {
	return &memStore{
		controllers: map[string]map[string]Controller{},
		aps:         map[string]map[string]AccessPoint{},
		radios:      map[string]map[string]Radio{},
		wlans:       map[string]map[string]WLAN{},
		bssids:      map[string]map[string]BSSID{},
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

func (m *memStore) UpsertController(_ context.Context, c Controller) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.controllers[c.TenantID]
	if t == nil {
		t = map[string]Controller{}
		m.controllers[c.TenantID] = t
	}
	prev, had := t[c.ControllerID]
	c.FirstSeen, c.LastSeen = upsertTimes(prev.FirstSeen, had)
	c.Stale = false
	t[c.ControllerID] = c
	return nil
}

func (m *memStore) ListControllers(_ context.Context, tenant string, cross bool) ([]Controller, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Controller
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

func (m *memStore) GetController(_ context.Context, tenant string, cross bool, id string) (Controller, bool, error) {
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
	return Controller{}, false, nil
}

func (m *memStore) UpsertAP(_ context.Context, ap AccessPoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.aps[ap.TenantID]
	if t == nil {
		t = map[string]AccessPoint{}
		m.aps[ap.TenantID] = t
	}
	prev, had := t[ap.APID]
	ap.FirstSeen, ap.LastSeen = upsertTimes(prev.FirstSeen, had)
	ap.Stale = false
	t[ap.APID] = ap
	return nil
}

func (m *memStore) UpsertRadios(_ context.Context, tenant string, radios []Radio) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.radios[tenant]
	if t == nil {
		t = map[string]Radio{}
		m.radios[tenant] = t
	}
	for _, r := range radios {
		id := RadioID(r.APID, r.Slot)
		prev, had := t[id]
		r.TenantID = tenant
		r.RadioID = id
		r.FirstSeen, r.LastSeen = upsertTimes(prev.FirstSeen, had)
		r.Stale = false
		t[id] = r
	}
	return nil
}

// overlayRadios merges separately-stored radio rows onto an AP (slot wins over
// any radio embedded at AP-upsert time).
func (m *memStore) overlayRadios(tenant string, ap AccessPoint) AccessPoint {
	rows := m.radios[tenant]
	if len(rows) == 0 {
		return ap
	}
	bySlot := map[int]Radio{}
	for _, r := range ap.Radios {
		bySlot[r.Slot] = r
	}
	for _, r := range rows {
		if r.APID == ap.APID {
			bySlot[r.Slot] = r
		}
	}
	if len(bySlot) == 0 {
		return ap
	}
	merged := make([]Radio, 0, len(bySlot))
	for _, r := range bySlot {
		merged = append(merged, r)
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].Slot < merged[j].Slot })
	ap.Radios = merged
	return ap
}

func (m *memStore) ListAPs(_ context.Context, tenant string, cross bool) ([]AccessPoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []AccessPoint
	for tid, rows := range m.aps {
		if !cross && tid != tenant {
			continue
		}
		for _, ap := range rows {
			out = append(out, m.overlayRadios(tid, ap))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].APID < out[j].APID })
	return out, nil
}

func (m *memStore) GetAP(_ context.Context, tenant string, cross bool, id string) (AccessPoint, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for tid, rows := range m.aps {
		if !cross && tid != tenant {
			continue
		}
		if ap, ok := rows[id]; ok {
			return m.overlayRadios(tid, ap), true, nil
		}
	}
	return AccessPoint{}, false, nil
}

func (m *memStore) UpsertWLAN(_ context.Context, wl WLAN) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.wlans[wl.TenantID]
	if t == nil {
		t = map[string]WLAN{}
		m.wlans[wl.TenantID] = t
	}
	prev, had := t[wl.WLANID]
	wl.FirstSeen, wl.LastSeen = upsertTimes(prev.FirstSeen, had)
	wl.Stale = false
	t[wl.WLANID] = wl
	return nil
}

func (m *memStore) ListWLANs(_ context.Context, tenant string, cross bool) ([]WLAN, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []WLAN
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

func (m *memStore) UpsertBSSID(_ context.Context, b BSSID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.bssids[b.TenantID]
	if t == nil {
		t = map[string]BSSID{}
		m.bssids[b.TenantID] = t
	}
	prev, had := t[b.BSSID]
	b.FirstSeen, b.LastSeen = upsertTimes(prev.FirstSeen, had)
	b.Stale = false
	t[b.BSSID] = b
	return nil
}

func (m *memStore) ListBSSIDs(_ context.Context, tenant string, cross bool) ([]BSSID, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []BSSID
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

// DB is the injected relational seam: run fn inside a transaction whose
// row-level security is scoped to tenant (or unscoped for a cross-tenant
// principal). Implemented by package main's pg adapter — the package owns
// wireless inventory, not how the platform scopes its transactions (the
// portintel.DB idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type pgStore struct{ db DB }

func NewPGStore(db DB) *pgStore { return &pgStore{db: db} }

// jsonBlob encodes the record's full shape for the `data` column. It returns an
// ERROR rather than substituting "{}": swallowing the encode failure wrote a row
// whose data column had silently lost every field the typed columns don't carry,
// and the upsert still reported success (§10). ("b == nil" was unreachable —
// json.Marshal only returns nil alongside an error — so the old
// `err != nil || b == nil` branch was purely the error branch in disguise.)
func jsonBlob(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode wireless record: %w", err)
	}
	return b, nil
}

func (p *pgStore) UpsertController(ctx context.Context, c Controller) error {
	ctlBlob, err := jsonBlob(c)
	if err != nil {
		return err
	}
	return p.db.WithTenant(ctx, c.TenantID, false, func(tx pgx.Tx) error {
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
			fwdOrUnknown(c.ForwardingDefault), orPartial(c.Visibility), ctlBlob)
		if err != nil {
			return err
		}
		for _, mb := range c.Members {
			mbBlob, err := jsonBlob(mb)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
INSERT INTO wireless_controller_members (tenant_id, member_id, controller_id, name, serial,
    member_state, redundancy_role, ap_capacity, data, last_seen, stale)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),false)
ON CONFLICT (tenant_id, member_id) DO UPDATE SET
    controller_id=EXCLUDED.controller_id, name=EXCLUDED.name, serial=EXCLUDED.serial,
    member_state=EXCLUDED.member_state, redundancy_role=EXCLUDED.redundancy_role,
    ap_capacity=EXCLUDED.ap_capacity, data=EXCLUDED.data, last_seen=now(), stale=false`,
				c.TenantID, mb.MemberID, c.ControllerID, mb.Name, mb.Serial,
				mb.MemberState, mb.RedundancyRole, mb.APCapacity, mbBlob); err != nil {
				return err
			}
		}
		return nil
	})
}

// fwdOrUnknown defaults an absent forwarding mode to the honest 'unknown'.
func fwdOrUnknown(f ForwardingMode) string {
	if f == "" {
		return string(ForwardUnknown)
	}
	return string(f)
}

func orPartial(v string) string {
	if v == "" {
		return "partial"
	}
	return v
}

func (p *pgStore) ListControllers(ctx context.Context, tenant string, cross bool) ([]Controller, error) {
	var out []Controller
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, data, first_seen, last_seen, stale FROM wireless_controllers ORDER BY controller_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanRow[Controller](rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// scanRow rehydrates the lossless JSONB record and overlays the
// store-owned lifecycle columns (first/last_seen, stale) — the columns are the
// truth for lifecycle, the blob for everything else.
type lifecycle interface {
	Controller | AccessPoint | WLAN | BSSID
}

func scanRow[T lifecycle](rows pgx.Rows) (T, error) {
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
	case *Controller:
		p.TenantID, p.FirstSeen, p.LastSeen, p.Stale = tenantID, first, last, staleFlag
	case *AccessPoint:
		p.TenantID, p.FirstSeen, p.LastSeen, p.Stale = tenantID, first, last, staleFlag
	case *WLAN:
		p.TenantID, p.FirstSeen, p.LastSeen, p.Stale = tenantID, first, last, staleFlag
	case *BSSID:
		p.TenantID, p.FirstSeen, p.LastSeen, p.Stale = tenantID, first, last, staleFlag
	}
	return v, nil
}

func (p *pgStore) GetController(ctx context.Context, tenant string, cross bool, id string) (Controller, bool, error) {
	var c Controller
	found := false
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, data, first_seen, last_seen, stale FROM wireless_controllers WHERE controller_id = $1`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			if c, err = scanRow[Controller](rows); err != nil {
				return err
			}
			found = true
		}
		return rows.Err()
	})
	return c, found, err
}

func (p *pgStore) UpsertAP(ctx context.Context, ap AccessPoint) error {
	apBlob, err := jsonBlob(ap)
	if err != nil {
		return err
	}
	return p.db.WithTenant(ctx, ap.TenantID, false, func(tx pgx.Tx) error {
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
			ap.MgmtAddress, ap.MgmtVLAN, fwdOrUnknown(ap.ForwardingMode), apBlob)
		if err != nil {
			return err
		}
		for _, r := range ap.Radios {
			radioBlob, err := jsonBlob(r)
			if err != nil {
				return err
			}
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
				ap.TenantID, RadioID(ap.APID, r.Slot), ap.APID, r.Slot, r.Band,
				r.Channel, r.ChannelWidthMHz, r.TxPowerDBm, r.TxPowerMaxDBm,
				r.AdminState, r.OperState, r.Generation, r.MLOCapable, radioBlob); err != nil {
				return err
			}
		}
		return nil
	})
}

func (p *pgStore) UpsertRadios(ctx context.Context, tenant string, radios []Radio) error {
	if len(radios) == 0 {
		return nil
	}
	return p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		for _, r := range radios {
			radioBlob, err := jsonBlob(r)
			if err != nil {
				return err
			}
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
				tenant, RadioID(r.APID, r.Slot), r.APID, r.Slot, r.Band,
				r.Channel, r.ChannelWidthMHz, r.TxPowerDBm, r.TxPowerMaxDBm,
				r.AdminState, r.OperState, r.Generation, r.MLOCapable, radioBlob); err != nil {
				return err
			}
		}
		return nil
	})
}

// pgOverlayRadios loads ap_radios rows in the SAME withTenant transaction and
// merges them onto the AP list by (ap_id, slot) — the row store is the truth
// for radios, the AP blob only a bootstrap.
func pgOverlayRadios(ctx context.Context, tx pgx.Tx, aps []AccessPoint) error {
	if len(aps) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT ap_id, data, first_seen, last_seen, stale FROM ap_radios`)
	if err != nil {
		return err
	}
	defer rows.Close()
	bySlotByAP := map[string]map[int]Radio{}
	for rows.Next() {
		var (
			apID        string
			blob        []byte
			first, last time.Time
			stale       bool
		)
		if err := rows.Scan(&apID, &blob, &first, &last, &stale); err != nil {
			return err
		}
		var r Radio
		if err := json.Unmarshal(blob, &r); err != nil {
			return err
		}
		r.APID, r.FirstSeen, r.LastSeen, r.Stale = apID, first, last, stale
		if bySlotByAP[apID] == nil {
			bySlotByAP[apID] = map[int]Radio{}
		}
		bySlotByAP[apID][r.Slot] = r
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range aps {
		slots := bySlotByAP[aps[i].APID]
		if len(slots) == 0 {
			continue
		}
		merged := map[int]Radio{}
		for _, r := range aps[i].Radios {
			merged[r.Slot] = r
		}
		for s, r := range slots {
			merged[s] = r
		}
		out := make([]Radio, 0, len(merged))
		for _, r := range merged {
			out = append(out, r)
		}
		sort.Slice(out, func(a, b int) bool { return out[a].Slot < out[b].Slot })
		aps[i].Radios = out
	}
	return nil
}

func (p *pgStore) ListAPs(ctx context.Context, tenant string, cross bool) ([]AccessPoint, error) {
	var out []AccessPoint
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, data, first_seen, last_seen, stale FROM access_points ORDER BY ap_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			ap, err := scanRow[AccessPoint](rows)
			if err != nil {
				return err
			}
			out = append(out, ap)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		return pgOverlayRadios(ctx, tx, out)
	})
	return out, err
}

func (p *pgStore) GetAP(ctx context.Context, tenant string, cross bool, id string) (AccessPoint, bool, error) {
	var ap AccessPoint
	found := false
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, data, first_seen, last_seen, stale FROM access_points WHERE ap_id = $1`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			if ap, err = scanRow[AccessPoint](rows); err != nil {
				return err
			}
			found = true
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		if !found {
			return nil
		}
		one := []AccessPoint{ap}
		if err := pgOverlayRadios(ctx, tx, one); err != nil {
			return err
		}
		ap = one[0]
		return nil
	})
	return ap, found, err
}

func (p *pgStore) UpsertWLAN(ctx context.Context, wl WLAN) error {
	wlanBlob, err := jsonBlob(wl)
	if err != nil {
		return err
	}
	return p.db.WithTenant(ctx, wl.TenantID, false, func(tx pgx.Tx) error {
		ssidRef := wl.SSIDRef
		if ssidRef == "" && wl.SSIDName != "" {
			ssidRef = SSIDID(wl.TenantID, wl.SSIDName)
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
			wl.Enabled, wlanBlob)
		return err
	})
}

func (p *pgStore) ListWLANs(ctx context.Context, tenant string, cross bool) ([]WLAN, error) {
	var out []WLAN
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, data, first_seen, last_seen, stale FROM wlans ORDER BY wlan_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			wl, err := scanRow[WLAN](rows)
			if err != nil {
				return err
			}
			out = append(out, wl)
		}
		return rows.Err()
	})
	return out, err
}

func (p *pgStore) UpsertBSSID(ctx context.Context, b BSSID) error {
	bssidBlob, err := jsonBlob(b)
	if err != nil {
		return err
	}
	return p.db.WithTenant(ctx, b.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO bssids (tenant_id, bssid, radio_ref, wlan_ref, ap_ref, data, last_seen, stale)
VALUES ($1,$2,$3,$4,$5,$6,now(),false)
ON CONFLICT (tenant_id, bssid) DO UPDATE SET
    radio_ref=EXCLUDED.radio_ref, wlan_ref=EXCLUDED.wlan_ref, ap_ref=EXCLUDED.ap_ref,
    data=EXCLUDED.data, last_seen=now(), stale=false`,
			b.TenantID, b.BSSID, b.RadioRef, b.WLANRef, b.APRef, bssidBlob)
		return err
	})
}

func (p *pgStore) ListBSSIDs(ctx context.Context, tenant string, cross bool) ([]BSSID, error) {
	var out []BSSID
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, data, first_seen, last_seen, stale FROM bssids ORDER BY bssid`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			b, err := scanRow[BSSID](rows)
			if err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}
