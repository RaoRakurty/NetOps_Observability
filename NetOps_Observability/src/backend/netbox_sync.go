package main

// netbox_sync.go — reconciles DISCOVERED devices INTO NetBox as the source of
// truth (the reverse of discovery.NetboxSource, which reads FROM NetBox). REST + idempotent
// + restart-safe. Runs only when the NetBox integration is enabled+configured.
//
// Why REST, not the Kafka bus: this is low-volume control-plane CRUD (devices
// change rarely), and the Go backend is stdlib-only (no Kafka client). The event
// bus is for high-volume telemetry; routing device sync through it would add a
// dependency + a consumer for no benefit.
//
// Matching: a discovered device is found-or-created in NetBox by NAME (then
// serial). NetBox mandates FKs (Site/Role/DeviceType→Manufacturer); we auto-
// provision "Discovered" defaults (idempotent, cached) so import is hands-free —
// operators re-home devices to real sites/roles in NetBox afterward, and we never
// overwrite an existing device's operator-managed fields (create-only).
//
// (The cross-source de-dup that makes a device appear ONCE in the UI lives in the
// discovery aggregator — deviceKey/mergeDevices, mgmt-IP→serial→name.)

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"netops/backend/internal/discovery"
	"strings"
	"sync"
	"time"

	"netops/backend/models"
)

const (
	netboxSyncInterval   = 5 * time.Minute
	netboxSyncFirstDelay = 90 * time.Second // let discovery complete a cycle first
	netboxDiscoveredSlug = "discovered"
)

type netboxSyncer struct {
	cfg     func() netboxConfig
	devices func() []models.Device
	client  *http.Client

	mu      sync.Mutex
	fk      map[string]int // FK id cache for the current run ("dcim/sites:discovered"→id)
	lastRun time.Time
	lastErr string
	created int
	present int
}

func newNetboxSyncer(cfg func() netboxConfig, devices func() []models.Device) *netboxSyncer {
	return &netboxSyncer{
		cfg: cfg, devices: devices,
		client: &http.Client{Timeout: 20 * time.Second},
		fk:     map[string]int{},
	}
}

// Start runs the periodic reconcile loop. No-op per tick while NetBox is disabled.
func (s *netboxSyncer) Start(ctx context.Context) {
	go func() {
		first := time.NewTimer(netboxSyncFirstDelay)
		defer first.Stop()
		tick := time.NewTicker(netboxSyncInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-first.C:
				_, _ = s.SyncOnce(ctx)
			case <-tick.C:
				_, _ = s.SyncOnce(ctx)
			}
		}
	}()
}

type netboxSyncStatus struct {
	Enabled bool      `json:"enabled"`
	LastRun time.Time `json:"last_run,omitempty"`
	LastErr string    `json:"last_error,omitempty"`
	Created int       `json:"created"` // devices created in NetBox on the last run
	Present int       `json:"present"` // devices already in NetBox (left untouched)
}

func (s *netboxSyncer) Status() netboxSyncStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return netboxSyncStatus{Enabled: s.cfg().Enabled, LastRun: s.lastRun, LastErr: s.lastErr, Created: s.created, Present: s.present}
}

func (s *netboxSyncer) setErr(msg string) {
	s.mu.Lock()
	s.lastRun = time.Now().UTC()
	s.lastErr = msg
	s.mu.Unlock()
	logWarn("netbox-sync", msg, nil)
}

// SyncOnce reconciles every discovered device into NetBox. Idempotent: existing
// devices (by name/serial) are left as-is; only new ones are created.
func (s *netboxSyncer) SyncOnce(ctx context.Context) (netboxSyncStatus, error) {
	cfg := s.cfg()
	base := strings.TrimRight(cfg.URL, "/")
	if !cfg.Enabled || base == "" || cfg.Token == "" {
		return s.Status(), nil // disabled/unconfigured → no-op
	}
	// Sync direction: only push discovered devices up when writes are enabled
	// (write/both). In read-only mode NetBox is authoritative and we never
	// create records from discovery.
	if !discovery.NetboxWritesDevices(cfg) {
		return s.Status(), nil
	}
	if bu, err := url.Parse(base); err != nil || bu.Host == "" {
		s.setErr(fmt.Sprintf("invalid NetBox URL %q", base))
		return s.Status(), fmt.Errorf("invalid netbox url")
	}
	token := cfg.Token

	s.mu.Lock()
	s.fk = map[string]int{} // fresh per run (tolerates manual NetBox edits between runs)
	s.mu.Unlock()

	// Shared "Discovered" site + role (created once, idempotent).
	siteID, err := s.ensure(ctx, base, token, "dcim/sites", netboxDiscoveredSlug,
		map[string]any{"name": "Discovered", "slug": netboxDiscoveredSlug, "status": "active"})
	if err != nil {
		s.setErr("ensure site: " + err.Error())
		return s.Status(), err
	}
	roleID, err := s.ensure(ctx, base, token, "dcim/device-roles", netboxDiscoveredSlug,
		map[string]any{"name": "Discovered", "slug": netboxDiscoveredSlug, "color": "9e9e9e"})
	if err != nil {
		s.setErr("ensure role: " + err.Error())
		return s.Status(), err
	}

	created, present := 0, 0
	for _, d := range s.devices() {
		name := strings.TrimSpace(d.Name)
		if name == "" {
			name = strings.TrimSpace(d.Address)
		}
		if name == "" {
			continue
		}
		vendor := firstNonEmpty(strings.TrimSpace(d.Vendor), "Unknown")
		model := firstNonEmpty(strings.TrimSpace(d.Model), "Unknown")
		mfgID, err := s.ensure(ctx, base, token, "dcim/manufacturers", slugify(vendor),
			map[string]any{"name": vendor, "slug": slugify(vendor)})
		if err != nil {
			s.setErr("ensure manufacturer " + vendor + ": " + err.Error())
			continue
		}
		dtSlug := slugify(vendor + "-" + model)
		dtID, err := s.ensure(ctx, base, token, "dcim/device-types", dtSlug,
			map[string]any{"manufacturer": mfgID, "model": model, "slug": dtSlug})
		if err != nil {
			s.setErr("ensure device-type " + dtSlug + ": " + err.Error())
			continue
		}

		found, err := s.deviceExists(ctx, base, token, name, strings.TrimSpace(d.Labels["serial"]))
		if err != nil {
			s.setErr("lookup device " + name + ": " + err.Error())
			continue
		}
		if found {
			present++ // create-only: never clobber operator-managed NetBox fields
			continue
		}
		payload := map[string]any{
			"name": name, "device_type": dtID, "role": roleID, "site": siteID, "status": "active",
		}
		if sn := strings.TrimSpace(d.Labels["serial"]); sn != "" {
			payload["serial"] = sn
		}
		comment := "Imported by NetOps discovery"
		if d.Address != "" {
			comment += " · mgmt " + d.Address
		}
		if d.Source != "" {
			comment += " · via " + d.Source
		}
		payload["comments"] = comment
		if _, err := s.req(ctx, http.MethodPost, base+"/api/dcim/devices/", token, payload); err != nil {
			s.setErr("create device " + name + ": " + err.Error())
			continue
		}
		created++
	}

	s.mu.Lock()
	s.lastRun = time.Now().UTC()
	s.lastErr = ""
	s.created = created
	s.present = present
	s.mu.Unlock()
	logInfo("netbox-sync", "reconciled devices into NetBox", map[string]any{"created": created, "present": present})
	return s.Status(), nil
}

// handleNetboxSync serves the device→NetBox reconciler control surface
// (platform-owner only): GET = last-run status, POST = reconcile now.
func (s *server) handleNetboxSync(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCrossTenant(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.netboxSync.Status())
	case http.MethodPost:
		st, err := s.netboxSync.SyncOnce(r.Context())
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, st)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ensure finds an object by slug, creating it from `create` if absent. Cached for
// the run. Returns the NetBox object id.
func (s *netboxSyncer) ensure(ctx context.Context, base, token, endpoint, slug string, create map[string]any) (int, error) {
	ck := endpoint + ":" + slug
	s.mu.Lock()
	if id, ok := s.fk[ck]; ok {
		s.mu.Unlock()
		return id, nil
	}
	s.mu.Unlock()

	m, err := s.req(ctx, http.MethodGet, base+"/api/"+endpoint+"/?slug="+url.QueryEscape(slug)+"&limit=1", token, nil)
	if err != nil {
		return 0, err
	}
	if id, ok := firstResultID(m); ok {
		s.cacheFK(ck, id)
		return id, nil
	}
	cm, err := s.req(ctx, http.MethodPost, base+"/api/"+endpoint+"/", token, create)
	if err != nil {
		return 0, err
	}
	id, ok := objID(cm)
	if !ok {
		return 0, fmt.Errorf("%s: created object missing id", endpoint)
	}
	s.cacheFK(ck, id)
	return id, nil
}

func (s *netboxSyncer) cacheFK(k string, id int) {
	s.mu.Lock()
	s.fk[k] = id
	s.mu.Unlock()
}

// deviceExists reports whether a device with this name (or serial) already exists.
func (s *netboxSyncer) deviceExists(ctx context.Context, base, token, name, serial string) (bool, error) {
	m, err := s.req(ctx, http.MethodGet, base+"/api/dcim/devices/?name="+url.QueryEscape(name)+"&limit=1", token, nil)
	if err != nil {
		return false, err
	}
	if _, ok := firstResultID(m); ok {
		return true, nil
	}
	if serial != "" {
		m, err := s.req(ctx, http.MethodGet, base+"/api/dcim/devices/?serial="+url.QueryEscape(serial)+"&limit=1", token, nil)
		if err != nil {
			return false, err
		}
		if _, ok := firstResultID(m); ok {
			return true, nil
		}
	}
	return false, nil
}

// req performs one authenticated NetBox API call against the configured host.
func (s *netboxSyncer) req(ctx context.Context, method, fullURL, token string, body any) (map[string]any, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("netbox %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var m map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	return m, nil
}

// firstResultID extracts results[0].id from a NetBox list response.
func firstResultID(m map[string]any) (int, bool) {
	results, ok := m["results"].([]any)
	if !ok || len(results) == 0 {
		return 0, false
	}
	first, ok := results[0].(map[string]any)
	if !ok {
		return 0, false
	}
	return objID(first)
}

// objID extracts an integer id from a NetBox object (JSON numbers are float64).
func objID(m map[string]any) (int, bool) {
	if m == nil {
		return 0, false
	}
	if f, ok := m["id"].(float64); ok {
		return int(f), true
	}
	return 0, false
}
