package backend

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/platformdb"
	"os"
	"sort"
	"strings"
	"sync"
)

// Body bounds for the SNMP profile surface (F-32). The metrics endpoint decodes
// into a slice with no element limit, so it needs BOTH a byte cap and a count
// cap — bytes alone still permit a very large number of very small structs.
const (
	snmpProfileBodyBytes     int64 = 1 << 20 // 1 MiB: a profile is an OID table
	snmpMetricsBodyBytes     int64 = 1 << 20
	maxSNMPMetricsPerRequest       = 2000
)

// catalogFS embeds an optional vendor profile catalog kept as data (not Go
// literals) so the library can grow without code churn. Profiles here are
// ORIGINAL — OID/metric definitions compiled from vendor + IETF RFC MIBs (OIDs
// are MIB facts). The file is "[]" by default; the active profile library is the
// hand-authored originals in snmp_profiles_seed.go. (No third-party catalog.)
//
//go:embed snmp_profiles_catalog.json
var catalogFS embed.FS

// embeddedCatalogProfiles returns the catalog profiles, or nil if empty/invalid.
func embeddedCatalogProfiles() []SNMPProfile {
	b, err := catalogFS.ReadFile("snmp_profiles_catalog.json")
	if err != nil {
		return nil
	}
	var list []SNMPProfile
	if json.Unmarshal(b, &list) != nil {
		return nil
	}
	for i := range list {
		list[i].Builtin = true
	}
	return list
}

// snmp_profiles.go — the SNMP profile manager (backlog #6).
//
// A profile is a vendor/category's pollable OID set: the metrics a monitoring
// template should collect. Built-in profiles ship for the common categories
// (universal standard MIBs + major router/switch/firewall vendors + printers +
// UPS), grounded in docs/research/snmp-vendor-profiles.md (OIDs verified against
// the source MIBs/RFCs; unverified leaves were intentionally omitted). Operators
// can extend any vendor with custom metrics or add whole new vendor profiles —
// custom additions are persisted and merged over the built-ins on load.
//
// Profiles are a platform-wide reference library (like the alert-rule library),
// not tenant-partitioned: viewable with infrastructure:read, mutable with
// infrastructure:write.

// SNMPMetric is one pollable OID.
type SNMPMetric struct {
	Name        string `json:"name"`
	OID         string `json:"oid"`
	Type        string `json:"type"` // counter | gauge | string | enum | table
	Unit        string `json:"unit,omitempty"`
	MIB         string `json:"mib,omitempty"`
	Category    string `json:"category,omitempty"` // System | CPU | Memory | Capacity | Utilization | …
	Description string `json:"description,omitempty"`
}

// SNMPProfile is a vendor/category metric set.
type SNMPProfile struct {
	ID                string `json:"id"`     // stable key, e.g. "cisco-ios"
	Vendor            string `json:"vendor"` // display name
	Description       string `json:"description,omitempty"`
	Category          string `json:"category"` // universal | router_switch | firewall | load_balancer | wireless | voip | printer | ups | server
	SysObjectIDPrefix string `json:"sysobjectid_prefix,omitempty"`
	Builtin           bool   `json:"builtin"`
	// Overlay marks a persistence-only record carrying an operator's metric
	// additions to a *built-in* profile (keyed by the built-in's id). Overlay
	// carriers are never part of the served profile set — the additions are
	// folded onto the source built-in at load. omitempty keeps them invisible in
	// normal API responses.
	Overlay bool         `json:"overlay,omitempty"`
	Metrics []SNMPMetric `json:"metrics"`
}

// snmpProfileStore is the SNMP profile library. The model is deliberately
// source-authoritative:
//
//   - Built-in profiles are defined ONLY in code (builtinSNMPProfiles() +
//     embeddedCatalogProfiles()). They are reconstructed from source on every
//     load — never read back from the persisted store. Removing a built-in from
//     source therefore removes it from the running system; nothing orphaned can
//     linger or become un-deletable.
//   - The persisted store holds ONLY operator intent: custom profiles
//     (builtin=false) and per-built-in metric overlays (metrics an operator
//     added to a built-in). These survive reboots; built-in base definitions do
//     not need to.
//
// This separation is what makes built-in changes deterministic. (Earlier the
// store merged built-ins INTO the persisted blob, so a removed catalog kept
// re-loading from disk as un-deletable builtin=true entries — the legacy
// migration in loadPersisted purges exactly that.)
type snmpProfileStore struct {
	mu       sync.RWMutex
	path     string
	custom   map[string]SNMPProfile  // operator-authored profiles (builtin=false)
	overlays map[string][]SNMPMetric // operator-added metrics, keyed by built-in id
	profiles map[string]SNMPProfile  // materialized view: source built-ins (+overlays) + custom
}

func newSNMPProfileStore(path string) (*snmpProfileStore, error) {
	if path == "" {
		path = "/data/snmp_profiles.json"
	}
	s := &snmpProfileStore{
		path:     path,
		custom:   make(map[string]SNMPProfile),
		overlays: make(map[string][]SNMPMetric),
	}
	if b, err := platformdb.Load(path); err == nil {
		s.loadPersisted(b)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s.rebuild()
	// Re-persist: rewrites a legacy store (purging any stale built-ins it carried)
	// into the operator-intent-only array (custom profiles + overlay carriers).
	if err := s.flush(); err != nil {
		return nil, err
	}
	return s, nil
}

// loadPersisted hydrates custom profiles + overlays from the persisted JSON array.
// The format is operator-intent-only; it also transparently migrates the legacy
// store, which carried full built-in profiles inline.
//
// Each array element is classified by its flags:
//   - overlay=true  → an operator metric overlay on a built-in (keyed by its id)
//   - builtin=false → an operator-authored custom profile
//   - builtin=true  → a legacy persisted built-in: DISCARDED (source is
//     authoritative), which purges removed/stale built-in catalogs that used to
//     re-load as un-deletable entries.
func (s *snmpProfileStore) loadPersisted(b []byte) {
	var list []SNMPProfile
	if json.Unmarshal(b, &list) != nil {
		return
	}
	for _, p := range list {
		id := strings.ToLower(strings.TrimSpace(p.ID))
		if id == "" {
			continue
		}
		switch {
		case p.Overlay:
			s.overlays[id] = p.Metrics
		case !p.Builtin:
			p.ID, p.Builtin, p.Overlay = id, false, false
			s.custom[id] = p
		}
	}
}

// rebuild materializes the served profile set: built-ins from source, with
// operator overlays applied, plus custom profiles. Callers hold s.mu (the
// constructor runs before the store is shared).
func (s *snmpProfileStore) rebuild() {
	profiles := make(map[string]SNMPProfile)
	// 1. Built-ins from source. Go built-ins are appended after the catalog so
	//    they win metadata on any id collision.
	for _, bp := range append(embeddedCatalogProfiles(), builtinSNMPProfiles()...) {
		bp.Builtin = true
		profiles[bp.ID] = bp
	}
	// 2. Apply operator metric-overlays onto matching built-ins (deduped by OID).
	//    An overlay for a built-in that no longer exists is silently dropped.
	for id, ms := range s.overlays {
		bp, ok := profiles[id]
		if !ok {
			continue
		}
		seen := make(map[string]bool, len(bp.Metrics))
		for _, m := range bp.Metrics {
			seen[m.OID] = true
		}
		for _, m := range ms {
			if m.OID != "" && !seen[m.OID] {
				bp.Metrics = append(bp.Metrics, m)
				seen[m.OID] = true
			}
		}
		profiles[id] = bp
	}
	// 3. Custom profiles. A custom id never shadows a built-in.
	for id, p := range s.custom {
		if _, isBuiltin := profiles[id]; isBuiltin {
			continue
		}
		p.Builtin = false
		profiles[id] = p
	}
	s.profiles = profiles
}

// flush persists operator intent only, as a JSON array (the shape the PG backend
// explodes by "id"): custom profiles plus one overlay-carrier per extended
// built-in. Built-in base definitions are never persisted — they come from source.
func (s *snmpProfileStore) flush() error {
	list := make([]SNMPProfile, 0, len(s.custom)+len(s.overlays))
	for _, p := range s.custom {
		p.Builtin, p.Overlay = false, false
		list = append(list, p)
	}
	for id, ms := range s.overlays {
		if len(ms) == 0 {
			continue
		}
		list = append(list, SNMPProfile{ID: id, Overlay: true, Metrics: ms})
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

func (s *snmpProfileStore) List() []SNMPProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SNMPProfile, 0, len(s.profiles))
	for _, p := range s.profiles {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Vendor < out[j].Vendor
	})
	return out
}

func (s *snmpProfileStore) Get(id string) (SNMPProfile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[strings.ToLower(strings.TrimSpace(id))]
	return p, ok
}

// Upsert creates or replaces a custom profile. A built-in id cannot be
// overridden wholesale (built-ins are source-defined); extend one with
// AddMetrics instead.
func (s *snmpProfileStore) Upsert(p SNMPProfile) (SNMPProfile, error) {
	p.ID = slugify(p.Vendor)
	if p.ID == "" {
		return SNMPProfile{}, errors.New("profile vendor/name required")
	}
	if p.Category == "" {
		p.Category = "custom"
	}
	p.Builtin = false
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.profiles[p.ID]; ok && cur.Builtin {
		return SNMPProfile{}, errors.New("cannot override a built-in profile; add metrics to extend it")
	}
	s.custom[p.ID] = p
	s.rebuild()
	if err := s.flush(); err != nil {
		return SNMPProfile{}, err
	}
	return s.profiles[p.ID], nil
}

// AddMetrics appends operator metrics to an existing profile. For a built-in the
// additions are recorded as an overlay (the source definition is untouched); for
// a custom profile they extend it directly. Duplicate OIDs (against the current
// materialized metric set) are skipped.
func (s *snmpProfileStore) AddMetrics(id string, metrics []SNMPMetric) (SNMPProfile, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.profiles[id]
	if !ok {
		return SNMPProfile{}, errors.New("no such profile")
	}
	seen := make(map[string]bool, len(cur.Metrics))
	for _, m := range cur.Metrics {
		seen[m.OID] = true
	}
	var added []SNMPMetric
	for _, m := range metrics {
		m.Name = strings.TrimSpace(m.Name)
		m.OID = strings.TrimSpace(m.OID)
		if m.Name == "" || m.OID == "" || seen[m.OID] {
			continue
		}
		if m.Type == "" {
			m.Type = "gauge"
		}
		added = append(added, m)
		seen[m.OID] = true
	}
	if cur.Builtin {
		s.overlays[id] = append(s.overlays[id], added...)
	} else {
		c := s.custom[id]
		c.Metrics = append(c.Metrics, added...)
		s.custom[id] = c
	}
	s.rebuild()
	if err := s.flush(); err != nil {
		return SNMPProfile{}, err
	}
	return s.profiles[id], nil
}

// Delete removes a custom profile. Built-ins are source-defined and cannot be
// deleted at runtime (remove them from source instead).
func (s *snmpProfileStore) Delete(id string) error {
	id = strings.ToLower(strings.TrimSpace(id))
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[id]
	if !ok {
		return errors.New("no such profile")
	}
	if p.Builtin {
		return errors.New("built-in profiles cannot be deleted")
	}
	delete(s.custom, id)
	s.rebuild()
	return s.flush()
}

// ---- handlers --------------------------------------------------------------

func (s *server) handleSNMPProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
			return
		}
		writeJSON(w, http.StatusOK, s.snmpProfiles.List())
	case http.MethodPost:
		if _, ok := s.requirePerm(w, r, "infrastructure", LevelWrite); !ok {
			return
		}
		var p SNMPProfile
		// F-32: a profile carries an OID table, so it is larger than a form post
		// but nowhere near 50 MiB.
		if err := decodeJSONBody(w, r, snmpProfileBodyBytes, &p); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		saved, err := s.snmpProfiles.Upsert(p)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, saved)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleSNMPProfileByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/snmp/profiles/")
	id, suffix, _ := strings.Cut(rest, "/")
	if id == "" {
		writeError(w, http.StatusBadRequest, errors.New("invalid profile id"))
		return
	}

	// POST /api/snmp/profiles/{id}/metrics — add custom metric(s).
	if suffix == "metrics" && r.Method == http.MethodPost {
		if _, ok := s.requirePerm(w, r, "infrastructure", LevelWrite); !ok {
			return
		}
		// F-32: this decodes into an UNBOUNDED SLICE. Under the 50 MiB global
		// backstop a single request could allocate millions of SNMPMetric
		// structs — the one shape in the handler set where body size becomes an
		// unbounded allocation rather than a bounded one. Cap the bytes AND the
		// element count: a profile with thousands of custom metrics is a
		// mistake, not a workload, and it must be refused rather than stored.
		var metrics []SNMPMetric
		if err := decodeJSONBody(w, r, snmpMetricsBodyBytes, &metrics); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if len(metrics) > maxSNMPMetricsPerRequest {
			writeError(w, http.StatusRequestEntityTooLarge,
				fmt.Errorf("too many metrics in one request: %d (max %d)", len(metrics), maxSNMPMetricsPerRequest))
			return
		}
		p, err := s.snmpProfiles.AddMetrics(id, metrics)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, p)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
			return
		}
		p, ok := s.snmpProfiles.Get(id)
		if !ok {
			writeError(w, http.StatusNotFound, errors.New("no such profile"))
			return
		}
		writeJSON(w, http.StatusOK, p)
	case http.MethodDelete:
		if _, ok := s.requirePerm(w, r, "infrastructure", LevelWrite); !ok {
			return
		}
		if err := s.snmpProfiles.Delete(id); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
