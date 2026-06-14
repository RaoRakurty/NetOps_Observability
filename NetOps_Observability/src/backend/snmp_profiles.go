package main

import (
	"embed"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
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
	ID                string       `json:"id"`          // stable key, e.g. "cisco-ios"
	Vendor            string       `json:"vendor"`      // display name
	Description       string       `json:"description,omitempty"`
	Category          string       `json:"category"` // universal | router_switch | firewall | wireless | voip | printer | ups | server
	SysObjectIDPrefix string       `json:"sysobjectid_prefix,omitempty"`
	Builtin           bool         `json:"builtin"`
	Metrics           []SNMPMetric `json:"metrics"`
}

type snmpProfileStore struct {
	mu       sync.RWMutex
	path     string
	profiles map[string]SNMPProfile
}

func newSNMPProfileStore(path string) (*snmpProfileStore, error) {
	if path == "" {
		path = "/data/snmp_profiles.json"
	}
	s := &snmpProfileStore{path: path, profiles: make(map[string]SNMPProfile)}
	// Load any persisted (custom) profiles first.
	if b, err := kvLoad(path); err == nil {
		var list []SNMPProfile
		if json.Unmarshal(b, &list) == nil {
			for _, p := range list {
				s.profiles[p.ID] = p
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// Overlay built-ins (Go-defined) + the embedded vendor catalog: ensure each
	// exists and that its base metrics are present (idempotent — operator-added
	// metrics are preserved). Go built-ins win on metadata when ids collide.
	builtins := append(embeddedCatalogProfiles(), builtinSNMPProfiles()...)
	for _, bp := range builtins {
		existing, ok := s.profiles[bp.ID]
		if !ok {
			s.profiles[bp.ID] = bp
			continue
		}
		seen := map[string]bool{}
		for _, m := range existing.Metrics {
			seen[m.OID] = true
		}
		for _, m := range bp.Metrics {
			if !seen[m.OID] {
				existing.Metrics = append(existing.Metrics, m)
			}
		}
		existing.Builtin = true
		existing.Vendor = bp.Vendor
		existing.Category = bp.Category
		existing.SysObjectIDPrefix = bp.SysObjectIDPrefix
		s.profiles[bp.ID] = existing
	}
	_ = s.flush()
	return s, nil
}

func (s *snmpProfileStore) flush() error {
	list := make([]SNMPProfile, 0, len(s.profiles))
	for _, p := range s.profiles {
		list = append(list, p)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
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

// Upsert creates or replaces a custom profile (or extends a built-in's metadata).
func (s *snmpProfileStore) Upsert(p SNMPProfile) (SNMPProfile, error) {
	p.ID = slugify(p.Vendor)
	if p.ID == "" {
		return SNMPProfile{}, errors.New("profile vendor/name required")
	}
	if p.Category == "" {
		p.Category = "custom"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.profiles[p.ID]; ok {
		p.Builtin = existing.Builtin // can't flip a built-in to custom
	}
	s.profiles[p.ID] = p
	if err := s.flush(); err != nil {
		return SNMPProfile{}, err
	}
	return p, nil
}

// AddMetrics appends custom metrics to a profile (creating a custom profile if
// the vendor is unknown). Duplicate OIDs are skipped.
func (s *snmpProfileStore) AddMetrics(id string, metrics []SNMPMetric) (SNMPProfile, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[id]
	if !ok {
		return SNMPProfile{}, errors.New("no such profile")
	}
	seen := map[string]bool{}
	for _, m := range p.Metrics {
		seen[m.OID] = true
	}
	for _, m := range metrics {
		m.Name = strings.TrimSpace(m.Name)
		m.OID = strings.TrimSpace(m.OID)
		if m.Name == "" || m.OID == "" || seen[m.OID] {
			continue
		}
		if m.Type == "" {
			m.Type = "gauge"
		}
		p.Metrics = append(p.Metrics, m)
		seen[m.OID] = true
	}
	s.profiles[id] = p
	if err := s.flush(); err != nil {
		return SNMPProfile{}, err
	}
	return p, nil
}

// Delete removes a custom profile. Built-ins are protected (they re-seed anyway).
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
	delete(s.profiles, id)
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
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
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
		var metrics []SNMPMetric
		if err := json.NewDecoder(r.Body).Decode(&metrics); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
