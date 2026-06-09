package main

// tenants.go — multi-tenancy. A tenant is a logical isolation boundary; users,
// devices, dashboards and alerts are scoped to one. File-backed (tenants.json),
// same pattern as the other stores. See docs/IDENTITY_ACCESS.md.

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// TenantGlobal is the seeded root tenant that owns shared defaults.
const TenantGlobal = "global"

type Tenant struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
	Note string `json:"note,omitempty"`
	// OrgID is the Organization this tenant belongs to (orgs.go). Every tenant
	// belongs to exactly one org; blank is treated as the Global org for
	// backward compatibility with tenants created before the org layer existed.
	OrgID string `json:"org_id,omitempty"`
	// Region is the data-residency region this tenant is assigned to. Blank means
	// "inherit the org's home_region" — see effectiveTenantRegion. It is a MODEL
	// attribute (where the tenant's data is meant to live); routing telemetry to a
	// per-region data plane is a later, deployment-time concern (regionDataPlane).
	Region        string        `json:"region,omitempty"`
	IsolationMode IsolationMode `json:"isolation_mode,omitempty"` // shared (default) | dedicated_schema|db|cluster
	// OperatorRestricted is the data-privacy / compliance switch: when true, the
	// platform operator (cross-tenant super-admin) may NOT view this tenant's
	// telemetry — its logs/syslog/flows/traps are excluded from the operator's
	// Global view and the operator is denied if it scopes into the tenant. The
	// tenant's OWN users are unaffected (they always see their own data). Default
	// false (zero value) = operator-visible, preserving existing behavior.
	OperatorRestricted bool      `json:"operator_restricted,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
}

type tenantStore struct {
	mu      sync.RWMutex
	path    string
	tenants map[string]Tenant
}

func newTenantStore(path string) (*tenantStore, error) {
	if path == "" {
		path = "/data/tenants.json"
	}
	s := &tenantStore{path: path, tenants: make(map[string]Tenant)}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, ok := s.tenants[TenantGlobal]; !ok {
		s.tenants[TenantGlobal] = Tenant{
			ID: TenantGlobal, Name: "Global", Slug: TenantGlobal, OrgID: OrgGlobal,
			Note:          "Root tenant — owns shared infrastructure & defaults.",
			IsolationMode: IsolationShared, CreatedAt: time.Now().UTC(),
		}
		if err := s.flushLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *tenantStore) load() error {
	b, err := kvLoad(s.path)
	if err != nil {
		return err
	}
	var list []Tenant
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, t := range list {
		s.tenants[t.ID] = t
	}
	return nil
}

func (s *tenantStore) flushLocked() error {
	list := make([]Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

func (s *tenantStore) List() []Tenant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID == TenantGlobal != (out[j].ID == TenantGlobal) {
			return out[i].ID == TenantGlobal // Global first
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (s *tenantStore) Get(id string) (Tenant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tenants[id]
	return t, ok
}

// restrictedIDs returns the (lower-cased) ids of tenants the platform operator may
// NOT view (OperatorRestricted). Used to exclude their telemetry from the
// operator's cross-tenant view. Empty when no tenant is restricted (the default).
func (s *tenantStore) restrictedIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for id, t := range s.tenants {
		if t.OperatorRestricted {
			out = append(out, strings.ToLower(id))
		}
	}
	return out
}

// SetRegion assigns a tenant to a data-residency region (blank = inherit the
// org's home_region). Validated against the known region set.
func (s *tenantStore) SetRegion(id, region string) (Tenant, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	reg := strings.ToLower(strings.TrimSpace(region))
	if reg != "" {
		if _, err := normalizeRegion(reg); err != nil {
			return Tenant{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[id]
	if !ok {
		return Tenant{}, errors.New("tenant not found")
	}
	t.Region = reg
	s.tenants[id] = t
	if err := s.flushLocked(); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// SetOperatorRestricted toggles a tenant's operator-visibility (compliance). The
// global tenant can never be restricted (it IS the platform/operator namespace).
func (s *tenantStore) SetOperatorRestricted(id string, restricted bool) (Tenant, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == TenantGlobal {
		return Tenant{}, errors.New("the global tenant cannot be operator-restricted")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[id]
	if !ok {
		return Tenant{}, errors.New("tenant not found")
	}
	t.OperatorRestricted = restricted
	s.tenants[id] = t
	if err := s.flushLocked(); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

func (s *tenantStore) Create(name, note, isolationMode, orgID string) (Tenant, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Tenant{}, errors.New("tenant name required")
	}
	id := slugify(name)
	if id == "" {
		return Tenant{}, errors.New("tenant name must contain letters or digits")
	}
	mode, err := normalizeIsolationMode(isolationMode)
	if err != nil {
		return Tenant{}, err
	}
	org := strings.ToLower(strings.TrimSpace(orgID))
	if org == "" {
		org = OrgGlobal
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[id]; ok {
		return Tenant{}, errors.New("tenant already exists")
	}
	t := Tenant{ID: id, Name: name, Slug: id, Note: note, OrgID: org, IsolationMode: mode, CreatedAt: time.Now().UTC()}
	s.tenants[id] = t
	if err := s.flushLocked(); err != nil {
		delete(s.tenants, id)
		return Tenant{}, err
	}
	return t, nil
}

// orgOf returns the org a tenant belongs to, treating blank as the Global org
// (tenants predating the org layer). Centralizes the backward-compat default.
func orgOf(t Tenant) string {
	if t.OrgID == "" {
		return OrgGlobal
	}
	return t.OrgID
}

// ListByOrg returns the tenants belonging to the given org, Global tenant first
// then alphabetical. Used by org-scoped views and delete-guard counting.
func (s *tenantStore) ListByOrg(orgID string) []Tenant {
	orgID = strings.ToLower(strings.TrimSpace(orgID))
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tenant, 0)
	for _, t := range s.tenants {
		if strings.EqualFold(orgOf(t), orgID) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].ID == TenantGlobal) != (out[j].ID == TenantGlobal) {
			return out[i].ID == TenantGlobal
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// CountByOrg reports how many tenants belong to an org — used to refuse deleting
// an org that still owns tenants.
func (s *tenantStore) CountByOrg(orgID string) int {
	orgID = strings.ToLower(strings.TrimSpace(orgID))
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, t := range s.tenants {
		if strings.EqualFold(orgOf(t), orgID) {
			n++
		}
	}
	return n
}

func (s *tenantStore) Delete(id string) error {
	if id == TenantGlobal {
		return errors.New("cannot delete the Global tenant")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[id]; !ok {
		return errors.New("no such tenant")
	}
	delete(s.tenants, id)
	return s.flushLocked()
}
