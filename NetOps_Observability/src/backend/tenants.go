package main

// tenants.go — multi-tenancy. A tenant is a logical isolation boundary; users,
// devices, dashboards and alerts are scoped to one. File-backed (tenants.json),
// same pattern as the other stores. See docs/IDENTITY_ACCESS.md.

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
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
	// Status is the lifecycle state of the tenant (ABAC-ready; surfaced in
	// TenantContext). Default "active"; a future suspend/archive flow flips it,
	// and policy can deny access to a non-active tenant. Blank is read as active
	// for tenants created before this field existed.
	Status string `json:"status,omitempty"`
	// DefaultLanding is the hash route a user lands on after sign-in, administratively
	// configurable per tenant (blank = inherit the platform default = the global
	// tenant's value, else the app's built-in home). Stored as a sanitized opaque
	// route ("#/section/leaf"); the SPA validates it resolves to a real, accessible
	// nav leaf and falls back gracefully, so a stale/forbidden route never traps a user.
	DefaultLanding string    `json:"default_landing,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// sanitizeLandingRoute validates an administratively-set landing route. Empty is
// allowed (inherit). Otherwise it must be a relative hash route — no scheme, host,
// whitespace or control chars — so it can never be turned into an open redirect or
// injection. Route EXISTENCE/authorization is the SPA's job (it knows the nav).
func sanitizeLandingRoute(route string) (string, error) {
	r := strings.TrimSpace(route)
	if r == "" {
		return "", nil
	}
	if len(r) > 128 || !landingRoutePattern.MatchString(r) {
		return "", errors.New("invalid landing route (expected a relative #/… route)")
	}
	return r, nil
}

// e.g. "#/incident/overview", "#/dashboards/home". Letters/digits/-/_/ only.
var landingRoutePattern = regexp.MustCompile(`^#/[A-Za-z0-9][A-Za-z0-9/_-]*$`)

// Tenant lifecycle states.
const (
	TenantStatusActive    = "active"
	TenantStatusSuspended = "suspended"
)

// status returns the tenant's lifecycle state, defaulting a blank (legacy) value
// to active so existing tenants behave unchanged.
func (t Tenant) status() string {
	if t.Status == "" {
		return TenantStatusActive
	}
	return t.Status
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
			ID: TenantGlobal, Name: "Provider", Slug: TenantGlobal, OrgID: OrgGlobal,
			Note:          "The provider (platform-owner) realm.",
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

// Get resolves a tenant by id OR slug — the legacy compatibility resolver. New
// code holds the opaque tenant id; this keeps the many slug-keyed call sites
// (scope parents, bindings, seed/demo data) working until they migrate. It is
// RESOLUTION only — authorization still happens on the resolved tenant's opaque
// ID, never on the slug. See Resolve (the canonical boundary name).
func (s *tenantStore) Get(ref string) (Tenant, bool) { return s.Resolve(ref) }

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
func (s *tenantStore) SetRegion(ref, region string) (Tenant, error) {
	reg := strings.ToLower(strings.TrimSpace(region))
	if reg != "" {
		if _, err := normalizeRegion(reg); err != nil {
			return Tenant{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.resolveLocked(ref) // id or slug
	if !ok {
		return Tenant{}, errors.New("tenant not found")
	}
	t.Region = reg
	s.tenants[t.ID] = t
	if err := s.flushLocked(); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// SetDefaultLanding sets the tenant's administratively-configured landing route
// (blank = inherit the platform default). Setting it on the GLOBAL tenant defines
// the platform-wide default. The route is sanitized; existence is the SPA's job.
func (s *tenantStore) SetDefaultLanding(ref, route string) (Tenant, error) {
	clean, err := sanitizeLandingRoute(route)
	if err != nil {
		return Tenant{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.resolveLocked(ref) // id or slug
	if !ok {
		return Tenant{}, errors.New("tenant not found")
	}
	t.DefaultLanding = clean
	s.tenants[t.ID] = t
	if err := s.flushLocked(); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// SetOperatorRestricted toggles a tenant's operator-visibility (compliance). The
// global tenant can never be restricted (it IS the platform/operator namespace).
func (s *tenantStore) SetOperatorRestricted(ref string, restricted bool) (Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.resolveLocked(ref) // id or slug
	if !ok {
		return Tenant{}, errors.New("tenant not found")
	}
	if t.ID == TenantGlobal {
		return Tenant{}, errors.New("the global tenant cannot be operator-restricted")
	}
	t.OperatorRestricted = restricted
	s.tenants[t.ID] = t
	if err := s.flushLocked(); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// SetStatus changes a tenant's lifecycle state (active|suspended). The global
// tenant is the platform realm and can never be suspended. Resolves id-or-slug.
func (s *tenantStore) SetStatus(ref, status string) (Tenant, error) {
	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case TenantStatusActive, TenantStatusSuspended:
	default:
		return Tenant{}, errors.New("status must be active or suspended")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.resolveLocked(ref)
	if !ok {
		return Tenant{}, errors.New("tenant not found")
	}
	if t.ID == TenantGlobal {
		return Tenant{}, errors.New("the global tenant cannot be suspended")
	}
	t.Status = status
	s.tenants[t.ID] = t
	if err := s.flushLocked(); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// Create makes a new tenant. The id is an OPAQUE, IMMUTABLE, cryptographically-
// random key (mintTenantID) — never derived from the name/slug, so the security
// boundary is stable across renames and not guessable. The slug is a human handle:
// taken from `slug` if supplied, else derived from the display name, and validated
// to the full contract either way (untrusted input). Slugs are globally unique.
func (s *tenantStore) Create(name, slug, note, isolationMode, orgID string) (Tenant, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Tenant{}, errors.New("tenant name required")
	}
	cand := strings.TrimSpace(slug)
	if cand == "" {
		cand = slugFromName(name)
	}
	cleanSlug, err := validateSlug(cand)
	if err != nil {
		return Tenant{}, err
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
	if s.slugTakenLocked(cleanSlug) {
		return Tenant{}, errors.New("tenant slug already exists")
	}
	id := mintTenantID()
	for {
		if _, ok := s.tenants[id]; !ok {
			break
		}
		id = mintTenantID() // astronomically unlikely; guard anyway
	}
	t := Tenant{ID: id, Name: name, Slug: cleanSlug, Note: note, OrgID: org, IsolationMode: mode, Status: TenantStatusActive, CreatedAt: time.Now().UTC()}
	s.tenants[id] = t
	if err := s.flushLocked(); err != nil {
		delete(s.tenants, id)
		return Tenant{}, err
	}
	return t, nil
}

// slugTakenLocked reports whether a tenant slug is already in use (globally
// unique). Checks both the Slug field and the id map key — legacy tenants have
// id==slug, so a new slug must also not collide with an existing readable id.
// Caller holds the write lock.
func (s *tenantStore) slugTakenLocked(slug string) bool {
	if _, ok := s.tenants[slug]; ok {
		return true
	}
	for _, t := range s.tenants {
		if t.Slug == slug {
			return true
		}
	}
	return false
}

// Resolve maps an UNTRUSTED id-or-slug reference to the canonical tenant. This is
// the compatibility resolver: a ref is tried as an id first (opaque t_ id, the
// global sentinel, or a legacy id==slug), then as a slug. Callers MUST resolve
// before authorizing — never authorize on the raw slug.
func (s *tenantStore) Resolve(ref string) (Tenant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.resolveLocked(ref)
}

// resolveLocked is Resolve's lock-free core, so write methods (Set*/Delete) can
// resolve an id-or-slug ref to the canonical record while already holding the
// write lock. Caller must hold s.mu (read or write).
func (s *tenantStore) resolveLocked(ref string) (Tenant, bool) {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if ref == "" {
		return Tenant{}, false
	}
	if t, ok := s.tenants[ref]; ok {
		return t, true
	}
	for _, t := range s.tenants {
		if t.Slug == ref {
			return t, true
		}
	}
	return Tenant{}, false
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

func (s *tenantStore) Delete(ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.resolveLocked(ref) // id or slug
	if !ok {
		return errors.New("no such tenant")
	}
	if t.ID == TenantGlobal {
		return errors.New("cannot delete the Global tenant")
	}
	delete(s.tenants, t.ID)
	return s.flushLocked()
}
