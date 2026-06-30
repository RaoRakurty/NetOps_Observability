package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
)

// WAN circuits (#1 of the WAN path-metrics program).
//
// Model only — no measurement here. This file defines the controller-style
// registry the SD-WAN world calls TLOCs + topology policy: every WAN-device
// interface is an ENDPOINT; the topology policy meshes them into CIRCUITS
// (local⇄remote interface pairs) that the echo-probe collector (#2) and the
// source-agnostic resolver (#3) will later measure and the per-interface table
// (#4) will render.
//
// Design notes (agreed with the owner):
//   - The unit is the CIRCUIT = local WAN interface ⇄ remote WAN interface, NOT
//     "interface → some host". Far-ends are NOT discovered by LLDP (a WAN port
//     only ever sees the provider PE one L2 hop away); like an SD-WAN controller
//     we build the endpoint registry CENTRALLY from the SNMP interface-IP table
//     and mesh it by policy.
//   - Topology is hub-and-spoke by default (enterprises rarely full-mesh); the
//     hub is operator INTENT, defaulted from the site's role, never sniffed.
//   - Endpoints + circuits are DERIVED (projected on demand from the registry ×
//     site roles × policy), exactly like the topology /view projector. Only the
//     policy (operator intent) is persisted (tenantKV). Circuit persistence with
//     an RLS table is reserved (migration 0017) for when we want history.

// WanRole is a device/site's place in the WAN topology — declared intent.
type WanRole string

const (
	WanRoleHub   WanRole = "hub"
	WanRoleSpoke WanRole = "spoke"
)

// RoleSource records HOW a role was decided, so the UI can show the "why" and
// never present an inferred role as fact (anti-black-box).
type RoleSource string

const (
	RoleDeclared  RoleSource = "declared"  // operator override / explicit hub list
	RoleFromSite  RoleSource = "site"      // inherited from the site SoT role
	RoleSuggested RoleSource = "suggested" // inferred (name hint; structural in a later pass)
	RoleDefault   RoleSource = "default"   // default-closed → spoke
)

// WanEndpoint is one WAN transport interface — the SD-WAN TLOC analog.
type WanEndpoint struct {
	TenantID   string `json:"tenant_id,omitempty"`
	Device     string `json:"device"`
	Interface  string `json:"interface"`       // ifName (Ethernet1)
	Address    string `json:"address"`         // physical interface IP (provider /30, maybe NAT'd)
	Measurable string `json:"measurable_addr"` // address we actually probe (loopback/public); default = Address
	Site       string `json:"site,omitempty"`

	Role         WanRole    `json:"role"`
	RoleSource   RoleSource `json:"role_source"`
	RoleEvidence string     `json:"role_evidence,omitempty"`
}

// WanCircuit is one measured direction local→remote. When the policy is
// bidirectional the reverse is its own row (loss/latency are often asymmetric).
type WanCircuit struct {
	TenantID string      `json:"tenant_id,omitempty"`
	ID       string      `json:"id"` // deterministic over the endpoint pair
	Local    WanEndpoint `json:"local"`
	Remote   WanEndpoint `json:"remote"`
	Topology string      `json:"topology"` // hub-spoke | full-mesh | manual
	Source   string      `json:"source"`   // registry | manual
	Enabled  bool        `json:"enabled"`
}

// WanTopologyPolicy is the controller-style mesh policy — one row per tenant.
// All operator intent for the WAN view lives here.
type WanTopologyPolicy struct {
	TenantID      string             `json:"tenant_id,omitempty"`
	Mode          string             `json:"mode"`                     // hub-spoke (default) | full-mesh
	Bidirectional bool               `json:"bidirectional"`            // default true
	Hubs          []string           `json:"hubs,omitempty"`           // device id/name OR site slug designated hub
	WanPattern    string             `json:"wan_pattern,omitempty"`    // which devices are WAN devices (default below)
	RoleOverrides map[string]WanRole `json:"role_overrides,omitempty"` // per-device id/name override
	UpdatedBy     string             `json:"updated_by,omitempty"`
	UpdatedAt     time.Time          `json:"updated_at"`
}

const defaultWanPattern = "wan|edge|gw|dmz"

// hubNameHint / spokeNameHint feed the weakest (suggested) role signal.
var (
	hubNameHint   = regexp.MustCompile(`(?i)(^|[-_])(hub|dc|hq|core|agg|gw|gateway)([-_]|\d|$)`)
	spokeNameHint = regexp.MustCompile(`(?i)(^|[-_])(spoke|branch|site|store|remote|cpe)([-_]|\d|$)`)
)

// withDefaults returns the policy with empty fields filled — the safe baseline
// a tenant gets before it has ever saved one.
func (p WanTopologyPolicy) withDefaults() WanTopologyPolicy {
	if p.Mode == "" {
		p.Mode = "hub-spoke"
	}
	if p.WanPattern == "" {
		p.WanPattern = defaultWanPattern
	}
	// Bidirectional defaults to true; a stored policy carries the explicit value.
	return p
}

func (p WanTopologyPolicy) validate() error {
	if p.Mode != "" && p.Mode != "hub-spoke" && p.Mode != "full-mesh" {
		return errors.New(`mode must be "hub-spoke" or "full-mesh"`)
	}
	if p.WanPattern != "" {
		if _, err := regexp.Compile("(?i)" + p.WanPattern); err != nil {
			return fmt.Errorf("wan_pattern is not a valid regex: %w", err)
		}
	}
	for dev, r := range p.RoleOverrides {
		if r != WanRoleHub && r != WanRoleSpoke {
			return fmt.Errorf("role_overrides[%q] must be hub or spoke", dev)
		}
	}
	return nil
}

// ---- policy store (operator intent) — tenantKV, one row per tenant ----

type wanPolicyStore struct {
	kv *tenantKV[WanTopologyPolicy]
}

func newWanPolicyStore(path string) (*wanPolicyStore, error) {
	if path == "" {
		path = "/data/wan_policy.json"
	}
	kv, err := newTenantKV[WanTopologyPolicy](path,
		func(p WanTopologyPolicy) string { return p.TenantID },
		func(p WanTopologyPolicy) string { return "policy" }) // single row per tenant
	if err != nil {
		return nil, err
	}
	return &wanPolicyStore{kv: kv}, nil
}

// Get returns the tenant's policy (with defaults applied) — never fails closed
// to "no view": an unconfigured tenant gets the hub-spoke baseline.
func (s *wanPolicyStore) Get(tenant string, cross bool) WanTopologyPolicy {
	if p, ok := s.kv.Get(tenant, cross, "policy"); ok {
		return p.withDefaults()
	}
	return WanTopologyPolicy{TenantID: tenant, Bidirectional: true}.withDefaults()
}

func (s *wanPolicyStore) Put(p WanTopologyPolicy) error { return s.kv.Upsert(p) }

// ---- projector: registry × site roles × policy → endpoints + circuits ----

// wanResolveRole decides a device's role with full provenance. Precedence:
// operator override → explicit hub list (device) → site role → hub list (site)
// → name hint (suggested) → default spoke.
func (s *server) wanResolveRole(tenant string, cross bool, d models.Device, pol WanTopologyPolicy) (WanRole, RoleSource, string) {
	if r, ok := pol.RoleOverrides[d.ID]; ok {
		return r, RoleDeclared, "operator override"
	}
	if r, ok := pol.RoleOverrides[d.Name]; ok {
		return r, RoleDeclared, "operator override"
	}
	hubSet := map[string]bool{}
	for _, h := range pol.Hubs {
		hubSet[strings.ToLower(h)] = true
	}
	if hubSet[strings.ToLower(d.ID)] || hubSet[strings.ToLower(d.Name)] {
		return WanRoleHub, RoleDeclared, "designated hub"
	}
	// Site role (the SD-WAN site-ID analog): device inherits its site's role.
	site := ""
	if b, ok := s.deviceSites.Get(tenant, cross, d.ID); ok {
		site = b.Site
	}
	if site != "" {
		if st, ok := s.sites.Get(tenant, cross, site); ok && st.Role != "" {
			return WanRole(st.Role), RoleFromSite, "site " + site
		}
		if hubSet[strings.ToLower(site)] {
			return WanRoleHub, RoleDeclared, "designated hub site " + site
		}
	}
	// Weakest signal: name hint. Structural inference (degree/routing) is a later pass.
	if hubNameHint.MatchString(d.Name) {
		return WanRoleHub, RoleSuggested, "name suggests hub"
	}
	if spokeNameHint.MatchString(d.Name) {
		return WanRoleSpoke, RoleSuggested, "name suggests spoke"
	}
	return WanRoleSpoke, RoleDefault, "default (no hub designated)"
}

// wanProject builds the endpoint registry and the circuit mesh for a principal.
// Endpoints come from the SNMP interface-IP table (FetchIfAddrMap) joined to the
// tenant via device ownership — the same join the entity-resolver export uses,
// so a tenant only ever sees its own devices' interfaces.
func (s *server) wanProject(ctx context.Context, tenant string, cross bool) ([]WanEndpoint, []WanCircuit) {
	pol := s.wanPolicy.Get(tenant, cross)
	pat := regexp.MustCompile("(?i)" + pol.WanPattern)

	// device id → device, restricted to WAN devices visible to this principal.
	wanDev := map[string]models.Device{}
	for _, d := range s.discovery.Devices() {
		if d.ID == "" || !pat.MatchString(d.Name) {
			continue
		}
		if !cross && deviceTenant(d) != tenant {
			continue
		}
		wanDev[d.ID] = d
	}
	if len(wanDev) == 0 {
		return nil, nil
	}

	fetchIfAddr := s.wanIfAddr
	if fetchIfAddr == nil {
		fetchIfAddr = collectors.FetchIfAddrMap
	}
	ifaddr, _ := fetchIfAddr(ctx) // device → ip → ifName (empty if collector off)

	// Build endpoints per device, plus a per-device representative endpoint (the
	// measurable address the OTHER end of a circuit targets).
	byDevice := map[string][]WanEndpoint{}
	for id, d := range wanDev {
		role, rsrc, evid := s.wanResolveRole(tenant, cross, d, pol)
		site := ""
		if b, ok := s.deviceSites.Get(tenant, cross, d.ID); ok {
			site = b.Site
		}
		var eps []WanEndpoint
		for ip, ifname := range ifaddr[id] {
			eps = append(eps, WanEndpoint{
				TenantID: deviceTenant(d), Device: d.Name, Interface: ifname,
				Address: ip, Measurable: ip, Site: site,
				Role: role, RoleSource: rsrc, RoleEvidence: evid,
			})
		}
		sort.Slice(eps, func(a, b int) bool {
			if eps[a].Interface != eps[b].Interface {
				return eps[a].Interface < eps[b].Interface
			}
			return eps[a].Address < eps[b].Address
		})
		byDevice[id] = eps
	}

	var endpoints []WanEndpoint
	for _, eps := range byDevice {
		endpoints = append(endpoints, eps...)
	}
	sort.Slice(endpoints, func(a, b int) bool {
		if endpoints[a].Device != endpoints[b].Device {
			return endpoints[a].Device < endpoints[b].Device
		}
		return endpoints[a].Interface < endpoints[b].Interface
	})

	circuits := s.wanMesh(byDevice, wanDev, pol)
	return endpoints, circuits
}

// repEndpoint returns a device's representative (measurable) endpoint — the
// address the far end of a circuit targets. Default = its first interface.
func repEndpoint(eps []WanEndpoint) (WanEndpoint, bool) {
	if len(eps) == 0 {
		return WanEndpoint{}, false
	}
	return eps[0], true
}

func wanCircuitID(local, remote WanEndpoint) string {
	h := sha1.Sum([]byte(local.Device + "|" + local.Interface + "|" + remote.Device + "|" + remote.Interface))
	return "ckt-" + hex.EncodeToString(h[:6])
}

// wanMesh generates circuits from the per-device endpoints by topology policy.
// hub-spoke (default): every spoke interface ⇄ each hub (and, when bidirectional,
// every hub interface ⇄ each spoke). full-mesh: every device's interfaces ⇄ every
// other device. The far end of each circuit is the remote device's measurable
// (representative) endpoint — exactly how an SD-WAN edge probes a remote TLOC.
func (s *server) wanMesh(byDevice map[string][]WanEndpoint, wanDev map[string]models.Device, pol WanTopologyPolicy) []WanCircuit {
	roleOf := func(id string) WanRole {
		if eps := byDevice[id]; len(eps) > 0 {
			return eps[0].Role
		}
		return WanRoleSpoke
	}
	bidir := pol.Bidirectional

	seen := map[string]bool{}
	var out []WanCircuit
	add := func(local, remote WanEndpoint) {
		id := wanCircuitID(local, remote)
		if seen[id] {
			return
		}
		seen[id] = true
		out = append(out, WanCircuit{
			TenantID: local.TenantID, ID: id, Local: local, Remote: remote,
			Topology: pol.Mode, Source: "registry", Enabled: true,
		})
	}

	if pol.Mode == "full-mesh" {
		for aID, aEps := range byDevice {
			for bID, bEps := range byDevice {
				if aID == bID {
					continue
				}
				rep, ok := repEndpoint(bEps)
				if !ok {
					continue
				}
				for _, e := range aEps {
					add(e, rep)
				}
			}
		}
		return out
	}

	// hub-spoke (default)
	var hubIDs, spokeIDs []string
	for id := range byDevice {
		if roleOf(id) == WanRoleHub {
			hubIDs = append(hubIDs, id)
		} else {
			spokeIDs = append(spokeIDs, id)
		}
	}
	for _, sID := range spokeIDs {
		for _, hID := range hubIDs {
			rep, ok := repEndpoint(byDevice[hID])
			if !ok {
				continue
			}
			for _, e := range byDevice[sID] {
				add(e, rep)
			}
		}
	}
	if bidir {
		for _, hID := range hubIDs {
			for _, sID := range spokeIDs {
				rep, ok := repEndpoint(byDevice[sID])
				if !ok {
					continue
				}
				for _, e := range byDevice[hID] {
					add(e, rep)
				}
			}
		}
	}
	return out
}

// ---- HTTP handlers ----

// handleWanEndpoints: GET /api/wan/endpoints — the derived WAN endpoint registry.
func (s *server) handleWanEndpoints(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	eps, _ := s.wanProject(r.Context(), tenant, cross)
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": eps})
}

// handleWanCircuits: GET /api/wan/circuits — the derived circuit mesh.
func (s *server) handleWanCircuits(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	_, circuits := s.wanProject(r.Context(), tenant, cross)
	writeJSON(w, http.StatusOK, map[string]any{"circuits": circuits})
}

// handleWanPolicy: GET|PUT /api/wan/policy — the per-tenant topology policy.
func (s *server) handleWanPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		writeJSON(w, http.StatusOK, s.wanPolicy.Get(tenant, cross))
	case http.MethodPut:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		var req WanTopologyPolicy
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad body: " + err.Error()})
			return
		}
		tenant, _ := principalTenant(claims)
		req.TenantID = tenant // owner from the token, never the body
		req.UpdatedBy = claims.Sub
		req.UpdatedAt = time.Now().UTC()
		req = req.withDefaults()
		if err := req.validate(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := s.wanPolicy.Put(req); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, req)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}
