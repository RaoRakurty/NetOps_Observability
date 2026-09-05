package ticketing

// caseconn_registry.go — one registry mapping a vendor/ITSM id onto its
// connector and its declared capabilities.
//
// This is the single place the UI and W1's TAC routes ask "what can Correlix
// actually do for this vendor?". Registration is explicit and closed: a vendor
// that is not registered does not silently appear, and a registered one always
// answers with a capability row even when it can do nothing (the Tier-3
// PortalOnly connectors exist precisely so the answer is "no API, here is the
// portal and its field list" rather than silence).
//
// ═══════════════════════════════════════════════════════════════════════════
// ADAPTER POINT FOR W1 (internal/tac/caseopener.go)
//
// CaseConnector here is the same shape as internal/tac.CaseOpener. When W1's
// file lands, internal/tac adapts with a wrapper of this form — in package tac,
// so internal/ticketing keeps its zero dependency on internal/tac:
//
//	type ticketingOpener struct{ c ticketing.CaseConnector }
//	func (o ticketingOpener) Name() string  { return o.c.Name() }
//	func (o ticketingOpener) Capabilities() tac.Caps { return tac.Caps{ ... } }  // field-for-field
//	func (o ticketingOpener) CreateCase(ctx context.Context, cfg tac.Config, req tac.CaseRequest) (tac.CaseRef, error) {
//	        ref, err := o.c.CreateCase(ctx, cfg.Ticketing, toTicketingRequest(req)); ...
//	}
//	// … AttachBundle / FetchCase / AddNote the same way.
//
// and the route layer builds its opener list from
// DefaultCaseConnectorRegistry().ForVendor(vendorID). If W1's Caps carries
// exactly the fields in the research's §6 matrix (it is written from the same
// table) the mapping is a struct copy.
// ═══════════════════════════════════════════════════════════════════════════

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ConnectorTier ranks a connector by what it costs the customer to enable.
type ConnectorTier int

const (
	// TierITSM: works today with credentials the customer already has.
	TierITSM ConnectorTier = 1
	// TierVendorAPI: a real vendor API behind a per-customer onboarding project.
	TierVendorAPI ConnectorTier = 2
	// TierPortal: no API exists; Correlix automates everything up to submission.
	TierPortal ConnectorTier = 3
)

// ConnectorEntry is one registry row.
type ConnectorEntry struct {
	// ID is the registry key: "servicenow", "jira", "cisco-cxd",
	// "cisco-smart-bonding", "juniper", "email-arista", "portal-nokia", …
	ID string `json:"id"`
	// Vendor is the vendor/system this connector serves ("cisco", "arista",
	// "servicenow"). Several connectors can serve one vendor — Cisco has three.
	Vendor string        `json:"vendor"`
	Tier   ConnectorTier `json:"tier"`
	Caps   Caps          `json:"capabilities"`
	// Connector is the live implementation.
	Connector CaseConnector `json:"-"`
}

// CaseConnectorRegistry is the closed connector map.
type CaseConnectorRegistry struct {
	mu      sync.RWMutex
	entries map[string]ConnectorEntry
	order   []string
}

// NewCaseConnectorRegistry builds an empty registry.
func NewCaseConnectorRegistry() *CaseConnectorRegistry {
	return &CaseConnectorRegistry{entries: map[string]ConnectorEntry{}}
}

// Register adds a connector. A duplicate id is an error, not a silent
// overwrite: two connectors answering to one id would make the capability
// matrix a lie.
func (r *CaseConnectorRegistry) Register(vendor string, tier ConnectorTier, c CaseConnector) error {
	if c == nil {
		return fmt.Errorf("connector registry: nil connector for vendor %q", vendor)
	}
	id := c.Name()
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.entries[id]; dup {
		return fmt.Errorf("connector registry: %q is already registered", id)
	}
	r.entries[id] = ConnectorEntry{
		ID: id, Vendor: strings.ToLower(strings.TrimSpace(vendor)),
		Tier: tier, Caps: c.Capabilities(), Connector: c,
	}
	r.order = append(r.order, id)
	sort.Strings(r.order)
	return nil
}

// Get resolves one connector by registry id.
func (r *CaseConnectorRegistry) Get(id string) (ConnectorEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[strings.ToLower(strings.TrimSpace(id))]
	return e, ok
}

// ForVendor lists every connector serving a vendor, cheapest tier first. Cisco
// returns CXD before Smart Bonding on purpose: attach-to-existing needs only an
// SR number and a token the admin can copy, while create needs an onboarding
// project (research §4.4, "attach first").
func (r *CaseConnectorRegistry) ForVendor(vendor string) []ConnectorEntry {
	want := strings.ToLower(strings.TrimSpace(vendor))
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []ConnectorEntry
	for _, id := range r.order {
		if e := r.entries[id]; e.Vendor == want {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Tier < out[j].Tier })
	return out
}

// Matrix returns every row, sorted by tier then id — the capability matrix the
// UI renders and W1's CaseOpener list is built from.
func (r *CaseConnectorRegistry) Matrix() []ConnectorEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ConnectorEntry, 0, len(r.entries))
	for _, id := range r.order {
		out = append(out, r.entries[id])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Tier != out[j].Tier {
			return out[i].Tier < out[j].Tier
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Vendors lists every vendor with at least one connector, sorted.
func (r *CaseConnectorRegistry) Vendors() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := map[string]struct{}{}
	for _, e := range r.entries {
		seen[e.Vendor] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// DefaultCaseConnectorRegistry builds the registry every deployment gets. It
// constructs connectors with production HTTP clients; tests build their own
// registry with injected fakes.
//
// It panics on a registration error because the only way to reach one is a
// duplicate id in this function — a programming mistake in a table that is
// evaluated once at start-up, not a runtime condition.
func DefaultCaseConnectorRegistry() *CaseConnectorRegistry {
	r := NewCaseConnectorRegistry()
	must := func(err error) {
		if err != nil {
			panic("tac connector registry: " + err.Error())
		}
	}

	// Tier 1 — ITSM, works with credentials the customer already has.
	must(r.Register("servicenow", TierITSM, NewServiceNowCaseConnector(nil)))
	must(r.Register("jira", TierITSM, NewJiraCaseConnector(nil)))

	// Tier 1 — email, the universal fallback and the ONLY path for Arista.
	for _, vendorID := range EmailVendorIDs() {
		c, err := NewEmailCaseConnector(vendorID)
		must(err)
		must(r.Register(vendorID, TierITSM, c))
	}

	// Tier 2 — the two vendors with a real create+attach API. CXD first.
	must(r.Register("cisco", TierVendorAPI, NewCiscoCXDConnector(nil)))
	must(r.Register("cisco", TierVendorAPI, NewCiscoSmartBondingConnector(nil)))
	must(r.Register("juniper", TierVendorAPI, NewJuniperConnector(nil)))

	// Tier 3 — no API exists. Registered so the UI can say so honestly.
	for _, vendorID := range PortalVendorIDs() {
		c, err := NewPortalOnlyConnector(vendorID)
		must(err)
		must(r.Register(vendorID, TierPortal, c))
	}
	return r
}
