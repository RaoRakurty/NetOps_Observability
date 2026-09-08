// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_routing.go — the tenant's TAC ROUTING settings: who Correlix names
// on a case, which connector carries which vendor's cases, which capture runs
// on which platform, and the support-contract data a vendor checks before it
// will open anything.
//
// WHY THIS IS A SEPARATE RECORD FROM TACConnectorConfig. That record holds
// CREDENTIALS — write-only, sealed, never serialised out. This one holds
// CHOICES and ENTITLEMENT IDENTIFIERS: a contract number, a CCO-ID, the name and
// phone number of the person the vendor calls back. None of it is a secret, all
// of it is echoed back to the screen that edits it, and it changes on a
// completely different clock (a contract is renewed yearly; an API token is
// rotated). Mixing the two would mean either serialising a credential to render
// a contract number, or hiding a contract number because it shares a struct with
// a password. So they are two records with two stores and one isolation model.
//
// ISOLATION (CLAUDE.md §3a). Per-tenant data: keyed by tenant, every read and
// write scoped by the CALLER's tenant, the owner stamped from the token and
// never from the body, a cross-tenant target answered with ErrTenantNotFound so
// the subtree is not an existence oracle. It is deliberately NOT platform-global
// — one tenant's Cisco contract is not another tenant's business, and a
// platform-admin gate here would be the wrong gate in the other direction.
//
// WHAT IT IS FOR. The one-click escalation (internal/tac) reads this to arrive
// at the confirmation screen ALREADY COMPLETE: the serial and model come from
// the device record, the contract and account id come from here, the contact
// comes from here, and the connector comes from here. Everything the owner
// described as "one or two clicks" depends on this record being filled in once,
// per tenant, instead of typed into every case.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
)

// Bounds. Every one is a §9 ceiling enforced server-side.
const (
	// MaxRoutingVendors bounds how many vendors one tenant may configure.
	MaxRoutingVendors = 64
	// MaxContractOverrides bounds the per-serial override table.
	MaxContractOverrides = 2000
	// maxRoutingFieldBytes bounds one free-text field.
	maxRoutingFieldBytes = 200
)

// TACContact is the NAMED HUMAN a vendor opens the case against.
//
// Every vendor either requires or strongly prefers one, and Juniper refuses an
// alias outright (isNamedHumanEmail). Correlix never substitutes a shared
// identity: with no contact configured the escalation asks for one rather than
// filing the case under a mailbox nobody reads.
type TACContact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}

// Empty reports a contact with nothing in it.
func (c TACContact) Empty() bool {
	return strings.TrimSpace(c.Name) == "" && strings.TrimSpace(c.Email) == "" &&
		strings.TrimSpace(c.Phone) == ""
}

// VendorContract is one vendor's support agreement as this tenant holds it.
//
// The field names are deliberately generic and the LABEL is per vendor: Cisco
// calls the account id a CCO-ID, Juniper a CSP user, Arista a portal account,
// Nokia a customer id + PIN, Palo Alto a support account, Fortinet a FortiCloud
// account. One shape with a vendor-specific label beats six near-identical
// structs, and the label lives with the connector that knows it.
type VendorContract struct {
	// Vendor is the vendor id this contract belongs to ("cisco", "juniper", …).
	Vendor string `json:"vendor"`
	// ContractID is the support contract / service agreement number.
	ContractID string `json:"contract_id,omitempty"`
	// AccountID is the vendor's account identifier (Cisco CCO-ID, Juniper CSP
	// user, Arista portal account, Nokia customer id, Palo Alto support account,
	// Fortinet FortiCloud account).
	AccountID string `json:"account_id,omitempty"`
	// SiteID is the site / installation id where the vendor tracks one.
	SiteID string `json:"site_id,omitempty"`
	// SupportLevel is the tenant's own words for the entitlement tier
	// (24x7x4, NBD, Premium). Correlix does not interpret it; it travels into
	// the case so the vendor's own intake sees what was purchased.
	SupportLevel string `json:"support_level,omitempty"`
	// ExpiresOn is the coverage end date, YYYY-MM-DD. It is here so the
	// escalation can warn BEFORE a case is refused for an expired contract
	// rather than after the vendor says no.
	ExpiresOn string `json:"expires_on,omitempty"`
	// Note is the tenant's own free-text reminder (a reseller's name, a PO).
	Note string `json:"note,omitempty"`
}

// Empty reports a contract with no identifying data at all.
func (c VendorContract) Empty() bool {
	return strings.TrimSpace(c.ContractID) == "" && strings.TrimSpace(c.AccountID) == "" &&
		strings.TrimSpace(c.SiteID) == "" && strings.TrimSpace(c.SupportLevel) == "" &&
		strings.TrimSpace(c.ExpiresOn) == "" && strings.TrimSpace(c.Note) == ""
}

// Expired reports whether the contract's coverage end date is in the past. An
// unparseable or absent date is NOT expired — Correlix does not invent a
// coverage gap out of a blank field.
func (c VendorContract) Expired(now time.Time) bool {
	d := strings.TrimSpace(c.ExpiresOn)
	if d == "" {
		return false
	}
	end, err := time.Parse("2006-01-02", d)
	if err != nil {
		return false
	}
	return now.After(end.AddDate(0, 0, 1))
}

// TACRoutingConfig is ONE tenant's routing record.
type TACRoutingConfig struct {
	// Contact is the named human on every case this tenant opens.
	Contact TACContact `json:"contact"`
	// RouteByVendor maps a DEVICE VENDOR id ("cisco", "juniper", "arista", …)
	// onto the connector id that opens its cases. It is how a tenant says "our
	// Cisco cases go through Smart Bonding" or "route everything to ServiceNow".
	//
	// An unset vendor is not an error: the escalation falls back to the vendor's
	// own configured native connector, then to portal text, and SAYS which it
	// chose. A route naming an unconfigured connector is honoured and then
	// refused at the confirmation screen, by name — silently rerouting a
	// deliberate choice would teach an operator that the setting does nothing.
	RouteByVendor map[string]string `json:"route_by_vendor,omitempty"`
	// CaptureByDialect maps a CLI dialect slug onto the tenant TEMPLATE id that
	// replaces the Correlix default capture for that platform. An id this tenant
	// cannot resolve falls back to the Correlix default, and the escalation says
	// so rather than collecting nothing.
	CaptureByDialect map[string]string `json:"capture_by_dialect,omitempty"`
	// ContractByVendor is this tenant's support agreement per vendor.
	ContractByVendor map[string]VendorContract `json:"contract_by_vendor,omitempty"`
	// ContractBySerial overrides ContractByVendor for ONE device, keyed by its
	// serial number. Several vendors entitle per serial rather than per account,
	// so a customer with two Cisco contracts needs to say which one covers which
	// chassis. The serial is the key because it is what the vendor checks.
	ContractBySerial map[string]VendorContract `json:"contract_by_serial,omitempty"`
}

// IsEmpty reports a record holding nothing, so a tenant that clears its last
// setting reads exactly like a tenant that never made one.
func (c TACRoutingConfig) IsEmpty() bool {
	return c.Contact.Empty() && len(c.RouteByVendor) == 0 && len(c.CaptureByDialect) == 0 &&
		len(c.ContractByVendor) == 0 && len(c.ContractBySerial) == 0
}

// ContractFor resolves the contract that covers one device: the per-serial
// override when there is one, otherwise the vendor's own row.
//
// The serial wins because it is the more specific statement — a customer who
// wrote down "this chassis is on contract X" meant that chassis.
func (c TACRoutingConfig) ContractFor(vendor, serial string) (VendorContract, bool) {
	if s := strings.TrimSpace(serial); s != "" {
		if v, ok := c.ContractBySerial[normalizeSerialKey(s)]; ok && !v.Empty() {
			return v, true
		}
	}
	if v, ok := c.ContractByVendor[normalizeVendorKey(vendor)]; ok && !v.Empty() {
		return v, true
	}
	return VendorContract{}, false
}

// RouteFor returns the connector this tenant chose for a vendor, if any.
func (c TACRoutingConfig) RouteFor(vendor string) (string, bool) {
	id, ok := c.RouteByVendor[normalizeVendorKey(vendor)]
	id = strings.TrimSpace(id)
	return id, ok && id != ""
}

// CaptureFor returns the template id this tenant prefers for a dialect, if any.
func (c TACRoutingConfig) CaptureFor(dialect string) (string, bool) {
	id, ok := c.CaptureByDialect[normalizeVendorKey(dialect)]
	id = strings.TrimSpace(id)
	return id, ok && id != ""
}

// normalizeVendorKey folds a vendor/dialect id to its storage form.
func normalizeVendorKey(v string) string { return strings.ToLower(strings.TrimSpace(v)) }

// normalizeSerialKey folds a serial to its storage form. Serials are printed in
// mixed case on labels and typed in either, and a lookup that missed because of
// that would silently lose a contract the customer configured.
func normalizeSerialKey(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

// ── validation ──────────────────────────────────────────────────────────────

// ValidateTACRoutingConfig checks one tenant's whole record. Everything here is
// operator-supplied text, so every field is bounded and every map is capped
// (§3 validate at the boundary, §9 bounded).
func ValidateTACRoutingConfig(c TACRoutingConfig, knownConnector func(string) bool) error {
	if e := strings.TrimSpace(c.Contact.Email); e != "" && !strings.Contains(e, "@") {
		return errors.New("contact: email must be an address")
	}
	for _, f := range []struct{ name, value string }{
		{"contact name", c.Contact.Name},
		{"contact email", c.Contact.Email},
		{"contact phone", c.Contact.Phone},
	} {
		if len(f.value) > maxRoutingFieldBytes {
			return fmt.Errorf("%s must be at most %d characters", f.name, maxRoutingFieldBytes)
		}
	}
	if len(c.RouteByVendor) > MaxRoutingVendors {
		return fmt.Errorf("at most %d vendor routes", MaxRoutingVendors)
	}
	// Ordered, not a map range: the same bad record must report the same field
	// every time, or an operator fixing one at a time chases a moving error.
	for _, vendor := range sortedKeys(c.RouteByVendor) {
		id := strings.TrimSpace(c.RouteByVendor[vendor])
		if id == "" {
			continue
		}
		if knownConnector != nil && !knownConnector(id) {
			return fmt.Errorf("route for %q names connector %q, which this platform does not have", vendor, id)
		}
	}
	if len(c.CaptureByDialect) > MaxRoutingVendors {
		return fmt.Errorf("at most %d preferred captures", MaxRoutingVendors)
	}
	for _, dialect := range sortedKeys(c.CaptureByDialect) {
		if len(c.CaptureByDialect[dialect]) > maxRoutingFieldBytes {
			return fmt.Errorf("preferred capture for %q: id must be at most %d characters", dialect, maxRoutingFieldBytes)
		}
	}
	if len(c.ContractByVendor) > MaxRoutingVendors {
		return fmt.Errorf("at most %d vendor contracts", MaxRoutingVendors)
	}
	for _, vendor := range sortedContractKeys(c.ContractByVendor) {
		if err := validateVendorContract(vendor, c.ContractByVendor[vendor]); err != nil {
			return err
		}
	}
	if len(c.ContractBySerial) > MaxContractOverrides {
		return fmt.Errorf("at most %d per-device contract overrides", MaxContractOverrides)
	}
	for _, serial := range sortedContractKeys(c.ContractBySerial) {
		if len(serial) > 64 {
			return errors.New("a device serial key must be at most 64 characters")
		}
		if err := validateVendorContract("serial "+serial, c.ContractBySerial[serial]); err != nil {
			return err
		}
	}
	return nil
}

func validateVendorContract(what string, v VendorContract) error {
	for _, f := range []struct{ name, value string }{
		{"contract_id", v.ContractID},
		{"account_id", v.AccountID},
		{"site_id", v.SiteID},
		{"support_level", v.SupportLevel},
		{"note", v.Note},
	} {
		if len(f.value) > maxRoutingFieldBytes {
			return fmt.Errorf("%s: %s must be at most %d characters", what, f.name, maxRoutingFieldBytes)
		}
	}
	if d := strings.TrimSpace(v.ExpiresOn); d != "" {
		if _, err := time.Parse("2006-01-02", d); err != nil {
			return fmt.Errorf("%s: expires_on must be YYYY-MM-DD", what)
		}
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedContractKeys(m map[string]VendorContract) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// normalize folds every key and trims every value, so what is stored is what a
// lookup will find regardless of how it was typed.
func (c TACRoutingConfig) normalize() TACRoutingConfig {
	out := TACRoutingConfig{Contact: TACContact{
		Name:  strings.TrimSpace(c.Contact.Name),
		Email: strings.TrimSpace(c.Contact.Email),
		Phone: strings.TrimSpace(c.Contact.Phone),
	}}
	if len(c.RouteByVendor) > 0 {
		out.RouteByVendor = map[string]string{}
		for k, v := range c.RouteByVendor {
			if key, val := normalizeVendorKey(k), strings.TrimSpace(v); key != "" && val != "" {
				out.RouteByVendor[key] = val
			}
		}
	}
	if len(c.CaptureByDialect) > 0 {
		out.CaptureByDialect = map[string]string{}
		for k, v := range c.CaptureByDialect {
			if key, val := normalizeVendorKey(k), strings.TrimSpace(v); key != "" && val != "" {
				out.CaptureByDialect[key] = val
			}
		}
	}
	if len(c.ContractByVendor) > 0 {
		out.ContractByVendor = map[string]VendorContract{}
		for k, v := range c.ContractByVendor {
			key := normalizeVendorKey(k)
			v = v.normalize(key)
			if key != "" && !v.Empty() {
				out.ContractByVendor[key] = v
			}
		}
	}
	if len(c.ContractBySerial) > 0 {
		out.ContractBySerial = map[string]VendorContract{}
		for k, v := range c.ContractBySerial {
			key := normalizeSerialKey(k)
			v = v.normalize(normalizeVendorKey(v.Vendor))
			if key != "" && !v.Empty() {
				out.ContractBySerial[key] = v
			}
		}
	}
	return out
}

func (c VendorContract) normalize(vendor string) VendorContract {
	return VendorContract{
		Vendor:       vendor,
		ContractID:   strings.TrimSpace(c.ContractID),
		AccountID:    strings.TrimSpace(c.AccountID),
		SiteID:       strings.TrimSpace(c.SiteID),
		SupportLevel: strings.TrimSpace(c.SupportLevel),
		ExpiresOn:    strings.TrimSpace(c.ExpiresOn),
		Note:         strings.TrimSpace(c.Note),
	}
}

// ── the tenant-keyed store ──────────────────────────────────────────────────

// tacRoutingFile is the persisted, versioned envelope.
type tacRoutingFile struct {
	Version int                         `json:"version"`
	Tenants map[string]TACRoutingConfig `json:"tenants"`
}

// TACRoutingStore is the per-tenant CRUD store. Every method takes the CALLER's
// resolved scope (tenant, cross) and never derives scope from a body (§3a.2).
type TACRoutingStore struct {
	mu   sync.RWMutex
	path string
	cfgs map[string]TACRoutingConfig
}

// NewTACRoutingStore loads the persisted per-tenant map. An unreadable store is
// LOUD, not silently "fresh" (§10) — a tenant whose contracts vanished must not
// look like a tenant that never had any.
func NewTACRoutingStore(path string) *TACRoutingStore {
	s := &TACRoutingStore{path: path, cfgs: map[string]TACRoutingConfig{}}
	b, err := platformdb.Load(path)
	switch {
	case errors.Is(err, os.ErrNotExist), len(b) == 0 && err == nil:
		return s
	case err != nil:
		applog.Error("tac-routing", "stored TAC routing config unreadable — starting empty; a save will OVERWRITE it",
			map[string]any{"err": err.Error()})
		return s
	}
	var f tacRoutingFile
	if json.Unmarshal(b, &f) != nil || f.Tenants == nil {
		applog.Error("tac-routing", "stored TAC routing config is not the expected envelope — starting empty", nil)
		return s
	}
	for k, v := range f.Tenants {
		s.cfgs[ITSMKey(k)] = v.normalize()
	}
	return s
}

// NewTACRoutingStoreForTest builds an unpersisted store (tests only).
func NewTACRoutingStoreForTest() *TACRoutingStore {
	return &TACRoutingStore{cfgs: map[string]TACRoutingConfig{}}
}

// Get returns the tenant's routing record. A tenant with no row gets the ZERO
// record and ok=false — "nothing configured" is a state with a next step, not
// an error, and every caller of this reads it that way.
//
// A NON-CROSS caller asking for another tenant gets ErrTenantNotFound, which the
// HTTP layer maps to 404: another tenant's row is never confirmed to exist.
func (s *TACRoutingStore) Get(tenant string, cross bool, target string) (TACRoutingConfig, bool, error) {
	key, err := s.scope(tenant, cross, target)
	if err != nil {
		return TACRoutingConfig{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg, ok := s.cfgs[key]
	return cfg, ok, nil
}

// Set validates and stores one tenant's record. The OWNER is stamped from the
// caller's scope, never from the payload.
func (s *TACRoutingStore) Set(tenant string, cross bool, target string, in TACRoutingConfig,
	knownConnector func(string) bool) (TACRoutingConfig, error) {
	key, err := s.scope(tenant, cross, target)
	if err != nil {
		return TACRoutingConfig{}, err
	}
	next := in.normalize()
	if verr := ValidateTACRoutingConfig(next, knownConnector); verr != nil {
		return TACRoutingConfig{}, verr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.cfgs[key]
	if next.IsEmpty() {
		delete(s.cfgs, key)
	} else {
		s.cfgs[key] = next
	}
	if perr := s.persist(); perr != nil {
		if had {
			s.cfgs[key] = prev // keep memory and storage consistent
		} else {
			delete(s.cfgs, key)
		}
		return TACRoutingConfig{}, perr
	}
	return next, nil
}

// Delete removes one tenant's record.
func (s *TACRoutingStore) Delete(tenant string, cross bool, target string) error {
	key, err := s.scope(tenant, cross, target)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.cfgs[key]
	if !ok {
		return ErrTenantNotFound
	}
	delete(s.cfgs, key)
	if perr := s.persist(); perr != nil {
		s.cfgs[key] = prev
		return perr
	}
	return nil
}

// Tenants lists the configured tenant keys visible to the caller, sorted. A
// non-cross caller sees at most its own.
func (s *TACRoutingStore) Tenants(tenant string, cross bool) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	own := ITSMKey(tenant)
	out := make([]string, 0, len(s.cfgs))
	for k := range s.cfgs {
		if !cross && k != own {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// scope is the single isolation gate: caller scope + requested target → storage
// key, or a refusal. Default-closed.
func (s *TACRoutingStore) scope(tenant string, cross bool, target string) (string, error) {
	own := ITSMKey(tenant)
	want := ITSMKey(target)
	if strings.TrimSpace(target) == "" {
		want = own
	}
	if cross {
		return want, nil
	}
	if want != own {
		return "", ErrTenantNotFound
	}
	return own, nil
}

// persist writes the whole map. Caller holds s.mu.
func (s *TACRoutingStore) persist() error {
	if s.path == "" {
		return nil // ForTest store: in-memory only
	}
	b, err := json.Marshal(tacRoutingFile{Version: 1, Tenants: s.cfgs})
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}
