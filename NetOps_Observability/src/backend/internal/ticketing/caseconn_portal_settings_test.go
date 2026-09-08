// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

import (
	"errors"
	"strings"
	"testing"

	"netops/backend/internal/tac"
)

// caseconn_portal_settings_test.go — the MANUAL vendor path's own settings.
//
// The owner's rule (2026-09-08): Administration → Ticket delivery is where a
// customer configures vendor portals; Troubleshooting is where they open the
// case. These tests pin the half that lives on the settings side — the block
// exists, it is per vendor, it holds no credential, and the two fields that
// leave this package as something dangerous (a link, a regex) are validated
// before they are stored.

func TestPortalSaveIsPerVendorAndTouchesNoOtherRow(t *testing.T) {
	prev := TACConnectorConfig{Portals: map[string]PortalConnectorConfig{
		"portal-fortinet": {Enabled: true, PortalURL: "https://support.fortinet.example/", SupportAccount: "FTNT-1"},
	}}
	body := []byte(`{"enabled":true,"portal_url":"https://customer.nokia.example/support",` +
		`"support_mailbox":"tac@nokia.example","support_account":"NOK-99","case_number_pattern":"TSR\\d{6}"}`)
	out, err := ApplyPortalWrite("portal-nokia", body, prev)
	if err != nil {
		t.Fatalf("a complete portal form must save: %v", err)
	}
	got := out.Portals["portal-nokia"]
	if got.PortalURL != "https://customer.nokia.example/support" || got.SupportAccount != "NOK-99" {
		t.Errorf("the saved row is not what was sent: %+v", got)
	}
	if got.SupportMailbox != "tac@nokia.example" || got.CaseNumberPattern != `TSR\d{6}` {
		t.Errorf("the saved row is not what was sent: %+v", got)
	}
	// Saving Nokia must not disturb Fortinet.
	if out.Portals["portal-fortinet"].SupportAccount != "FTNT-1" {
		t.Errorf("another vendor's row was changed: %+v", out.Portals["portal-fortinet"])
	}
	// And the previous record is untouched (the store applies a COPY).
	if len(prev.Portals) != 1 {
		t.Errorf("the write mutated the previous record: %+v", prev.Portals)
	}

	left, err := ClearPortalSection("portal-nokia", out)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, still := left.Portals["portal-nokia"]; still {
		t.Error("remove must take the row away")
	}
	if left.Portals["portal-fortinet"].SupportAccount != "FTNT-1" {
		t.Error("removing one vendor must never take another's with it")
	}
}

func TestPortalFormRefusesAFieldItDoesNotHave(t *testing.T) {
	// §3 fail-closed: a form cannot smuggle a field belonging to another block.
	_, err := ApplyPortalWrite("portal-nokia", []byte(`{"enabled":true,"portal_url":"https://a.example/","password":"x"}`), TACConnectorConfig{})
	if err == nil {
		t.Fatal("an unknown field must be refused, not ignored")
	}
	// And a write aimed at something that is not a portal is refused by name.
	if _, err := ApplyPortalWrite("servicenow", []byte(`{"enabled":true}`), TACConnectorConfig{}); !errors.Is(err, ErrNoSettings) {
		t.Errorf("a non-portal id must be refused, got %v", err)
	}
	if _, err := ClearPortalSection("servicenow", TACConnectorConfig{}); !errors.Is(err, ErrNoSettings) {
		t.Errorf("a non-portal id must be refused, got %v", err)
	}
}

// The portal URL becomes an href with target=_blank on an incident screen. Every
// shape that makes an href dangerous is refused HERE, once, at the boundary.
func TestPortalURLIsRefusedUnlessItIsASafeLink(t *testing.T) {
	for _, bad := range []string{
		"", "   ",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
		"customer.nokia.example/support", // no scheme at all
		"https://",                       // no host
		"https://user:pass@portal.example/",
	} {
		if err := ValidatePortalURL(bad); err == nil {
			t.Errorf("%q must never become a link on an incident screen", bad)
		}
	}
	for _, ok := range []string{
		"https://customer.nokia.example/support/s/",
		"http://tac.internal.example:8443/cases",
	} {
		if err := ValidatePortalURL(ok); err != nil {
			t.Errorf("%q is a legitimate portal address: %v", ok, err)
		}
	}
	// An ENABLED row without a usable address is refused; a disabled one is not
	// validated at all, so a path can be switched off without first repairing it.
	if err := ValidatePortalConnectorConfig("portal-nokia", PortalConnectorConfig{Enabled: true}); err == nil {
		t.Error("an enabled portal path must name where the case is opened")
	}
	if err := ValidatePortalConnectorConfig("portal-nokia", PortalConnectorConfig{PortalURL: "not a url"}); err != nil {
		t.Errorf("a disabled row is not validated: %v", err)
	}
	// A mailbox, when there is one, must be an address.
	bad := PortalConnectorConfig{Enabled: true, PortalURL: "https://a.example/", SupportMailbox: "not-an-address"}
	if err := ValidatePortalConnectorConfig("portal-nokia", bad); err == nil {
		t.Error("a support mailbox that is not an address must be refused")
	}
}

func TestPortalCaseNumberPatternIsValidatedBeforeItIsStored(t *testing.T) {
	_, err := ApplyPortalWrite("portal-nokia",
		[]byte(`{"enabled":true,"portal_url":"https://a.example/","support_mailbox":"","support_account":"","case_number_pattern":"([unclosed"}`),
		TACConnectorConfig{})
	if err == nil {
		t.Fatal("a pattern that cannot compile must be refused at save time")
	}
	if !errors.Is(err, tac.ErrCaseNumberPattern) {
		t.Errorf("the refusal must name the pattern as the cause, got %v", err)
	}
	if !strings.Contains(err.Error(), "portal-nokia") {
		t.Errorf("the refusal must name the connector, got %q", err)
	}
}

// The form opens on the vendor's published portal so nobody has to research it —
// and the tenant's own value wins the moment they save one.
func TestPortalSettingsFallBackToThePublishedDefaultAndAreOverridden(t *testing.T) {
	def := PortalSettingsFor("portal-nokia", TACConnectorConfig{})
	if def.Enabled {
		t.Error("a default is a starting point, not a configured path")
	}
	if def.PortalURL != "https://customer.nokia.com/support/s/" {
		t.Errorf("the form must open on the vendor's published portal, got %q", def.PortalURL)
	}
	if def.CaseNumberPattern != tac.DefaultCaseNumberPattern {
		t.Errorf("the default shape must be offered, got %q", def.CaseNumberPattern)
	}
	own := PortalSettingsFor("portal-nokia", TACConnectorConfig{Portals: map[string]PortalConnectorConfig{
		"portal-nokia": {Enabled: true, PortalURL: "https://partner.example/tac"},
	}})
	if own.PortalURL != "https://partner.example/tac" {
		t.Errorf("the tenant's own address must win, got %q", own.PortalURL)
	}
	if own.CaseNumberPattern != tac.DefaultCaseNumberPattern {
		t.Errorf("a field they left blank keeps the default, got %q", own.CaseNumberPattern)
	}
}

// A manual path is NOT ready until the customer has brought its details — the
// state the owner caught reading "Ready" on every deployment.
func TestPortalConnectorIsNotConfiguredUntilItsDetailsAreBrought(t *testing.T) {
	c, err := NewPortalOnlyConnector("nokia")
	if err != nil {
		t.Fatal(err)
	}
	if verr := c.ValidateConfig(TACConnectorConfig{}); verr == nil {
		t.Fatal("a fresh tenant has brought nothing and the path must say so")
	} else if !strings.Contains(verr.Error(), "Ticket delivery") {
		t.Errorf("the refusal must say where the details are brought, got %q", verr)
	}
	ok := TACConnectorConfig{Portals: map[string]PortalConnectorConfig{
		"portal-nokia": {Enabled: true, PortalURL: "https://customer.nokia.example/"},
	}}
	if verr := c.ValidateConfig(ok); verr != nil {
		t.Errorf("a configured manual path is usable: %v", verr)
	}
	if !c.PortalOnly() {
		t.Error("a Tier-3 connector must declare itself portal-only")
	}
	if c.VendorDisplayName() != "Nokia" {
		t.Errorf("the vendor's own name is what the row says, got %q", c.VendorDisplayName())
	}
	// The scoping parenthetical is research, not a row's words.
	h, err := NewPortalOnlyConnector("huawei")
	if err != nil {
		t.Fatal(err)
	}
	if h.VendorDisplayName() != "Huawei" {
		t.Errorf("a scoped display name must shorten for a sentence, got %q", h.VendorDisplayName())
	}
}

// The whole record must still validate, and a bad portal row must be caught by
// the record-level validator the store calls — not only by the form.
func TestRecordValidationCoversEveryPortalRow(t *testing.T) {
	c := TACConnectorConfig{Portals: map[string]PortalConnectorConfig{
		"portal-nokia":    {Enabled: true, PortalURL: "https://a.example/"},
		"portal-fortinet": {Enabled: true, PortalURL: "javascript:alert(1)"},
	}}
	if err := ValidateTACConnectorConfig(c); err == nil {
		t.Fatal("a stored row that would become a dangerous link must be refused")
	}
	// A record holding only portal rows is not empty, so the store keeps it.
	if (TACConnectorConfig{Portals: map[string]PortalConnectorConfig{"portal-nokia": {Enabled: true}}}).IsEmpty() {
		t.Error("a record holding a portal row is not empty")
	}
	if !(TACConnectorConfig{}).IsEmpty() {
		t.Error("a record holding nothing is empty")
	}
}

// A portal row holds nothing write-only, so it round-trips whole.
func TestPortalRowsSurviveRedaction(t *testing.T) {
	c := TACConnectorConfig{Portals: map[string]PortalConnectorConfig{
		"portal-nokia": {Enabled: true, PortalURL: "https://a.example/", SupportAccount: "NOK-99"},
	}}
	red := c.Redacted()
	if red.Portals["portal-nokia"].SupportAccount != "NOK-99" {
		t.Error("a portal row carries no secret and must come back whole")
	}
	if len(SectionSecretNames(SectionPortal)) != 0 {
		t.Error("the portal section must declare no secrets")
	}
}
