// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_portal_settings.go — the settings block a MANUAL vendor path holds.
//
// WHY A PORTAL NEEDS SETTINGS AT ALL. Until now the Tier-3 vendors were the one
// group of connectors with nothing to configure, on the reasoning that "there is
// no API, so there is no credential". That reasoning was half right: there is no
// credential, and there are still four facts only the customer knows —
//
//	portal_url           WHICH portal this customer opens cases in. Nokia's
//	                     published address is a default, not a fact: partners,
//	                     regions and managed-service contracts route elsewhere.
//	support_mailbox      the desk that also accepts a case by mail, when the
//	                     customer's contract gives them one. Optional, because
//	                     most do not.
//	support_account      the customer number / support account the portal's own
//	                     wizard asks for on its first screen.
//	case_number_pattern  what a case number for this vendor looks like, so the
//	                     number typed back in is checked at the keyboard.
//
// — and without them the escalation step could only ever hand an operator a
// generic link and hope. The owner's rule (2026-09-08): Administration → Ticket
// delivery is where a customer configures vendor portals; Troubleshooting is
// where they open the case. This block is the first half of that.
//
// NO SECRETS LIVE HERE. Every field is plain text a person could read off their
// own portal, so the write-only tri-state machinery the credential blocks need
// does not apply and is deliberately absent: a portal form round-trips exactly
// what it stores.
//
// §3 zero trust: portal_url is operator input that becomes a LINK on an incident
// screen. It is validated to an absolute http(s) URL with a host and no
// user-info before it is stored, so no javascript:, data: or credential-bearing
// address can ever reach a browser through this field.

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"

	"netops/backend/internal/tac"
)

// PortalConnectorConfig is one vendor's stored manual-path settings.
type PortalConnectorConfig struct {
	// Enabled marks the path as configured for this tenant. A row that exists
	// but is switched off reads exactly like no row: the operator is told to
	// bring the details, not shown a half-built path.
	Enabled bool `json:"enabled"`
	// PortalURL is where the case is opened. Required when Enabled.
	PortalURL string `json:"portal_url,omitempty"`
	// SupportMailbox is the desk that also takes a case by mail. Optional.
	SupportMailbox string `json:"support_mailbox,omitempty"`
	// SupportAccount is the customer/support account the portal asks for.
	SupportAccount string `json:"support_account,omitempty"`
	// CaseNumberPattern is the shape a case number for this vendor takes.
	// Empty means tac.DefaultCaseNumberPattern.
	CaseNumberPattern string `json:"case_number_pattern,omitempty"`
}

// IsZero reports an untouched block, so the record can drop it rather than keep
// a shell that reads differently from a fresh tenant.
func (p PortalConnectorConfig) IsZero() bool { return p == PortalConnectorConfig{} }

// portalFieldLimit bounds each plain field (§9). Generous for a URL, far below
// anything that could bloat a tenant's record.
const portalFieldLimit = 300

// PortalConnectorWrite is the wire form. It is field-for-field the stored block
// because there is no secret to hide and nothing to merge — but it stays a
// separate type so DisallowUnknownFields is a contract rather than a
// coincidence, exactly as the credential forms do it.
type PortalConnectorWrite struct {
	Enabled           bool   `json:"enabled"`
	PortalURL         string `json:"portal_url"`
	SupportMailbox    string `json:"support_mailbox"`
	SupportAccount    string `json:"support_account"`
	CaseNumberPattern string `json:"case_number_pattern"`
}

func (w PortalConnectorWrite) apply(PortalConnectorConfig) PortalConnectorConfig {
	return PortalConnectorConfig{
		Enabled:           w.Enabled,
		PortalURL:         strings.TrimSpace(w.PortalURL),
		SupportMailbox:    strings.TrimSpace(w.SupportMailbox),
		SupportAccount:    strings.TrimSpace(w.SupportAccount),
		CaseNumberPattern: strings.TrimSpace(w.CaseNumberPattern),
	}
}

// DefaultPortalConnectorConfig is what the form OPENS on for a tenant that has
// configured nothing: the vendor's published portal address from the Tier-3
// research table and the default case-number shape. It is a starting point the
// customer overrides, never a claim that this is where their cases go — which is
// why Enabled is false and the connector stays "Not configured" until a person
// saves it.
func DefaultPortalConnectorConfig(connectorID string) PortalConnectorConfig {
	out := PortalConnectorConfig{CaseNumberPattern: tac.DefaultCaseNumberPattern}
	if v, ok := PortalVendorFor(portalVendorID(connectorID)); ok {
		out.PortalURL = v.PortalURL
	}
	return out
}

// portalVendorID turns a connector id into the Tier-3 vendor key
// ("portal-nokia" → "nokia"). A id that is not a portal id yields "".
func portalVendorID(connectorID string) string {
	key := strings.ToLower(strings.TrimSpace(connectorID))
	if !strings.HasPrefix(key, "portal-") {
		return ""
	}
	return strings.TrimPrefix(key, "portal-")
}

// ValidatePortalConnectorConfig checks one vendor's block. A DISABLED block is
// not validated at all (opt-in, exactly like every other connector), so a tenant
// can switch a path off without first repairing a field they no longer use.
func ValidatePortalConnectorConfig(connectorID string, c PortalConnectorConfig) error {
	name := connectorID
	if name == "" {
		name = "portal"
	}
	if len(c.PortalURL) > portalFieldLimit || len(c.SupportMailbox) > portalFieldLimit ||
		len(c.SupportAccount) > portalFieldLimit {
		return fmt.Errorf("%s: a portal field is longer than %d characters", name, portalFieldLimit)
	}
	if _, err := tac.CompileCaseNumberPattern(c.CaseNumberPattern); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if !c.Enabled {
		return nil
	}
	if err := ValidatePortalURL(c.PortalURL); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if c.SupportMailbox != "" {
		if _, err := mail.ParseAddress(c.SupportMailbox); err != nil {
			return fmt.Errorf("%s: %q is not an email address", name, c.SupportMailbox)
		}
	}
	return nil
}

// ErrPortalURL is the refusal for an address that must not become a link.
var ErrPortalURL = errors.New("the portal address must be an https:// or http:// link")

// ValidatePortalURL is the ONE place the link rule is written. The escalation
// screen renders this value as an href with target=_blank, so everything that
// makes an href dangerous is refused here, at the boundary, once.
func ValidatePortalURL(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return fmt.Errorf("%w: it is empty", ErrPortalURL)
	}
	if len(s) > portalFieldLimit {
		return fmt.Errorf("%w: it is longer than %d characters", ErrPortalURL, portalFieldLimit)
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrPortalURL, err.Error())
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("%w: %q is not one", ErrPortalURL, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: it names no host", ErrPortalURL)
	}
	if u.User != nil {
		// A sign-in embedded in a URL is a credential in a plain-text field and
		// a credential in a browser's history. It is refused rather than
		// stripped: silently changing what an administrator saved is worse.
		return fmt.Errorf("%w: it must not carry a sign-in", ErrPortalURL)
	}
	return nil
}

// PortalSettingsFor resolves one connector's EFFECTIVE manual-path settings:
// what the tenant stored, with the vendor's published default filling anything
// they left blank. It is what both the connector's declaration and the case form
// read, so the step and the settings screen can never disagree.
func PortalSettingsFor(connectorID string, cfg TACConnectorConfig) PortalConnectorConfig {
	out := DefaultPortalConnectorConfig(connectorID)
	stored, ok := cfg.Portals[strings.ToLower(strings.TrimSpace(connectorID))]
	if !ok {
		return out
	}
	out.Enabled = stored.Enabled
	if stored.PortalURL != "" {
		out.PortalURL = stored.PortalURL
	}
	if stored.SupportMailbox != "" {
		out.SupportMailbox = stored.SupportMailbox
	}
	if stored.SupportAccount != "" {
		out.SupportAccount = stored.SupportAccount
	}
	if stored.CaseNumberPattern != "" {
		out.CaseNumberPattern = stored.CaseNumberPattern
	}
	return out
}

// NotConfiguredPortalNote is the state a tenant with no portal details is in. It
// names the four facts and where they are brought, because unlike a credential
// there is nothing to obtain from a vendor first.
const NotConfiguredPortalNote = "No portal details for this tenant yet — add the portal address on Ticket delivery."
