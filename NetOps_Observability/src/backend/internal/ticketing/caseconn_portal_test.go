// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_portal_test.go — Tier 3. The value of these connectors is entirely
// in what they REFUSE and what they tell the operator instead, so that is what
// is asserted: capabilities all false, a portal URL, the field list the portal
// asks for, and a refusal message an operator can act on.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPortalOnlyVendorsDeclareNoCapabilities(t *testing.T) {
	want := []string{"fortinet", "huawei", "nokia", "paloalto"}
	got := PortalVendorIDs()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Tier-3 vendors = %v, want %v", got, want)
	}
	for _, id := range got {
		t.Run(id, func(t *testing.T) {
			c, err := NewPortalOnlyConnector(id)
			if err != nil {
				t.Fatal(err)
			}
			caps := c.Capabilities()
			if caps.Create || caps.Attach || caps.Poll || caps.Webhook || caps.Note {
				t.Errorf("%s declares a capability it does not have: %+v", id, caps)
			}
			if caps.PortalURL == "" {
				t.Error("a portal-only connector must name the portal")
			}
			if len(caps.RequiredFields) == 0 {
				t.Error("a portal-only connector must list what the portal asks for, so the case text can be pre-filled")
			}
			if !strings.Contains(caps.Notes, "2026-09-05") {
				t.Error("the negative must be dated so it can be re-checked rather than re-guessed")
			}
		})
	}
}

func TestPortalOnlyRefusalsAreActionable(t *testing.T) {
	c, err := NewPortalOnlyConnector("nokia")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CreateCase(context.Background(), TACConnectorConfig{}, CaseRequest{})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	for _, want := range []string{"Nokia", "customer.nokia.com", "Technical Problem"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal should mention %q: %v", want, err)
		}
	}
	if _, err := c.AttachBundle(context.Background(), TACConnectorConfig{}, CaseRef{}, Bundle{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("attach = %v, want ErrUnsupported", err)
	}
	if _, _, err := c.FetchCase(context.Background(), TACConnectorConfig{}, CaseRef{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("fetch = %v, want ErrUnsupported", err)
	}
	if err := c.AddNote(context.Background(), TACConnectorConfig{}, CaseRef{}, "x"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("note = %v, want ErrUnsupported", err)
	}
}

func TestPortalOnlySeverityIsNilWhereTheVendorPublishesNone(t *testing.T) {
	// Fortinet and Palo Alto publish their scales; Nokia and Huawei do not, and
	// a made-up scale would be worse than an empty one.
	for id, wantValues := range map[string]bool{
		"fortinet": true, "paloalto": true, "nokia": false, "huawei": false,
	} {
		c, err := NewPortalOnlyConnector(id)
		if err != nil {
			t.Fatal(err)
		}
		got := len(c.Capabilities().SeverityValues) > 0
		if got != wantValues {
			t.Errorf("%s: published severity values = %v, want %v", id, got, wantValues)
		}
	}
}

func TestPaloAltoNotesTheMandatoryZipFormat(t *testing.T) {
	v, ok := PortalVendorFor("paloalto")
	if !ok {
		t.Fatal("missing")
	}
	if !strings.Contains(v.Notes, ".zip") {
		t.Error("the bundle must be produced as a .zip to be acceptable to the CSP; the note must say so")
	}
	if !strings.Contains(strings.ToLower(strings.Join(v.RequiredFields, " ")), "tsf") {
		t.Error("the TSF is mandatory for many issue concentrations and must be in the field list")
	}
}

func TestPortalOnlyConnectorRejectsAnUnknownVendor(t *testing.T) {
	if _, err := NewPortalOnlyConnector("acme"); err == nil {
		t.Fatal("an unknown vendor must be refused, never defaulted into a portal claim")
	}
}
