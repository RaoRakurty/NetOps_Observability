// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_form_test.go — the settings FORM: which block a connector edits, the
// tri-state secret, the refusal of a foreign field, and the atomic per-section
// update the HTTP layer relies on.

import (
	"strings"
	"testing"
)

// Every connector the product ships resolves to exactly one settings block, and
// the portal-only ones resolve to none. A new connector that forgot the mapping
// would silently render an empty form; this is what notices.
func TestEveryRegisteredConnectorResolvesItsSettingsBlock(t *testing.T) {
	want := map[string]ConnectorSection{
		"servicenow":          SectionServiceNow,
		"jira":                SectionJira,
		"cisco-cxd":           SectionCisco,
		"cisco-smart-bonding": SectionCisco,
		"juniper":             SectionJuniper,
	}
	for _, e := range DefaultCaseConnectorRegistry().Matrix() {
		got := SectionForConnector(e.ID)
		switch {
		case want[e.ID] != "":
			if got != want[e.ID] {
				t.Errorf("%s edits %q, want %q", e.ID, got, want[e.ID])
			}
		case strings.HasPrefix(e.ID, "email-"):
			if got != SectionEmail {
				t.Errorf("%s must edit the shared SMTP relay, got %q", e.ID, got)
			}
		case strings.HasPrefix(e.ID, "portal-"):
			if got != SectionNone {
				t.Errorf("%s stores no credential and must offer no form, got %q", e.ID, got)
			}
		default:
			t.Errorf("connector %q has no settings mapping — add one to SectionForConnector", e.ID)
		}
	}
}

// The whole point of the pointer: three intentions, not two.
func TestASecretIsKeptClearedOrReplacedByIntention(t *testing.T) {
	prev := TACConnectorConfig{Email: EmailConnectorConfig{
		Enabled: true, Host: "smtp.acme.example:587", From: "noc@acme.example",
		User: "relay", Password: "stored-secret",
	}}
	base := `"enabled":true,"host":"smtp.acme.example:587","from":"noc@acme.example","user":"relay"`

	for _, tc := range []struct {
		name, body, want string
	}{
		{"omitted keeps the stored secret", "{" + base + "}", "stored-secret"},
		{"null keeps the stored secret", `{` + base + `,"password":null}`, "stored-secret"},
		{"an empty string clears it", `{` + base + `,"password":""}`, ""},
		{"a value replaces it", `{` + base + `,"password":"rotated"}`, "rotated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ApplyConnectorWrite(SectionEmail, []byte(tc.body), prev)
			if err != nil {
				t.Fatalf("apply: %v", err)
			}
			if out.Email.Password != tc.want {
				t.Fatalf("password = %q, want %q", out.Email.Password, tc.want)
			}
		})
	}
}

// A form may not carry a field belonging to another vendor — or a tenant.
func TestTheFormRefusesAFieldItDoesNotHave(t *testing.T) {
	for _, body := range []string{
		`{"enabled":true,"tenant_id":"globex"}`,
		`{"enabled":true,"app_id":"juniper-thing"}`,
		`{"enabled":true,"host":"smtp.x:25"} {"enabled":false}`,
	} {
		if _, err := ApplyConnectorWrite(SectionEmail, []byte(body), TACConnectorConfig{}); err == nil {
			t.Fatalf("body %q was accepted; it must be refused", body)
		}
	}
	if _, err := ApplyConnectorWrite(SectionNone, []byte(`{}`), TACConnectorConfig{}); err == nil {
		t.Fatal("a connector with no settings must refuse a save")
	}
}

// Editing one connector must not disturb another's block, and a record emptied
// of everything must leave no shell behind.
func TestUpdatingOneBlockLeavesTheOthersAlone(t *testing.T) {
	s := NewTACConnectorStoreForTest()
	set := func(section ConnectorSection, body string) TACConnectorConfig {
		t.Helper()
		out, err := s.Update("acme", false, "acme", func(prev TACConnectorConfig) (TACConnectorConfig, error) {
			return ApplyConnectorWrite(section, []byte(body), prev)
		})
		if err != nil {
			t.Fatalf("update %s: %v", section, err)
		}
		return out
	}
	set(SectionEmail, `{"enabled":true,"host":"smtp.acme.example:587","from":"noc@acme.example","password":"p"}`)
	got := set(SectionJira, `{"enabled":true,"deployment":"cloud"}`)
	if got.Email.Host != "smtp.acme.example:587" || got.Email.Password != "p" {
		t.Fatalf("saving Jira disturbed the relay: %+v", got.Email)
	}
	if !got.Jira.Enabled || got.Jira.Deployment != "cloud" {
		t.Fatalf("jira block not stored: %+v", got.Jira)
	}

	// Remove them one at a time; the last removal drops the row entirely, so the
	// tenant reads exactly like one that never configured anything.
	if _, err := s.Update("acme", false, "acme", func(p TACConnectorConfig) (TACConnectorConfig, error) {
		return ClearConnectorSection(SectionEmail, p)
	}); err != nil {
		t.Fatalf("clear email: %v", err)
	}
	if cfg, err := s.Get("acme", false, "acme"); err != nil || cfg.Email.Host != "" || !cfg.Jira.Enabled {
		t.Fatalf("clearing the relay must keep Jira: %+v %v", cfg, err)
	}
	if _, err := s.Update("acme", false, "acme", func(p TACConnectorConfig) (TACConnectorConfig, error) {
		return ClearConnectorSection(SectionJira, p)
	}); err != nil {
		t.Fatalf("clear jira: %v", err)
	}
	if _, err := s.Get("acme", false, "acme"); err != ErrTenantNotFound {
		t.Fatalf("an emptied record must leave no row, got %v", err)
	}
}

// A refused save changes nothing, and the refusal names the field.
func TestARefusedSaveNamesTheFieldAndStoresNothing(t *testing.T) {
	s := NewTACConnectorStoreForTest()
	_, err := s.Update("acme", false, "acme", func(p TACConnectorConfig) (TACConnectorConfig, error) {
		return ApplyConnectorWrite(SectionEmail, []byte(`{"enabled":true,"host":"smtp.acme.example","from":"noc@acme.example"}`), p)
	})
	if err == nil || !strings.Contains(err.Error(), "host:port") {
		t.Fatalf("refusal = %v, want the host:port field named", err)
	}
	if _, gerr := s.Get("acme", false, "acme"); gerr != ErrTenantNotFound {
		t.Fatalf("a refused save stored a row: %v", gerr)
	}

	// Juniper's ordered refusal: the same incomplete form always names the same
	// missing field, so an operator fixing them one at a time makes progress.
	_, err = s.Update("acme", false, "acme", func(p TACConnectorConfig) (TACConnectorConfig, error) {
		return ApplyConnectorWrite(SectionJuniper, []byte(`{"enabled":true}`), p)
	})
	if err == nil || !strings.Contains(err.Error(), "app_id") {
		t.Fatalf("juniper refusal = %v, want app_id named first", err)
	}
}

// The store never hands a secret to a caller, and reports only its presence.
func TestSecretsAreReportedAsPresenceOnly(t *testing.T) {
	cfg := TACConnectorConfig{
		Email:   EmailConnectorConfig{Enabled: true, Password: "p"},
		Juniper: JuniperConnectorConfig{Enabled: true, APIKey: "k"},
	}
	if red := cfg.Redacted(); red.Email.Password != "" || red.Juniper.APIKey != "" {
		t.Fatalf("Redacted left a secret behind: %+v", red)
	}
	if got := SectionSecretsPresent(SectionJuniper, cfg); !got["api_key"] || got["client_secret"] {
		t.Fatalf("juniper secret presence = %v", got)
	}
	if got := SectionSecretsPresent(SectionEmail, cfg); !got["password"] {
		t.Fatalf("email secret presence = %v", got)
	}
	if got := SectionSecretsPresent(SectionJira, cfg); len(got) != 0 {
		t.Fatalf("the Jira attach block holds no secret, got %v", got)
	}
}
