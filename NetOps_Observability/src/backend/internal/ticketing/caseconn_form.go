// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_form.go — the EDIT surface of the per-tenant TAC connector record:
// which settings block a connector id edits, the wire form for that block, and
// the write-only secret semantics of a save.
//
// WHY THIS FILE EXISTS. The store, the validators and the adapters have all
// been able to READ a tenant's connector credentials since W2 landed; nothing
// could ever WRITE them. Every connector therefore read "Not configured" on
// every deployment forever, and the one honest thing the escalation step could
// say about a vendor path was that the customer had not brought credentials it
// had no way to bring. This is the missing half.
//
// ONE FORM PER CONNECTOR, NOT ONE FORM FOR ALL. Twelve connectors share five
// settings blocks: the two ITSM attach tunings, the shared SMTP relay, Cisco's
// two halves and Juniper's onboarding identifiers. A connector id resolves to
// exactly ONE block, and a save decodes into that block's own struct with
// unknown fields REFUSED — so a form can neither carry a field the connector
// does not have nor smuggle one belonging to another vendor (§3 fail-closed).
//
// SECRETS ARE WRITE-ONLY AND TRI-STATE. The record's secret fields never leave
// the process (TACConnectorConfig.Redacted), so a form cannot round-trip one.
// The wire therefore distinguishes three intentions with a POINTER:
//
//	absent / null  → keep the stored secret     (the ordinary edit)
//	""             → CLEAR the stored secret    (an explicit removal)
//	"value"        → replace it
//
// A plain string could only express two of those, which is why the ITSM store's
// blank-keeps-stored rule cannot be reused verbatim here: an operator who
// rotates a credential away must be able to take it away.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// ConnectorSection names the settings block one connector edits. It is part of
// the wire contract: the UI renders the fields of the section the server names,
// so a connector can never be shown a form the server would refuse.
type ConnectorSection string

const (
	// SectionNone: nothing to configure. The portal-only connectors are in this
	// state permanently and honestly — there is no API to hold a credential for.
	SectionNone ConnectorSection = ""
	// SectionServiceNow / SectionJira tune the ATTACH path only. The CONNECTION
	// (instance URL, credentials) is the tenant's existing ITSM configuration
	// and is deliberately not duplicated here.
	SectionServiceNow ConnectorSection = "servicenow"
	SectionJira       ConnectorSection = "jira"
	// SectionEmail is the tenant's own SMTP relay, shared by every email
	// connector: one relay serves Arista and Cisco alike.
	SectionEmail ConnectorSection = "email"
	// SectionCisco covers both Cisco halves (CXD attach, Smart Bonding create).
	SectionCisco ConnectorSection = "cisco"
	// SectionJuniper is the Service Case API onboarding identifiers.
	SectionJuniper ConnectorSection = "juniper"
)

// SectionForConnector maps a registry id onto the block it edits. It is a closed
// switch: an id nobody taught it answers SectionNone, which the HTTP layer turns
// into an honest "there is nothing to configure here" rather than a guess.
func SectionForConnector(id string) ConnectorSection {
	key := strings.ToLower(strings.TrimSpace(id))
	switch key {
	case "servicenow":
		return SectionServiceNow
	case "jira":
		return SectionJira
	case "juniper":
		return SectionJuniper
	case "cisco-cxd", "cisco-smart-bonding":
		return SectionCisco
	}
	if strings.HasPrefix(key, "email-") {
		return SectionEmail
	}
	return SectionNone
}

// ── the wire forms ──────────────────────────────────────────────────────────

// ServiceNowAttachWrite is the ServiceNow form. It holds no credential: the
// instance and its login are the tenant's existing ITSM connection.
type ServiceNowAttachWrite struct {
	Enabled        bool  `json:"enabled"`
	MaxAttachBytes int64 `json:"max_attach_bytes"`
}

// The form and the stored block happen to be field-for-field identical here
// (there is no secret and nothing to normalise), so this is a conversion rather
// than a copy. The two types still exist separately: the form is what a client
// may send, and keeping that distinct is what makes DisallowUnknownFields a
// contract rather than a coincidence.
func (w ServiceNowAttachWrite) apply(ServiceNowAttachConfig) ServiceNowAttachConfig {
	return ServiceNowAttachConfig(w)
}

// JiraAttachWrite is the Jira form. Deployment selects the auth + API-version
// pair as well as the default ceiling, so it is a field and not a guess.
type JiraAttachWrite struct {
	Enabled        bool   `json:"enabled"`
	Deployment     string `json:"deployment"`
	MaxAttachBytes int64  `json:"max_attach_bytes"`
}

func (w JiraAttachWrite) apply(JiraAttachConfig) JiraAttachConfig {
	return JiraAttachConfig{
		Enabled:        w.Enabled,
		Deployment:     strings.ToLower(strings.TrimSpace(w.Deployment)),
		MaxAttachBytes: w.MaxAttachBytes,
	}
}

// EmailConnectorWrite is the SMTP relay form. Password is the tri-state secret.
type EmailConnectorWrite struct {
	Enabled      bool    `json:"enabled"`
	Host         string  `json:"host"`
	From         string  `json:"from"`
	User         string  `json:"user"`
	Password     *string `json:"password"`
	TLSOnConnect bool    `json:"tls_on_connect"`
	ReplyTo      string  `json:"reply_to"`
}

func (w EmailConnectorWrite) apply(prev EmailConnectorConfig) EmailConnectorConfig {
	return EmailConnectorConfig{
		Enabled:      w.Enabled,
		Host:         strings.TrimSpace(w.Host),
		From:         strings.TrimSpace(w.From),
		User:         strings.TrimSpace(w.User),
		Password:     mergeSecret(w.Password, prev.Password),
		TLSOnConnect: w.TLSOnConnect,
		ReplyTo:      strings.TrimSpace(w.ReplyTo),
	}
}

// CiscoConnectorWrite is the Cisco form: the CXD half needs nothing stored, the
// Smart Bonding half needs the onboarding project's identifiers and its OAuth
// client. FieldMap is the binding Cisco does not publish and we refuse to guess.
type CiscoConnectorWrite struct {
	Enabled             bool              `json:"enabled"`
	CCOID               string            `json:"cco_id"`
	CustomerSourceID    string            `json:"customer_source_id"`
	SmartBondingEnabled bool              `json:"smart_bonding_enabled"`
	StagingHost         string            `json:"staging_host"`
	ClientID            string            `json:"client_id"`
	ClientSecret        *string           `json:"client_secret"`
	TokenURL            string            `json:"token_url"`
	FieldMap            map[string]string `json:"field_map"`
}

func (w CiscoConnectorWrite) apply(prev CiscoConnectorConfig) CiscoConnectorConfig {
	out := CiscoConnectorConfig{
		Enabled:             w.Enabled,
		CCOID:               strings.TrimSpace(w.CCOID),
		CustomerSourceID:    strings.TrimSpace(w.CustomerSourceID),
		SmartBondingEnabled: w.SmartBondingEnabled,
		StagingHost:         strings.TrimSpace(w.StagingHost),
		ClientID:            strings.TrimSpace(w.ClientID),
		ClientSecret:        mergeSecret(w.ClientSecret, prev.ClientSecret),
		TokenURL:            strings.TrimSpace(w.TokenURL),
	}
	if len(w.FieldMap) > 0 {
		out.FieldMap = make(map[string]string, len(w.FieldMap))
		for k, v := range w.FieldMap {
			out.FieldMap[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// JuniperConnectorWrite is the Service Case API form. Both secrets are
// tri-state; auth_mode decides which of them the validator demands.
type JuniperConnectorWrite struct {
	Enabled             bool    `json:"enabled"`
	AppID               string  `json:"app_id"`
	CustomerSourceID    string  `json:"customer_source_id"`
	UserID              string  `json:"user_id"`
	AccountID           string  `json:"account_id"`
	DefaultContactEmail string  `json:"default_contact_email"`
	AuthMode            string  `json:"auth_mode"`
	ClientID            string  `json:"client_id"`
	ClientSecret        *string `json:"client_secret"`
	APIKey              *string `json:"api_key"`
}

func (w JuniperConnectorWrite) apply(prev JuniperConnectorConfig) JuniperConnectorConfig {
	return JuniperConnectorConfig{
		Enabled:             w.Enabled,
		AppID:               strings.TrimSpace(w.AppID),
		CustomerSourceID:    strings.TrimSpace(w.CustomerSourceID),
		UserID:              strings.TrimSpace(w.UserID),
		AccountID:           strings.TrimSpace(w.AccountID),
		DefaultContactEmail: strings.TrimSpace(w.DefaultContactEmail),
		AuthMode:            strings.ToLower(strings.TrimSpace(w.AuthMode)),
		ClientID:            strings.TrimSpace(w.ClientID),
		ClientSecret:        mergeSecret(w.ClientSecret, prev.ClientSecret),
		APIKey:              mergeSecret(w.APIKey, prev.APIKey),
	}
}

// mergeSecret resolves the tri-state. It is the ONLY place the rule is written.
func mergeSecret(in *string, stored string) string {
	if in == nil {
		return stored
	}
	return *in
}

// ── decoding a save ─────────────────────────────────────────────────────────

// ErrNoSettings is the honest answer for a connector that holds no settings at
// all: the portal-only paths automate everything up to submission and store no
// credential, so there is no form to save.
var ErrNoSettings = fmt.Errorf("this connector holds no settings: it stores no credential")

// ApplyConnectorWrite decodes body as the section's OWN form and returns the
// record it produces. It never reads a tenant from the body — the caller has
// already resolved the owner from the token (§3a rule 2) — and an unknown field
// is a refusal rather than a silently ignored intention.
func ApplyConnectorWrite(section ConnectorSection, body []byte, prev TACConnectorConfig) (TACConnectorConfig, error) {
	decode := func(v any) error {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			return fmt.Errorf("this form does not accept that: %w", err)
		}
		if dec.More() {
			return fmt.Errorf("the body carries more than one object")
		}
		return nil
	}
	out := prev
	out.ITSM = SystemConfig{} // resolved at call time, never persisted
	switch section {
	case SectionServiceNow:
		var w ServiceNowAttachWrite
		if err := decode(&w); err != nil {
			return TACConnectorConfig{}, err
		}
		out.ServiceNow = w.apply(prev.ServiceNow)
	case SectionJira:
		var w JiraAttachWrite
		if err := decode(&w); err != nil {
			return TACConnectorConfig{}, err
		}
		out.Jira = w.apply(prev.Jira)
	case SectionEmail:
		var w EmailConnectorWrite
		if err := decode(&w); err != nil {
			return TACConnectorConfig{}, err
		}
		out.Email = w.apply(prev.Email)
	case SectionCisco:
		var w CiscoConnectorWrite
		if err := decode(&w); err != nil {
			return TACConnectorConfig{}, err
		}
		out.Cisco = w.apply(prev.Cisco)
	case SectionJuniper:
		var w JuniperConnectorWrite
		if err := decode(&w); err != nil {
			return TACConnectorConfig{}, err
		}
		out.Juniper = w.apply(prev.Juniper)
	default:
		return TACConnectorConfig{}, ErrNoSettings
	}
	return out, nil
}

// ClearConnectorSection removes one block, leaving every other connector's
// settings untouched. Removing Jira must never take the SMTP relay with it.
func ClearConnectorSection(section ConnectorSection, prev TACConnectorConfig) (TACConnectorConfig, error) {
	out := prev
	out.ITSM = SystemConfig{}
	switch section {
	case SectionServiceNow:
		out.ServiceNow = ServiceNowAttachConfig{}
	case SectionJira:
		out.Jira = JiraAttachConfig{}
	case SectionEmail:
		out.Email = EmailConnectorConfig{}
	case SectionCisco:
		out.Cisco = CiscoConnectorConfig{}
	case SectionJuniper:
		out.Juniper = JuniperConnectorConfig{}
	default:
		return TACConnectorConfig{}, ErrNoSettings
	}
	return out, nil
}

// IsEmpty reports that a record holds nothing at all, so the store can drop the
// row rather than keep a shell that reads differently from a fresh tenant.
// Written out field by field on purpose: reflect.DeepEqual is forbidden here
// (CLAUDE.md §5) and a struct holding a map cannot be compared with ==.
func (c TACConnectorConfig) IsEmpty() bool {
	return c.ServiceNow == (ServiceNowAttachConfig{}) &&
		c.Jira == (JiraAttachConfig{}) &&
		c.Email == (EmailConnectorConfig{}) &&
		c.Juniper == (JuniperConnectorConfig{}) &&
		ciscoIsEmpty(c.Cisco)
}

// ciscoIsEmpty spells the Cisco block out field by field: a struct carrying a
// map cannot be compared with == at all, and reflect.DeepEqual is not available
// to us (§5). Spelled out, adding a field to the block and forgetting it here is
// a compile-time-visible omission rather than a silently wrong answer.
func ciscoIsEmpty(c CiscoConnectorConfig) bool {
	return !c.Enabled && !c.SmartBondingEnabled &&
		c.CCOID == "" && c.CustomerSourceID == "" && c.StagingHost == "" &&
		c.ClientID == "" && c.ClientSecret == "" && c.TokenURL == "" &&
		len(c.FieldMap) == 0
}

// SectionSecretNames lists the write-only secrets a section holds, in a stable
// order, so the UI can render "stored" beside each without ever receiving one.
func SectionSecretNames(section ConnectorSection) []string {
	switch section {
	case SectionEmail:
		return []string{"password"}
	case SectionCisco:
		return []string{"client_secret"}
	case SectionJuniper:
		return []string{"client_secret", "api_key"}
	default:
		return nil
	}
}

// SectionSecretsPresent reports which of a section's secrets are stored.
func SectionSecretsPresent(section ConnectorSection, c TACConnectorConfig) map[string]bool {
	out := map[string]bool{}
	for _, name := range SectionSecretNames(section) {
		switch {
		case section == SectionEmail && name == "password":
			out[name] = c.Email.Password != ""
		case section == SectionCisco && name == "client_secret":
			out[name] = c.Cisco.ClientSecret != ""
		case section == SectionJuniper && name == "client_secret":
			out[name] = c.Juniper.ClientSecret != ""
		case section == SectionJuniper && name == "api_key":
			out[name] = c.Juniper.APIKey != ""
		}
	}
	return out
}
