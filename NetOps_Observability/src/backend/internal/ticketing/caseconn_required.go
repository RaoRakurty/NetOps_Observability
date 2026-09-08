// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_required.go — the mandatory data each vendor needs before a case can
// be opened, as DATA, plus the refusal that names what is still missing.
//
// SOURCE OF RECORD: docs/design/TAC_CASE_FIELDS_2026-09-07.md §3. That document
// carries a citation per claim and separates two senses of "mandatory":
//
//	V — the vendor's own published contract requires it (omitting it is refused
//	    AT THE VENDOR: Cisco's entitlement triple, Juniper's createsr field list)
//	C — Correlix refuses locally, because the field is an entitlement input, a
//	    named-human rule, or the only thing that makes the case usable. A C row
//	    is a product decision and is never presented as a vendor claim.
//
// caseconn_required_test.go PARSES that document and fails when this table and
// the document disagree, so neither can drift from the other. Adding a
// connector without deciding what it requires also fails, because the test
// walks DefaultCaseConnectorRegistry().
//
// WHY IT IS A LOOKUP AND NOT A METHOD ON THE CONNECTOR. A connector answers
// "what can I do" (Caps); this answers "what must a HUMAN still supply". The
// second question has to be answerable before any credential is resolved and
// before any I/O happens — the case form asks it on every render — so it is a
// pure function over a table, with no receiver and no network.
//
// WHAT IS NOT A ROW HERE. A field belongs in this table when it is part of the
// CASE: a request field, an entitlement identifier, or the reference a case
// attaches to. Transport credentials (the SMTP relay, an OAuth client secret, a
// ServiceNow login) are connector SETTINGS, validated by ValidateConfig. Mixing
// them in would tell an operator that a missing password is a missing case
// field, which sends them to the wrong screen.

import (
	"sort"
	"strings"
)

// RequiredField is one piece of mandatory data, named the way the operator has
// to think about it: what it is, why the vendor wants it, and where it is set.
type RequiredField struct {
	// Key is the internal/tac.CaseForm field name where one exists (title,
	// description, severity, product, serial_number, contract_id, contact_name,
	// contact_email, existing_case_number), otherwise the CaseRequest.Fields key
	// the connector reads (software_version, pid, cco_id, contact_phone,
	// upload_token, app_id, customer_source_id, user_id, account_id).
	Key string `json:"key"`
	// Label is the operator-facing name AS IT READS INSIDE A SENTENCE — "a
	// serial number", not "Serial number" — because its first job is to make
	// MissingRequiredMessage a sentence a person can act on. A form renders its
	// own heading; only the refusal needs the grammar.
	Label string `json:"label"`
	// Why is the vendor's own reason in one sentence, so a refusal explains
	// itself instead of merely blocking.
	Why string `json:"why"`
	// SettingsHint names WHERE the operator supplies it — the case form, the
	// device record, or the exact Administration screen.
	SettingsHint string `json:"settings_hint"`
	// AnyOf groups alternatives: the group is satisfied by ONE alternative, so
	// "a serial number OR a contract id + PID" is one refusal sentence rather
	// than three unexplained blanks. Empty means the field stands alone.
	AnyOf string `json:"any_of,omitempty"`
	// Alt is the alternative id WITHIN the group. Fields sharing an Alt must all
	// be present for that alternative to count; an empty Alt means the field is
	// an alternative by itself.
	Alt string `json:"alt,omitempty"`
}

// alternative resolves the alternative this field belongs to inside its group.
func (f RequiredField) alternative() string {
	if f.Alt != "" {
		return f.Alt
	}
	return f.Key
}

// ── the table ───────────────────────────────────────────────────────────────

// requiredCaseFieldTable builds the table. It is a FUNCTION, not a package
// variable: CLAUDE.md §5 forbids a mutable global, and a caller that mutated a
// shared slice would silently change what every other tenant's case form
// demands. Each call returns fresh slices, exactly like EmailVendorIDs() and
// PortalVendorIDs() return fresh copies of their closed tables.
func requiredCaseFieldTable() map[string][]RequiredField {
	const (
		// A hint is rendered INSIDE a refusal sentence, so it carries no comma
		// and no semicolon of its own — those are the separators that sentence
		// uses, and a hint that borrowed one would read as two hints.
		fromForm    = "the case form"
		fromSCM     = "the case form (copy it from Cisco Support Case Manager)"
		fromDevice  = "the device record in Correlix inventory"
		ciscoAdmin  = "Administration → Ticket delivery → Case connectors → Cisco"
		juniperAdmn = "Administration → Ticket delivery → Case connectors → Juniper"
		portalNote  = "the case form (Correlix pre-fills the portal text you paste)"
	)

	title := RequiredField{
		Key: "title", Label: "a case title", SettingsHint: fromForm,
		Why: "the one-line synopsis is the first thing the assignee reads; every path carries it and Juniper caps it at 250 characters",
	}
	description := RequiredField{
		Key: "description", Label: "a problem description", SettingsHint: fromForm,
		Why: "the evidence-only problem statement is the case; without it the vendor has nothing to work from",
	}
	contactEmail := func(why string) RequiredField {
		return RequiredField{Key: "contact_email", Label: "a contact email", SettingsHint: fromForm, Why: why}
	}
	contactName := RequiredField{
		Key: "contact_name", Label: "a contact name", SettingsHint: fromForm,
		Why: "a case is owned by a person: Arista asks for your name and contact information, and Cisco binds a contact name into every Smart Bonding case",
	}

	return map[string][]RequiredField{
		// ── Tier 1, ITSM ────────────────────────────────────────────────────
		// No vendor entitlement. Both rows are C: neither platform fixes a
		// mandatory field set — a ServiceNow dictionary entry or a Jira project
		// field configuration can make ANY field mandatory per instance (doc
		// OPEN QUESTION Q1), so these are Correlix's own minimum.
		"servicenow": {
			withWhy(title, "ServiceNow writes it to short_description, the only case field Correlix always sends; an incident without one is unusable in the queue"),
			description,
		},
		"jira": {
			withWhy(title, "it becomes the issue summary; the project key and issue type come from the tenant's Jira connection, not from the case form"),
			description,
		},

		// ── Tier 1, email ───────────────────────────────────────────────────
		// Arista's only path. Severity is deliberately absent: the default is
		// P3 and Arista publishes no per-level definitions (doc Q5).
		"email-arista": {
			withWhy(title, "the title becomes the subject line, which is also where Arista reads a priority if you state one (the default is P3)"),
			withWhy(description, "Arista asks for the problem description, a compressed show tech-support and network diagrams"),
			contactName,
			contactEmail("Arista asks for your name and contact information so a human owns the case"),
		},
		"email-cisco": {
			{
				Key: "existing_case_number", Label: "the 9-digit Cisco SR number", SettingsHint: fromSCM,
				Why: "attach@cisco.com files the mail against the SR named in the subject as \"SR xxxxxxxxx\"; it cannot open a case",
			},
		},

		// ── Tier 2, Cisco ───────────────────────────────────────────────────
		"cisco-cxd": {
			{
				Key: "existing_case_number", Label: "the Cisco SR number", SettingsHint: fromSCM,
				Why: "CXD authenticates the upload with the SR number as the Basic-auth user, so there is nothing to attach to without it",
			},
			{
				Key: "upload_token", Label: "the per-case CXD upload token", SettingsHint: fromSCM,
				Why: "the token from Support Case Manager is the Basic-auth password; it is valid 72 days, is supplied per attach and is never stored by Correlix",
			},
		},
		// The entitlement triple is V and is validated locally before any call.
		// The five case-body rows are C: Cisco does not publish the push/call
		// request schema, so they are the canonical set Correlix binds through
		// cisco.field_map (doc Q3), not a claim about Cisco's own field names.
		"cisco-smart-bonding": {
			title,
			description,
			{
				Key: "severity", Label: "a severity", SettingsHint: fromForm,
				Why: "Cisco's S1–S4 vocabulary sets the response commitment; Correlix never translates a Correlix severity into it, the operator picks",
			},
			contactName,
			contactEmail("Cisco binds a contact email into every case so the TAC engineer can reach a person"),
			{
				Key: "cco_id", Label: "your CCO-ID", SettingsHint: ciscoAdmin,
				Why: "Cisco requires the CCO-ID on every case; it is the identity the entitlement check runs against",
			},
			{
				Key: "serial_number", Label: "a serial number", SettingsHint: fromDevice,
				Why:   "Cisco entitles a hardware case on the device serial number",
				AnyOf: "cisco-entitlement", Alt: "serial",
			},
			{
				Key: "contract_id", Label: "a contract id", SettingsHint: ciscoAdmin,
				Why:   "Cisco entitles a software case on the contract id together with the PID",
				AnyOf: "cisco-entitlement", Alt: "contract",
			},
			{
				Key: "pid", Label: "a PID", SettingsHint: ciscoAdmin,
				Why:   "the product id completes the software entitlement; a contract id alone is refused",
				AnyOf: "cisco-entitlement", Alt: "contract",
			},
		},

		// ── Tier 2, Juniper ─────────────────────────────────────────────────
		// Every row except serial_number is V, from CreateSRRequest.Validate().
		// serial_number is C: the pinned OpenAPI marks serialNumber optional,
		// but "missing serial" is one of the 600–614 entitlement failures, so
		// Correlix asks up front rather than failing at the vendor (doc Q2).
		"juniper": {
			withWhy(title, "synopsis is a required createsr field and is capped at 250 characters"),
			withWhy(description, "problemDescription is a required createsr field and is capped at 15000 characters"),
			{
				Key: "severity", Label: "a priority", SettingsHint: fromForm,
				Why: "priority is a required createsr field whose legal values come from the API's own /getlov list — Correlix fetches them and never hard-codes them",
			},
			contactEmail("Juniper requires contactEmail to be a real person and not an alias, so a shared mailbox is refused before the call"),
			{
				Key: "software_version", Label: "the software version", SettingsHint: fromDevice,
				Why: "softwareVersion has been mandatory on createsr since 2024-05-16",
			},
			{
				Key: "serial_number", Label: "a serial number", SettingsHint: fromDevice,
				Why: "the schema marks serialNumber optional, but a missing serial is one of Juniper's 600–614 entitlement failures — supplying it up front turns a vendor rejection into a local one",
			},
			{
				Key: "account_id", Label: "your Juniper account id", SettingsHint: juniperAdmn,
				Why: "accountID is a required createsr field identifying the support account the case is filed under",
			},
			{
				Key: "app_id", Label: "your Juniper appId", SettingsHint: juniperAdmn,
				Why: "appId is a required createsr field issued by Juniper's per-customer onboarding",
			},
			{
				Key: "customer_source_id", Label: "your Juniper customerSourceID", SettingsHint: juniperAdmn,
				Why: "customerSourceID is a required createsr field issued alongside the appId at onboarding",
			},
			{
				Key: "user_id", Label: "a Juniper userId", SettingsHint: juniperAdmn,
				Why: "userId is a required createsr field and must be a registered Customer Service Portal user",
			},
		},

		// ── Tier 3, portal-only ─────────────────────────────────────────────
		// Nothing is submitted by Correlix, so a "missing" field here means
		// "the portal will ask you for this and the paste text would be
		// incomplete", not "submit is disabled". Fixed choices (Fortinet's
		// request type, Nokia's three request types) are not rows: they are not
		// operator-supplied data.
		"portal-fortinet": {
			{
				Key: "serial_number", Label: "a serial number", SettingsHint: fromDevice,
				Why: "FortiCare entitles on registered assets, so the ticket wizard asks for the serial first",
			},
			{
				Key: "severity", Label: "a priority", SettingsHint: portalNote,
				Why: "Fortinet publishes P1–P4 definitions and the wizard asks you to pick one",
			},
			withWhy(description, "the ticket wizard asks for a problem description and the attachments produced on the device by `execute tac report`"),
		},
		"portal-paloalto": {
			{
				Key: "product", Label: "the product", SettingsHint: fromDevice,
				Why: "Create a Case starts with the product, which selects the rest of the form",
			},
			{
				Key: "serial_number", Label: "an asset or serial number", SettingsHint: fromDevice,
				Why: "the CSP entitles on the asset and its support contract",
			},
			withWhy(description, "the portal asks for the symptoms with the date and time they occurred, and for a problem type"),
			{
				Key: "severity", Label: "an impact or severity", SettingsHint: portalNote,
				Why: "Palo Alto publishes Sev 1–4 definitions and asks for the impact; phone is the channel for Sev 1",
			},
			{
				Key: "contact_phone", Label: "a contact phone number", SettingsHint: fromForm,
				Why: "the portal asks you to confirm a contact phone before filing",
			},
		},
		"portal-nokia": {
			{
				Key: "product", Label: "the product", SettingsHint: fromDevice,
				Why: "the TSR wizard asks for the request type and then the product",
			},
			withWhy(description, "the TSR wizard asks for the problem details; phone is Nokia's preferred channel for an outage"),
		},
		"portal-huawei": {
			{
				Key: "product", Label: "the product", SettingsHint: fromDevice,
				Why: "the enterprise SR portal asks for the product; its full field list is JS-gated and not publicly retrievable",
			},
			withWhy(description, "the enterprise SR portal asks for a problem description and attachments"),
		},
	}
}

// withWhy returns a copy of f with a connector-specific reason. The shared rows
// (title, description) are worth stating in the vendor's own terms without
// re-typing the key, the label and the hint four times.
func withWhy(f RequiredField, why string) RequiredField {
	f.Why = why
	return f
}

// ── the lookups ─────────────────────────────────────────────────────────────

// RequiredCaseFields returns the mandatory data for one connector id, in the
// order the operator should be asked for it. An id the table does not know
// returns nil — the caller must treat that as "unknown", not as "nothing
// required"; RequiredCaseFieldConnectorIDs is the way to tell the two apart.
func RequiredCaseFields(connectorID string) []RequiredField {
	fields, ok := requiredCaseFieldTable()[connectorKey(connectorID)]
	if !ok {
		return nil
	}
	return fields
}

// RequiredCaseFieldConnectorIDs lists every connector the table covers, sorted.
// A registered connector missing from this list is a silent gap, which is
// exactly what caseconn_required_test.go refuses to allow.
func RequiredCaseFieldConnectorIDs() []string {
	table := requiredCaseFieldTable()
	out := make([]string, 0, len(table))
	for id := range table {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// MissingRequired names what is still blank for one connector, honouring the
// AnyOf groups: an unsatisfied group returns ALL of its fields so the caller can
// refuse with one sentence that offers both ways out, and a satisfied group
// returns none of them even though several of its fields are empty.
//
// `have` is the merged view of what the caller holds — the case form plus the
// tenant's connector settings — keyed by RequiredField.Key. A whitespace-only
// value counts as absent: a space is not a serial number.
func MissingRequired(connectorID string, have map[string]string) []RequiredField {
	fields := RequiredCaseFields(connectorID)
	if len(fields) == 0 {
		return nil
	}
	present := func(key string) bool { return strings.TrimSpace(have[key]) != "" }

	// Resolve each group once: it is satisfied when EVERY field of at least one
	// alternative is present.
	satisfied := map[string]bool{}
	for _, f := range fields {
		if f.AnyOf == "" || satisfied[f.AnyOf] {
			continue
		}
		for alt := range groupAlternatives(fields, f.AnyOf) {
			if altComplete(fields, f.AnyOf, alt, present) {
				satisfied[f.AnyOf] = true
				break
			}
		}
	}

	var missing []RequiredField
	emitted := map[string]bool{}
	for _, f := range fields {
		if f.AnyOf == "" {
			if !present(f.Key) {
				missing = append(missing, f)
			}
			continue
		}
		if satisfied[f.AnyOf] || emitted[f.AnyOf] {
			continue
		}
		emitted[f.AnyOf] = true
		for _, g := range fields {
			if g.AnyOf == f.AnyOf {
				missing = append(missing, g)
			}
		}
	}
	return missing
}

// groupAlternatives lists the alternative ids inside one group.
func groupAlternatives(fields []RequiredField, group string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, f := range fields {
		if f.AnyOf == group {
			out[f.alternative()] = struct{}{}
		}
	}
	return out
}

// altComplete reports whether every field of one alternative is present.
func altComplete(fields []RequiredField, group, alt string, present func(string) bool) bool {
	found := false
	for _, f := range fields {
		if f.AnyOf != group || f.alternative() != alt {
			continue
		}
		found = true
		if !present(f.Key) {
			return false
		}
	}
	return found
}

// MissingRequiredMessage renders the refusal as one sentence naming what is
// missing, and a second naming the screens it is set on:
//
//	Cisco Smart Bonding needs your CCO-ID; a serial number, or a contract id and
//	a PID. Set them in Administration → Ticket delivery → Case connectors →
//	Cisco and the device record in Correlix inventory.
//
// Requirements are separated by a SEMICOLON, never by "and": an AnyOf group
// already contains an "or", and "A, and B or C" is genuinely ambiguous about
// which of the three the operator has to produce. A refusal an operator can
// misread is a support call.
//
// It returns "" when nothing is missing, so a caller can use it directly as the
// condition. A refusal that only says "incomplete" costs the operator that same
// call; this one tells them which screen to open.
func MissingRequiredMessage(connectorID string, have map[string]string) string {
	missing := MissingRequired(connectorID, have)
	if len(missing) == 0 {
		return ""
	}
	var parts []string
	emitted := map[string]bool{}
	for _, f := range missing {
		if f.AnyOf == "" {
			parts = append(parts, f.Label)
			continue
		}
		if emitted[f.AnyOf] {
			continue
		}
		emitted[f.AnyOf] = true
		parts = append(parts, groupPhrase(missing, f.AnyOf))
	}
	var hints []string
	for _, f := range missing {
		if f.SettingsHint != "" && !containsString(hints, f.SettingsHint) {
			hints = append(hints, f.SettingsHint)
		}
	}
	msg := requiredVendorLabel(connectorID) + " needs " + strings.Join(parts, "; ") + "."
	if len(hints) == 0 {
		return msg
	}
	return msg + " Set " + pluralIt(len(missing)) + " in " + joinPhrases(hints, " and ") + "."
}

// groupPhrase renders one AnyOf group as "a serial number, or a contract id and
// a PID": alternatives joined with "or", the fields inside one alternative
// joined with "and".
func groupPhrase(fields []RequiredField, group string) string {
	var alts []string
	seen := map[string]bool{}
	for _, f := range fields {
		if f.AnyOf != group || seen[f.alternative()] {
			continue
		}
		seen[f.alternative()] = true
		var labels []string
		for _, g := range fields {
			if g.AnyOf == group && g.alternative() == f.alternative() {
				labels = append(labels, g.Label)
			}
		}
		alts = append(alts, joinPhrases(labels, " and "))
	}
	return joinPhrases(alts, ", or ")
}

// joinPhrases joins with ", " and uses last for the final separator.
func joinPhrases(parts []string, last string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + last + parts[len(parts)-1]
}

func pluralIt(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// SeverityVocabulary returns the vendor's own published severity tokens for a
// connector, or nil when the vendor publishes none — Nokia, Huawei-enterprise
// and Arista genuinely do not, and Juniper's list must be FETCHED from /getlov,
// so a hard-coded list would be an invented vendor fact in all four cases.
//
// It is deliberately derived from the same closed tables the capability matrix
// reads (ciscoSeverities, the Tier-3 portal table), so a vocabulary cannot drift
// between the case form and Caps.SeverityValues.
func SeverityVocabulary(connectorID string) []string {
	id := connectorKey(connectorID)
	switch id {
	case "cisco-cxd", "cisco-smart-bonding":
		return ciscoSeverities()
	}
	if vendorID, ok := strings.CutPrefix(id, "portal-"); ok {
		if v, found := PortalVendorFor(vendorID); found {
			return append([]string(nil), v.SeverityValues...)
		}
	}
	return nil
}

// requiredVendorLabel names the vendor in a refusal sentence. It reuses the
// closed vendor tables wherever one exists so there is no second list of vendor
// names to drift.
func requiredVendorLabel(connectorID string) string {
	id := connectorKey(connectorID)
	switch id {
	case "servicenow":
		return "ServiceNow"
	case "jira":
		return "Jira"
	case "juniper":
		return "Juniper"
	case "cisco-cxd":
		return "Cisco CXD"
	case "cisco-smart-bonding":
		return "Cisco Smart Bonding"
	}
	if vendorID, ok := strings.CutPrefix(id, "email-"); ok {
		if v, found := EmailVendorFor(vendorID); found {
			return v.Vendor
		}
	}
	if vendorID, ok := strings.CutPrefix(id, "portal-"); ok {
		if v, found := PortalVendorFor(vendorID); found {
			return v.Vendor
		}
	}
	return id
}

// connectorKey normalises a registry id the way every other lookup in this
// package does.
func connectorKey(id string) string { return strings.ToLower(strings.TrimSpace(id)) }
