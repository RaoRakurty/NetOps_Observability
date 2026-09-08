// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_required_test.go — the anti-drift harness for the mandatory-field
// table.
//
// The point of this file is that docs/design/TAC_CASE_FIELDS_2026-09-07.md is
// not decoration. It carries the citation for every vendor claim, and the Go
// table carries the enforcement; if the two are allowed to disagree then one of
// them is lying to whoever reads it. So the test PARSES the document's
// machine-checked blocks and compares them to the table, field by field and
// token by token, in order.
//
// It also closes the two silent-gap holes:
//   - a connector registered in DefaultCaseConnectorRegistry() with no entry in
//     the table (a new vendor whose required data nobody decided), and
//   - a severity vocabulary that drifts between the case form and the
//     capability matrix the UI renders.

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// designDocPath is the document this table is generated from, relative to the
// package directory.
const designDocPath = "../../../../docs/design/TAC_CASE_FIELDS_2026-09-07.md"

// noSeverityToken is the document's spelling of "this vendor publishes no
// severity vocabulary". It is a literal line rather than an empty block so a
// reviewer can tell "deliberately none" from "someone deleted the block".
const noSeverityToken = "(none published)"

// docConnector is one connector as the DOCUMENT describes it.
type docConnector struct {
	fields   []RequiredField
	severity []string
}

// parseDesignDoc reads the machine-checked blocks out of the design document.
//
// The format is deliberately line-oriented rather than table-oriented: several
// severity tokens contain commas AND semicolons (Palo Alto's Sev 1 contains
// both), so any single-character separator would need escaping, and an escaped
// document is one nobody proof-reads.
func parseDesignDoc(t *testing.T, path string) map[string]docConnector {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatalf("open design doc: %v", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			t.Errorf("close design doc: %v", cerr)
		}
	}()

	out := map[string]docConnector{}
	var current string
	var pending string // "" | "fields" | "severity"
	var block []string
	inBlock := false

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t")
		switch {
		case inBlock && strings.HasPrefix(line, "```"):
			inBlock = false
			entry := out[current]
			switch pending {
			case "fields":
				entry.fields = parseFieldLines(t, current, block)
			case "severity":
				entry.severity = parseSeverityLines(block)
			}
			out[current] = entry
			pending, block = "", nil
		case inBlock:
			if strings.TrimSpace(line) != "" {
				block = append(block, strings.TrimSpace(line))
			}
		case strings.HasPrefix(line, "### `"):
			rest := strings.TrimPrefix(line, "### `")
			if i := strings.Index(rest, "`"); i > 0 {
				current = rest[:i]
				out[current] = docConnector{}
			}
		case line == "<!-- machine-checked: required-fields -->":
			pending = "fields"
		case line == "<!-- machine-checked: severity -->":
			pending = "severity"
		case pending != "" && strings.HasPrefix(line, "```"):
			inBlock = true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read design doc: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("design doc %s carries no machine-checked connector sections", path)
	}
	return out
}

// parseFieldLines reads "key" or "key | anyof=<group> alt=<alternative>".
func parseFieldLines(t *testing.T, connector string, lines []string) []RequiredField {
	t.Helper()
	var out []RequiredField
	for _, line := range lines {
		parts := strings.SplitN(line, "|", 2)
		f := RequiredField{Key: strings.TrimSpace(parts[0])}
		if len(parts) == 2 {
			for _, tok := range strings.Fields(parts[1]) {
				k, v, ok := strings.Cut(tok, "=")
				if !ok {
					t.Fatalf("%s: malformed field modifier %q", connector, tok)
				}
				switch k {
				case "anyof":
					f.AnyOf = v
				case "alt":
					f.Alt = v
				default:
					t.Fatalf("%s: unknown field modifier %q", connector, k)
				}
			}
		}
		out = append(out, f)
	}
	return out
}

// parseSeverityLines turns the block into the token list, or nil for the
// explicit "(none published)" marker.
func parseSeverityLines(lines []string) []string {
	if len(lines) == 1 && lines[0] == noSeverityToken {
		return nil
	}
	return append([]string(nil), lines...)
}

// TestRequiredCaseFieldsMatchDesignDoc is the drift gate: the Go table and the
// document must describe the same connectors, the same fields in the same
// order, and the same AnyOf grouping.
func TestRequiredCaseFieldsMatchDesignDoc(t *testing.T) {
	doc := parseDesignDoc(t, designDocPath)

	// Same connector set, both directions.
	for _, id := range RequiredCaseFieldConnectorIDs() {
		if _, ok := doc[id]; !ok {
			t.Errorf("connector %q is in the Go table but has no section in %s", id, designDocPath)
		}
	}
	for id := range doc {
		if RequiredCaseFields(id) == nil {
			t.Errorf("connector %q is documented in %s but has no Go table entry", id, designDocPath)
		}
	}

	for id, want := range doc {
		got := RequiredCaseFields(id)
		if len(got) != len(want.fields) {
			t.Errorf("%s: doc lists %d required fields, the Go table has %d (doc %v)",
				id, len(want.fields), len(got), fieldKeys(want.fields))
			continue
		}
		for i := range got {
			if got[i].Key != want.fields[i].Key {
				t.Errorf("%s: required field %d is %q in the Go table and %q in the doc", id, i, got[i].Key, want.fields[i].Key)
			}
			if got[i].AnyOf != want.fields[i].AnyOf || got[i].Alt != want.fields[i].Alt {
				t.Errorf("%s: field %q grouping is anyof=%q alt=%q in the Go table and anyof=%q alt=%q in the doc",
					id, got[i].Key, got[i].AnyOf, got[i].Alt, want.fields[i].AnyOf, want.fields[i].Alt)
			}
		}
		gotSev := SeverityVocabulary(id)
		if len(gotSev) != len(want.severity) {
			t.Errorf("%s: doc lists %d severity tokens, the Go table has %d", id, len(want.severity), len(gotSev))
			continue
		}
		for i := range gotSev {
			if gotSev[i] != want.severity[i] {
				t.Errorf("%s: severity token %d is\n  go:  %q\n  doc: %q", id, i, gotSev[i], want.severity[i])
			}
		}
	}
}

// TestRequiredFieldsAreFullyAuthored keeps the table honest as prose too: a row
// with no label, no reason or no settings hint produces a refusal an operator
// cannot act on, which is the failure mode this whole file exists to prevent.
func TestRequiredFieldsAreFullyAuthored(t *testing.T) {
	for _, id := range RequiredCaseFieldConnectorIDs() {
		for _, f := range RequiredCaseFields(id) {
			switch {
			case strings.TrimSpace(f.Key) == "":
				t.Errorf("%s: a required field has no key", id)
			case strings.TrimSpace(f.Label) == "":
				t.Errorf("%s: %q has no label", id, f.Key)
			case strings.TrimSpace(f.Why) == "":
				t.Errorf("%s: %q has no reason", id, f.Key)
			case strings.TrimSpace(f.SettingsHint) == "":
				t.Errorf("%s: %q does not say where the operator sets it", id, f.Key)
			}
			if f.Alt != "" && f.AnyOf == "" {
				t.Errorf("%s: %q carries an alternative id but no AnyOf group", id, f.Key)
			}
		}
	}
}

// TestEveryRegisteredConnectorHasRequiredFields closes the silent-gap hole: a
// connector that ships without a decision about its mandatory data would show
// an empty case form and fail at the vendor instead of in the UI.
func TestEveryRegisteredConnectorHasRequiredFields(t *testing.T) {
	for _, entry := range DefaultCaseConnectorRegistry().Matrix() {
		if RequiredCaseFields(entry.ID) == nil {
			t.Errorf("connector %q is registered but has no entry in the required-field table", entry.ID)
		}
	}
}

// TestSeverityVocabularyMatchesCapabilities stops the vocabulary drifting
// between the case form and the capability matrix the UI renders — they must be
// the same tokens or the operator picks a value the connector will not send.
func TestSeverityVocabularyMatchesCapabilities(t *testing.T) {
	for _, entry := range DefaultCaseConnectorRegistry().Matrix() {
		got, want := SeverityVocabulary(entry.ID), entry.Caps.SeverityValues
		if len(got) != len(want) {
			t.Errorf("%s: SeverityVocabulary has %d tokens, Caps.SeverityValues has %d", entry.ID, len(got), len(want))
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s: severity token %d is %q in the table and %q in Caps", entry.ID, i, got[i], want[i])
			}
		}
	}
}

// TestRequiredCaseFieldsUnknownConnector: an id nobody taught the table answers
// nil, and MissingRequired says nothing about it. Answering "nothing is
// missing" for an unknown connector would let a caller submit a case with no
// checks at all, so the two states must stay distinguishable.
func TestRequiredCaseFieldsUnknownConnector(t *testing.T) {
	if got := RequiredCaseFields("not-a-connector"); got != nil {
		t.Errorf("unknown connector returned %v, want nil", got)
	}
	if got := MissingRequired("not-a-connector", map[string]string{}); got != nil {
		t.Errorf("unknown connector returned %v missing fields, want nil", got)
	}
	if got := MissingRequiredMessage("not-a-connector", nil); got != "" {
		t.Errorf("unknown connector returned message %q, want empty", got)
	}
	for _, id := range RequiredCaseFieldConnectorIDs() {
		if strings.TrimSpace(id) != id || id == "" {
			t.Errorf("connector id %q is not normalised", id)
		}
	}
}

func TestMissingRequired(t *testing.T) {
	complete := map[string]string{
		"title": "BGP session flapping on core-rtr-01", "description": "evidence …",
		"severity": "S2 — Substantial impact (degradation)", "contact_name": "Dana Rao",
		"contact_email": "dana.rao@example.com", "cco_id": "dana-cco",
		"serial_number": "FTX1840ABCD",
	}
	cases := []struct {
		name        string
		connector   string
		have        map[string]string
		wantMissing []string
		wantInMsg   []string
	}{
		{
			name:      "cisco entitlement satisfied by the serial alone",
			connector: "cisco-smart-bonding", have: complete,
			wantMissing: nil,
		},
		{
			name:      "cisco entitlement satisfied by contract id and PID together",
			connector: "cisco-smart-bonding",
			have: merged(complete, map[string]string{
				"serial_number": "", "contract_id": "C-1234", "pid": "N9K-C9336C-FX2",
			}),
			wantMissing: nil,
		},
		{
			name:      "a contract id without a PID leaves the whole group unsatisfied",
			connector: "cisco-smart-bonding",
			have: merged(complete, map[string]string{
				"serial_number": "", "contract_id": "C-1234",
			}),
			// The refusal names BOTH ways out, not just the blank field.
			wantMissing: []string{"serial_number", "contract_id", "pid"},
			wantInMsg:   []string{"a serial number, or a contract id and a PID"},
		},
		{
			name:      "no entitlement at all names the group once",
			connector: "cisco-smart-bonding",
			have: merged(complete, map[string]string{
				"serial_number": "", "cco_id": "",
			}),
			wantMissing: []string{"cco_id", "serial_number", "contract_id", "pid"},
			wantInMsg:   []string{"your CCO-ID", "a serial number, or a contract id and a PID"},
		},
		{
			name: "whitespace is not a value", connector: "cisco-cxd",
			have:        map[string]string{"existing_case_number": "   ", "upload_token": "tok"},
			wantMissing: []string{"existing_case_number"},
			wantInMsg:   []string{"Cisco CXD needs the Cisco SR number", "Support Case Manager"},
		},
		{
			name: "juniper names every blank createsr field", connector: "juniper",
			have: map[string]string{
				"title": "t", "description": "d", "severity": "P3",
				"contact_email": "dana.rao@example.com", "software_version": "23.4R2",
				"serial_number": "JN123", "account_id": "A1",
			},
			wantMissing: []string{"app_id", "customer_source_id", "user_id"},
			wantInMsg:   []string{"Juniper needs", "Administration → Ticket delivery → Case connectors → Juniper"},
		},
		{
			name: "an ITSM connector needs only the case body", connector: "servicenow",
			have:        map[string]string{"title": "t"},
			wantMissing: []string{"description"},
			wantInMsg:   []string{"ServiceNow needs a problem description"},
		},
		{
			name: "a portal connector still names what the portal will ask for", connector: "portal-paloalto",
			have: map[string]string{
				"product": "PA-5220", "serial_number": "001801", "description": "d", "severity": "Sev 2",
			},
			wantMissing: []string{"contact_phone"},
			wantInMsg:   []string{"Palo Alto Networks needs a contact phone number"},
		},
		{
			name: "everything supplied means no message at all", connector: "email-cisco",
			have:        map[string]string{"existing_case_number": "612345678"},
			wantMissing: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := fieldKeys(MissingRequired(tc.connector, tc.have))
			if len(got) != len(tc.wantMissing) {
				t.Fatalf("missing = %v, want %v", got, tc.wantMissing)
			}
			for i := range got {
				if got[i] != tc.wantMissing[i] {
					t.Fatalf("missing = %v, want %v", got, tc.wantMissing)
				}
			}
			msg := MissingRequiredMessage(tc.connector, tc.have)
			if len(tc.wantMissing) == 0 {
				if msg != "" {
					t.Fatalf("nothing is missing but the message was %q", msg)
				}
				return
			}
			if msg == "" {
				t.Fatal("fields are missing but the refusal message is empty")
			}
			for _, want := range tc.wantInMsg {
				if !strings.Contains(msg, want) {
					t.Errorf("refusal %q does not contain %q", msg, want)
				}
			}
		})
	}
}

// TestMissingRequiredDoesNotMutateInput guards the pure-lookup contract: the
// caller's map and the table itself are both left alone.
func TestMissingRequiredDoesNotMutateInput(t *testing.T) {
	have := map[string]string{"title": "t"}
	first := RequiredCaseFields("cisco-smart-bonding")
	if len(first) == 0 {
		t.Fatal("cisco-smart-bonding has no required fields")
	}
	first[0].Key = "mutated"
	if got := RequiredCaseFields("cisco-smart-bonding"); got[0].Key == "mutated" {
		t.Error("RequiredCaseFields hands out a shared slice: a caller can rewrite the table")
	}
	_ = MissingRequired("cisco-smart-bonding", have)
	if len(have) != 1 || have["title"] != "t" {
		t.Errorf("MissingRequired mutated the caller's map: %v", have)
	}
}

// fieldKeys reduces a field list to its keys for readable failures.
func fieldKeys(fields []RequiredField) []string {
	if len(fields) == 0 {
		return nil
	}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, f.Key)
	}
	return out
}

// merged overlays changes onto a base map without touching the base.
func merged(base, over map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}
