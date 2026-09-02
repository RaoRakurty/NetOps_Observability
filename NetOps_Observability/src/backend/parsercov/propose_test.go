package parsercov

// propose_test.go — the drafted catalog row is CHECKED, not merely produced.
//
// WHY A GO-SIDE CHECKER. The obligation is "validate the proposal against the
// catalog schema". `telemetry-catalog/bake_rules.py` has no --validate mode —
// it exposes only `--check`, a drift guard that re-bakes the WHOLE events.yaml
// and cannot be pointed at one candidate row — and shelling out to python from
// a Go unit test would make this package's suite depend on an interpreter and a
// sibling tree. So the rules are re-derived here from bake_rules.validate_row
// and applied to the emitted text:
//
//	ROW_KEYS / ROW_REQUIRED         allowed and required row keys
//	LANES / SOURCES / ENTITY_TYPES  the enumerations
//	SEVERITIES / FIDELITY_STATUSES  the ladders
//	markers must be UPPER-CASE      (the ingest screen matches upper-cased tokens)
//	pattern_src ∈ the guard's `re` nodes
//	EMIT_KEYS, and emit.{metric,modality,native_id} for a runtime lane
//	guard/extract may only read LANE_FIELDS["syslog"]
//	an extraction may not shadow a LANE_VARS["syslog"] name
//
// If bake_rules.py's rules move, this test is where the two are reconciled.

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// ---- the catalog schema, mirrored from bake_rules.py ------------------------

var (
	rowKeys = set(
		"rule_id", "lane", "source", "kind", "entity_type", "family", "vendors",
		"markers", "pattern_src", "state", "state_re", "severity", "generic",
		"shadow", "guard", "extract", "emit", "fidelity_status")
	rowRequired       = []string{"rule_id", "lane", "source", "kind", "entity_type", "guard", "emit"}
	emitKeys          = set("kind", "metric", "modality", "entity", "severity", "native_id", "content_tag", "tokens", "tokens_fallback", "attrs")
	lanes             = set("syslog", "port", "trap", "catalog")
	sources           = set("syslog", "trap")
	entityTypes       = set("device", "interface", "device_or_interface")
	fidelityStatuses  = set("doc_claimed", "lab_validated", "live_validated", "degraded", "failed")
	syslogLaneFields  = set("msg", "msg_u", "tag", "ctoken", "ctoken_msg_u")
	syslogSeededVars  = set("host", "ts_ms", "tag", "msg")
	runtimeEmitNeeded = []string{"metric", "modality", "native_id"}
)

func set(vals ...string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}

func sampleItem() Item {
	return Item{
		TemplateID:  "t-0123456789",
		Template:    "%LINK-3-UPDOWN: Interface <*> changed state to <*>",
		Count:       812,
		Devices:     14,
		SeverityMax: 3,
		FirstSeen:   "2026-08-27T04:11:00Z",
		LastSeen:    "2026-09-02T09:41:00Z",
		Sample:      "%LINK-3-UPDOWN: Interface GigabitEthernet0/3, changed state to down",
		AppName:     "%LINK-3-UPDOWN",
		Mnemonic:    "UPDOWN",
	}
}

// ---- a minimal block-YAML reader, sufficient for the row this code emits ----

// yamlLine is one significant line: its indent, its key (when it opens a
// mapping entry) and the rest of the text.
type yamlLine struct {
	indent int
	key    string
	value  string
	raw    string
}

func readRow(t *testing.T, doc string) []yamlLine {
	t.Helper()
	var out []yamlLine
	items := 0
	for _, raw := range strings.Split(doc, "\n") {
		if strings.Contains(raw, "\t") {
			t.Fatalf("tab character in YAML output: %q", raw)
		}
		trimmed := strings.TrimLeft(raw, " ")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(trimmed)
		if indent%2 != 0 {
			t.Fatalf("indent %d is not a multiple of 2: %q", indent, raw)
		}
		if indent == 0 {
			if !strings.HasPrefix(trimmed, "- ") {
				t.Fatalf("a top-level line that is not a list item: %q", raw)
			}
			items++
			trimmed = strings.TrimPrefix(trimmed, "- ")
			indent = 2
		}
		l := yamlLine{indent: indent, raw: raw}
		body := strings.TrimPrefix(trimmed, "- ")
		if i := strings.Index(body, ": "); i > 0 && !strings.HasPrefix(body, "{") {
			l.key, l.value = body[:i], strings.TrimSpace(body[i+2:])
		} else if strings.HasSuffix(body, ":") && !strings.HasPrefix(body, "{") {
			l.key = strings.TrimSuffix(body, ":")
		} else {
			l.value = body
		}
		out = append(out, l)
	}
	if items != 1 {
		t.Fatalf("expected exactly ONE top-level list item, got %d", items)
	}
	return out
}

// keysAt returns the mapping keys at `indent` that belong to the block opened
// by `parent` (or the whole row when parent is empty).
func keysAt(lines []yamlLine, parent string, indent int) map[string]string {
	out := map[string]string{}
	inBlock := parent == ""
	for _, l := range lines {
		if parent != "" {
			if l.indent == indent-2 && l.key == parent {
				inBlock = true
				continue
			}
			if inBlock && l.indent <= indent-2 {
				break
			}
		}
		if inBlock && l.indent == indent && l.key != "" {
			out[l.key] = l.value
		}
	}
	return out
}

// blockText returns the raw text of the block opened by `key` at `indent`.
func blockText(lines []yamlLine, key string, indent int) string {
	var b strings.Builder
	in := false
	for _, l := range lines {
		if l.indent == indent && l.key == key {
			in = true
			b.WriteString(l.raw)
			b.WriteString("\n")
			continue
		}
		if in {
			if l.indent <= indent {
				break
			}
			b.WriteString(l.raw)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// ---- the tests ---------------------------------------------------------------

func TestProposalRowMatchesTheCatalogSchema(t *testing.T) {
	p := BuildProposal(sampleItem())
	lines := readRow(t, p.CatalogRow)
	row := keysAt(lines, "", 2)

	for k := range row {
		if !rowKeys[k] {
			t.Errorf("unknown row key %q (bake_rules.ROW_KEYS refuses it)", k)
		}
	}
	for _, k := range rowRequired {
		if _, ok := row[k]; !ok {
			t.Errorf("missing required row key %q", k)
		}
	}
	if _, ok := row["family"]; !ok {
		t.Error("a row must declare `family` (null when it has none)")
	}
	if !lanes[row["lane"]] {
		t.Errorf("lane %q not in the catalog's LANES", row["lane"])
	}
	if !sources[row["source"]] {
		t.Errorf("source %q not in SOURCES", row["source"])
	}
	if !entityTypes[row["entity_type"]] {
		t.Errorf("entity_type %q unknown", row["entity_type"])
	}
	if !fidelityStatuses[row["fidelity_status"]] {
		t.Errorf("fidelity_status %q is not on the ladder", row["fidelity_status"])
	}
	if row["fidelity_status"] != "doc_claimed" {
		t.Errorf("a draft must sit at doc_claimed, got %q", row["fidelity_status"])
	}
	if row["shadow"] != "true" {
		t.Errorf("a draft must be shadow: true, got %q", row["shadow"])
	}
	if row["kind"] != draftKind {
		t.Errorf("kind %q — a draft must use the generic keystone %q", row["kind"], draftKind)
	}
	// markers must be UPPER-CASE.
	markers := strings.Trim(row["markers"], "[]")
	for _, m := range strings.Split(markers, ",") {
		m = strings.TrimSpace(m)
		if m != "" && m != strings.ToUpper(m) {
			t.Errorf("marker %q must be UPPER-CASE", m)
		}
	}
	// pattern_src must be a live `re` node of the row's own guard.
	pat := strings.TrimSuffix(strings.TrimPrefix(row["pattern_src"], "'"), "'")
	if pat == "" {
		t.Fatal("pattern_src is empty")
	}
	guard := blockText(lines, "guard", 2)
	if !strings.Contains(guard, "re: [msg, '"+pat+"'") {
		t.Fatalf("pattern_src is not an `re` node of its own guard.\nguard:\n%s\npattern: %s", guard, pat)
	}
	// emit
	emit := keysAt(lines, "emit", 4)
	for k := range emit {
		if !emitKeys[k] {
			t.Errorf("unknown emit key %q", k)
		}
	}
	for _, k := range runtimeEmitNeeded {
		if emit[k] == "" {
			t.Errorf("a runtime-lane rule needs emit.%s", k)
		}
	}
	if emit["severity"] == "" && row["severity"] == "" {
		t.Error("declares neither emit.severity nor severity")
	}
	// A rule may only read the haystacks ITS LANE builds.
	fields := regexp.MustCompile(`\{(?:contains|re|eq|ne|equals_any|not_in|truthy)\s*:\s*\[\s*([a-z_]+)`)
	for _, m := range fields.FindAllStringSubmatch(guard+blockText(lines, "extract", 2), -1) {
		if !syslogLaneFields[m[1]] {
			t.Errorf("guard/extract reads %q, which lane syslog does not build", m[1])
		}
	}
	// An extraction may not shadow a var the lane seeds.
	for k := range keysAt(lines, "extract", 4) {
		if syslogSeededVars[k] {
			t.Errorf("extraction %q shadows a seeded lane var — the seeded value wins and the grammar never runs", k)
		}
	}
}

// TestProposalPatternMatchesTheObservedLine is the substantive check behind the
// draft: a rule whose regex does not match the very line it was mined from
// would be a row that looks plausible and fires never.
func TestProposalPatternMatchesTheObservedLine(t *testing.T) {
	it := sampleItem()
	pat := patternFromTemplate(it.Template)
	re, err := regexp.Compile(pat)
	if err != nil {
		t.Fatalf("generated pattern does not compile: %v\n%s", err, pat)
	}
	if !re.MatchString(it.Sample) {
		t.Fatalf("generated pattern does not match its own sample.\npattern: %s\nsample:  %s", pat, it.Sample)
	}
	// It must also match the OTHER variants the shape covers...
	for _, ok := range []string{
		"%LINK-3-UPDOWN: Interface GigabitEthernet0/7, changed state to up",
		"%LINK-3-UPDOWN: Interface TenGigE0/0/0/1, changed state to down",
	} {
		if !re.MatchString(ok) {
			t.Errorf("pattern does not match a variant of its own shape: %q", ok)
		}
	}
	// ...and not an unrelated line.
	if re.MatchString("%BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down Interface flap") {
		t.Error("pattern is so general it matches an unrelated shape")
	}
}

func TestProposalIsDeterministicAndIdentifiedByTheTemplate(t *testing.T) {
	a := BuildProposal(sampleItem())
	b := BuildProposal(sampleItem())
	if a != b {
		t.Fatal("BuildProposal is not deterministic")
	}
	if a.ProposalID != ProposalID(sampleItem().TemplateID) {
		t.Fatalf("proposal_id %q is not hash(template_id)", a.ProposalID)
	}
	if !strings.HasPrefix(a.ProposalID, "prop-") {
		t.Fatalf("proposal_id %q", a.ProposalID)
	}
	if a.Status != "drafted" {
		t.Fatalf("status = %q, want %q", a.Status, "drafted")
	}
	// Two different templates must not draft under one id.
	other := sampleItem()
	other.TemplateID = "t-9999999999"
	if BuildProposal(other).ProposalID == a.ProposalID {
		t.Fatal("two templates collided on one proposal_id")
	}
}

// TestProposalSaysItAppliesNothing: the row's own header is the operator's
// only signal that this is a draft. It is part of the contract, not decoration.
func TestProposalSaysItAppliesNothing(t *testing.T) {
	row := BuildProposal(sampleItem()).CatalogRow
	for _, want := range []string{
		"NOTHING HAS BEEN APPLIED",
		"telemetry-catalog/events.yaml",
		"bake_rules.py",
		"fidelity_status: doc_claimed",
		"shadow: true",
	} {
		if !strings.Contains(row, want) {
			t.Errorf("the drafted row does not mention %q", want)
		}
	}
}

func TestProposalFixtureIsTheCatalogFixtureShape(t *testing.T) {
	p := BuildProposal(sampleItem())
	var row map[string]any
	if err := json.Unmarshal([]byte(p.Fixture), &row); err != nil {
		t.Fatalf("fixture is not one JSON object: %v (%s)", err, p.Fixture)
	}
	for _, k := range []string{"hostname", "appname", "message", "timestamp"} {
		if _, ok := row[k]; !ok {
			t.Errorf("fixture is missing %q (fixtures/syslog_events.jsonl shape)", k)
		}
	}
	if _, ok := row["_expect"]; ok {
		t.Error("a draft fixture must NOT carry `_expect`: the row has family: null and shadow: true, so it deliberately parses to nothing")
	}
	if row["hostname"] == "rtr-1" {
		t.Error("the fixture must not carry a real device name — it travels in a pull request")
	}
	if row["message"] != sampleItem().Sample {
		t.Errorf("fixture message = %v, want the observed sample", row["message"])
	}
	if strings.Contains(p.Fixture, "\n") {
		t.Error("a JSONL fixture must be exactly one line")
	}
}

func TestDraftRuleIDStaysInItsOwnNamespace(t *testing.T) {
	cases := []struct{ app, mnemonic, want string }{
		{"%LINK-3-UPDOWN", "UPDOWN", "draft.link_3_updown.updown"},
		{"PFE", "", "draft.pfe"},
		{"", "UPDOWN", "draft.updown"},
		{"", "", "draft.unclassified.0123456789"},
		{"!!!", "???", "draft.unclassified.0123456789"},
	}
	for _, c := range cases {
		it := sampleItem()
		it.AppName, it.Mnemonic = c.app, c.mnemonic
		if got := draftRuleID(it); got != c.want {
			t.Errorf("draftRuleID(%q,%q) = %q, want %q", c.app, c.mnemonic, got, c.want)
		}
	}
	// Every id is in the reserved namespace, so a pasted row cannot collide
	// with the baked corpus.
	for _, c := range cases {
		it := sampleItem()
		it.AppName, it.Mnemonic = c.app, c.mnemonic
		if !strings.HasPrefix(draftRuleID(it), "draft.") {
			t.Errorf("draftRuleID escaped the draft namespace: %q", draftRuleID(it))
		}
	}
}

// TestProposalIsSafeAgainstHostileTemplateText: a template is device-supplied
// text. It must not be able to close a quote, open a new YAML key, or inject a
// comment line that changes the row below it.
func TestProposalIsSafeAgainstHostileTemplateText(t *testing.T) {
	it := sampleItem()
	it.Template = "evil' \nrule_id: pwned\n#"
	it.Sample = it.Template
	it.AppName = "A'B"
	it.Mnemonic = "M'N"
	p := BuildProposal(it)
	lines := readRow(t, p.CatalogRow) // fails the test on structural damage
	row := keysAt(lines, "", 2)
	if row["rule_id"] == "pwned" {
		t.Fatal("template text forged a row key")
	}
	if !strings.HasPrefix(row["rule_id"], "draft.") {
		t.Fatalf("rule_id = %q", row["rule_id"])
	}
	// Single-quoted YAML scalars escape a quote by doubling it; a lone quote
	// would terminate the scalar early.
	for _, l := range lines {
		if strings.Contains(l.value, "'") && strings.Count(l.value, "'")%2 != 0 {
			t.Fatalf("unbalanced quote in emitted scalar: %q", l.raw)
		}
	}
	if strings.Contains(p.Fixture, "\n") {
		t.Fatal("hostile text produced a multi-line fixture")
	}
}

func TestPatternFromTemplateIsBounded(t *testing.T) {
	long := strings.Repeat("averyverylongtokenindeed ", 500)
	pat := patternFromTemplate(long)
	if len(pat) > maxPatternBytes {
		t.Fatalf("pattern is %d bytes, cap is %d", len(pat), maxPatternBytes)
	}
	if _, err := regexp.Compile(pat); err != nil {
		t.Fatalf("truncated pattern does not compile: %v", err)
	}
}
