package collectors

import (
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/parsetrace"
)

const hookMarker = "01m1kyybjwne1fpjzktftka0wd"

type hookCapture struct {
	mu    sync.Mutex
	lines []map[string]any
	msgs  []string
}

func (c *hookCapture) sink(_, _, msg string, fields map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, msg)
	c.lines = append(c.lines, fields)
}

// armDefault installs a capture sink on the process-wide filter and restores it.
// The filter is package-level by necessity (the trap decoder runs deep inside a
// receive loop), so a test that armed it and walked away would leak into every
// other test in this package.
func armDefault(t *testing.T) *hookCapture {
	t.Helper()
	c := &hookCapture{}
	f := parsetrace.Default()
	f.SetSink(c.sink)
	t.Cleanup(func() {
		f.Disarm()
		f.SetSink(nil)
	})
	return c
}

// The decision path — not the event — is what the hook adds: which OID matched
// which MIB entry, what severity that implied, which fields were extracted.
func TestTrapParseHookRecordsTheDecisionPath(t *testing.T) {
	c := armDefault(t)
	ev := &TrapEvent{
		Message:  "linkDown 1.3.6.1.6.3.1.1.5.3 ifIndex=7 cx_synthetic=true cx_debug=" + hookMarker,
		TrapOID:  "1.3.6.1.6.3.1.1.5.3",
		TrapName: "linkDown",
		Severity: "warning",
		Vendor:   "cisco",
		Device:   "spine1",
		Host:     "10.70.245.11",
		Varbinds: []TrapVarbind{
			{OID: "1.3.6.1.2.1.2.2.1.1.7", Name: "ifIndex", Value: "7"},
			{OID: "1.3.6.1.4.1.9.9.9.9.1", Value: "opaque"},
		},
	}
	traceTrapDecision(ev)
	if len(c.lines) != 1 {
		t.Fatalf("the hook emitted %d lines, want 1", len(c.lines))
	}
	f := c.lines[0]
	if f["matched_trap_name"] != "linkDown" || f["matched_trap_oid"] != "1.3.6.1.6.3.1.1.5.3" {
		t.Errorf("the matched rule is not recorded: %v", f)
	}
	if f["severity"] != "warning" || f["vendor"] != "cisco" || f["device"] != "spine1" {
		t.Errorf("the derived attribution is not recorded: %v", f)
	}
	names, _ := f["extracted_fields"].([]string)
	if len(names) != 2 || names[0] != "ifIndex" {
		t.Errorf("the extracted fields are not recorded: %v", f["extracted_fields"])
	}
	if f["unresolved_oids"] != 1 {
		t.Errorf("an unresolved OID was not counted: %v", f["unresolved_oids"])
	}
}

// EVERY DROP GETS A REASON. A count with no reason is the shape that makes an
// operator guess, which is the whole defect this hook removes.
func TestTrapParseHookNamesEveryDropReason(t *testing.T) {
	c := armDefault(t)
	traceTrapDecision(&TrapEvent{
		Message:         "cx_debug=" + hookMarker + " probe",
		VarbindsDropped: 4,
		Truncated:       true,
	})
	if len(c.lines) != 1 {
		t.Fatalf("emitted %d lines", len(c.lines))
	}
	f := c.lines[0]
	reason, _ := f["drop_reason"].(string)
	if !strings.Contains(reason, "varbind cap") {
		t.Errorf("the drop has no reason naming the rule: %q", reason)
	}
	trunc, _ := f["truncation_reason"].(string)
	if !strings.Contains(trunc, "character cap") {
		t.Errorf("the truncation has no reason: %q", trunc)
	}
	if f["no_match_reason"] == nil {
		t.Error("an unmatched trap OID must say what that costs downstream")
	}
}

// An unmarked trap must cost one substring search and produce nothing. This is
// the cost argument for putting the hook on a receive path at all.
func TestTrapParseHookIsSilentForOrdinaryTraps(t *testing.T) {
	c := armDefault(t)
	traceTrapDecision(&TrapEvent{
		Message: "linkDown ifIndex=7", TrapOID: "1.3.6.1.6.3.1.1.5.3", TrapName: "linkDown",
	})
	traceTrapDecision(nil)
	if len(c.lines) != 0 {
		t.Fatalf("an ordinary trap produced %d decision lines", len(c.lines))
	}
}

// The armed needle traces a REAL trap that carries no marker — the case the
// runtime switch exists for.
func TestTrapParseHookHonoursAnArmedNeedle(t *testing.T) {
	c := armDefault(t)
	if _, err := parsetrace.Default().Arm("ifIndex=7", time.Minute); err != nil {
		t.Fatal(err)
	}
	traceTrapDecision(&TrapEvent{
		Message: "linkDown ifIndex=7", TrapOID: "1.3.6.1.6.3.1.1.5.3", TrapName: "linkDown",
	})
	if len(c.lines) != 1 {
		t.Fatalf("an armed needle traced %d records, want 1", len(c.lines))
	}
}

// A refusal leaves no event to tap, so the trace line is the ONLY record of it.
func TestTraceParseDropRecordsTheRefusal(t *testing.T) {
	c := armDefault(t)
	TraceParseDrop("cx_debug="+hookMarker+" probe", "parse:snmptrap",
		"the source IP is not in the inventory and the community did not match any device",
		map[string]any{"source_ip": "10.70.245.11"})
	if len(c.lines) != 1 {
		t.Fatalf("emitted %d lines", len(c.lines))
	}
	if c.lines[0]["dropped"] != true {
		t.Errorf("the drop flag is missing: %v", c.lines[0])
	}
	if !strings.Contains(c.msgs[0], "DROPPED") {
		t.Errorf("the message does not say the record was dropped: %q", c.msgs[0])
	}
	if c.lines[0]["source_ip"] != "10.70.245.11" {
		t.Errorf("caller fields were not merged: %v", c.lines[0])
	}
}

// The `parse:` prefix is the whole routing rule between the trace's PARSER
// stage and its api stage. Losing it would file every decision line under the
// wrong hop.
func TestTrapParseComponentCarriesTheStagePrefix(t *testing.T) {
	if !strings.HasPrefix(TrapParseComponent, "parse:") {
		t.Fatalf("%q would be filed under the api stage, not the parser stage", TrapParseComponent)
	}
}
