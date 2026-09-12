// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package parsercov

// admission.go — WHERE "the engine would not admit this line" COMES FROM.
//
// THE PREDICATE, AND WHY WE DO NOT REIMPLEMENT IT
//
// `src/correlation/producers.syslog_promotable` is the necessary condition for
// a raw syslog line to become correlation evidence:
//
//	tag = upcase(appname)
//	sev = min(severity-keyword lookup, %FAC-N-MNEMONIC tag digit)   # 99 = none
//	if sev <= ALARM_SEVERITY_FLOOR (4)          -> admit  (gate "severity")
//	hay = downcase(message + " " + tag + " " + facility + " " + event_type)
//	if any screen literal is a substring of hay -> admit  (gate "marker")
//	otherwise                                   -> REJECT
//
// The screen's literal set is DERIVED from the rule table (producers._CP_GUARD_
// MARKERS + _CP_GUARD_PATTERNS + the port-event rules), so it moves whenever
// events.yaml moves. It is not exported by the engine: `corr_parser_info`
// carries only parser_rev / rules_hash / rule count, and the /healthz `parser`
// block (producers.parser_stats) carries counters, not the literals or the
// floor. So there is nothing to fetch.
//
// A Go transcription of the 61 literals plus the severity ladder would be the
// THIRD copy of this predicate (Python, generated VRL, Go) and the only one
// with no drift guard behind it. §13 exists to stop exactly that, and the repo
// has already paid for a hand-mirrored parser once (see telemetry-catalog's
// "the catalog IS the parser" note). So this package does not guess.
//
// WHAT IT READS INSTEAD: THE PUBLISHED PER-DOCUMENT VERDICT
//
// A4 Phase 1 put the screen where we can read it. `scripts/gen-syslog-
// admission.py` imports `producers`, reads ALARM_SEVERITY_FLOOR and the literal
// set, and COMPILES them into VRL that the aggregator runs as
// `syslog_admission_stamp` (deployment/docker/vector/vector.yaml). CI fails on
// drift (`--check`, tests/test_syslog_admission.py). That transform stamps
//
//	.cx_admission = {"v": "<rules_hash prefix>", "by": "severity"|"marker"|"unscreenable"}
//
// on a line the engine COULD promote and leaves the field UNSET otherwise — and
// it stamps the FULL firehose, not just the admitted subset, precisely so "the
// same field is queryable in OpenSearch across the whole firehose"
// (vector.yaml's own words, kafka_syslog sink note). So:
//
//	unrecognized  ==  a syslog document in the window with NO cx_admission
//
// That is the engine's verdict, per document, with a drift guard already on it.
//
// THE ONE THING THAT CAN GO WRONG, AND HOW IT IS HANDLED
//
// An absent field cannot, on its own, distinguish "the screen rejected this
// line" from "this document predates the stamp / arrived by a path that does
// not stamp". So every run first PROBES the window: it counts documents that
// DO carry the stamp. Zero stamped documents means the lane is not publishing
// the verdict, and the route answers 503 with a note that says so — it never
// falls back to a guess. A partial stamp is reported as a coverage figure in
// the note, so the operator can see how much of the window was judged.
//
// THE TRAP LANE HAS NO EQUIVALENT. There is no trap-side screen at all (every
// trap is consumed; an unclassified one falls to the generic `device_alarm`
// net), so nothing publishes a trap admission verdict. `lane=trap` therefore
// answers 503 with that note rather than mining a set we cannot define.

import "strings"

// admissionField is the leaf under `.cx_admission` that an `exists` query can
// test unambiguously. The stamp is an OBJECT ({v, by}); `exists` on an object
// path depends on field-name expansion, whereas a leaf keyword is exact.
const admissionField = "cx_admission.by"

// admissionVersionField carries the rules_hash prefix of the corpus that
// judged the line. It is reported in the note so an operator knows WHICH
// parser corpus called these lines unrecognized.
const admissionVersionField = "cx_admission.v"

// Lane names the telemetry lane a mining run covers.
type Lane string

const (
	// LaneSyslog is the device syslog lane — the only lane with a published
	// admission verdict.
	LaneSyslog Lane = "syslog"
	// LaneTrap is the SNMP trap lane.
	LaneTrap Lane = "trap"
)

// severityNum maps a syslog severity keyword to its numeric level, mirroring
// `producers.syslog_severity_num`'s keyword table and the generated VRL's copy
// of it byte for byte. Unknown/absent returns severityNone.
//
// This IS a transcription — but of a fixed, standards-defined ladder (RFC 5424
// severities and their common abbreviations), not of the moving screen. It
// decides only how a mined template's `severity_max` is DISPLAYED; it never
// decides admission.
func severityNum(keyword string) int {
	switch strings.ToLower(strings.TrimSpace(keyword)) {
	case "emerg", "emergency":
		return 0
	case "alert":
		return 1
	case "c", "crit", "critical":
		return 2
	case "e", "err", "error":
		return 3
	case "w", "warn", "warning":
		return 4
	case "n", "note", "notice":
		return 5
	case "i", "info", "informational":
		return 6
	case "d", "debug":
		return 7
	}
	return severityNone
}

// tagSeverity reads the digit out of a %FACILITY-N-MNEMONIC app name, the
// second half of the engine's severity resolution. Returns severityNone when
// the app name is not of that shape.
func tagSeverity(appName string) int {
	s := strings.ToUpper(appName)
	i := strings.IndexByte(s, '%')
	if i < 0 {
		return severityNone
	}
	s = s[i+1:]
	// %FAC-N-MNEMONIC: facility, dash, one digit, dash, mnemonic.
	j := strings.IndexByte(s, '-')
	if j <= 0 || j+2 >= len(s) {
		return severityNone
	}
	d := s[j+1]
	if d < '0' || d > '7' || s[j+2] != '-' {
		return severityNone
	}
	return int(d - '0')
}

// mostSevere returns the engine's resolved severity for a record: the more
// severe (numerically smaller) of the keyword and the tag digit.
func mostSevere(keyword, appName string) int {
	a, b := severityNum(keyword), tagSeverity(appName)
	if b < a {
		return b
	}
	return a
}
