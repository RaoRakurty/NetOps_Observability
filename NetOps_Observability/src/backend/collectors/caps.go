// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import "strings"

// caps.go — BOUNDS on untrusted device-supplied strings (audit PIPE-MED-8/9/11).
//
// The collectors validate the SHAPE of what a device sends (BER tags, OID arcs,
// JSON types) but historically not its SIZE. Every string decoded here ends up in
// one of three places, and each has a different failure mode when it is unbounded:
//
//	VictoriaMetrics LABEL  — a distinct value creates a distinct time series. An
//	                         attacker (or a broken agent) that varies ifAlias per
//	                         poll is a CARDINALITY BOMB: unbounded series, unbounded
//	                         memory, and the TSDB degrades for every tenant.
//	ClickHouse String      — unbounded row width, unbounded part size.
//	OpenSearch document    — unbounded doc size; a 100 KB keyword field is rejected
//	                         or silently dropped by the index mapping.
//
// The cap is therefore applied by FIELD CLASS at the point the string is decoded,
// not per call site — one bounded string primitive, three documented classes, so a
// new collector inherits the bound instead of having to remember it. Truncation is
// deterministic and idempotent: capping an already-capped value is a no-op, so it
// never perturbs a replayed/reprocessed value.
//
// Bounds are on RUNES, not bytes, so a multi-byte value is never cut mid-codepoint
// (a torn UTF-8 sequence is exactly the kind of thing an OpenSearch mapping rejects).
const (
	// maxLabelChars bounds anything that becomes a metric LABEL or a short
	// identity column (ifName, ifAlias, sysName, model, serial, port id). RFC 2863
	// caps ifAlias at 64 octets and ifName at 255; 128 keeps every legitimate
	// value and cuts a hostile one long before it reaches the TSDB.
	maxLabelChars = 128

	// maxTextChars bounds descriptive free text that is stored but never used as a
	// label (sysDescr, ifDescr, chassis/port descriptions). Cisco IOS sysDescr runs
	// to ~400 characters legitimately, so the bound is generous but finite.
	maxTextChars = 512
)

// clampRunes truncates s to at most n runes. Deterministic and idempotent.
func clampRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	// Fast path: an ASCII-length under the bound can never exceed it in runes.
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// scrubControl replaces control characters with spaces and collapses runs of
// whitespace. Device strings routinely carry CR/LF/tabs (and NUL padding), all of
// which corrupt a Prometheus exposition line and a log record.
func scrubControl(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	return strings.TrimSpace(strings.Join(strings.Fields(s), " "))
}

// sanitizeLabel makes an SNMP/controller string safe for a Prometheus label value:
// strip control chars, collapse whitespace, and BOUND THE LENGTH (the cardinality
// and exposition-size guard — see the file header).
func sanitizeLabel(s string) string { return clampRunes(scrubControl(s), maxLabelChars) }

// sanitizeText is sanitizeLabel's looser sibling for descriptive fields that are
// stored (ClickHouse/OpenSearch) but never used as a metric label.
func sanitizeText(s string) string { return clampRunes(scrubControl(s), maxTextChars) }
