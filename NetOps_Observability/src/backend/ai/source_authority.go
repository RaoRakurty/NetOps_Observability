// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import "strings"

// EnsureDisagreementStated is the deterministic half of the source-authority
// rule (tracker 337 N-F6, owner 2026-11-09): Iris never silently picks between
// sources. An answer that repeats a value the sources disagree on, without
// citing the item that states the disagreement, gets that item appended — so
// the guarantee does not rest on the model following the doctrine.
//
// An answer that never mentions a contested value is left alone: a question
// about CPU does not need a note about the serial number. The appended text is
// flattened and redacted like any other evidence crossing this boundary, and
// the SPA renders it as escaped text (§15).
func EnsureDisagreementStated(text string, evidence []EvidenceItem) string {
	lower := strings.ToLower(text)
	seen := map[string]bool{}
	for _, it := range evidence {
		if len(it.Contested) == 0 || seen[it.CitationID] {
			continue
		}
		seen[it.CitationID] = true
		if strings.Contains(text, "["+it.CitationID+"]") {
			continue // the answer already cites where the disagreement is stated
		}
		for _, v := range it.Contested {
			if v = strings.ToLower(strings.TrimSpace(v)); v != "" && strings.Contains(lower, v) {
				text = strings.TrimRight(text, " \n") + "\n\n" + Redact(OneLine(it.Text)) + " [" + it.CitationID + "]"
				break
			}
		}
	}
	return text
}
