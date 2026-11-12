// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package noclabel

// wording.go — sentences that more than one RCA surface must say identically
// (RCA document v2, docs/design/RCA_DOCUMENT_V2_2026-11-12.md §3). The report
// builder, the HTML/PDF, the path view and Iris call these; none of them
// composes its own variant. When one changes, every surface changes with it.

import "strings"

// NearestCompetitorNotObserved labels a ranked template none of whose REQUIRED
// observations was seen (§3.3). It reached the ranking only through an optional
// clause, so it is a nearest competitor, never an observed or active candidate.
const NearestCompetitorNotObserved = "nearest competitor — not observed"

// LocalisationSentence is THE localisation sentence (§3.4). When independent
// evidence localised the fault to an object, it says so; otherwise it says where
// the evidence concentrates and that this is not a localisation. subject is the
// device (or other object) the evidence concentrates on; empty → the evidence
// names no object at all.
//
//	localised=false: "Evidence concentrates on cedge-60-07ae8615; not independently localised."
//	localised=true:  "Fault localised to cedge-60-07ae8615 by independent evidence."
func LocalisationSentence(subject string, localised bool) string {
	subject = strings.TrimSpace(subject)
	switch {
	case subject == "":
		return "The evidence does not concentrate on a single object; not localised."
	case localised:
		return "Fault localised to " + subject + " by independent evidence."
	}
	return "Evidence concentrates on " + subject + "; not independently localised."
}
