// Package experience is the Digital Experience causality domain: the canonical
// objects an experience verdict is built from (evidence, hypotheses, journeys,
// changes, incidents), the confidence maths that grades them, and the published
// experience score.
//
// It is the layer ABOVE internal/dem. internal/dem answers "was this subject
// reachable, how fast, and did its path move"; this package answers the nine
// questions the product exists to answer — who is affected, which journey is
// failing, where the path breaks, what changed, why, how confident we are, who
// owns the failing seam, what action is safe, and whether it recovered.
//
// # WHAT THIS PACKAGE IS NOT
//
// It is NOT a second RCA engine and NOT a second incident store. Two rules from
// the design of record (docs/design/DEM_2026-09-05.md §M.2) are structural here:
//
//   - An ExperienceIncident is the platform's existing incident with
//     source_type "experience" plus the DEM evidence packet defined here. The
//     packet references the incident; it never becomes a parallel lifecycle.
//   - A CausalHypothesis is graded by the SAME independence rule the Python
//     correlation engine applies (two distinct modality classes, two
//     independent observers). [Hypothesis.Grade] is that rule written once, in
//     Go, over the evidence this package models — never a looser one.
//
// # PURITY
//
// Everything in evidence.go, hypothesis.go, confidence.go, score.go, journey.go
// and incident.go is PURE: no clock, no network, no store. A time is always an
// argument. That is what makes the acceptance scenario
// (docs/design/DEM_2026-09-05.md §M.10, the owner's Phase T) a table test rather
// than a lab booking.
//
// # HONESTY (§10, and the not-measured rule of §M.4)
//
// Missing telemetry is DATA. An absent source lowers confidence, is listed in
// [Hypothesis.MissingEvidence], and can block CONFIRMED outright. A score with
// too little evidence behind it is NOT rendered — never 0, never 100. UNKNOWN
// and NO DATA are never healthy.
package experience
