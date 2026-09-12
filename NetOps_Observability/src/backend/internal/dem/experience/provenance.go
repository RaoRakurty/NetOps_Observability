// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// provenance.go — Phase D ("provenance everywhere") and Phase L (data
// classification), written once so every object in this package carries the
// same block and no future object can quietly omit it.
//
// The vocabulary is deliberately a SUPERSET of pathgraph's four data classes
// (live/synthetic/replay/lab describe how a MEASUREMENT was produced) with the
// owner's privacy ladder (how a value must be HANDLED). They answer different
// questions and are kept as separate fields for exactly that reason: a `live`
// measurement can carry a `pseudonymous_user` value, and conflating the two is
// how a PII rule gets applied to the wrong column.

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Data classes (Phase L). Ordered least → most sensitive; the order is
// load-bearing — [MostSensitive] and the AI packet redactor read it.
const (
	DataClassPublic           = "public"
	DataClassInternal         = "internal"
	DataClassCustomerMetadata = "customer_metadata"
	DataClassPseudonymousUser = "pseudonymous_user"
	DataClassPII              = "pii"
	DataClassRegulated        = "regulated"
	DataClassCredential       = "credential"
	DataClassSecret           = "secret"
)

// dataClassRank orders the ladder. An unknown class is treated as the MOST
// sensitive value in the ladder, never the least: a class we do not recognise
// is a class whose handling rules we do not know (§3 fail-closed).
var dataClassRank = map[string]int{
	DataClassPublic: 0, DataClassInternal: 1, DataClassCustomerMetadata: 2,
	DataClassPseudonymousUser: 3, DataClassPII: 4, DataClassRegulated: 5,
	DataClassCredential: 6, DataClassSecret: 7,
}

// DataClasses is the closed vocabulary, least → most sensitive.
var DataClasses = []string{
	DataClassPublic, DataClassInternal, DataClassCustomerMetadata,
	DataClassPseudonymousUser, DataClassPII, DataClassRegulated,
	DataClassCredential, DataClassSecret,
}

// ValidDataClass reports whether c is one of the eight declared classes.
func ValidDataClass(c string) bool { _, ok := dataClassRank[c]; return ok }

// DataClassRank returns the sensitivity rank of c. An UNKNOWN class ranks above
// every known one, so "is this safe to send to a model" answers "no" for a
// class nobody declared.
func DataClassRank(c string) int {
	if r, ok := dataClassRank[c]; ok {
		return r
	}
	return len(dataClassRank) // unknown ⇒ most sensitive
}

// MayLeaveThePlatform reports whether a value of class c may be included in an
// outbound LLM prompt or an exported bundle (CLAUDE.md §15 LLM06). Everything
// at or above pseudonymous_user is withheld by default; a pseudonymous user id
// is admitted only because it is, by construction, not a person's identifier.
func MayLeaveThePlatform(c string) bool {
	return DataClassRank(c) <= dataClassRank[DataClassPseudonymousUser]
}

// Observed/inferred (Phase D). Kept as an explicit enum rather than a bool so a
// third honest state — "we did not look" — is expressible and cannot be
// silently coerced into "inferred".
const (
	ObservationObserved  = "observed"
	ObservationInferred  = "inferred"
	ObservationUnknown   = "unknown"
	ObservationSimulated = "simulated" // fixtures, replays, demos — never a live verdict
)

// ValidObservation reports whether o is one of the four observation modes.
func ValidObservation(o string) bool {
	switch o {
	case ObservationObserved, ObservationInferred, ObservationUnknown, ObservationSimulated:
		return true
	}
	return false
}

// SchemaName / SchemaVersion identify THIS package's canonical contract
// (Phase F: an unstable external convention is never the permanent internal
// one). Bumping SchemaVersion is a deliberate, documented act.
const (
	SchemaName    = "correlix.dem.experience"
	SchemaVersion = 1
)

// Bounds. Every one of them is a refusal, never a truncation, at the HTTP
// boundary; inside the package clip() bounds a value that is already trusted to
// exist but not to be small.
const (
	MaxIDBytes      = 128
	MaxLabelBytes   = 128
	MaxSummaryBytes = 512
	MaxDetailBytes  = 2048
	MaxListLen      = 200 // steps, evidence per hypothesis, hops rendered, …
)

// Provenance is the Phase D block every fact in this package carries.
//
// It answers, for one value: who produced it, out of which upstream object,
// when the EVENT happened and when we OBSERVED it (they are different and the
// difference is diagnostic), whether we measured it or inferred it, how much we
// trust it, how stale it is allowed to be, and how it must be handled.
type Provenance struct {
	Source       string `json:"source"`                  // the producing subsystem: synthetic | pathgraph | correlation | configdrift | cloud | bgp | rum | flow | sdwan | wireless | agent | manual
	SourceObject string `json:"source_object,omitempty"` // the upstream object's own id
	Producer     string `json:"producer,omitempty"`      // the concrete producer instance (prober id, collector id)

	EventAt    time.Time `json:"event_at"`    // when the thing being described happened
	ObservedAt time.Time `json:"observed_at"` // when Correlix learned of it

	Observation string `json:"observation"` // observed | inferred | unknown | simulated
	DataClass   string `json:"data_class"`

	// SchemaName/SchemaVersion are the CANONICAL contract; External* record the
	// foreign schema an adapter translated FROM (OpenTelemetry, a vendor API),
	// so an upstream convention change is a diff in these fields rather than a
	// silent change in meaning (Phase M).
	SchemaName      string `json:"schema_name"`
	SchemaVersion   int    `json:"schema_version"`
	ExternalSchema  string `json:"external_schema,omitempty"`
	ExternalVersion string `json:"external_version,omitempty"`
}

// Sources — the closed producer vocabulary. It intentionally mirrors
// internal/dem's measurement sources plus the non-measurement producers an
// experience verdict also reads.
const (
	SourceSynthetic   = "synthetic"
	SourcePathGraph   = "pathgraph"
	SourceCorrelation = "correlation"
	SourceConfigDrift = "configdrift"
	SourceCloud       = "cloud"
	SourceBGP         = "bgp"
	SourceRUM         = "rum"
	SourceFlow        = "flow"
	SourceSDWAN       = "sdwan"
	SourceWireless    = "wireless"
	SourceAgent       = "agent"
	SourceServiceHTTP = "service_health"
	SourceManual      = "manual"
)

var knownSources = map[string]bool{
	SourceSynthetic: true, SourcePathGraph: true, SourceCorrelation: true,
	SourceConfigDrift: true, SourceCloud: true, SourceBGP: true, SourceRUM: true,
	SourceFlow: true, SourceSDWAN: true, SourceWireless: true, SourceAgent: true,
	SourceServiceHTTP: true, SourceManual: true,
}

// ValidSource reports whether s is a declared producer.
func ValidSource(s string) bool { return knownSources[s] }

// Normalize fills the canonical schema fields and lowercases the enums. It is
// called by Validate; a caller that builds a Provenance by hand and skips
// Validate gets a record that will be REFUSED at the boundary rather than one
// that is quietly repaired.
func (p *Provenance) Normalize() {
	p.Source = strings.ToLower(strings.TrimSpace(p.Source))
	p.Observation = strings.ToLower(strings.TrimSpace(p.Observation))
	p.DataClass = strings.ToLower(strings.TrimSpace(p.DataClass))
	p.SourceObject = clip(strings.TrimSpace(p.SourceObject), MaxIDBytes)
	p.Producer = clip(strings.TrimSpace(p.Producer), MaxIDBytes)
	p.SchemaName = SchemaName
	p.SchemaVersion = SchemaVersion
	p.ExternalSchema = clip(strings.TrimSpace(p.ExternalSchema), MaxLabelBytes)
	p.ExternalVersion = clip(strings.TrimSpace(p.ExternalVersion), MaxLabelBytes)
	if p.ObservedAt.IsZero() {
		p.ObservedAt = p.EventAt
	}
	p.EventAt, p.ObservedAt = p.EventAt.UTC(), p.ObservedAt.UTC()
}

// Validate refuses a provenance block that cannot say who produced the fact,
// how it was arrived at, or how it must be handled. An object that cannot state
// its own provenance is not admissible evidence (the pathgraph contract's §1
// rule, applied to the experience domain).
func (p *Provenance) Validate() error {
	p.Normalize()
	if !ValidSource(p.Source) {
		return fmt.Errorf("provenance: unknown source %q", clip(p.Source, 32))
	}
	if !ValidObservation(p.Observation) {
		return fmt.Errorf("provenance: observation must be observed|inferred|unknown|simulated (got %q)", clip(p.Observation, 32))
	}
	if !ValidDataClass(p.DataClass) {
		return fmt.Errorf("provenance: unknown data_class %q", clip(p.DataClass, 32))
	}
	if p.EventAt.IsZero() {
		return errors.New("provenance: event_at is required (a fact with no time cannot be correlated)")
	}
	return nil
}

// Age is how stale the fact is at now. Negative ages (a producer's clock ahead
// of ours) are reported as zero rather than as negative freshness — a clock
// skew must not read as "fresher than possible".
func (p Provenance) Age(now time.Time) time.Duration {
	d := now.Sub(p.ObservedAt)
	if d < 0 {
		return 0
	}
	return d
}

// clip bounds an untrusted string WITHOUT splitting a UTF-8 rune. Duplicated
// from internal/dem rather than shared through a "utils" package (CLAUDE.md §2
// forbids the dumping ground) — six lines is cheaper than a coupling.
func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.ToValidUTF8(s[:cut], "")
}
