package secfindings

import (
	"fmt"
	"strings"
)

// StatusID is the OCSF-normalized verdict. The core rule of the compliance model
// is that an unassessed control is NEVER a false "clear": Pass/Warning/Fail are
// real verdicts, NotApplicable and Error are honest non-verdicts, and the zero
// value StatusUnknown means "no verdict reached" rather than success.
type StatusID int

const (
	StatusUnknown       StatusID = 0 // no verdict — never render as green
	StatusPass          StatusID = 1
	StatusWarning       StatusID = 2
	StatusFail          StatusID = 3
	StatusNotApplicable StatusID = 4
	StatusError         StatusID = 5
)

// String returns the canonical name used in the Finding.Status JSON field and in
// ParseStatus round-trips.
func (s StatusID) String() string {
	switch s {
	case StatusPass:
		return "Pass"
	case StatusWarning:
		return "Warning"
	case StatusFail:
		return "Fail"
	case StatusNotApplicable:
		return "NotApplicable"
	case StatusError:
		return "Error"
	case StatusUnknown:
		return "Unknown"
	default:
		return "Unknown"
	}
}

// Valid reports whether s is a known status id.
func (s StatusID) Valid() bool {
	return s >= StatusUnknown && s <= StatusError
}

// ParseStatus is the inverse of String: it parses a canonical status name back
// into its id. It is case-insensitive so a hand-written or round-tripped value
// parses regardless of casing. An unrecognized name is an error rather than a
// silent Unknown, so a typo in stored data surfaces instead of masquerading as
// "no verdict".
func ParseStatus(name string) (StatusID, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "pass":
		return StatusPass, nil
	case "warning":
		return StatusWarning, nil
	case "fail":
		return StatusFail, nil
	case "notapplicable", "not applicable", "not-applicable":
		return StatusNotApplicable, nil
	case "error":
		return StatusError, nil
	case "unknown", "":
		return StatusUnknown, nil
	default:
		return StatusUnknown, fmt.Errorf("secfindings: unknown status %q", name)
	}
}

// NormalizeStatus maps a PROVIDER's raw verdict token (OpenSCAP XCCDF result,
// Lynis status, CIS-CAT result, a Correlix net-rule outcome) onto the owned
// OCSF StatusID. It is provider-agnostic on purpose — the normalization is where
// every external tool's vocabulary collapses into Correlix's single verdict
// space, per §5h (Correlix owns the model, never depends on a tool's shape).
//
// Unrecognized/absent verdicts return StatusUnknown so nothing an external tool
// emits is ever silently promoted to Pass.
func NormalizeStatus(raw string) StatusID {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "pass", "passed", "ok", "compliant", "success", "fixed":
		return StatusPass
	case "warning", "warn", "suggestion", "informational", "info":
		return StatusWarning
	case "fail", "failed", "noncompliant", "non-compliant", "violation":
		return StatusFail
	case "notapplicable", "not applicable", "not-applicable", "na", "n/a",
		"notchecked", "not-checked", "notselected", "not-selected":
		return StatusNotApplicable
	case "error", "cannot-assess":
		return StatusError
	default:
		return StatusUnknown
	}
}

// SetStatus stamps both the numeric id and its canonical string on a finding,
// keeping the pair consistent (the two fields must never disagree).
func (f *Finding) SetStatus(id StatusID) {
	f.StatusID = id
	f.Status = id.String()
}
