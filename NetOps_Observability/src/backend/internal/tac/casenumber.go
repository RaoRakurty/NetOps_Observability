// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// casenumber.go — the case number a human types back in.
//
// WHY IT NEEDS A RULE AT ALL. On a MANUAL path the vendor's case is created in
// the vendor's own portal, so the only way the number ever reaches Correlix is
// an operator reading it off one screen and typing it into another. That is the
// one value on the whole escalation Correlix cannot derive, cannot verify
// against the vendor, and must still put on the incident — where it becomes the
// thing the next operator searches for.
//
// A transposed digit therefore files the evidence under a case that does not
// exist, and nothing downstream can tell. The shape check is what catches it at
// the keyboard, which is the only place it CAN be caught: the vendor publishes
// no API to ask (that is why this path is manual).
//
// THE PATTERN IS THE ADMIN'S, NOT OURS. Correlix does not know what a Nokia TSR
// number looks like and will not pretend to — the Tier-3 research established
// that these vendors publish no case API, and none of them publishes a case-id
// grammar either. So the pattern is configured per vendor on Administration →
// Ticket delivery by the customer, who has their own cases in front of them, and
// DefaultCaseNumberPattern is a deliberately loose shape that rejects prose and
// nothing else.
//
// §3 zero trust: the pattern is operator-supplied and therefore hostile until
// proven otherwise. It is length-bounded, compiled (never interpolated into
// anything), and anchored HERE rather than trusted to anchor itself — an
// unanchored `\d{4}` would happily accept "please open case 1234 for me".

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// DefaultCaseNumberPattern is the shape a case number takes when the tenant has
// not stated the vendor's own: a leading alphanumeric then alphanumerics and the
// separators every vendor's case ids use. It exists to reject a sentence, a URL
// or an empty box — not to claim knowledge of a vendor's format.
const DefaultCaseNumberPattern = `[A-Za-z0-9][A-Za-z0-9._/-]{2,63}`

// MaxCaseNumberLen bounds what may be typed into the box (§9: every input is
// bounded). It is far above any real case id and far below a regex-cost problem.
const MaxCaseNumberLen = 64

// MaxCaseNumberPatternLen bounds the PATTERN an administrator may store. A
// pattern is compiled, not executed, but an unbounded one is still an unbounded
// input crossing a trust boundary.
const MaxCaseNumberPatternLen = 200

// ErrCaseNumberPattern is returned when a stored pattern cannot be compiled.
var ErrCaseNumberPattern = errors.New("that case-number pattern is not a valid expression")

// CompileCaseNumberPattern compiles an operator-supplied pattern, ANCHORED, so
// a partial match can never pass for a whole case number. An empty pattern
// compiles to the default shape rather than to "anything": a manual path with no
// check at all is how a typo becomes a permanent record.
func CompileCaseNumberPattern(pattern string) (*regexp.Regexp, error) {
	p := strings.TrimSpace(pattern)
	if p == "" {
		p = DefaultCaseNumberPattern
	}
	if len(p) > MaxCaseNumberPatternLen {
		return nil, fmt.Errorf("%w: it is longer than %d characters", ErrCaseNumberPattern, MaxCaseNumberPatternLen)
	}
	// Anchoring is ours to do. A pattern that already carries its own anchors is
	// still correct inside these: `^(?:^TSR\d+$)$` matches exactly what
	// `^TSR\d+$` does.
	re, err := regexp.Compile("^(?:" + p + ")$")
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCaseNumberPattern, err.Error())
	}
	return re, nil
}

// ValidateCaseNumber checks one typed case number against the tenant's pattern.
//
// It returns an error an OPERATOR can act on — the box they are looking at and
// the shape it expects — because this refusal lands on the confirmation screen
// beside the field, not in a log.
func ValidateCaseNumber(pattern, number string) error {
	n := strings.TrimSpace(number)
	if n == "" {
		return errors.New("type the case number the vendor's portal gave you")
	}
	if len(n) > MaxCaseNumberLen {
		return fmt.Errorf("that case number is longer than %d characters", MaxCaseNumberLen)
	}
	re, err := CompileCaseNumberPattern(pattern)
	if err != nil {
		// A broken stored pattern is an ADMINISTRATOR's problem and must never
		// become an operator's dead end mid-incident: it is named, and the
		// number is accepted on the default shape instead of being refused by a
		// rule nobody can read.
		re, err = CompileCaseNumberPattern("")
		if err != nil {
			return fmt.Errorf("the case-number check could not be built: %w", err)
		}
	}
	if !re.MatchString(n) {
		return fmt.Errorf("%q does not look like a case number for this vendor", n)
	}
	return nil
}
