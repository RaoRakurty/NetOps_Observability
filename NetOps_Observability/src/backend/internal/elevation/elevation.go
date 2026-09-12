// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package elevation is the domain for ELEVATION IDENTITY PROVIDERS — the
// "second IdP" pattern the owner brought back from customers on 2026-09-07:
//
//	"In extreme secure environments they maintain different IdPs, one for
//	 regular auth and another one to maintain the JIT access."
//
// A STANDING provider is the everyday front door: it provisions accounts, sets
// the tenant on first login, and carries the standing role. An ELEVATION
// provider is a second, separately governed door that provisions NOTHING. A
// successful sign-in through it produces exactly one artefact — a time-bound
// role binding on an account that ALREADY exists — and then gets out of the
// way. It cannot create an account, cannot move a tenant, and cannot change a
// standing role. Those three refusals are the whole point of the pattern: the
// blast radius of the elevation IdP is one expiring grant, not an identity.
//
// This package is deliberately pure — no net/http, no stores, no clock of its
// own. It answers three questions and nothing else:
//
//	Window()  how long may this grant last, given the token and the policy?
//	Reason()  what change/ticket justifies it?
//	Scope()   which resource (if any) does the token ask to be confined to?
//
// Everything that needs the world — does the account exist, does that resource
// belong to the caller's tenant, write the binding, audit it — stays with the
// integrator (breakglass.go), which is where the §3a tenant rules are already
// enforced. The split matters: a claim reaching this package can only ever make
// a grant SHORTER or NARROWER, never longer or wider, and that is provable here
// without a server.
package elevation

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CodeRequired is the stable machine code a step-up refusal carries, so the SPA
// can render "sign in through <provider>" instead of a generic 403.
const CodeRequired = "ELEVATION_REQUIRED"

// DefaultReason is what a grant records when the provider names no reason claim
// (or the token carries none). It is never blank: a grant with no stated reason
// is still a grant somebody has to explain later.
const DefaultReason = "elevation login"

// UnknownAccountRefusal is the message an elevation sign-in gets when no
// account exists. It is deliberately specific — the whole failure mode this
// pattern must avoid is an operator staring at "access denied" without knowing
// that the elevation door is not the door that creates accounts.
const UnknownAccountRefusal = "sign in through your standing provider first — the elevation provider does not create accounts"

// Bounds on what a claim may carry into a grant. A token is untrusted input
// (§3): its strings are length- and charset-bounded before they are persisted
// into an audit-visible binding.
const (
	MaxReasonLen = 200
	MaxScopeLen  = 128
	// EpochThreshold separates the two accepted TTL-claim shapes by MAGNITUDE
	// rather than by yet another configuration knob. Anything at or above it is
	// UNIX seconds (2001-09-09 onward); anything below is a duration in
	// minutes. The two ranges cannot overlap in practice — the provider ceiling
	// is hours, and no epoch we will ever see is under a billion.
	EpochThreshold = 1_000_000_000
)

// scopeRe bounds a scope value read from a claim: an opaque resource id, not a
// path, a URL or anything that could steer a lookup somewhere else.
var scopeRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ErrScopeMalformed is returned when the scope claim is present but is not a
// plausible resource id. Present-but-unusable is an ERROR, never a silent
// fallback to the wider tenant scope: a token that asked to be confined must
// never end up with more reach because its request could not be parsed.
var ErrScopeMalformed = errors.New("elevation: scope claim is not a usable resource id")

// Policy is one elevation provider's rules, resolved from its stored record.
// Every field is a claim NAME to read or a bound to enforce — never a value the
// token supplies.
type Policy struct {
	// Provider is the IdP alias. It becomes the binding's granted_by, so a
	// grant always names the door it came through.
	Provider string
	// TTLClaim names the claim carrying the requested lifetime (absolute UNIX
	// seconds, an RFC3339 instant, or a count of minutes). Blank ⇒ the
	// provider maximum.
	TTLClaim string
	// MaxMinutes is the provider ceiling. A grant is min(claim, ceiling); the
	// claim shortens, never extends.
	MaxMinutes int
	// ReasonClaim names the change/ticket claim.
	ReasonClaim string
	// ScopeClaim names the resource the grant should be confined to.
	ScopeClaim string
}

// Claim is the accessor the caller supplies over a VERIFIED token: name → value
// (in its JSON scalar form), ok=false when absent. Injected rather than taken as
// a map so this package never has to decide what "verified" means.
type Claim func(name string) (string, bool)

// WindowSource records WHY a grant ends when it does — the token asked for it,
// or the provider ceiling capped it. Recorded on the binding's condition and in
// the audit line, because "why is this only 15 minutes" is the first question an
// operator asks the first time they use it.
const (
	SourceClaim    = "claim"
	SourceProvider = "provider_max"
)

// Window computes the grant's [NotBefore, ExpiresAt).
//
// NotBefore is always `now`: an elevation is live the moment it is granted, and
// a future-dated grant would be a scheduling feature nobody asked for.
//
// ExpiresAt is min(now + claimed, now + ceiling). A missing, blank, malformed,
// zero or NEGATIVE claim falls back to the ceiling rather than failing the
// sign-in — the ceiling is the safe answer in every one of those cases, and
// refusing the login instead would make a typo in an IdP mapping look like an
// outage. An ALREADY-EXPIRED absolute claim is the one exception the caller
// must handle: it yields a zero-length window, reported by ok=false, and the
// caller refuses rather than minting a grant that is dead on arrival.
func (p Policy) Window(now time.Time, claim Claim) (notBefore, expiresAt time.Time, source string, ok bool) {
	now = now.UTC()
	max := p.MaxMinutes
	if max <= 0 {
		max = 1 // a policy with no ceiling still gets the shortest possible one
	}
	ceiling := now.Add(time.Duration(max) * time.Minute)
	if p.TTLClaim == "" || claim == nil {
		return now, ceiling, SourceProvider, true
	}
	raw, present := claim(p.TTLClaim)
	if !present {
		return now, ceiling, SourceProvider, true
	}
	asked, understood := parseTTL(now, raw)
	if !understood {
		return now, ceiling, SourceProvider, true
	}
	if !asked.After(now) {
		// The IdP said this grant is already over. Honour it literally.
		return now, now, SourceClaim, false
	}
	if asked.Before(ceiling) {
		return now, asked, SourceClaim, true
	}
	return now, ceiling, SourceProvider, true
}

// parseTTL reads the three shapes a TTL claim is written in across IdPs:
// RFC3339 (`access_expires_at: "2026-09-07T18:00:00Z"`), UNIX seconds
// (`exp`, `access_expires_at: 1789...`), and a minute count
// (`max_session_minutes: 30`). Returns the absolute instant it asks for.
func parseTTL(now time.Time, raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), true
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	if n >= EpochThreshold {
		return time.Unix(n, 0).UTC(), true
	}
	return now.Add(time.Duration(n) * time.Minute), true
}

// Reason resolves the justification recorded on the grant: the configured claim
// when it carries one, else DefaultReason. Control characters are stripped and
// the value is truncated — it is written into an audit-visible record that
// admins read, and a token does not get to inject line breaks into it.
func (p Policy) Reason(claim Claim) string {
	if p.ReasonClaim == "" || claim == nil {
		return DefaultReason
	}
	raw, ok := claim(p.ReasonClaim)
	if !ok {
		return DefaultReason
	}
	clean := sanitize(raw)
	if clean == "" {
		return DefaultReason
	}
	if len(clean) > MaxReasonLen {
		clean = clean[:MaxReasonLen]
	}
	return clean
}

// Scope resolves the resource id the token asks to be confined to.
//
//	("", nil)                  — no scope claim configured, or the token carried
//	                             none: the grant is tenant-scoped.
//	(id, nil)                  — a plausible resource id; the CALLER must still
//	                             prove it belongs to the account's tenant.
//	("", ErrScopeMalformed)    — present but unusable: refuse the sign-in.
func (p Policy) Scope(claim Claim) (string, error) {
	if p.ScopeClaim == "" || claim == nil {
		return "", nil
	}
	raw, ok := claim(p.ScopeClaim)
	if !ok {
		return "", nil
	}
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", nil
	}
	if len(v) > MaxScopeLen || !scopeRe.MatchString(v) {
		return "", ErrScopeMalformed
	}
	return v, nil
}

// sanitize drops control characters and collapses whitespace, so a claim can
// never smuggle newlines into a log line or an audit record.
func sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		switch {
		case r < 0x20 || r == 0x7f:
			space = true
		case r == ' ' || r == '\t':
			space = true
		default:
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// ProviderRef is one elevation door as a refusal names it: enough for the SPA
// to render a button, and nothing more.
type ProviderRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Refusal is the body of a step-up 403. It is a NAMED refusal, not a generic
// one: an operator who is told "you cannot do this" and not told where to go
// gets stuck, and a stuck operator during an incident is the failure this whole
// feature exists to prevent.
type Refusal struct {
	Error     string        `json:"error"`
	Code      string        `json:"code"`
	Providers []ProviderRef `json:"elevation_providers"`
}

// NewRefusal builds the 403 body for an action that requires elevated access.
// With no provider configured the message says so plainly rather than pointing
// at a door that does not exist.
func NewRefusal(providers []ProviderRef) Refusal {
	msg := "elevated access is required for this action"
	if len(providers) == 1 {
		msg = "elevated access is required — sign in through " + providers[0].Name
	} else if len(providers) > 1 {
		names := make([]string, 0, len(providers))
		for _, p := range providers {
			names = append(names, p.Name)
		}
		msg = "elevated access is required — sign in through " + strings.Join(names, " or ")
	}
	if providers == nil {
		providers = []ProviderRef{}
	}
	return Refusal{Error: msg, Code: CodeRequired, Providers: providers}
}
