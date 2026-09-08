// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package tenantlocator is the login-locator domain: it resolves a CANDIDATE
// realm from the entry URL a customer hands to its people, and binds an SSO
// callback to that realm by URL.
//
// Spec of record: docs/design/sso-saml-oidc-design-2026-08-03.md §6.1 "Login
// locators". Two locator types exist today:
//
//	shared_path        /t/{tenant-slug}      slug is a DISPLAY ALIAS; the
//	                                         resolved candidate carries the
//	                                         immutable tenant id
//	immutable_org_url  /org/{org_public_id}  opaque, immutable, safe to share —
//	                                         the recovery locator that survives
//	                                         a slug rename
//
// `managed_subdomain` and `custom_domain` are reserved names and DEFERRED
// (design §15): they need a Correlix-operated DNS/TLS plane a single-port
// compose product does not have. Everything below is written against the
// locator abstraction (Kind + ref) so adding them later is additive.
//
// THE INVARIANTS THIS PACKAGE EXISTS TO HOLD (all inviolable):
//
//   - A slug is an ALIAS. It is untrusted routing input: normalize it, resolve
//     it to the opaque tenant id, and carry the id from there on. Nothing
//     authorizes on a slug.
//   - The tenant id is IMMUTABLE. A rename moves the alias, never the tenant.
//   - A CANDIDATE IS NOT A CLAIM. Resolving a locator decides only WHICH SIGN-IN
//     DOORS TO SHOW and which callback URL is legitimate. It never grants
//     access, never sets a tenant on a session, and never moves an account
//     between tenants.
//   - Resolution FAILS CLOSED: unknown, malformed, or non-active resolves to no
//     candidate — never to a fallback, a default, or the first tenant. Unknown
//     and known-but-not-active are deliberately INDISTINGUISHABLE to the caller,
//     in both answer and cost (see Resolve).
package tenantlocator

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Locator kinds. The two live types plus the two reserved-but-deferred names,
// declared so the enum is complete where it is read and a later phase adds a
// case rather than a concept.
const (
	KindTenant = "tenant" // shared_path        /t/{slug}
	KindOrg    = "org"    // immutable_org_url  /org/{org_public_id}

	// Reserved, DEFERRED (design §6.1/§15). Never returned by ParsePath; listed
	// so the vocabulary is one place and a future phase is additive.
	KindManagedSubdomain = "managed_subdomain"
	KindCustomDomain     = "custom_domain"
)

// Path prefixes. Exported because the route registrations, the nginx comment
// and the docs all quote the same two literals.
const (
	TenantPrefix = "/t/"
	OrgPrefix    = "/org/"
)

// refMax bounds a locator ref before it is ever compared or logged. A tenant
// slug is <= 40 chars (identity_ids.go) and an opaque org id is 36; 64 leaves
// room without letting a caller push megabytes through the resolver.
const refMax = 64

// StatusActive is the only tenant status a locator resolves for. A blank status
// is read as active — tenants created before the field existed.
const StatusActive = "active"

// TenantRef is the directory's view of one tenant: the identity facts the
// resolver needs and nothing else.
type TenantRef struct {
	ID     string // opaque, immutable (t_…)
	Slug   string // display alias, mutable
	Name   string // display name
	OrgID  string // owning org (blank = the global org)
	Status string // "" or "active" = active
}

// Active reports whether this tenant may be resolved to. Blank = active.
func (t TenantRef) Active() bool {
	s := strings.ToLower(strings.TrimSpace(t.Status))
	return s == "" || s == StatusActive
}

// OrgRef is the directory's view of one org.
type OrgRef struct {
	ID   string // opaque, immutable (org_… ; the seeded root org is "global")
	Slug string
	Name string
}

// Directory is the seam onto the tenant/org registries. It hands over WHOLE
// LISTS rather than a lookup, on purpose: the resolver scans every entry in
// every case, so an unknown ref and a known-but-suspended ref cost the same
// (see Resolve). The integrator adapts its stores to this; this package reads
// no store, no env and no clock of its own.
type Directory interface {
	Tenants() []TenantRef
	Orgs() []OrgRef
}

// Candidate is a RESOLVED locator: which realm's sign-in doors to show. It is
// server-derived, carries immutable ids, and is never an authorization fact.
type Candidate struct {
	Kind        string // KindTenant | KindOrg
	TenantID    string // immutable tenant id (KindTenant only; blank for KindOrg)
	TenantSlug  string // display alias, for rebuilding the canonical path
	OrgID       string // the tenant's org, or the org itself
	DisplayName string // what the sign-in page names the candidate
}

// Path is the canonical locator path for this candidate — the URL a customer
// hands out and the prefix every per-tenant callback URL is built on.
func (c Candidate) Path() string {
	switch c.Kind {
	case KindTenant:
		return TenantPrefix + c.TenantSlug
	case KindOrg:
		return OrgPrefix + c.OrgID
	}
	return ""
}

// CallbackPath is the per-tenant SSO callback URL for one provider alias: the
// redirect URI handed to the IdP, and the only URL on which that provider's
// token is accepted for this realm.
func (c Candidate) CallbackPath(alias string) string {
	if p := c.Path(); p != "" && alias != "" {
		return p + "/sso/" + alias + "/callback"
	}
	return ""
}

// LoginPath is the per-tenant entry point for IdP-initiated sign-in (the tile
// URL an IdP admin pastes into Okta/Entra): it pins the realm, then starts the
// ordinary SP-initiated flow through that provider.
func (c Candidate) LoginPath(alias string) string {
	if p := c.Path(); p != "" && alias != "" {
		return p + "/sso/" + alias + "/login"
	}
	return ""
}

// Reaches reports whether a provider registration bound to boundTenant (with
// boundOrg as that tenant's org) is offered at this candidate.
//
// A BLANK boundTenant is the PLATFORM REALM: a registration nobody has bound to
// a tenant — every registration written before this feature existed, and the
// env-configured buttons. Those stay visible everywhere, because hiding them
// would silently lock every existing deployment out of its own front door. Once
// an operator binds a registration to a tenant it disappears from every other
// tenant's sign-in page, which is the whole point.
func (c Candidate) Reaches(boundTenant, boundOrg string) bool {
	boundTenant = strings.ToLower(strings.TrimSpace(boundTenant))
	if boundTenant == "" {
		return true // platform realm — shared front door
	}
	switch c.Kind {
	case KindTenant:
		return boundTenant == strings.ToLower(strings.TrimSpace(c.TenantID))
	case KindOrg:
		// Org isolation is DERIVED from tenant isolation (CLAUDE.md §3a): an org
		// locator reaches exactly the registrations of the tenants it owns.
		return orgOf(boundOrg) == orgOf(c.OrgID)
	}
	return false
}

// ParsePath extracts a locator from a request path. It accepts the locator
// itself ("/t/acme"), a trailing slash, and any deeper path under it
// ("/t/acme/sso/okta/callback") so one parser serves the SPA entry, the login
// entry and the callback.
//
// It is a PARSER, not a resolver: ok=true only says the path is shaped like a
// locator. Nothing may be trusted from it until Resolve has spoken.
func ParsePath(p string) (kind, ref string, ok bool) {
	switch {
	case strings.HasPrefix(p, TenantPrefix):
		kind, ref = KindTenant, p[len(TenantPrefix):]
	case strings.HasPrefix(p, OrgPrefix):
		kind, ref = KindOrg, p[len(OrgPrefix):]
	default:
		return "", "", false
	}
	if i := strings.IndexByte(ref, '/'); i >= 0 {
		ref = ref[:i]
	}
	ref = normalizeRef(ref)
	if ref == "" {
		return "", "", false
	}
	return kind, ref, true
}

// ParseCallbackPath parses the per-tenant SSO callback URL:
//
//	/t/{slug}/sso/{alias}/callback
//	/org/{org_public_id}/sso/{alias}/callback
//
// and its login twin (…/sso/{alias}/login), reporting which via `leaf`. Exact
// shape only — four segments after the prefix, nothing more, nothing less.
func ParseCallbackPath(p string) (kind, ref, alias, leaf string, ok bool) {
	kind, ref, ok = ParsePath(p)
	if !ok {
		return "", "", "", "", false
	}
	var rest string
	switch kind {
	case KindTenant:
		rest = p[len(TenantPrefix):]
	case KindOrg:
		rest = p[len(OrgPrefix):]
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 4 || parts[1] != "sso" {
		return "", "", "", "", false
	}
	alias = normalizeRef(parts[2])
	leaf = strings.ToLower(strings.TrimSpace(parts[3]))
	if alias == "" || (leaf != "callback" && leaf != "login") {
		return "", "", "", "", false
	}
	return kind, ref, alias, leaf, true
}

// normalizeRef lower-cases, trims and BOUNDS an untrusted URL segment, and
// rejects anything that is not a plain identifier — no traversal, no encoded
// separators, no control characters, whatever the router did or did not decode.
func normalizeRef(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > refMax || s == "." || s == ".." {
		return ""
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return ""
		}
	}
	return s
}

// Resolve turns a parsed locator into a candidate realm, or reports no
// candidate at all.
//
// COST IS DELIBERATELY FLAT. Every call scans the whole tenant list and the
// whole org list, with no early return on a hit and no short-circuit on a miss,
// so "no such slug" and "that slug names a suspended tenant" are the same
// answer AND the same amount of work. An enumeration probe learns nothing from
// either the body or the clock. (TestResolveCostIsFlat pins this.)
func Resolve(dir Directory, kind, ref string) (Candidate, bool) {
	ref = normalizeRef(ref)
	if dir == nil || ref == "" || (kind != KindTenant && kind != KindOrg) {
		return Candidate{}, false
	}
	tenants := dir.Tenants()
	orgs := dir.Orgs()

	// Pass 1 — the tenant the slug names (KindTenant). No early exit.
	var hit TenantRef
	tenantFound := false
	for _, t := range tenants {
		if kind == KindTenant && strings.ToLower(strings.TrimSpace(t.Slug)) == ref && t.Active() && !tenantFound {
			hit, tenantFound = t, true
		}
	}

	// The org under consideration: the named one (KindOrg) or the hit tenant's.
	wantOrg := ref
	if kind == KindTenant {
		wantOrg = orgOf(hit.OrgID)
	}

	// Pass 2 — that org's record. No early exit.
	var org OrgRef
	orgFound := false
	for _, o := range orgs {
		if id := strings.ToLower(strings.TrimSpace(o.ID)); id != "" && id == wantOrg && !orgFound {
			org, orgFound = o, true
		}
	}

	// Pass 3 — does the org still own a live tenant? Always run: an unknown org
	// and an org whose every tenant is suspended must cost the same.
	live := false
	for _, t := range tenants {
		if orgOf(t.OrgID) == wantOrg && t.Active() {
			live = true
		}
	}

	switch kind {
	case KindTenant:
		if !tenantFound {
			return Candidate{}, false
		}
		return Candidate{
			Kind:        KindTenant,
			TenantID:    strings.ToLower(strings.TrimSpace(hit.ID)),
			TenantSlug:  strings.ToLower(strings.TrimSpace(hit.Slug)),
			OrgID:       orgOf(hit.OrgID),
			DisplayName: display(hit.Name, hit.Slug),
		}, true
	default: // KindOrg
		// An org locator resolves only while the org exists AND still owns at
		// least one active tenant: an org with no working sign-in door must not
		// be offered one.
		if !orgFound || !live {
			return Candidate{}, false
		}
		return Candidate{
			Kind:        KindOrg,
			OrgID:       strings.ToLower(strings.TrimSpace(org.ID)),
			DisplayName: display(org.Name, org.Slug),
		}, true
	}
}

// DefaultOrgID is the seeded root org a tenant with no org of its own belongs
// to — tenants created before the org layer existed (internal/tenant/org.go).
const DefaultOrgID = "global"

// orgOf normalizes a tenant's org id, mapping blank onto the root org so a
// pre-org tenant is reachable from the root org's locator like any other.
func orgOf(id string) string {
	if id = strings.ToLower(strings.TrimSpace(id)); id != "" {
		return id
	}
	return DefaultOrgID
}

// display picks the human label for a candidate: the name, else the slug.
func display(name, slug string) string {
	if n := strings.TrimSpace(name); n != "" {
		return n
	}
	return strings.TrimSpace(slug)
}

// ResolveID re-resolves a candidate from the IMMUTABLE id carried in a signed
// cookie. The signature proves the id came from us; this proves the realm still
// exists and is still active, so a suspension takes effect on the next request
// rather than at cookie expiry.
func ResolveID(dir Directory, kind, id string) (Candidate, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	if dir == nil || id == "" {
		return Candidate{}, false
	}
	if kind == KindOrg {
		return Resolve(dir, KindOrg, id)
	}
	if kind != KindTenant {
		return Candidate{}, false
	}
	slug := ""
	for _, t := range dir.Tenants() {
		if strings.ToLower(strings.TrimSpace(t.ID)) == id && t.Active() && slug == "" {
			slug = strings.ToLower(strings.TrimSpace(t.Slug))
		}
	}
	if slug == "" {
		return Candidate{}, false
	}
	return Resolve(dir, KindTenant, slug)
}

// ---- signed candidate token ------------------------------------------------

// Claim is what actually travels in the short-lived HttpOnly cookie: the
// locator KIND and the IMMUTABLE id, nothing else. No slug, no display name,
// no role, no tenant assertion — a stale cookie can never contradict the
// directory, because everything but the id is re-read from it.
type Claim struct {
	Kind string `json:"k"`
	ID   string `json:"i"`
	Exp  int64  `json:"e"`
}

// TTL is how long a minted candidate cookie is honoured. It only has to outlive
// "land on the sign-in page, pick a door, come back from the IdP".
const TTL = 15 * time.Minute

// signLabel domain-separates this MAC from every other use of the platform
// signing secret, so a locator token can never be replayed as a session token
// or a capability link and vice versa.
const signLabel = "correlix/login-locator/v1\x00"

var (
	// ErrBadToken is returned for every rejection — malformed, wrong signature,
	// expired. One error, on purpose: the caller must not be able to tell an
	// attacker which of the three it was.
	ErrBadToken = errors.New("locator: invalid candidate token")
)

// Signer mints and verifies candidate tokens.
type Signer struct{ key []byte }

// NewSigner derives the locator MAC key from the platform signing secret.
func NewSigner(secret string) *Signer {
	sum := sha256.Sum256([]byte(signLabel + secret))
	k := make([]byte, len(sum))
	copy(k, sum[:])
	return &Signer{key: k}
}

// Mint returns the signed token for a resolved candidate.
func (s *Signer) Mint(c Candidate, now time.Time) (string, error) {
	if s == nil || len(s.key) == 0 {
		return "", ErrBadToken
	}
	id := c.TenantID
	if c.Kind == KindOrg {
		id = c.OrgID
	}
	if c.Kind == "" || strings.TrimSpace(id) == "" {
		return "", ErrBadToken
	}
	body, err := json.Marshal(Claim{Kind: c.Kind, ID: strings.ToLower(strings.TrimSpace(id)), Exp: now.Add(TTL).Unix()})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	return payload + "." + base64.RawURLEncoding.EncodeToString(s.mac(payload)), nil
}

// Verify checks the MAC in constant time and the expiry, and returns the claim.
func (s *Signer) Verify(tok string, now time.Time) (Claim, error) {
	if s == nil || len(s.key) == 0 || tok == "" || len(tok) > 512 {
		return Claim{}, ErrBadToken
	}
	payload, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return Claim{}, ErrBadToken
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return Claim{}, ErrBadToken
	}
	if subtle.ConstantTimeCompare(got, s.mac(payload)) != 1 {
		return Claim{}, ErrBadToken
	}
	body, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return Claim{}, ErrBadToken
	}
	var c Claim
	if err := json.Unmarshal(body, &c); err != nil {
		return Claim{}, ErrBadToken
	}
	if c.Kind != KindTenant && c.Kind != KindOrg {
		return Claim{}, ErrBadToken
	}
	if strings.TrimSpace(c.ID) == "" || c.Exp <= 0 || now.Unix() > c.Exp {
		return Claim{}, ErrBadToken
	}
	return c, nil
}

func (s *Signer) mac(payload string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(payload)) // hash.Hash never returns an error
	return m.Sum(nil)
}
