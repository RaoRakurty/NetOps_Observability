// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

// identity.go — the canonical identity key (tracker 300,
// docs/design/IDENTITY_NAMESPACING_2026-09-13.md).
//
// THE RULE THIS FILE EXISTS TO ENFORCE (owner, 2026-09-13): a principal is
// identified by **tenant_id + issuer + subject**, never by username and never
// by email. Local authentication is its OWN issuer namespace ("local"), so
// tenant A's `admin` and tenant B's `admin` are two unrelated accounts, and an
// IdP that asserts the login name `admin` never reaches either of them.
//
// Nothing here resolves an identity by email or username. The single, bounded
// exception is the legacy lazy bind (store.go / pg.go, design §2.6) which
// consults `users.id` equality once, for a pre-migration account created by the
// very same door, and is refused for anything already bound.
//
// SUBJECT CASE IS NOT NORMALISED HERE, deliberately. Each door supplies the
// subject in the form §2.3 prescribes — an OIDC `sub` VERBATIM (the spec makes
// it case-sensitive, so lowercasing it could fuse two distinct principals), an
// LDAP DN and a TACACS+/local login name already lowercased. The store
// lowercases only what it owns: the local username. Trimming is the only
// normalisation applied to a subject in transit.

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"net"
	"strings"
	"time"
)

// Issuer namespaces and the protocol vocabulary (§2.2/§2.3). These strings are
// KEY MATERIAL: changing one re-namespaces every account minted under it, so
// they are as stable as a database column name.
const (
	// LocalIssuer is the issuer of a locally-managed account. Its subject is
	// lower(trim(username)) — which is what makes a local username unique PER
	// TENANT rather than globally.
	LocalIssuer = "local"

	ProtocolLocal  = "local"
	ProtocolOIDC   = "oidc"
	ProtocolSAML   = "saml"
	ProtocolLDAP   = "ldap"
	ProtocolTACACS = "tacacs"

	// ldapIssuerPrefix / tacacsIssuerPrefix namespace a directory by the server
	// it was read from, so two directories are two namespaces even when they
	// hand out the same login names.
	ldapIssuerPrefix   = "ldap:"
	tacacsIssuerPrefix = "tacacs:"
)

// Provenance records HOW an identity row came to exist — the audit trail the
// owner's rule 6 requires ("ambiguous legacy provenance is flagged for manual
// remediation, never guessed").
const (
	// ProvenanceAsserted: a door verified this tuple and the account was
	// provisioned (or the row written) from it.
	ProvenanceAsserted = "asserted"
	// ProvenanceBackfilledLocal: written by the migration for an existing LOCAL
	// account, whose issuer/subject are derivable offline with certainty.
	ProvenanceBackfilledLocal = "backfilled-local"
	// ProvenanceLegacyLazyBound: a pre-migration FEDERATED account adopted by
	// the bounded §2.6 rule. Every one of these is visible to the operator.
	ProvenanceLegacyLazyBound = "legacy-lazy-bound"
)

// SubjectKind records WHICH string an LDAP directory gave us as the subject, so
// a later DN-vs-login policy change is visible rather than silent (§2.3).
const (
	SubjectKindDN    = "dn"
	SubjectKindLogin = "login"
)

// globalTenant is the platform/provider realm sentinel (tenant.Global,
// duplicated per the no-shared-utils rule — this package must not import the
// tenant directory).
const globalTenant = "global"

// tenantIDPrefix mirrors the backend's opaque tenant-id prefix (identity_ids.go),
// duplicated for the same reason.
const tenantIDPrefix = "t_"

// Identity is the canonical identity of ONE account: the tuple, plus the
// provenance metadata an operator needs to judge it.
//
// On the Postgres backend it is a row of `user_identities` (the PK enforces
// uniqueness IN THE DATABASE, per the owner's rule 2). On the file backend it is
// a field of the persisted User, and FileStore's byTuple/byLocalLogin indexes
// enforce the same two constraints inside the store lock. A nil Identity means
// PENDING — the account has no tuple yet (a pre-migration federated row).
type Identity struct {
	TenantID     string `json:"tenant_id,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	Subject      string `json:"subject,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"` // ssoidp alias; "" = platform/legacy global
	SubjectKind  string `json:"subject_kind,omitempty"`  // dn | login | "" (LDAP only)
	Provenance   string `json:"provenance,omitempty"`

	FirstSeenAt time.Time `json:"first_seen_at,omitempty"`
	LastLoginAt time.Time `json:"last_login_at,omitempty"`
}

// Assertion is what a door actually VERIFIED, handed to the store as the only
// way a federated sign-in may become an account (§2.5). The embedded Identity
// carries the tuple; TenantID is the PROVISIONING tenant for a new account.
//
// Email/DisplayName/Role are PROFILE attributes, refreshed on every login and
// never part of the key. LegacyUsername is the pre-migration derivation of that
// door (firstNonEmpty(preferred_username, email, sub) for OIDC; the login name
// for LDAP/TACACS+) and is consulted ONLY by the bounded §2.6 lazy bind.
type Assertion struct {
	Identity

	Email       string
	DisplayName string
	Role        string

	// LegacyUsername is for §2.6 ONLY. Leaving it empty disables the lazy bind
	// for this assertion, which is the correct thing for any NEW door.
	LegacyUsername string
}

// ---- normalisation --------------------------------------------------------

// NormalizeIssuer canonicalises an issuer string so the same IdP is always the
// same namespace: the scheme and host are lowercased, trailing slashes are
// trimmed, and query/fragment (which an issuer never has) are dropped rather
// than keyed on. The PATH KEEPS ITS CASE — a Keycloak realm name is
// case-sensitive, and folding it would fuse two realms into one namespace.
//
// A non-URL issuer (our own "local", "ldap:…", "tacacs:…" forms) is lowercased
// whole and slash-trimmed; those are already canonical by construction.
func NormalizeIssuer(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	scheme, rest, ok := splitScheme(s)
	if !ok {
		return strings.TrimRight(strings.ToLower(s), "/")
	}
	authority := rest
	path := ""
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority, path = rest[:i], rest[i:]
	}
	// Drop query/fragment: an OIDC issuer has neither, and keying on one would
	// let a redirect-shaped variant mint a second namespace for one IdP.
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	return strings.ToLower(scheme) + "://" + strings.ToLower(authority) + strings.TrimRight(path, "/")
}

// splitScheme splits "scheme://rest". It does NOT use net/url: url.Parse accepts
// shapes an issuer never has and would silently re-encode the path we must key
// on byte-for-byte.
func splitScheme(s string) (scheme, rest string, ok bool) {
	i := strings.Index(s, "://")
	if i <= 0 {
		return "", s, false
	}
	scheme = s[:i]
	for _, r := range scheme {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '+', r == '-', r == '.':
		default:
			return "", s, false
		}
	}
	return scheme, s[i+3:], true
}

// LDAPIssuer is the issuer namespace of one directory: "ldap:" + host:port,
// normalised from LDAP_URL (scheme case, userinfo and path discarded; the
// scheme's default port supplied when the URL omits it, so ldap://dir and
// ldap://dir:389 are ONE namespace rather than two).
func LDAPIssuer(rawURL string) string {
	hp := normalizeHostPort(rawURL, "389", map[string]string{"ldap": "389", "ldaps": "636"})
	if hp == "" {
		return ""
	}
	return ldapIssuerPrefix + hp
}

// TACACSIssuer is the issuer namespace of one TACACS+ server: "tacacs:" +
// host:port (default port 49).
func TACACSIssuer(host string) string {
	hp := normalizeHostPort(host, "49", nil)
	if hp == "" {
		return ""
	}
	return tacacsIssuerPrefix + hp
}

// normalizeHostPort reduces a URL, authority or bare host to a lowercase
// host:port. An explicit port always wins; otherwise the scheme's default port
// is used, falling back to defaultPort. IPv6 literals come back bracketed.
func normalizeHostPort(raw, defaultPort string, schemePorts map[string]string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	port := defaultPort
	if scheme, rest, ok := splitScheme(s); ok {
		if p, found := schemePorts[scheme]; found {
			port = p
		}
		s = rest
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i] // a directory URL's base DN is not part of the namespace
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:] // never key on (or log) a bind DN / userinfo
	}
	if s == "" {
		return ""
	}
	if h, p, err := net.SplitHostPort(s); err == nil && h != "" && p != "" {
		return net.JoinHostPort(h, p)
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if s == "" {
		return ""
	}
	return net.JoinHostPort(s, port)
}

// normalized returns the identity with every keyed field canonicalised. The
// SUBJECT IS ONLY TRIMMED — see this file's header for why case-folding it would
// be a correctness bug for OIDC.
func (i Identity) normalized() Identity {
	i.TenantID = normTenant(i.TenantID)
	i.Issuer = NormalizeIssuer(i.Issuer)
	i.Subject = strings.TrimSpace(i.Subject)
	i.Protocol = strings.ToLower(strings.TrimSpace(i.Protocol))
	i.SubjectKind = strings.ToLower(strings.TrimSpace(i.SubjectKind))
	i.ConnectionID = strings.TrimSpace(i.ConnectionID)
	i.Provenance = strings.ToLower(strings.TrimSpace(i.Provenance))
	if i.Issuer == LocalIssuer {
		// The one subject the store owns rather than receives.
		i.Subject = strings.ToLower(i.Subject)
	}
	return i
}

// identityKey is the primary key of an identity — the exact tuple the Postgres
// PRIMARY KEY (tenant_id, issuer, subject) enforces.
type identityKey struct{ tenant, issuer, subject string }

func (i Identity) key() identityKey {
	return identityKey{i.TenantID, i.Issuer, i.Subject}
}

// localLoginKey is the per-tenant local login handle — the "local is its own
// namespace" rule (§0 rule 3) expressed as an index key. It is the SAME row as
// the identity tuple: (tenant, "local", lower(username)).
type localLoginKey struct{ tenant, username string }

func localKeyFor(tenant, username string) localLoginKey {
	return localLoginKey{normTenant(tenant), strings.ToLower(strings.TrimSpace(username))}
}

// localKey is the local-login index key of a LOCAL identity. It is meaningless
// for any other issuer, so callers gate on Issuer == LocalIssuer.
func (i Identity) localKey() localLoginKey {
	return localLoginKey{tenant: i.TenantID, username: i.Subject}
}

// validate mirrors migration 0049's CHECK constraints so the file backend
// refuses exactly what the database refuses (§3 Enforce).
func (i Identity) validate() error {
	switch {
	case i.Issuer == "":
		return errors.New("users: identity issuer required")
	case i.Subject == "":
		return errors.New("users: identity subject required")
	case i.Protocol == "":
		return errors.New("users: identity protocol required")
	}
	return nil
}

// localIdentity builds the identity row of a LOCAL account: its own issuer
// namespace, subject = lower(trim(username)), scoped to the account's tenant.
func localIdentity(tenant, username, provenance string, now time.Time) Identity {
	return Identity{
		TenantID:    normTenant(tenant),
		Issuer:      LocalIssuer,
		Subject:     strings.ToLower(strings.TrimSpace(username)),
		Protocol:    ProtocolLocal,
		Provenance:  provenance,
		FirstSeenAt: now,
	}
}

// ---- federated id derivation (§2.4) ---------------------------------------

const (
	fedIDPrefix = "fed_"
	// fedHashShort is 26 base32 chars = 130 bits — collision-free in practice,
	// and short enough that an opaque handle stays readable in a log line.
	fedHashShort = 26
	// fedHashFull is the whole SHA-256 in base32 (52 chars). §4.3's collision
	// escape hatch: if the 130-bit form is somehow taken by a DIFFERENT tuple,
	// extend rather than guess.
	fedHashFull = 52
)

// identityDigest is the domain-separated hash of the canonical tuple (§2.4):
//
//	base32-lower-unpadded( SHA-256( 0x01 || tenant || 0x00 || issuer || 0x00 || subject ) )
//
// The 0x01 prefix is a version byte (so a future derivation change is a
// different namespace, not a silent re-key) and the 0x00 separators make the
// concatenation unambiguous — without them ("a","bc") and ("ab","c") would hash
// alike and two distinct principals could share an id.
//
// Inputs must already be NORMALISED (Identity.normalized); the store never calls
// this with raw door input.
func identityDigest(tenant, issuer, subject string) string {
	h := sha256.New()
	// hash.Hash.Write never returns an error (documented); the sequence is kept
	// explicit so the wire format is readable.
	h.Write([]byte{0x01})
	h.Write([]byte(tenant))
	h.Write([]byte{0x00})
	h.Write([]byte(issuer))
	h.Write([]byte{0x00})
	h.Write([]byte(subject))
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h.Sum(nil)))
}

// TenantFragment is the human-readable hint in a federated id: the first 7
// id-safe characters of the tenant id after its "t_" prefix, or "global" for the
// platform realm. It is a CONVENIENCE ONLY — the tenant is authoritative inside
// the hash, so a fragment collision changes nothing.
func TenantFragment(tenant string) string {
	t := normTenant(tenant)
	if t == "" || t == globalTenant {
		return globalTenant
	}
	t = strings.TrimPrefix(t, tenantIDPrefix)
	var b strings.Builder
	for _, r := range t {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			if b.Len() == 7 {
				break
			}
		}
	}
	if b.Len() == 0 {
		return "tenant" // an id with no representable character; the hash still separates it
	}
	return b.String()
}

// FederatedID is the deterministic id of a federated account: a JIT race and a
// re-run migration converge on the SAME id for the same tuple, which is what
// makes provisioning idempotent without a coordination lock.
func FederatedID(tenant, issuer, subject string) string {
	return fedIDPrefix + TenantFragment(tenant) + "_" + identityDigest(tenant, issuer, subject)[:fedHashShort]
}

// FederatedIDExtended is §4.3's collision escape: the full 52-char digest. Only
// reached when FederatedID's id is already held by a DIFFERENT tuple.
func FederatedIDExtended(tenant, issuer, subject string) string {
	return fedIDPrefix + TenantFragment(tenant) + "_" + identityDigest(tenant, issuer, subject)[:fedHashFull]
}
