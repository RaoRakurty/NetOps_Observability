package main

// identity_ids.go — the centralized, opaque identity primitives for orgs and
// tenants (docs/design/opaque-identity-model.md). The security contract:
//
//   - An org/tenant ID is an OPAQUE, IMMUTABLE, cryptographically-random handle —
//     NEVER derived from name, slug, email, domain, region, or any customer
//     metadata (so it can't be guessed from public attributes and never has to
//     change when the customer renames). This mirrors AWS account ids / Azure
//     directory GUIDs / GCP project numbers.
//   - A SLUG is a human URL/display handle ONLY. It is untrusted input: validate,
//     normalize, then resolve it to the opaque id — code NEVER authorizes on a
//     slug (see TenantContext).
//
// This is the single source of id minting + slug validation; everything else
// calls these so the rules can't drift. Stdlib-only (crypto/rand + hex).

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
)

// ID prefixes. The prefix is a fast, self-describing type tag (and the
// compatibility resolver's discriminator: a ref starting with the tenant prefix
// is an id, otherwise it's a legacy slug). Keep these stable forever.
const (
	orgIDPrefix    = "org_"
	tenantIDPrefix = "t_"
)

// opaqueIDBytes is the entropy per id: 16 bytes = 128 bits, hex-encoded to 32
// chars. Comfortably collision-free for the lifetime of any deployment and not
// enumerable.
const opaqueIDBytes = 16

// slug length bounds. Min 2 keeps degenerate single-char handles out; max 40 is
// well under any downstream label/index-name limit (DNS label = 63).
const (
	slugMinLen = 2
	slugMaxLen = 40
)

// newOpaqueID returns a prefixed, cryptographically-random opaque id. It panics
// only if the OS CSPRNG fails, which is unrecoverable (we must never mint a
// predictable identity) — consistent with the rest of the crypto code here.
func newOpaqueID(prefix string) string {
	var b [opaqueIDBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("identity: CSPRNG unavailable: " + err.Error())
	}
	return prefix + hex.EncodeToString(b[:])
}

// mintOrgID / mintTenantID are the ONLY ways a new org/tenant id is created.
func mintOrgID() string    { return newOpaqueID(orgIDPrefix) }
func mintTenantID() string { return newOpaqueID(tenantIDPrefix) }

// isTenantID reports whether a reference is a minted opaque tenant id (vs a slug
// or a legacy id==slug). Used by the compatibility resolver to short-circuit.
func isTenantID(ref string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ref)), tenantIDPrefix)
}

// isOrgID reports whether a reference is a minted opaque org id.
func isOrgID(ref string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ref)), orgIDPrefix)
}

// reservedSlugs are handles a customer may never take, because they collide with
// platform routes, sentinels, or well-known paths (an attacker must not be able
// to register a tenant whose slug shadows /api, /admin, the global realm, etc.).
var reservedSlugs = map[string]bool{
	// platform routes / well-known paths
	"admin": true, "api": true, "login": true, "logout": true, "signup": true,
	"support": true, "root": true, "system": true, "internal": true, "auth": true,
	"sso": true, "billing": true, "metrics": true, "health": true, "status": true,
	"static": true, "assets": true,
	// our sentinels (the platform/provider realm)
	"global": true, "platform": true, "provider": true,
}

// slugFromName derives a candidate slug from a display name: lowercase, keep
// [a-z0-9], turn spaces/underscores/hyphens into a single hyphen, collapse runs,
// trim. The result is then run through validateSlug like any other slug — so a
// derived slug is held to the exact same rules as an explicitly-supplied one.
func slugFromName(name string) string {
	return collapseHyphens(slugify(name))
}

// collapseHyphens squeezes runs of '-' into one and trims leading/trailing '-'.
func collapseHyphens(s string) string {
	var b strings.Builder
	prevHyphen := false
	for _, r := range s {
		if r == '-' {
			if prevHyphen {
				continue
			}
			prevHyphen = true
		} else {
			prevHyphen = false
		}
		b.WriteRune(r)
	}
	return strings.Trim(b.String(), "-")
}

// validateSlug enforces the full slug contract and returns the normalized
// (trimmed/lowered) slug or an error. Slug is UNTRUSTED input; this is the one
// gate. Rules: lowercase letters, digits, hyphen only; no underscore; no spaces;
// no uppercase; no leading/trailing hyphen; no consecutive hyphens; bounded
// length; not a reserved word.
func validateSlug(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("slug required")
	}
	if s != strings.ToLower(s) {
		return "", errors.New("slug must be lowercase")
	}
	if len(s) < slugMinLen || len(s) > slugMaxLen {
		return "", errors.New("slug length out of range (2–40)")
	}
	if strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return "", errors.New("slug must not start or end with a hyphen")
	}
	if strings.Contains(s, "--") {
		return "", errors.New("slug must not contain consecutive hyphens")
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			// ok
		case r == '_':
			return "", errors.New("slug must not contain underscores")
		case r == ' ':
			return "", errors.New("slug must not contain spaces")
		default:
			return "", errors.New("slug may contain only lowercase letters, digits and hyphens")
		}
	}
	if reservedSlugs[s] {
		return "", errors.New("slug is reserved")
	}
	return s, nil
}
