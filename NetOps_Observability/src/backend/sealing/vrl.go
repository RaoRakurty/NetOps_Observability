// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package sealing

// vrl.go — the EDGE half of sealing.
//
// Sealing happens where the data first lands (Vector's VRL at the router), not
// in this process: a value that reaches storage in the clear has already leaked,
// so the encryption must precede indexing. That means the cipher exists in two
// implementations — Go here, VRL at the edge — and they MUST agree byte for
// byte or a sealed value becomes permanently unreadable.
//
// This file is why that agreement holds: BOTH sides are generated from this
// package. package processors never writes `encrypt!` or `hmac`; it asks for a
// snippet. If the cipher changes, one package changes, and vrl_parity_test.go
// runs the real pinned Vector binary and unseals its output with the Go
// implementation — drift fails the build rather than corrupting a tenant's data
// silently, months later, when someone tries to reveal a value.
//
// KEY DELIVERY. VRL has no HKDF, so the edge cannot derive anything: it
// receives the already-derived seal key AND mac key from EdgeKey, base64'd,
// through Vector's `exec` secret backend (`SECRET[…]`, resolved at config load,
// held in memory only — never written to disk). The tenant DEK never leaves
// this process.

import (
	"fmt"
	"strconv"
	"strings"
)

// Edge secret backend names. The router's secret backend serves two entries per
// tenant because the edge cannot derive the MAC key from the seal key.
const (
	EdgeSealBackend = "cxseal"
	EdgeMACBackend  = "cxmac"
)

// EdgeSecretRef renders the SECRET[…] reference Vector resolves at config load.
func EdgeSecretRef(backend, tenant string) string {
	return "SECRET[" + backend + "." + tenant + "]"
}

// validSecretKey reports whether a tenant id can be used as a Vector secret key.
// Vector's SECRET[backend.key] syntax has no escaping, so a tenant id carrying a
// "." or "]" would silently produce a reference to the WRONG secret — which at
// the edge means sealing with another tenant's key. Rejected, never sanitised:
// mapping two distinct tenants onto one key is the same failure wearing a
// friendlier face.
func validSecretKey(tenant string) bool {
	if tenant == "" || len(tenant) > maxContextField {
		return false
	}
	for _, r := range tenant {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// EdgeSealSpec describes one field to seal at the edge.
type EdgeSealSpec struct {
	Context    Context // the authenticated binding; Tenant must be secret-key safe
	KeyVersion int     // active version at config-render time
	Path       string  // VRL path of the field, e.g. `.message` or `.fields.ssn`
}

// vrlString renders a Go string as a VRL string literal.
//
// It escapes `$` as well as the obvious characters: Vector performs ENV/SECRET
// interpolation on the config text BEFORE the VRL is parsed, so an unescaped
// `$` in a tenant id or field name would be substituted away — corrupting every
// tenant's config, not just the offending one. (The same trap the processor
// generator hit; see processors/generate.go escapeEnv.)
func vrlString(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		"\n", `\n`,
		"\t", `\t`,
		`$`, `$$`,
	)
	return `"` + r.Replace(s) + `"`
}

// macPrefix renders the CONSTANT head of the MAC input — every part that is
// known when the config is generated.
//
// The lengths here are Go byte lengths, emitted as literals rather than
// computed at the edge on purpose: VRL's strlen counts CHARACTERS, not bytes, so
// a tenant or field name containing any non-ASCII rune would make the two
// engines disagree on the prefix and produce a MAC that never verifies. Only the
// base64 parts use strlen at runtime, where character count and byte count are
// equal by construction.
func macPrefix(c Context, version int) string {
	var b strings.Builder
	w := func(s string) {
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
		b.WriteByte(':')
	}
	w(tokenVersion)
	w(c.Tenant)
	w(c.ProcessorID)
	w(c.Field)
	w(c.DataType)
	w(strconv.Itoa(version))
	return b.String()
}

// SealVRL renders the VRL that seals one field in place.
//
// The emitted program is a no-op when the field is absent or empty, so a rule
// that matches an event lacking the field leaves it untouched rather than
// writing a token over nothing. Intermediates — including the plaintext — are
// VRL LOCAL variables (`_cx_seal_…`, no leading dot), never event fields, so
// they are confined to the remap and cannot reach storage. Naming them as
// event fields would index the plaintext next to its own ciphertext.
func SealVRL(spec EdgeSealSpec) (string, error) {
	if err := spec.Context.valid(); err != nil {
		return "", err
	}
	if !validSecretKey(spec.Context.Tenant) {
		return "", fmt.Errorf("sealing: tenant %q cannot be used as an edge secret key", spec.Context.Tenant)
	}
	if spec.KeyVersion < 1 {
		return "", fmt.Errorf("sealing: key version must be >= 1, got %d", spec.KeyVersion)
	}
	path := strings.TrimSpace(spec.Path)
	if !strings.HasPrefix(path, ".") || len(path) < 2 {
		return "", fmt.Errorf("sealing: %q is not a VRL field path", spec.Path)
	}

	sealKey := vrlString(EdgeSecretRef(EdgeSealBackend, spec.Context.Tenant))
	macKey := vrlString(EdgeSecretRef(EdgeMACBackend, spec.Context.Tenant))
	header := vrlString(tokenPrefix + tokenVersion + ":" +
		b64.EncodeToString([]byte(spec.Context.Tenant)) + ":" +
		strconv.Itoa(spec.KeyVersion) + ":")

	var b strings.Builder
	fmt.Fprintf(&b, "_cx_seal_pt = to_string(%s) ?? \"\"\n", path)
	b.WriteString("if _cx_seal_pt != \"\" {\n")
	b.WriteString("  _cx_seal_iv = random_bytes(16)\n")
	fmt.Fprintf(&b, "  _cx_seal_ct = encrypt!(_cx_seal_pt, \"AES-256-CTR\", decode_base64!(%s), iv: _cx_seal_iv)\n", sealKey)
	b.WriteString("  _cx_seal_ivb = encode_base64(_cx_seal_iv, padding: false, charset: \"url_safe\")\n")
	b.WriteString("  _cx_seal_ctb = encode_base64(_cx_seal_ct, padding: false, charset: \"url_safe\")\n")
	fmt.Fprintf(&b, "  _cx_seal_mi = %s + to_string(strlen(_cx_seal_ivb)) + \":\" + _cx_seal_ivb + \":\" + to_string(strlen(_cx_seal_ctb)) + \":\" + _cx_seal_ctb + \":\"\n",
		vrlString(macPrefix(spec.Context, spec.KeyVersion)))
	fmt.Fprintf(&b, "  _cx_seal_mac = encode_base64(hmac(_cx_seal_mi, decode_base64!(%s), algorithm: \"SHA-256\"), padding: false, charset: \"url_safe\")\n", macKey)
	fmt.Fprintf(&b, "  %s = %s + _cx_seal_ivb + \":\" + _cx_seal_ctb + \":\" + _cx_seal_mac + %s\n",
		path, header, vrlString(tokenSuffix))
	b.WriteString("}\n")
	return b.String(), nil
}
