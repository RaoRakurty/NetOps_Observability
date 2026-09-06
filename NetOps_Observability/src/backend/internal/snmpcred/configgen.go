// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package snmpcred

// configgen.go — the SNMP onboarding credential generator (extracted P2
// RA.14): real credential minting (crypto/rand, CLI-safe base32) and the
// rendering of the vendor device-CLI block. Secrets are generated HERE and
// embedded in the returned config block — credential handling, so it lives with
// the credential store. The HTTP handler, profile persistence and the once-only
// secret return stay with the entrypoint.
//
// WHERE THE VENDOR TEMPLATES LIVE. In the Vendor Profile registry
// (internal/vendorprofile), under each vendor document's `snmp_configgen` block
// (`v2c_template` / `v3_template`), beside everything else that platform
// declares. This file owns the SECRET, not the syntax: it mints the credential,
// supplies the placeholder values, and falls back to generic guidance for a
// vendor with no first-class template. Onboarding a vendor is "author a
// profile", not "add a case to a switch".
//
// WHY A TEMPLATE AND NOT A FORMAT STRING. The block this function returns is
// pasted verbatim into a production device by an operator, and it carries MINTED
// KEY MATERIAL. A positional `fmt.Sprintf` table gets that wrong silently — an
// argument in the wrong position renders a key where a user name belongs and
// nobody sees it until a device rejects the paste. Named `<<holes>>`, validated
// at LOAD against a closed set (vendorprofile.SNMPConfigGenPlaceholders), make
// that class of defect visible in the document instead.

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"

	"netops/backend/internal/vendorprofile"
)

// GenVendors are the vendors with a first-class device template — the ones whose
// profile declares an `snmp_configgen` block. Anything else falls back to the
// generic guidance (and still gets a real, minted credential).
//
// It is built ONCE from the embedded registry: immutable reference data derived
// from immutable reference data, the same carve-out the registry itself
// documents for its embedded FS. The map shape is preserved because it is this
// package's published API.
var GenVendors = func() map[string]bool {
	ids := vendorprofile.Default().SNMPConfigGenVendors()
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}()

// genSecret returns a URL/CLI-safe random secret of ~n characters (base32, no
// padding, lowercased) — safe to paste into any vendor CLI (no quotes/specials).
func GenSecret(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	s := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "="))
	if len(s) > n {
		s = s[:n]
	}
	return s, nil
}

// titleVendor uppercases the first letter of an ASCII vendor slug ("cisco" →
// "Cisco") — replaces the deprecated strings.Title for this single use.
func titleVendor(v string) string {
	if v == "" {
		return v
	}
	return strings.ToUpper(v[:1]) + v[1:]
}

// GeneratedAuthProtocol / GeneratedPrivProtocol are the v3 protocols the
// onboarding generator PROVISIONS on the credential it mints. They are the ONE
// source of truth for that pairing: the vendor `snmp_configgen.v3_template`
// blocks must name the same protocols, because the operator pastes the block
// into the device and Correlix then polls it with this credential. A device
// configured for one auth protocol and a poller credential built for another
// simply fails to authenticate, and nothing in the generated pair says why —
// so the agreement is asserted against these constants
// (TestGeneratedV3TemplatesNameTheProtocolTheBuilderProvisions), never against
// two hand-copied strings.
//
// SHA is HMAC-SHA-1 (USM's original auth protocol) and AES128 is CFB128-AES-128:
// the widest interoperable pairing Correlix supports. AuthProtocols in store.go
// carries the full set a hand-authored credential may use; this pair is what the
// GENERATOR picks, and raising it means updating every v3 template with it.
const (
	GeneratedAuthProtocol = "SHA"
	GeneratedPrivProtocol = "AES128"
)

// buildSNMPCredential builds the credential profile that matches a generated
// config (pure; the caller persists it). v3 uses GeneratedAuthProtocol +
// GeneratedPrivProtocol (SHA + AES128).
func BuildGeneratedCredential(vendor, version, community, secName, authKey, privKey string) Credential {
	c := Credential{
		ID:      fmt.Sprintf("%s-%s-gen", vendor, version),
		Name:    fmt.Sprintf("%s %s (generated)", titleVendor(vendor), version),
		Version: version,
		Port:    161,
	}
	if version == "v2c" {
		c.Community = community
	} else {
		c.SecurityName = secName
		c.SecurityLevel = "authPriv"
		c.AuthProtocol = GeneratedAuthProtocol
		c.AuthKey = authKey
		c.PrivProtocol = GeneratedPrivProtocol
		c.PrivKey = privKey
	}
	return c
}

// DeviceConfig renders the vendor CLI block for the generated credential. Pure
// + unit-tested (a byte-parity golden pins every shipped vendor's block).
// mgmtSubnet/mask default to the whole space when empty.
//
// A vendor whose profile declares no template gets the GENERIC guidance below:
// the credential is real, and the operator applies it with their own vendor's
// syntax. That is the honest answer — inventing a CLI block for a platform
// nobody has validated would be a claim about a device we cannot make.
func DeviceConfig(vendor, version, community, secName, authKey, privKey, mgmtSubnet, mask string) string {
	v3 := version == "v3"
	// The placeholder values. Only the vendor's own template decides which of
	// them appear in the rendered block, and the registry renders in a SINGLE
	// left-to-right pass so an operator-supplied subnet can never name a hole
	// and pull a minted key into itself.
	vals := map[string]string{
		"community":   community,
		"sec_name":    secName,
		"auth_key":    authKey,
		"priv_key":    privKey,
		"mgmt_subnet": orDefaultGen(mgmtSubnet, "0.0.0.0"),
		"mask":        orDefaultGen(mask, "0.0.0.0"),
	}
	if block, ok := vendorprofile.Default().RenderSNMPConfig(vendor, version, vals); ok {
		return block
	}
	// Generic fallback — the credential is real; the operator applies it with
	// their vendor's syntax (enable SNMP + a read-only credential).
	if v3 {
		return fmt.Sprintf("# Configure an SNMPv3 read-only user on this device:\n#   user=%s  auth=SHA key=%s  priv=AES-128 key=%s", secName, authKey, privKey)
	}
	return fmt.Sprintf("# Configure an SNMPv2c read-only community on this device:\n#   community=%s", community)
}

// orDefaultGen mirrors main's orDefault for the template defaults.
func orDefaultGen(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
