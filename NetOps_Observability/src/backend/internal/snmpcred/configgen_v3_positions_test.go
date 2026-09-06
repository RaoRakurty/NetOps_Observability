// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package snmpcred

// configgen_v3_positions_test.go — the two structural contracts a generated
// SNMPv3 onboarding block must satisfy, pinned so the defects they describe
// cannot silently return.
//
//  1. A minted key must never occupy a POSITION that names something else.
//     The Ubiquiti block used to render the privacy key where the user name
//     belongs (see the golden's "DELIBERATE GOLDEN UPDATES" note). Byte parity
//     alone cannot catch that class: it only says "the same bytes as before".
//
//  2. Every vendor's block must name the auth protocol the credential builder
//     actually PROVISIONS. The Huawei block used to say sha2-256 while
//     BuildGeneratedCredential minted a SHA (HMAC-SHA-1) credential, so the pair
//     the operator was handed could not authenticate. Both sides are asserted
//     against the single constant GeneratedAuthProtocol — never against two
//     hand-copied strings, which is how they drifted apart in the first place.

import (
	"strings"
	"testing"
)

// ─── 1. placeholder POSITIONS in the Ubiquiti v3 block ───────────────────────

// TestUbiquitiV3NamesTheUserAtTheUserPositionAndTheKeyOnlyAfterThePrivKeyword
// parses the rendered EdgeOS block structurally rather than comparing it to a
// string, so it fails for ANY transposition, not just the one that shipped.
//
// EdgeOS grammar the block uses:
//
//	set service snmp v3 user <USER> <keyword...> [<VALUE>]
//
// so the token after "user" is ALWAYS the security name, and the minted privacy
// key may appear only as the value following "privacy plaintext-key".
func TestUbiquitiV3NamesTheUserAtTheUserPositionAndTheKeyOnlyAfterThePrivKeyword(t *testing.T) {
	const (
		secName = "SECNAMEMARKER"
		authKey = "AUTHKEYMARKER"
		privKey = "PRIVKEYMARKER"
	)
	block := DeviceConfig("ubiquiti", "v3", "", secName, authKey, privKey, "", "")
	if block == "" || strings.HasPrefix(block, "# Configure") {
		t.Fatalf("ubiquiti must render a first-class v3 block, got %q", block)
	}

	userLines := 0
	for _, line := range strings.Split(block, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || strings.Join(f[:5], " ") != "set service snmp v3 user" {
			continue // "commit ; save" and anything else
		}
		userLines++

		// The token at the USER position is the security name — never a key.
		if got := f[5]; got != secName {
			t.Errorf("USER POSITION CARRIES THE WRONG VALUE on %q: got %q, want the security name %q", line, got, secName)
		}

		// The privacy key may appear ONLY as the value after "privacy
		// plaintext-key"; the auth key only after "auth plaintext-key".
		rest := f[6:]
		switch {
		case len(rest) == 3 && rest[0] == "privacy" && rest[1] == "plaintext-key":
			if rest[2] != privKey {
				t.Errorf("privacy plaintext-key must carry the privacy key, got %q on %q", rest[2], line)
			}
		case len(rest) == 3 && rest[0] == "auth" && rest[1] == "plaintext-key":
			if rest[2] != authKey {
				t.Errorf("auth plaintext-key must carry the auth key, got %q on %q", rest[2], line)
			}
		default:
			// A keyword-only line ("auth type sha", "mode ro"): it must carry no
			// minted key material at all.
			for _, tok := range rest {
				if tok == privKey || tok == authKey {
					t.Errorf("MINTED KEY ON A KEYWORD LINE: %q appears on %q", tok, line)
				}
			}
		}
	}
	if userLines != 5 {
		t.Fatalf("expected 5 `set service snmp v3 user …` lines, parsed %d:\n%s", userLines, block)
	}
	// Belt and braces on the whole block: the privacy key is written exactly
	// once, and never immediately after the word "user".
	if n := strings.Count(block, privKey); n != 1 {
		t.Errorf("privacy key must appear exactly once, appears %d times:\n%s", n, block)
	}
	if strings.Contains(block, "user "+privKey) {
		t.Errorf("REGRESSION: the privacy key is at the user position:\n%s", block)
	}
}

// ─── 2. auth protocol agreement, builder ↔ every v3 template ─────────────────

// authProtoCLISpellings maps a Credential.AuthProtocol id (what the builder
// provisions) to the vendor-CLI tokens that MEAN it. A rendered v3 block may
// name only tokens from the entry for GeneratedAuthProtocol; naming any other
// known protocol spelling is the disagreement this test exists to catch.
//
// Keyed by the protocol id so the assertion follows the constant: flip
// GeneratedAuthProtocol to "SHA256" and every template that still says `sha`
// fails here until it is updated with it.
var authProtoCLISpellings = map[string][]string{
	"MD5":    {"md5"},
	"SHA":    {"sha", "sha1", "sha-1"},
	"SHA224": {"sha224", "sha-224", "sha2-224"},
	"SHA256": {"sha256", "sha-256", "sha2-256"},
	"SHA384": {"sha384", "sha-384", "sha2-384"},
	"SHA512": {"sha512", "sha-512", "sha2-512"},
}

// knownAuthSpellings is every spelling above, flattened — the vocabulary the
// scanner recognises as "this token names an auth protocol".
func knownAuthSpellings() map[string]string {
	out := map[string]string{}
	for proto, spellings := range authProtoCLISpellings {
		for _, s := range spellings {
			out[s] = proto
		}
	}
	return out
}

// authProtocolsNamedIn returns the protocol ids a rendered CLI block names, by
// scanning its tokens for known auth-protocol spellings. It handles the three
// shapes the shipped templates use: a bare token (`auth sha`), a hyphenated
// keyword+value (`authentication-sha`) and a `key=value` token
// (`authentication-protocol=SHA1`).
func authProtocolsNamedIn(block string) map[string]bool {
	known := knownAuthSpellings()
	found := map[string]bool{}
	for _, raw := range strings.Fields(strings.ToLower(block)) {
		tok := strings.Trim(raw, "{}(),;\"")
		if i := strings.LastIndex(tok, "="); i >= 0 { // authentication-protocol=sha1
			tok = tok[i+1:]
		}
		if proto, ok := known[tok]; ok { // sha, sha1, sha2-256
			found[proto] = true
			continue
		}
		if i := strings.LastIndex(tok, "-"); i >= 0 { // authentication-sha
			if proto, ok := known[tok[i+1:]]; ok {
				found[proto] = true
			}
		}
	}
	return found
}

// TestGeneratedV3TemplatesNameTheProtocolTheBuilderProvisions is the agreement
// contract. The operator pastes the rendered block into the device and Correlix
// then polls that device with the credential BuildGeneratedCredential minted in
// the same call. If the block configures one auth protocol and the credential
// carries another, the poll fails to authenticate and neither artefact says why.
//
// Both sides are read from GeneratedAuthProtocol, so this cannot pass by two
// hard-coded strings happening to match.
func TestGeneratedV3TemplatesNameTheProtocolTheBuilderProvisions(t *testing.T) {
	// The builder is the authority: assert it actually provisions the constant.
	cred := BuildGeneratedCredential("huawei", "v3", "", "correlix", "AK", "PK")
	if cred.AuthProtocol != GeneratedAuthProtocol {
		t.Fatalf("BuildGeneratedCredential provisions AuthProtocol %q, want GeneratedAuthProtocol %q",
			cred.AuthProtocol, GeneratedAuthProtocol)
	}
	if cred.PrivProtocol != GeneratedPrivProtocol {
		t.Fatalf("BuildGeneratedCredential provisions PrivProtocol %q, want GeneratedPrivProtocol %q",
			cred.PrivProtocol, GeneratedPrivProtocol)
	}
	// …and that the constant is a protocol the credential store accepts, or the
	// generated credential could never be persisted.
	if !inList(GeneratedAuthProtocol, AuthProtocols) {
		t.Fatalf("GeneratedAuthProtocol %q is not in AuthProtocols %v", GeneratedAuthProtocol, AuthProtocols)
	}
	if _, ok := authProtoCLISpellings[GeneratedAuthProtocol]; !ok {
		t.Fatalf("GeneratedAuthProtocol %q has no CLI spellings declared — add them and update every v3 template",
			GeneratedAuthProtocol)
	}

	vendors := make([]string, 0, len(GenVendors))
	for v := range GenVendors {
		vendors = append(vendors, v)
	}
	if len(vendors) == 0 {
		t.Fatal("no templated vendors — the assertion would be vacuous")
	}
	for _, vendor := range vendors {
		block := DeviceConfig(vendor, "v3", "", "correlix", "AK", "PK", "", "")
		named := authProtocolsNamedIn(block)
		if len(named) == 0 {
			t.Errorf("%s v3 block names no auth protocol at all:\n%s", vendor, block)
			continue
		}
		for proto := range named {
			if proto != GeneratedAuthProtocol {
				t.Errorf("PROTOCOL DISAGREEMENT: the %s v3 block configures %s, but BuildGeneratedCredential provisions %s:\n%s",
					vendor, proto, GeneratedAuthProtocol, block)
			}
		}
	}

	// The generic fallback is operator-facing guidance for an untemplated vendor
	// and names the protocol too — same contract, same constant.
	generic := DeviceConfig("no-such-vendor", "v3", "", "correlix", "AK", "PK", "", "")
	for proto := range authProtocolsNamedIn(generic) {
		if proto != GeneratedAuthProtocol {
			t.Errorf("the generic v3 guidance names %s, but the builder provisions %s:\n%s",
				proto, GeneratedAuthProtocol, generic)
		}
	}
}
