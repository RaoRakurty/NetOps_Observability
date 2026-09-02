package configstore

import (
	"regexp"
	"strings"
)

// redact.go — the per-vendor SECRET-LINE rule list.
//
// A running-config is a secret store: SNMP communities, IKE pre-shared keys,
// TACACS/RADIUS keys, type-7/type-5/type-9 password hashes, embedded private
// keys. The SEALED copy keeps the original byte for byte (it is the artifact an
// operator restores from); everything that leaves this module toward a HUMAN —
// the version text endpoint, the unified diff, a log line, a drift summary —
// goes through Redact first.
//
// Two deliberate design choices:
//
//   - The rules ERR TOWARD MASKING. A regex that masks one token too many costs
//     an operator a keyword; a regex that masks one token too few publishes a
//     device credential. Where the grammar is ambiguous (the trailing token of
//     `snmp-server host`, a Junos quoted value) the wider match wins.
//   - The mask is a FIXED token, not a length-preserving blob. `****` leaks
//     nothing about the secret's length, and every masked value renders
//     identically so a diff of two configs whose ONLY difference is a rotated
//     password shows no spurious change... which is also why the DRIFT verdict
//     is computed on the unredacted normalized text, never on the redacted view.
//
// Every rule below is named; the test suite drives canaries (Cisco
// `enable secret`, `snmp-server community`, Junos `encrypted-password`,
// `pre-shared-key`) through Redact and asserts the secret value is absent from
// the output.

// Mask is the fixed replacement token for a redacted secret.
const Mask = "****"

// secretRule is one documented redaction rule. Re MUST contain exactly one
// capture group: the span that is replaced by Mask.
type secretRule struct {
	Name string
	Re   *regexp.Regexp
}

// secretCommon are the vendor-independent secret-line rules.
//
//	pre-shared-key   IKE/IPsec PSK in every dialect's spelling
//	key-string       inline key material (`key-string`, keychains, EIGRP/OSPF)
//	shared-secret    generic `shared-secret <v>` (RADIUS proxies, TACACS+)
//	auth-priv-token  the trailing token after an SNMPv3 auth/priv algorithm
var secretCommon = []secretRule{
	{"pre-shared-key", regexp.MustCompile(`(?i)(?:pre-shared-key|pre-shared-secret)\s+(?:local\s+|remote\s+)?(?:ascii-text\s+|hexadecimal\s+)?"?([^"\s]+)"?`)},
	{"key-string", regexp.MustCompile(`(?i)\bkey-string\s+(?:\d+\s+)?"?([^"\s]+)"?`)},
	{"shared-secret", regexp.MustCompile(`(?i)\bshared-secret\s+"?([^"\s]+)"?`)},
	{"auth-priv-token", regexp.MustCompile(`(?i)\b(?:auth|priv)\s+(?:md5|sha|sha1|sha256|sha512|des|3des|aes|aes128|aes192|aes256)\s+"?([^"\s]+)"?`)},
}

// secretRules is the per-vendor secret-line rule list.
//
// Cisco / Arista
//
//	enable-secret        `enable secret|password [<type>] <v>`
//	username-secret      `username <u> [privilege N] secret|password [<type>] <v>`
//	snmp-community       `snmp-server community <v> …`
//	snmp-host-community  the community/user token on `snmp-server host …`
//	aaa-server-key       `tacacs-server|radius-server [host <h>] key [<type>] <v>`
//	keychain-key         `key <0|6|7> <v>` inside a key chain
//	isakmp-key           `crypto isakmp key [<type>] <v>`
//	line-password        `password [<type>] <v>` (line vty/con, ppp, ftp)
//	bgp-neighbor-pass    `neighbor <peer> password [<type>] <v>`
//	ospf-md5-key         `ip ospf message-digest-key N md5 [<type>] <v>`
//	ppp-password         `ppp chap|pap password|sent-username … password <v>`
//	wpa-psk              `wpa-psk ascii|hex [<type>] <v>`
//	ftp-password         `ip ftp password [<type>] <v>`
//
// Juniper (Junos, set-format)
//
//	junos-encrypted-pw   `encrypted-password "<v>"`
//	junos-plain-text-pw  `plain-text-password-value "<v>"`
//	junos-auth-key       `authentication-key "<v>"`
//	junos-secret         `secret "<v>"` (RADIUS/TACACS shared secret)
//	junos-ssh-key        `ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-* "<v>"`
//	junos-snmp-community `snmp community <v>` (the community NAME is the secret)
//
// Huawei (VRP)
//
//	vrp-cipher           `… cipher <v>` / `irreversible-cipher <v>`
//	vrp-password-simple  `password simple <v>`
//	vrp-snmp-community   `snmp-agent community read|write [cipher] <v>`
//
// Nokia (SR OS)
//
//	sros-hashed-value    `"<v>" hash|hash2` (the value precedes the marker)
//	sros-password        `password "<v>"`
//	sros-community       `community "<v>"`
//	sros-auth-key        `authentication-key "<v>"`
var secretRules = map[Vendor][]secretRule{
	VendorCisco: {
		{"enable-secret", regexp.MustCompile(`(?i)^\s*enable\s+(?:secret|password)\s+(?:\d+\s+)?(\S+)`)},
		{"username-secret", regexp.MustCompile(`(?i)^\s*username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+(?:\d+\s+)?(\S+)`)},
		{"snmp-community", regexp.MustCompile(`(?i)^\s*snmp-server\s+community\s+(\S+)`)},
		{"snmp-host-community", regexp.MustCompile(`(?i)^\s*snmp-server\s+host\s+\S+(?:\s+vrf\s+\S+)?(?:\s+(?:informs|traps))?(?:\s+version\s+\S+(?:\s+(?:auth|noauth|priv))?)?\s+(\S+)`)},
		{"aaa-server-key", regexp.MustCompile(`(?i)^\s*(?:tacacs-server|radius-server)\s+(?:host\s+\S+\s+)?key\s+(?:\d+\s+)?(\S+)`)},
		{"keychain-key", regexp.MustCompile(`(?i)^\s*key\s+(?:0|6|7)\s+(\S+)`)},
		{"isakmp-key", regexp.MustCompile(`(?i)^\s*crypto\s+isakmp\s+key\s+(?:\d+\s+)?(\S+)`)},
		{"line-password", regexp.MustCompile(`(?i)^\s*password\s+(?:\d+\s+)?(\S+)`)},
		{"bgp-neighbor-pass", regexp.MustCompile(`(?i)^\s*neighbor\s+\S+\s+password\s+(?:\d+\s+)?(\S+)`)},
		{"ospf-md5-key", regexp.MustCompile(`(?i)message-digest-key\s+\d+\s+md5\s+(?:\d+\s+)?(\S+)`)},
		{"ppp-password", regexp.MustCompile(`(?i)\bppp\s+(?:chap|pap)\s+(?:sent-username\s+\S+\s+)?password\s+(?:\d+\s+)?(\S+)`)},
		{"wpa-psk", regexp.MustCompile(`(?i)\bwpa-psk\s+(?:ascii|hex)\s+(?:\d+\s+)?(\S+)`)},
		{"ftp-password", regexp.MustCompile(`(?i)^\s*ip\s+ftp\s+password\s+(?:\d+\s+)?(\S+)`)},
	},
	VendorJuniper: {
		{"junos-encrypted-pw", regexp.MustCompile(`(?i)\bencrypted-password\s+"?([^"\s]+)"?`)},
		{"junos-plain-text-pw", regexp.MustCompile(`(?i)\bplain-text-password-value\s+"?([^"\s]+)"?`)},
		{"junos-auth-key", regexp.MustCompile(`(?i)\bauthentication-key\s+"?([^"]+?)"?\s*$`)},
		{"junos-secret", regexp.MustCompile(`(?i)\bsecret\s+"?([^"\s]+)"?`)},
		{"junos-ssh-key", regexp.MustCompile(`(?i)\b(?:ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-\S+)\s+"?([^"]+?)"?\s*$`)},
		{"junos-snmp-community", regexp.MustCompile(`(?i)\bsnmp\s+community\s+"?([^"\s]+)"?`)},
	},
	VendorHuawei: {
		{"vrp-cipher", regexp.MustCompile(`(?i)\b(?:irreversible-)?cipher\s+(\S+)`)},
		{"vrp-password-simple", regexp.MustCompile(`(?i)\bpassword\s+simple\s+(\S+)`)},
		{"vrp-snmp-community", regexp.MustCompile(`(?i)^\s*snmp-agent\s+community\s+(?:read|write)\s+(?:cipher\s+)?(\S+)`)},
	},
	VendorNokia: {
		{"sros-hashed-value", regexp.MustCompile(`(?i)"([^"]+)"\s+hash2?\b`)},
		{"sros-password", regexp.MustCompile(`(?i)^\s*password\s+"?([^"\s]+)"?`)},
		{"sros-community", regexp.MustCompile(`(?i)^\s*community\s+"?([^"\s]+)"?`)},
		{"sros-auth-key", regexp.MustCompile(`(?i)\bauthentication-key\s+"?([^"\s]+)"?`)},
	},
}

func init() {
	// Arista shares the Cisco-style CLI grammar; bind it to the same rule set
	// rather than maintaining a second copy that could drift out of parity.
	secretRules[VendorArista] = secretRules[VendorCisco]
}

// SecretRuleNames returns the documented redaction rule names applied for a
// vendor (common rules first). Exported so the suite can pin the list.
func SecretRuleNames(v Vendor) []string {
	out := make([]string, 0, len(secretCommon)+8)
	for _, r := range secretCommon {
		out = append(out, r.Name)
	}
	for _, r := range secretRules[v] {
		out = append(out, r.Name)
	}
	return out
}

// pemBegin / pemEnd bracket an inline private key or certificate. Everything
// between them is masked wholesale — a PEM body has no grammar worth preserving
// and every byte of it is key material.
var (
	pemBegin = regexp.MustCompile(`(?i)^\s*-+\s*begin [a-z0-9 ]*(private key|rsa private key|certificate)`)
	pemEnd   = regexp.MustCompile(`(?i)^\s*-+\s*end [a-z0-9 ]*(private key|rsa private key|certificate)`)
)

// isHexBlobLine reports whether a line is nothing but hex digits and spaces with
// at least 32 hex characters — Cisco's inline `crypto pki certificate chain`
// body, which is certificate/key material printed straight into the config. No
// configuration statement looks like this, and every byte of one that does is
// key material, so the whole line is masked.
func isHexBlobLine(line string) bool {
	n := 0
	for _, r := range line {
		switch {
		case r == ' ' || r == '\t':
		case (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F'):
			n++
		default:
			return false
		}
	}
	return n >= 32
}

// RedactLine masks every secret this module knows how to recognize on ONE line.
// It is idempotent (masking an already-masked line is a no-op) and never widens
// the line.
func RedactLine(v Vendor, line string) string {
	for _, r := range secretCommon {
		line = maskGroup1(line, r.Re)
	}
	for _, r := range secretRules[v] {
		line = maskGroup1(line, r.Re)
	}
	return line
}

// Redact masks every secret in a whole configuration, including multi-line PEM
// and hex key blobs (which no single-line rule can see).
func Redact(v Vendor, text string) string {
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	inPEM := false
	for _, ln := range lines {
		switch {
		case pemBegin.MatchString(ln):
			inPEM = true
			out = append(out, ln)
			continue
		case inPEM && pemEnd.MatchString(ln):
			inPEM = false
			out = append(out, ln)
			continue
		case inPEM:
			out = append(out, Mask)
			continue
		case isHexBlobLine(ln):
			// A bare long hex run inside a config is key/certificate material
			// (Cisco `crypto pki certificate chain` bodies) — never intent.
			out = append(out, Mask)
			continue
		}
		out = append(out, RedactLine(v, ln))
	}
	return strings.Join(out, "\n")
}

// maskGroup1 replaces capture group 1 of every match with Mask. It works on
// INDEXES rather than a replacement template so the surrounding text (keywords,
// interface names, peer addresses) survives untouched.
func maskGroup1(line string, re *regexp.Regexp) string {
	locs := re.FindAllStringSubmatchIndex(line, -1)
	if len(locs) == 0 {
		return line
	}
	var b strings.Builder
	prev := 0
	for _, m := range locs {
		if len(m) < 4 || m[2] < 0 || m[3] < 0 || m[2] < prev {
			continue
		}
		if line[m[2]:m[3]] == Mask {
			continue // idempotent
		}
		b.WriteString(line[prev:m[2]])
		b.WriteString(Mask)
		prev = m[3]
	}
	if prev == 0 {
		return line
	}
	b.WriteString(line[prev:])
	return b.String()
}
