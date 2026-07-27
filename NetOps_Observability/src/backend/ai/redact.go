package ai

import (
	"regexp"
	"strings"
)

// redact.go — the OUTBOUND data-loss-prevention (DLP) filter: the one dialect
// this repo uses to strip credentials and direct identifiers from anything that
// crosses the external-provider boundary (CLAUDE.md §8 "sanitize all logs, no
// PII leakage"; §15 LLM06 "the backend must not send secrets, other tenants'
// data or PII to an external provider").
//
// WHY IT LIVES IN package ai
// It is applied at three layers — the orchestrator's grounded prompts, the
// agent loop's rendered TOOL RESULTS, and a final credential sweep of the
// assembled provider payload — plus the syslog tool's per-line redaction in
// package main (redactAILogLine). package ai is the only package all of those
// can import, so there is exactly ONE dialect to review and extend rather than
// a second one growing beside it (audit PIPE-MED-5: the seam was declared on
// Orchestrator.Redactor and never wired, so redact() was the identity function
// in production while tool results shipped verbatim to OpenAI/Gemini/Anthropic).
//
// TWO TIERS, on purpose:
//
//	RedactSecrets — credential-shaped material ONLY (tokens, keys, passwords,
//	  community strings, private keys, inline connection-string creds). Safe to
//	  apply to ANYTHING, including the operator's own typed question, because no
//	  legitimate NOC question contains a credential.
//	Redact — RedactSecrets PLUS direct identifiers (client MAC addresses, email
//	  addresses, usernames / EAP identities). Applied to SERVER-ORIGINATED
//	  content: grounded prompts and tool results, i.e. data the platform pulled
//	  out of a tenant's stores. It is deliberately NOT applied to the operator's
//	  own message, because masking a MAC the operator typed would break the
//	  wireless client lookups they typed it for.
//
// FAIL SAFE: every rule prefers a false positive (mask something harmless) over
// a false negative (leak). The rules are all precompiled and run in a single
// pass each — the whole filter is a handful of regex scans over ≤ a few hundred
// KB, which is nothing next to the provider round-trip it guards.
//
// IDEMPOTENT: applying the filter twice yields the same string, so layering it
// (tool result → prompt → payload sweep) is safe.

// Mask is the replacement token. Short, obviously synthetic, and free of
// quoting/escaping characters so substituting it inside a JSON payload can
// never produce invalid JSON.
const Mask = "***"

// valueChars is the character class of a "value" that follows a secret-ish key.
// Quotes, backslashes, whitespace and the usual separators terminate it, so the
// filter can run over a JSON payload (`"password":"x"` → `"password":"***"`)
// without ever eating a structural character.
const valueChars = `[^\s"'\\,;&)]+`

var (
	// A pasted private key — the highest-severity single leak. Matched as a whole
	// block (DOTALL) so nothing of the body survives.
	rePrivateKeyBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

	// Authorization-scheme credentials: "Bearer eyJ…", "Basic dXNlcjpwdw==".
	reAuthScheme = regexp.MustCompile(`(?i)\b(bearer|basic|digest)\s+[A-Za-z0-9._~+/=-]{8,}`)

	// A JWT anywhere (header.payload.signature) — session tokens, our own
	// capability tokens, provider service-account assertions.
	reJWT = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}`)

	// Vendor-shaped API keys that are recognisable on sight and therefore
	// immediately abusable if they land in a prompt or a log.
	reVendorKey = regexp.MustCompile(`(?i)\b(sk-[A-Za-z0-9_-]{12,}|xox[abprs]-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{12,}|ASIA[0-9A-Z]{12,}|AIza[0-9A-Za-z_-]{30,})`)

	// key=value / key: value where the key names a secret. The KEY survives so
	// the line stays diagnostically useful ("auth failed, password ***").
	reSecretKV = regexp.MustCompile(`(?i)\b(passwords?|passwd|pwd|secrets?|client[_-]?secret|community|community[_-]?string|tokens?|api[_-]?keys?|apikey|access[_-]?key|secret[_-]?key|private[_-]?key|ssh[_-]?key|authorization|credentials?|passphrase|psk|pre[_-]?shared[_-]?key|shared[_-]?secret|auth[_-]?token|session[_-]?token|refresh[_-]?token|bearer|cookie|set[_-]?cookie|snmp[_-]?community|enable[_-]?secret)\b(\s*[:=]\s*"?)` + valueChars)

	// The CLI/syslog form, where the value follows whitespace rather than a
	// separator: "snmp-server community public RO", "password 7 08701E1D",
	// "enable secret 5 $1$…". The value is captured so cliSecretStopwords can
	// spare ordinary English (see below).
	reSecretCLI = regexp.MustCompile(`(?i)\b(snmp-server community|community-string|enable secret|password|passwd|secret|community|passphrase)\s+(\d\s+)?(` + valueChars + `)`)

	// Inline credentials in a connection string / URL userinfo:
	// postgres://user:pw@host, https://admin:pw@device/api.
	reURLCreds = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`)

	// ---- identifier tier -------------------------------------------------

	// A MAC address in colon/hyphen form. The OUI (first three octets) survives
	// because "which vendor is this client" is a legitimate NOC question; the
	// device-unique half is masked, so it is no longer a direct identifier.
	// A fully 2-hex-per-group IPv6 literal can trip this — that is the fail-safe
	// direction (we mask part of an address rather than leak a client MAC).
	reMACColon = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`)
	// The Cisco/Aruba dotted-triplet form: aabb.ccdd.eeff.
	reMACDotted = regexp.MustCompile(`\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b`)

	// An email address / EAP outer identity. The DOMAIN survives (realm routing
	// is operationally meaningful and is not a direct identifier); the local
	// part — the person — does not.
	reEmail = regexp.MustCompile(`\b[A-Za-z0-9._%+-]{1,64}@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})\b`)

	// user=/username:/identity=… — the 802.1X supplicant, the RADIUS account,
	// the SSH login. Same key-survives shape as reSecretKV.
	// The keys are deliberately SINGULAR ("user", not "users"): a plural key is
	// almost always a count ("users: 42"), and masking counts would degrade the
	// answers without protecting anyone.
	reIdentityKV = regexp.MustCompile(`(?i)\b(user|user[_-]?name|userid|user[_-]?id|login|logon|account|identity|eap[_-]?identity|eap[_-]?id|principal|upn|sam[_-]?account[_-]?name|calling[_-]?station[_-]?id|supplicant|dot1x[_-]?user|nt[_-]?user)\b(\s*[:=]\s*"?)` + valueChars)
)

// cliSecretStopwords are words that CANNOT be a credential but do follow
// "password"/"secret"/"community" in ordinary English and in auth-failure log
// lines. Without this, "password expired for admin" became "password *** for
// admin" and the embedded product knowledge lost words to the payload sweep —
// noise that teaches operators (and reviewers) to distrust the filter, which is
// how filters get removed. Everything NOT on this list is still masked,
// including dictionary-word community strings like "public" and "private", and
// the Cisco "password 7 <hash>" form bypasses the list entirely.
var cliSecretStopwords = map[string]bool{
	"a": true, "an": true, "and": true, "are": true, "as": true, "at": true,
	"be": true, "been": true, "but": true, "by": true, "can": true,
	"change": true, "changed": true, "complexity": true, "could": true,
	"do": true, "does": true, "expired": true, "expires": true, "expiry": true,
	"failed": true, "failure": true, "for": true, "from": true, "has": true,
	"have": true, "hash": true, "hashed": true, "if": true, "in": true,
	"incorrect": true, "invalid": true, "is": true, "it": true, "length": true,
	"may": true, "mismatch": true, "must": true, "no": true, "not": true,
	"of": true, "on": true, "or": true, "policy": true, "required": true,
	"reset": true, "rotated": true, "rotation": true, "set": true,
	"should": true, "string": true, "that": true, "the": true, "then": true,
	"this": true, "to": true, "unchanged": true, "unknown": true, "up": true,
	"used": true, "verification": true, "was": true, "were": true, "when": true,
	"will": true, "with": true, "without": true, "would": true,
}

// maskCLISecret masks the value after a whitespace-separated secret keyword,
// unless that "value" is plainly an English word (cliSecretStopwords) and no
// encoding-type digit precedes it.
func maskCLISecret(m string) string {
	sub := reSecretCLI.FindStringSubmatch(m)
	if sub == nil {
		return Mask // unexpected — fail safe
	}
	if sub[2] == "" && cliSecretStopwords[strings.ToLower(sub[3])] {
		return m
	}
	return sub[1] + " " + Mask
}

// RedactSecrets masks credential-shaped material. Safe on any string — it never
// touches operational identifiers, so an operator can still ask about the MAC
// or username they typed themselves.
func RedactSecrets(s string) string {
	if s == "" {
		return s
	}
	s = rePrivateKeyBlock.ReplaceAllString(s, Mask)
	s = reJWT.ReplaceAllString(s, Mask)
	s = reAuthScheme.ReplaceAllString(s, "${1} "+Mask)
	s = reVendorKey.ReplaceAllString(s, Mask)
	s = reSecretKV.ReplaceAllString(s, "${1}${2}"+Mask)
	s = reSecretCLI.ReplaceAllStringFunc(s, maskCLISecret)
	s = reURLCreds.ReplaceAllString(s, "${1}"+Mask+":"+Mask+"@")
	return s
}

// Redact is the full outbound filter: credentials plus direct identifiers. This
// is what server-originated content (grounded prompts, rendered tool results)
// must pass through before it crosses the provider boundary.
func Redact(s string) string {
	if s == "" {
		return s
	}
	s = RedactSecrets(s)
	s = reMACColon.ReplaceAllStringFunc(s, maskMACColon)
	s = reMACDotted.ReplaceAllStringFunc(s, maskMACDotted)
	s = reEmail.ReplaceAllString(s, Mask+"@${1}")
	s = reIdentityKV.ReplaceAllString(s, "${1}${2}"+Mask)
	return s
}

// maskMACColon keeps the OUI (vendor) and masks the device-unique half:
// "aa:bb:cc:dd:ee:ff" → "aa:bb:cc:xx:xx:xx".
func maskMACColon(mac string) string {
	sep := ":"
	if strings.Contains(mac, "-") {
		sep = "-"
	}
	parts := strings.Split(mac, sep)
	if len(parts) != 6 {
		return Mask // unexpected shape — fail safe
	}
	return strings.Join(parts[:3], sep) + sep + "xx" + sep + "xx" + sep + "xx"
}

// maskMACDotted is maskMACColon for the dotted-triplet form:
// "aabb.ccdd.eeff" → "aabb.ccxx.xxxx".
func maskMACDotted(mac string) string {
	parts := strings.Split(mac, ".")
	if len(parts) != 3 || len(parts[1]) != 4 {
		return Mask // unexpected shape — fail safe
	}
	return parts[0] + "." + parts[1][:2] + "xx.xxxx"
}
