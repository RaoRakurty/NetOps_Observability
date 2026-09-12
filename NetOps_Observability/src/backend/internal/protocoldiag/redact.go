// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// redactionMark is the placeholder a redacted secret is replaced with.
const redactionMark = "[REDACTED]"

// redactor is a compiled redaction pass. It is built once (compiled regexps are
// captured, not package-level globals, §5) and applied to captured output before
// it is logged or exported (§8: output can carry credentials/PII). Each rule
// keeps the surrounding structure (so a TAC reader still sees WHICH knob it was)
// and replaces only the sensitive VALUE.
type redactor struct {
	rules []redactRule
	// PEM private-key block markers for the stateful multi-line scanner in
	// redactText. Matched unanchored so indentation and CRLF line endings do
	// not defeat detection. Certificate blocks (public material that
	// legitimately appears in `show crypto pki certificates` output) are
	// deliberately NOT block-redacted — only private-key-class labels are.
	pemBegin   *regexp.Regexp
	pemEnd     *regexp.Regexp
	pemOneLine *regexp.Regexp
	// anchors is the union of every rule's anchors, lowercased. A line carrying
	// none of them cannot be matched by ANY rule, so the rule loop is skipped.
	//
	// This is a performance property with a safety proof, not a heuristic. Each
	// rule declares the literal alternatives that its own pattern REQUIRES —
	// they sit at an alternation the pattern cannot match around — and
	// TestPrefilterCannotMissARule asserts, per rule, that the pattern text
	// still contains each declared anchor, so an edit that drops a literal fails
	// the build rather than quietly widening what gets through.
	//
	// It exists because of the first-ask capture: `show tech-support` is tens of
	// megabytes of lines with no secret in them, and running ten regexes over
	// every one of them made a 50 MB collection cost half a minute of CPU.
	//
	// It is a BYTE SCAN and not a regexp on purpose. The obvious spelling —
	// one `(?i)a|b|c` alternation — is 1 MB/s in Go, because a case-insensitive
	// alternation with no literal prefix defeats the engine's memchr fast path;
	// it made the prefilter slower than the rules it was meant to skip. A
	// lowercase copy plus bytes.Contains is two orders of magnitude faster and
	// answers exactly the same question.
	anchors [][]byte
	// scratch is the reusable lowercase buffer. A redactor is used by ONE
	// goroutine at a time (RedactOutput builds its own; RedactingWriter owns
	// one for the life of one command's stream), which is what makes reusing it
	// safe — and is asserted by the race build in CI.
	scratch []byte
}

type redactRule struct {
	re   *regexp.Regexp
	repl string
	// anchors are LOWERCASE literals, at least one of which must appear
	// (case-insensitively) in any string this rule can match.
	anchors []string
}

// newRedactor builds the default redaction pass. The patterns target the secrets
// that realistically appear in `show run`-adjacent and neighbor output: local
// user passwords, enable secrets, SNMP communities, routing/auth keys (OSPF/ISIS
// message-digest and authentication keys, BGP TCP-AO/MD5 passwords), IPsec
// pre-shared keys, and PEM private-key blocks. It is conservative — it redacts
// the value, never the whole line — and fail-safe: an unmatched line is passed
// through unchanged (redaction never fabricates or drops evidence).
func newRedactor() *redactor {
	rule := func(pat, repl string, anchors ...string) redactRule {
		if len(anchors) == 0 {
			panic("protocoldiag: a redaction rule must declare its anchors")
		}
		return redactRule{re: regexp.MustCompile(pat), repl: repl, anchors: anchors}
	}
	// Private-key-class PEM labels: PRIVATE KEY and any prefixed variant
	// (RSA/EC/DSA/ENCRYPTED/OPENSSH …), plus PGP's "PRIVATE KEY BLOCK".
	const pemKeyLabel = `[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?`
	r := &redactor{
		pemBegin:   regexp.MustCompile(`(?i)-----BEGIN ` + pemKeyLabel + `-----`),
		pemEnd:     regexp.MustCompile(`(?i)-----END ` + pemKeyLabel + `-----`),
		pemOneLine: regexp.MustCompile(`(?i)-----BEGIN ` + pemKeyLabel + `-----.*-----END ` + pemKeyLabel + `-----`),
		rules: []redactRule{
			// `username X password [enc] <secret>` / `... secret <secret>` — redact the secret.
			rule(`(?i)((?:username\s+\S+\s+)?(?:password|secret)\s+(?:\d+\s+)?)(\S+)`, "${1}"+redactionMark,
				"password", "secret"),
			// `enable secret 5 <hash>` / `enable password <secret>`.
			rule(`(?i)(enable\s+(?:secret|password)\s+(?:\d+\s+)?)(\S+)`, "${1}"+redactionMark,
				"secret", "password"),
			// SNMP community string.
			rule(`(?i)(snmp-server\s+community\s+)(\S+)`, "${1}"+redactionMark, "community"),
			// OSPF/IS-IS/generic keychain: `... md5 <secret>`, `authentication-key <secret>`,
			// `key-string <secret>`, `message-digest-key N md5 <secret>`.
			rule(`(?i)((?:md5|authentication-key|key-string|password)\s+(?:\d+\s+)?)(\S+)`, "${1}"+redactionMark,
				"md5", "authentication-key", "key-string", "password"),
			// BGP neighbor password: `neighbor <x> password <secret>` handled by the
			// password rule above; TCP-AO keychain name is not a secret, left intact.
			// IPsec / IKE pre-shared keys: `pre-shared-key <secret>`,
			// `crypto isakmp key <secret> address …`, `keyring … key <secret>`.
			rule(`(?i)(pre-shared-key\s+(?:\S+\s+)?(?:key\s+)?)(\S+)`, "${1}"+redactionMark, "pre-shared-key"),
			rule(`(?i)((?:isakmp|keyring)\s+key\s+(?:\d+\s+)?)(\S+)`, "${1}"+redactionMark, "isakmp", "keyring"),
			// A PEM private key squeezed onto a single line. Real multi-line PEM
			// blocks are handled by the stateful scanner in redactText — this
			// per-line rule cannot see across lines.
			rule(`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`, redactionMark,
				"private key"),
		}}
	r.anchors = buildAnchors(r.rules)
	return r
}

// buildAnchors is the deduplicated union of every rule's anchors, lowercased.
func buildAnchors(rules []redactRule) [][]byte {
	seen := map[string]bool{}
	out := make([][]byte, 0, len(rules)*2)
	for _, ru := range rules {
		for _, a := range ru.anchors {
			low := strings.ToLower(a)
			if seen[low] {
				continue
			}
			seen[low] = true
			out = append(out, []byte(low))
		}
	}
	return out
}

// prefilterHit reports whether line carries at least one rule anchor, matched
// case-insensitively. A false answer means no rule can match the line.
func (r *redactor) prefilterHit(line string) bool {
	r.scratch = appendLowerASCII(r.scratch[:0], line)
	for _, a := range r.anchors {
		if bytes.Contains(r.scratch, a) {
			return true
		}
	}
	return false
}

// appendLowerASCII appends s to dst with ASCII letters lowered. Every anchor is
// ASCII, so a Unicode-aware fold would buy nothing and cost a great deal;
// non-ASCII bytes are copied through untouched and therefore cannot make a
// non-matching line match.
func appendLowerASCII(dst []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}

// redactLine applies every rule to one line.
//
// The prefilter runs first. A line carrying none of the rules' literal anchors
// cannot be matched by any of them, so it is returned untouched without running
// a single regex — which is what makes streaming a 50 MB support bundle through
// this pass cost seconds rather than half a minute.
func (r *redactor) redactLine(line string) string {
	if !r.prefilterHit(line) {
		return line
	}
	for _, rule := range r.rules {
		line = rule.re.ReplaceAllString(line, rule.repl)
	}
	return line
}

// redactText applies the redaction pass to a multi-line blob.
//
// It is a stateful line scanner: a line carrying a private-key-class PEM BEGIN
// marker (without its END on the same line — that case is the single-line rule's
// job) enters redaction mode. The BEGIN and END marker lines are kept, so a TAC
// reader still sees WHICH block was redacted, while every body line between them
// is replaced by a single redaction mark. A block left unterminated at EOF is
// redacted through to the end (fail closed: key material never survives a
// truncated capture). Nested or repeated BEGIN markers inside a block are body
// and are redacted with it.
func (r *redactor) redactText(text string) string {
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	inKeyBlock := false
	for _, ln := range lines {
		if inKeyBlock {
			if r.pemEnd.MatchString(ln) {
				inKeyBlock = false
				out = append(out, ln) // keep the END marker line
			}
			continue // body line: dropped (the mark was emitted at BEGIN)
		}
		if r.pemBegin.MatchString(ln) && !r.pemOneLine.MatchString(ln) {
			inKeyBlock = true
			out = append(out, ln, redactionMark) // keep BEGIN, mark the body
			continue
		}
		out = append(out, r.redactLine(ln))
	}
	return strings.Join(out, "\n")
}

// Redact returns a COPY of col with every command's output run through the
// redaction pass. The input is never mutated (a fresh Commands slice is built),
// so the caller keeps the raw capture for its own authorized, in-tenant use while
// the redacted copy is what gets exported/shared.
func Redact(col *Collection) *Collection {
	if col == nil {
		return nil
	}
	r := newRedactor()
	out := *col // shallow copy of scalar fields
	out.Commands = make([]CollectedCommand, len(col.Commands))
	for i, cc := range col.Commands {
		rc := cc // copy the command; only the output is rewritten
		rc.Output = r.redactText(cc.Output)
		out.Commands[i] = rc
	}
	return &out
}

// RedactOutput runs the redaction pass over ONE raw command output and returns
// the redacted copy. It is the single-string form of Redact, for the paths that
// hold a command's text rather than a whole Collection — today the STATE BATTERY
// (fanout.go), which redacts every capture BEFORE it is parsed, so nothing
// unredacted can reach a typed evidence row, a log line, or a caller.
//
// It is deliberately the SAME pass Redact and TACExport use: there is one
// redaction implementation in this package and no way to take a capture out of
// it without going through this function or Redact.
func RedactOutput(raw string) string {
	if raw == "" {
		return ""
	}
	return newRedactor().redactText(raw)
}

// TACExport assembles a redacted, shareable text blob from a Collection and its
// AnalyzeResult: a header (device / vendor / protocol / issue / ruleset / time),
// the analyze verdict(s) with evidence, then every captured command with its
// REDACTED output and timestamp. It is the explicit, auditable "hand this to TAC"
// action (§8) — it runs the redaction pass itself, so a caller cannot forget it.
//
// The tenant id is deliberately NOT written into the export: the blob is meant to
// leave the operator's hands (to a vendor TAC or a peer), and the org identifier
// is not TAC's business. Device hostname/id (operational, not secret) are kept.
// vendorHeaderLine writes the export's vendor/dialect line. When the platform
// resolved to a KNOWN dialect the two agree and the line is unremarkable. When
// it did not — an SR Linux box, a MikroTik, anything without an authored show
// dialect — the bundle must not let a TAC engineer assume the commands below
// were the right ones for their operating system: it says plainly that no
// dialect is authored for this platform and which dialect was attempted
// instead. A bundle that names the wrong operating system is worse than one
// that admits it does not know (QA 2026-09-03, D-2).
func vendorHeaderLine(vendor, rendered Vendor) string {
	if vendor == rendered {
		return DisplayVendor(vendor)
	}
	return fmt.Sprintf("%s — no authored CLI dialect for this platform; the commands below were rendered in the fallback %s dialect and may not be valid here",
		DisplayVendor(vendor), DisplayVendor(rendered))
}

func TACExport(col *Collection, res AnalyzeResult) string {
	if col == nil {
		return ""
	}
	red := Redact(col)
	var b strings.Builder

	fmt.Fprintf(&b, "CORRELIX PROTOCOL DIAGNOSTICS — TAC EXPORT (redacted)\n")
	fmt.Fprintf(&b, "=====================================================\n")
	fmt.Fprintf(&b, "Device      : %s (%s)\n", red.Hostname, red.DeviceID)
	fmt.Fprintf(&b, "Platform    : %s\n", red.Platform)
	fmt.Fprintf(&b, "Vendor      : %s\n", vendorHeaderLine(red.Vendor, red.RenderedVendor))
	fmt.Fprintf(&b, "Protocol    : %s\n", strings.ToUpper(string(red.Protocol)))
	fmt.Fprintf(&b, "Issue       : %s [%s]\n", red.IssueTitle, red.IssueID)
	fmt.Fprintf(&b, "Ruleset     : %s\n", red.RulesetVersion)
	fmt.Fprintf(&b, "Collected   : %s\n", red.CollectedAt.Format("2006-01-02T15:04:05Z07:00"))
	b.WriteString("\n")

	b.WriteString("ANALYSIS\n--------\n")
	if res.Matched() {
		for _, f := range res.Findings {
			fmt.Fprintf(&b, "[%s] %s\n", strings.ToUpper(string(f.Confidence)), f.Verdict)
			fmt.Fprintf(&b, "  cause      : %s\n", f.Cause)
			fmt.Fprintf(&b, "  remediation: %s\n", f.Remediation)
			if f.Evidence.Line != "" {
				fmt.Fprintf(&b, "  evidence   : %q (from `%s`)\n", f.Evidence.Line, f.Evidence.Command)
			}
			b.WriteString("\n")
		}
	} else {
		fmt.Fprintf(&b, "%s\n\n", res.Unmatched)
	}

	b.WriteString("CAPTURED OUTPUT (redacted)\n--------------------------\n")
	for _, cc := range red.Commands {
		fmt.Fprintf(&b, "$ %s   [%s]\n", cc.Command, cc.Timestamp.Format("2006-01-02T15:04:05Z07:00"))
		if cc.Purpose != "" {
			fmt.Fprintf(&b, "# %s\n", cc.Purpose)
		}
		if cc.Err != "" {
			fmt.Fprintf(&b, "!! command error: %s\n", cc.Err)
		} else if strings.TrimSpace(cc.Output) == "" {
			b.WriteString("(no output)\n")
		} else {
			b.WriteString(cc.Output)
			if !strings.HasSuffix(cc.Output, "\n") {
				b.WriteString("\n")
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}
