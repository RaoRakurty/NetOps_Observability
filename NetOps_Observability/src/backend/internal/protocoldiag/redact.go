package protocoldiag

import (
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
}

type redactRule struct {
	re   *regexp.Regexp
	repl string
}

// newRedactor builds the default redaction pass. The patterns target the secrets
// that realistically appear in `show run`-adjacent and neighbor output: local
// user passwords, enable secrets, SNMP communities, routing/auth keys (OSPF/ISIS
// message-digest and authentication keys, BGP TCP-AO/MD5 passwords), IPsec
// pre-shared keys, and PEM private-key blocks. It is conservative — it redacts
// the value, never the whole line — and fail-safe: an unmatched line is passed
// through unchanged (redaction never fabricates or drops evidence).
func newRedactor() *redactor {
	rule := func(pat, repl string) redactRule {
		return redactRule{re: regexp.MustCompile(pat), repl: repl}
	}
	return &redactor{rules: []redactRule{
		// `username X password [enc] <secret>` / `... secret <secret>` — redact the secret.
		rule(`(?i)((?:username\s+\S+\s+)?(?:password|secret)\s+(?:\d+\s+)?)(\S+)`, "${1}"+redactionMark),
		// `enable secret 5 <hash>` / `enable password <secret>`.
		rule(`(?i)(enable\s+(?:secret|password)\s+(?:\d+\s+)?)(\S+)`, "${1}"+redactionMark),
		// SNMP community string.
		rule(`(?i)(snmp-server\s+community\s+)(\S+)`, "${1}"+redactionMark),
		// OSPF/IS-IS/generic keychain: `... md5 <secret>`, `authentication-key <secret>`,
		// `key-string <secret>`, `message-digest-key N md5 <secret>`.
		rule(`(?i)((?:md5|authentication-key|key-string|password)\s+(?:\d+\s+)?)(\S+)`, "${1}"+redactionMark),
		// BGP neighbor password: `neighbor <x> password <secret>` handled by the
		// password rule above; TCP-AO keychain name is not a secret, left intact.
		// IPsec / IKE pre-shared keys: `pre-shared-key <secret>`,
		// `crypto isakmp key <secret> address …`, `keyring … key <secret>`.
		rule(`(?i)(pre-shared-key\s+(?:\S+\s+)?(?:key\s+)?)(\S+)`, "${1}"+redactionMark),
		rule(`(?i)((?:isakmp|keyring)\s+key\s+(?:\d+\s+)?)(\S+)`, "${1}"+redactionMark),
		// A PEM private key line/body.
		rule(`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`, redactionMark),
	}}
}

// redactLine applies every rule to one line.
func (r *redactor) redactLine(line string) string {
	for _, rule := range r.rules {
		line = rule.re.ReplaceAllString(line, rule.repl)
	}
	return line
}

// redactText applies the redaction pass to a multi-line blob.
func (r *redactor) redactText(text string) string {
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	for i, ln := range lines {
		lines[i] = r.redactLine(ln)
	}
	return strings.Join(lines, "\n")
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

// TACExport assembles a redacted, shareable text blob from a Collection and its
// AnalyzeResult: a header (device / vendor / protocol / issue / ruleset / time),
// the analyze verdict(s) with evidence, then every captured command with its
// REDACTED output and timestamp. It is the explicit, auditable "hand this to TAC"
// action (§8) — it runs the redaction pass itself, so a caller cannot forget it.
//
// The tenant id is deliberately NOT written into the export: the blob is meant to
// leave the operator's hands (to a vendor TAC or a peer), and the org identifier
// is not TAC's business. Device hostname/id (operational, not secret) are kept.
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
	fmt.Fprintf(&b, "Vendor      : %s (dialect: %s)\n", DisplayVendor(red.Vendor), DisplayVendor(red.RenderedVendor))
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
