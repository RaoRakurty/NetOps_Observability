package pipedebug

// redact.go — the debugger's redaction adapter (design §5).
//
// There is exactly ONE redaction implementation in this repository:
// internal/protocoldiag/redact.go, the pass the TAC bundle already runs
// (passwords, enable secrets, SNMP communities, routing/auth keys, IPsec
// pre-shared keys, PEM private-key blocks). This file does not re-implement any
// of it — it ADAPTS it to the two shapes the debugger holds evidence in (a
// line, and a decoded JSON object) and adds the one thing the debugger needs
// that a device capture does not: bearer-token/authorization stripping, because
// a debug session captures HTTP-shaped container logs, not just CLI output.
//
// Tenant ids are deliberately KEPT (design §5): support needs them to reason
// about isolation, and they are identifiers, not credentials.

import (
	"strings"

	"netops/backend/internal/protocoldiag"
)

// RedactionNote is stamped into every manifest so a bundle says which pass ran.
const RedactionNote = "internal/protocoldiag redactor (secrets, communities, auth keys, PEM private keys) + bearer/authorization stripping; tenant ids retained"

// bearerPrefixes are the case-insensitive markers after which the remainder of
// a token-looking word is replaced. Kept as a small explicit list rather than a
// regex zoo: each entry is a real shape seen in this stack's own logs.
var bearerPrefixes = []string{
	"authorization: bearer ",
	"authorization:bearer ",
	"authorization: basic ",
	"authorization:basic ",
	"bearer ",
	"x-api-key: ",
	"x-api-key:",
	"access_token=",
	"refresh_token=",
	"token=",
	"api_key=",
	"apikey=",
}

const mark = "[REDACTED]"

// RedactString runs one line through the shared device-output pass and then
// strips HTTP-style credentials.
func RedactString(s string) string {
	if s == "" {
		return ""
	}
	return stripBearer(protocoldiag.RedactOutput(s))
}

// stripBearer replaces the value that follows any known credential prefix,
// keeping the prefix so a reader still sees WHICH credential was present.
func stripBearer(s string) string {
	lower := strings.ToLower(s)
	for _, p := range bearerPrefixes {
		for idx := 0; ; {
			i := strings.Index(lower[idx:], p)
			if i < 0 {
				break
			}
			start := idx + i + len(p)
			end := start
			for end < len(s) && !isTokenBreak(s[end]) {
				end++
			}
			if end == start {
				idx = start
				continue
			}
			s = s[:start] + mark + s[end:]
			lower = strings.ToLower(s)
			idx = start + len(mark)
			if idx >= len(s) {
				break
			}
		}
	}
	return s
}

func isTokenBreak(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '"', '\'', ',', ';', '&', ')', '}', ']':
		return true
	}
	return false
}

// RedactFields runs the pass over a decoded JSON object's string leaves,
// recursing into nested maps and slices. Non-string leaves (numbers, bools) are
// passed through: a credential is never a float, and rewriting numbers would
// corrupt the evidence.
//
// The returned map is a fresh copy — the caller's input is never mutated, the
// same contract protocoldiag.Redact holds.
func RedactFields(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = redactValue(v)
	}
	return out
}

func redactValue(v any) any {
	switch t := v.(type) {
	case string:
		return RedactString(t)
	case map[string]any:
		return RedactFields(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = redactValue(e)
		}
		return out
	case []string:
		out := make([]string, len(t))
		for i, e := range t {
			out[i] = RedactString(e)
		}
		return out
	default:
		return v
	}
}
