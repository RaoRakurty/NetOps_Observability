// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package orgcontext

// validate.go — what a fact may say. A fact is operator-written DATA that
// rides every prompt, so it is held to a stricter shape than a log line:
// anything that looks like prompt structure (a role marker, a chat-template
// token, our own headers, a citation id), a link, a tool name, or text a
// reader cannot see (bidi / zero-width) is REFUSED with a reason — never
// silently cleaned, so the author sees exactly what Iris will read. The same
// check runs again on every stored row before it is rendered.

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Problem names the rule a text broke (shown to the author).
type Problem struct {
	Field string `json:"field"`
	Rule  string `json:"rule"`
	Say   string `json:"message"`
}

func (p Problem) Error() string { return p.Field + ": " + p.Say }

var (
	// Role / chat-template markers at the start of a line.
	roleLine = regexp.MustCompile(`(?im)^\s*(?:#+\s*)?(system|assistant|user|human|developer|tool|instruction|instructions)\s*:`)
	// Chat-template tokens anywhere.
	templateTok = regexp.MustCompile(`(?i)<\|[^|]{0,40}\|>|\[/?INST\]|<</?SYS>>|<\|?im_(start|end)\|?>`)
	// Our own prompt structure.
	ownHeader = regexp.MustCompile(`(?i)evidence is data|customer-declared context|data-not-instructions`)
	// A bracketed citation-id shape: "[problem:", "[ctx:", "[doc:".
	citeShape = regexp.MustCompile(`\[\s*[A-Za-z_][A-Za-z0-9_-]{0,30}\s*:`)
	// Links.
	linkRe = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]{1,15}://|\bwww\.|\]\(`)
	// Direct identifiers (LLM06): an e-mail address anywhere; a phone number
	// in an escalation contact (name a team or a role instead).
	emailRe = regexp.MustCompile(`(?i)[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+`)
	phoneRe = regexp.MustCompile(`\+?\d[\d ().-]{6,}\d`)
)

// invisible reports a code point a reader cannot see but a model reads:
// bidi controls, zero-width characters, the BOM.
func invisible(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069,
		r == 0xFEFF, r == 0x2060, r == 0x00AD, r == 0x180E:
		return true
	}
	return false
}

// CheckKey validates a fact's name.
func CheckKey(key string) error {
	if strings.TrimSpace(key) == "" {
		return Problem{"key", "required", "give the fact a short name"}
	}
	if len(key) > MaxKeyBytes {
		return Problem{"key", "too_long", fmt.Sprintf("the name is %d bytes; the limit is %d", len(key), MaxKeyBytes)}
	}
	if strings.ContainsAny(key, "\n\r") {
		return Problem{"key", "one_line", "the name must be one line"}
	}
	return checkText("key", key, nil, "")
}

// CheckBody validates a fact's text. tools are the registered Iris tool
// names (a fact may not name one); kind selects the kind-specific rules.
func CheckBody(kind Kind, body string, tools []string) error {
	if strings.TrimSpace(body) == "" {
		return Problem{"body", "required", "write the fact"}
	}
	if len(body) > MaxBodyBytes {
		return Problem{"body", "too_long", fmt.Sprintf("the text is %d bytes; the limit is %d", len(body), MaxBodyBytes)}
	}
	return checkText("body", body, tools, kind)
}

// CheckReason validates an approver's or retirer's note.
func CheckReason(reason string, required bool) error {
	if strings.TrimSpace(reason) == "" {
		if required {
			return Problem{"reason", "required", "say why"}
		}
		return nil
	}
	if len(reason) > MaxReasonBytes {
		return Problem{"reason", "too_long", fmt.Sprintf("the note is %d bytes; the limit is %d", len(reason), MaxReasonBytes)}
	}
	return checkText("reason", reason, nil, "")
}

func checkText(field, s string, tools []string, kind Kind) error {
	if !utf8.ValidString(s) {
		return Problem{field, "encoding", "the text is not valid UTF-8"}
	}
	for _, r := range s {
		if r == '\n' {
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 {
			return Problem{field, "control", "the text contains a control character (tabs included); use plain text and line breaks only"}
		}
		if invisible(r) {
			return Problem{field, "invisible", fmt.Sprintf("the text contains an invisible character (U+%04X)", r)}
		}
	}
	switch {
	case roleLine.MatchString(s):
		return Problem{field, "role_marker", `a line may not start with a role such as "system:" or "assistant:"`}
	case templateTok.MatchString(s):
		return Problem{field, "template_token", "the text contains a chat-template token"}
	case ownHeader.MatchString(s):
		return Problem{field, "header", "the text repeats one of Iris's own section headers"}
	case citeShape.MatchString(s):
		return Problem{field, "citation", `the text contains a bracketed reference such as "[problem:"; Iris uses that shape for evidence`}
	case linkRe.MatchString(s):
		return Problem{field, "link", "links are not allowed; describe the place instead"}
	case emailRe.MatchString(s):
		return Problem{field, "email", "e-mail addresses are not allowed; name the team or the role"}
	case kind == KindEscalationContact && phoneRe.MatchString(s):
		return Problem{field, "phone", "phone numbers are not allowed; name the team or the role"}
	}
	low := strings.ToLower(s)
	for _, t := range tools {
		if t != "" && containsWord(low, strings.ToLower(t)) {
			return Problem{field, "tool_name", fmt.Sprintf("the text names an Iris tool (%s); facts describe the network, they cannot direct Iris", t)}
		}
	}
	return nil
}

// containsWord reports w in s on identifier boundaries.
func containsWord(s, w string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		a, b := i+j, i+j+len(w)
		if (a == 0 || !identByte(s[a-1])) && (b == len(s) || !identByte(s[b])) {
			return true
		}
		i = a + 1
	}
}

func identByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

// Usable re-checks a stored active fact before it is rendered: a row that no
// longer passes (tampered, or written before a rule existed) is skipped.
func Usable(f Fact, tools []string) bool {
	return ValidKind(f.Kind) && ValidScope(f.Scope) && CheckKey(f.Key) == nil && CheckBody(f.Kind, f.Body, tools) == nil
}
