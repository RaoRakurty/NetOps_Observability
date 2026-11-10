// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package lex

// split.go — several questions in one message (hybrid NLU plan A6). "What is
// going on right now? What should the NOC focus on first?" used to reach the
// grammar as ONE token stream, half understood. Split cuts it at sentence
// boundaries so each question is read on its own.

import (
	"regexp"
	"strings"
)

// MaxParts is the most questions one message is split into. A longer message
// is not split (it is read whole, as before): more than three questions in
// one breath is better asked one at a time.
const MaxParts = 3

// splitRe marks a boundary between two questions: a question mark or a
// semicolon, or a sentence-ending full stop / exclamation mark before the
// next word, or " and also " / ". then ".
var splitRe = regexp.MustCompile(`\?+\s*|;\s*|[.!]+\s+|\s+and also\s+|\s*,?\s+then\s+(?:show|list|tell|what|which|how|give)\b`)

// Split returns the questions in text, each trimmed, in order. A text with
// one question (or more than MaxParts) comes back as one part, unchanged.
// A full stop inside a name or a number ("10.0.0.1", "v1.2") is not a
// boundary: a boundary needs the following whitespace.
func Split(text string) []string {
	t := strings.TrimSpace(text)
	if t == "" {
		return nil
	}
	var parts []string
	last := 0
	for _, loc := range splitRe.FindAllStringIndex(t, -1) {
		seg := t[last:loc[0]]
		m := t[loc[0]:loc[1]]
		// " then show …": the verb belongs to the next question.
		if i := strings.Index(m, "then"); i >= 0 && strings.Contains(m, "then ") {
			verbAt := loc[0] + i + len("then")
			parts = appendPart(parts, seg)
			last = verbAt
			continue
		}
		if strings.HasPrefix(m, "?") {
			seg += "?"
		}
		parts = appendPart(parts, seg)
		last = loc[1]
	}
	parts = appendPart(parts, t[last:])
	if len(parts) <= 1 || len(parts) > MaxParts {
		return []string{t}
	}
	return parts
}

func appendPart(parts []string, s string) []string {
	s = strings.TrimRight(strings.TrimSpace(s), ".! ")
	if len(strings.Fields(s)) == 0 || strings.Trim(s, "?.!; ") == "" {
		return parts
	}
	return append(parts, s)
}
