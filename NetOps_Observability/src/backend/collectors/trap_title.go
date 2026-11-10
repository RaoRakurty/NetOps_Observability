// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"fmt"
	"strings"
)

// trap_title.go — one sentence an operator can read instead of a MIB name
// (tracker 387, trap semantics).
//
// Titles are DATA, in the trap packs (`title_templates`, chosen per notification
// by `titles`), so the wording for a new vendor is a pack edit. A template is
// text with `{field}` placeholders and `[ ... ]` optional clauses:
//
//	BGP neighbour {peer}[ (AS {peer_as})] on {device} went from {prev_state} to {state}[ ({transition})]
//
//   - a `{field}` outside brackets is required: if it is missing the template is
//     skipped and the next one in the list is tried;
//   - a bracketed clause is dropped whole when any field inside it is missing;
//   - `{field=value}` is a guard: it renders nothing and holds only when the
//     field has exactly that value ({condition=raised} words a raise only).
//
// A missing value therefore removes words; it never becomes invented text. When
// no template can be filled, the receiver keeps its old summary and says so
// (title_basis=fallback), which a metric counts.

const maxTitleChars = 240

// compileTitleTemplate checks a template's syntax once, at pack load.
func compileTitleTemplate(t string) error {
	depth := 0
	inField := false
	for _, r := range t {
		switch r {
		case '[':
			if inField || depth > 0 {
				return fmt.Errorf("nested or misplaced '[' in %q", t)
			}
			depth++
		case ']':
			if inField || depth == 0 {
				return fmt.Errorf("unbalanced ']' in %q", t)
			}
			depth--
		case '{':
			if inField {
				return fmt.Errorf("nested '{' in %q", t)
			}
			inField = true
		case '}':
			if !inField {
				return fmt.Errorf("unbalanced '}' in %q", t)
			}
			inField = false
		}
	}
	if depth != 0 || inField {
		return fmt.Errorf("unterminated clause in %q", t)
	}
	if strings.TrimSpace(t) == "" {
		return fmt.Errorf("empty template")
	}
	return nil
}

// renderTitleTemplate fills one template from vals; ok=false when a required
// field is missing.
func renderTitleTemplate(t string, vals map[string]string) (string, bool) {
	var out, clause strings.Builder
	inClause, clauseOK := false, true
	for i := 0; i < len(t); {
		c := t[i]
		switch c {
		case '[':
			inClause, clauseOK = true, true
			clause.Reset()
			i++
		case ']':
			if clauseOK {
				out.WriteString(clause.String())
			}
			inClause = false
			i++
		case '{':
			end := strings.IndexByte(t[i:], '}')
			if end < 0 {
				return "", false
			}
			name := t[i+1 : i+end]
			i += end + 1
			if k, want, guard := strings.Cut(name, "="); guard {
				// A guard: renders nothing, and holds only when the field has
				// exactly this value ({condition=raised}).
				if vals[k] != want {
					if !inClause {
						return "", false
					}
					clauseOK = false
				}
				continue
			}
			v := vals[name]
			if v == "" {
				if !inClause {
					return "", false
				}
				clauseOK = false
				continue
			}
			if inClause {
				clause.WriteString(v)
			} else {
				out.WriteString(v)
			}
		default:
			if inClause {
				clause.WriteByte(c)
			} else {
				out.WriteByte(c)
			}
			i++
		}
	}
	s := strings.Join(strings.Fields(out.String()), " ")
	if s == "" {
		return "", false
	}
	return clampRunes(s, maxTitleChars), true
}

// titleValue makes a device-supplied value safe for a one-line title: control
// characters become spaces and the length is bounded. The UI escapes it again.
func titleValue(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	return clampRunes(strings.Join(strings.Fields(s), " "), 96)
}
