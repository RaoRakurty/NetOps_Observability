// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chatops

// format.go — an Iris answer as chat text. The chat gets the answer's words,
// its suggested next steps and its citations as links INTO Correlix — never a
// dump of the evidence itself. Links are built only from relative UI paths on
// the connection's Correlix address; anything else is shown as a bare label.

import (
	"strings"
	"unicode/utf8"
)

// Answer is the platform-neutral answer the Asker returns.
type Answer struct {
	Title       string
	Text        string
	Bullets     []string // structured lines (incidents, focus) when Text is thin
	Next        []string // suggested next steps — nothing has been run
	Citations   []Citation
	Disclaimers []string
	Note        string // one small provider note
	// ConversationID is the Iris conversation this answer was recorded in, so
	// the next message in the same chat thread is a follow-up.
	ConversationID string
}

// Citation is one piece of evidence: its label and its relative UI path.
type Citation struct {
	Label string
	Href  string
}

// Limits keep a reply inside each platform's message size.
const (
	slackMaxChars = 3000
	teamsMaxChars = 6000
	maxCitations  = 5
	maxBullets    = 6
	maxNext       = 3
)

// Render formats a for platform p, linking citations under base.
func Render(p Platform, a Answer, base string) string {
	var b strings.Builder
	esc := func(s string) string { return escapeFor(p, s) }
	if t := strings.TrimSpace(a.Title); t != "" {
		b.WriteString(bold(p, esc(t)))
		b.WriteString("\n")
	}
	if t := strings.TrimSpace(a.Text); t != "" {
		b.WriteString(esc(t))
		b.WriteString("\n")
	}
	for i, l := range a.Bullets {
		if i == maxBullets {
			break
		}
		if l = strings.TrimSpace(l); l != "" {
			b.WriteString("• " + esc(l) + "\n")
		}
	}
	if len(a.Next) > 0 {
		b.WriteString("\n" + bold(p, "Suggested next steps") + " (nothing has been run):\n")
		for i, l := range a.Next {
			if i == maxNext {
				break
			}
			b.WriteString("• " + esc(strings.TrimSpace(l)) + "\n")
		}
	}
	if len(a.Citations) > 0 {
		b.WriteString("\n" + bold(p, "Evidence") + ":\n")
		for i, c := range a.Citations {
			if i == maxCitations {
				b.WriteString("• and " + itoa(len(a.Citations)-maxCitations) + " more in Correlix\n")
				break
			}
			b.WriteString("• " + link(p, base, c) + "\n")
		}
	}
	for i, d := range a.Disclaimers {
		if i == 2 {
			break
		}
		if d = strings.TrimSpace(d); d != "" {
			b.WriteString("\n" + italic(p, esc(d)))
		}
	}
	if n := strings.TrimSpace(a.Note); n != "" {
		b.WriteString("\n" + italic(p, esc(n)))
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		out = "Iris had nothing to say about that — try asking it another way."
	}
	return truncate(out, maxFor(p))
}

// Plain formats a short service message (link prompt, refusal) for p.
func Plain(p Platform, s string) string { return truncate(escapeFor(p, s), maxFor(p)) }

func maxFor(p Platform) int {
	if p == Teams {
		return teamsMaxChars
	}
	return slackMaxChars
}

// link renders a citation: a clickable link only for a relative UI path on a
// configured Correlix address; otherwise the label alone.
func link(p Platform, base string, c Citation) string {
	label := strings.TrimSpace(c.Label)
	if label == "" {
		label = "evidence"
	}
	href := strings.TrimSpace(c.Href)
	if base == "" || !strings.HasPrefix(href, "/") || strings.HasPrefix(href, "//") || strings.ContainsAny(href, " <>|()[]\r\n\t") {
		return escapeFor(p, label)
	}
	full := base + href
	if p == Slack {
		return "<" + full + "|" + strings.NewReplacer("|", "/", "<", "", ">", "", "&", "and").Replace(label) + ">"
	}
	return "[" + strings.NewReplacer("[", "(", "]", ")").Replace(label) + "](" + full + ")"
}

// escapeFor neutralises the platform's markup so answer text renders as text:
// Slack's control characters (&, <, >) and Teams markdown link syntax.
func escapeFor(p Platform, s string) string {
	if p == Slack {
		return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
	}
	return strings.NewReplacer("<", "&lt;", ">", "&gt;", "[", "\\[", "]", "\\]").Replace(s)
}

func bold(p Platform, s string) string {
	if p == Slack {
		return "*" + s + "*"
	}
	return "**" + s + "**"
}

func italic(p Platform, s string) string { return "_" + s + "_" }

func truncate(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max-1]) + "…"
}

func itoa(n int) string {
	if n <= 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}
