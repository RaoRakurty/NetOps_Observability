// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devname

import (
	"net"
	"strings"
)

// Replacer rewrites device ids to display names inside OPERATOR TEXT — an RCA
// document, a ticket body, an Iris answer — at the moment that text leaves the
// server. Machine fields (ids in JSON, links, hashes) are never passed through
// it: the id stays the key everywhere, only the words a person reads change.
//
// A token is replaced only when it is EXACTLY a known id, bounded on both sides
// by a character that cannot be part of an id, and not preceded by a URL/query
// character — so "#/devices/<id>" and "?device=<id>" keep working links. An
// interface entity keeps its colon form ("cedge-81-dde8d64d:Gi2" reads
// "cEDGE-81:Gi2", as the UI shows it). An id that is an IP address is never
// replaced: an address in prose is a fact, not a name.
//
// The names map decides the tenant scope: build it from the devices the reader
// may see (§3a) — a Replacer never looks anything up itself. A nil Replacer is
// valid and changes nothing.
type Replacer struct {
	names map[string]string
}

// NewReplacer keeps the usable entries of an id → name map (see Names). It
// returns nil when nothing could ever be replaced.
func NewReplacer(names map[string]string) *Replacer {
	keep := make(map[string]string, len(names))
	for id, n := range names {
		id, n = strings.TrimSpace(id), strings.TrimSpace(n)
		if id == "" || n == "" || id == n || net.ParseIP(id) != nil || !isIDToken(id) {
			continue
		}
		keep[id] = n
	}
	if len(keep) == 0 {
		return nil
	}
	return &Replacer{names: keep}
}

// idByte: the characters a device id is made of (sanitized sysName, '-',
// address hash; controller ids "ctl-vmanage-…").
func idByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
}

func isIDToken(s string) bool {
	for i := 0; i < len(s); i++ {
		if !idByte(s[i]) {
			return false
		}
	}
	return true
}

// urlByte: a character that, directly before a token, means the token is part
// of a link or query (path segment, parameter value, fragment) — left alone.
func urlByte(c byte) bool {
	switch c {
	case '/', '=', '?', '#', '&', '%', '@', '\\':
		return true
	}
	return false
}

// Text returns s with every bounded known id replaced by its name.
func (r *Replacer) Text(s string) string {
	if r == nil || s == "" {
		return s
	}
	var b strings.Builder
	last := 0
	replaced := false
	for i := 0; i < len(s); {
		if !idByte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && idByte(s[j]) {
			j++
		}
		end := j
		// Trailing punctuation is not part of an id (an id ends in its hash): a
		// sentence's full stop, the '-' of an "a->b" path arrow.
		for end > i && (s[end-1] == '.' || s[end-1] == '-' || s[end-1] == '_') {
			end--
		}
		if name, ok := r.names[s[i:end]]; ok && (i == 0 || !urlByte(s[i-1])) {
			if !replaced {
				b.Grow(len(s))
				replaced = true
			}
			b.WriteString(s[last:i])
			b.WriteString(name)
			last = end
		}
		i = j
	}
	if !replaced {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// All maps Text over a slice, returning a new slice (nil stays nil).
func (r *Replacer) All(in []string) []string {
	if r == nil || in == nil {
		return in
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = r.Text(s)
	}
	return out
}

// HTML rewrites only the TEXT of a document our own html/template produced:
// tags (and so every attribute — ids, hrefs, data-*), comments, and the bodies
// of <style>/<script> pass through byte for byte. html/template escapes '<' and
// '>' inside attribute values, so a tag always ends at the next '>'. Text nodes
// are replaced as plain text; an id contains no '&', so entities are unaffected.
// Truncated markup is copied through from the point it stops making sense.
func (r *Replacer) HTML(doc []byte) []byte {
	if r == nil || len(doc) == 0 {
		return doc
	}
	s := string(doc)
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		lt := strings.IndexByte(s[i:], '<')
		if lt < 0 {
			b.WriteString(r.Text(s[i:]))
			break
		}
		b.WriteString(r.Text(s[i : i+lt]))
		i += lt
		if strings.HasPrefix(s[i:], "<!--") {
			end := strings.Index(s[i:], "-->")
			if end < 0 {
				b.WriteString(s[i:])
				break
			}
			b.WriteString(s[i : i+end+3])
			i += end + 3
			continue
		}
		gt := strings.IndexByte(s[i:], '>')
		if gt < 0 {
			b.WriteString(s[i:])
			break
		}
		tag := s[i : i+gt+1]
		b.WriteString(tag)
		i += gt + 1
		if name := rawTextElement(tag); name != "" {
			end := strings.Index(strings.ToLower(s[i:]), "</"+name)
			if end < 0 {
				b.WriteString(s[i:])
				break
			}
			b.WriteString(s[i : i+end])
			i += end
		}
	}
	return []byte(b.String())
}

// rawTextElement names an opening <style> or <script> tag, whose body is not
// text a person reads.
func rawTextElement(tag string) string {
	t := strings.ToLower(tag)
	for _, n := range []string{"style", "script"} {
		if strings.HasPrefix(t, "<"+n) && len(t) > len(n)+1 {
			switch t[len(n)+1] {
			case '>', ' ', '\t', '\n', '/':
				return n
			}
		}
	}
	return ""
}
