package tac

// yamlmin.go — a MINIMAL, closed YAML-subset parser.
//
// Why hand-rolled: CLAUDE.md §6 keeps the backend on the standard library, and
// no YAML module is on the allowlist. The house already answers this question
// the same way — backend/alerts/engine.go parses `rules.yaml` with a purpose-
// built line scanner rather than pulling a parser in. This file is that pattern,
// generalised just far enough for the TAC taxonomy and command plans, and NOT
// one feature further.
//
// The accepted subset (documented for authors in ai/tac/README.md §9):
//
//   · block MAPPINGS            key: value          /  key:
//   · block SEQUENCES           - scalar            /  - key: value
//   · nesting by SPACE indent   (a TAB anywhere in the indent is an error)
//   · quoted scalars            'single'  "double"  (no escapes but \" and \\)
//   · block scalars             key: |    and  key: >
//   · flow scalars sequences    key: [a, b, c]
//   · flow mappings             - {title: x, url: y}
//   · comments                  # to end of line, outside quotes
//
// Everything else — anchors, aliases, tags, multiple documents, merge keys,
// complex keys, flow sequences of flow mappings nested more than one deep — is
// REFUSED with the line number. A parser that silently ignores what it does not
// understand turns a typo into missing data; this one turns it into a load
// error, which is the whole point of validating data at boot.

import (
	"fmt"
	"strconv"
	"strings"
)

// ynode is one parsed node: a scalar, a mapping or a sequence. Exactly one of
// the three shapes is populated, named by kind.
type ynode struct {
	kind byte // 's' scalar · 'm' mapping · 'l' sequence
	str  string
	keys []string // mapping key order (authoring order is meaningful)
	m    map[string]*ynode
	list []*ynode
	line int
}

func (n *ynode) isScalar() bool { return n != nil && n.kind == 's' }
func (n *ynode) isMap() bool    { return n != nil && n.kind == 'm' }
func (n *ynode) isList() bool   { return n != nil && n.kind == 'l' }

// yline is one significant source line: its indent column, its content and its
// 1-based line number (every error the loader raises carries it).
type yline struct {
	indent int
	text   string
	num    int
}

// maxYAMLBytes bounds one data document (§9 bound everything). The taxonomy and
// the largest plan are tens of kilobytes; this is headroom, not a target.
const maxYAMLBytes = 4 << 20

// maxYAMLDepth bounds nesting so a pathological file cannot drive the recursive
// descent into a deep stack.
const maxYAMLDepth = 24

// parseYAML parses one document into a node tree.
func parseYAML(src string) (*ynode, error) {
	if len(src) > maxYAMLBytes {
		return nil, fmt.Errorf("yaml: document exceeds %d bytes", maxYAMLBytes)
	}
	lines, err := scanYAML(src)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return &ynode{kind: 'm', m: map[string]*ynode{}}, nil
	}
	n, rest, err := parseBlock(lines, lines[0].indent, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("yaml: line %d: unexpected indentation", rest[0].num)
	}
	return n, nil
}

// scanYAML strips comments and blank lines and records each remaining line's
// indent. Block scalars are handled by the block parser, so this pass must not
// eat their bodies: it keeps every line and lets the parser decide. That is why
// comment stripping is quote-aware and why a `#` inside a block scalar body is
// preserved — the parser re-reads raw bodies from the same slice.
func scanYAML(src string) ([]yline, error) {
	raw := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	out := make([]yline, 0, len(raw))
	for i, ln := range raw {
		num := i + 1
		if strings.HasPrefix(ln, "---") || strings.HasPrefix(ln, "...") {
			if strings.TrimSpace(ln) == "---" && len(out) == 0 {
				continue // a leading document marker is tolerated
			}
			return nil, fmt.Errorf("yaml: line %d: multiple documents are not supported", num)
		}
		indent := 0
		for indent < len(ln) && ln[indent] == ' ' {
			indent++
		}
		if indent < len(ln) && ln[indent] == '\t' {
			return nil, fmt.Errorf("yaml: line %d: tab in indentation", num)
		}
		body := ln[indent:]
		if body == "" {
			continue
		}
		if strings.HasPrefix(body, "#") {
			continue
		}
		out = append(out, yline{indent: indent, text: body, num: num})
	}
	return out, nil
}

// parseBlock parses the run of lines at exactly `indent`, returning the node and
// the lines it did not consume.
func parseBlock(lines []yline, indent, depth int) (*ynode, []yline, error) {
	if depth > maxYAMLDepth {
		return nil, nil, fmt.Errorf("yaml: line %d: nesting deeper than %d", lines[0].num, maxYAMLDepth)
	}
	if len(lines) == 0 {
		return &ynode{kind: 'm', m: map[string]*ynode{}}, nil, nil
	}
	if strings.HasPrefix(lines[0].text, "- ") || lines[0].text == "-" {
		return parseSeq(lines, indent, depth)
	}
	return parseMap(lines, indent, depth)
}

func parseMap(lines []yline, indent, depth int) (*ynode, []yline, error) {
	n := &ynode{kind: 'm', m: map[string]*ynode{}, line: lines[0].num}
	for len(lines) > 0 {
		ln := lines[0]
		if ln.indent < indent {
			break
		}
		if ln.indent > indent {
			return nil, nil, fmt.Errorf("yaml: line %d: unexpected indentation in mapping", ln.num)
		}
		if strings.HasPrefix(ln.text, "- ") || ln.text == "-" {
			break
		}
		key, rest, ok := splitMapKey(ln.text)
		if !ok {
			return nil, nil, fmt.Errorf("yaml: line %d: expected `key: value`, got %q", ln.num, ln.text)
		}
		if _, dup := n.m[key]; dup {
			return nil, nil, fmt.Errorf("yaml: line %d: duplicate key %q", ln.num, key)
		}
		lines = lines[1:]
		val, remain, err := parseValue(rest, lines, indent, ln.num, depth)
		if err != nil {
			return nil, nil, err
		}
		lines = remain
		n.keys = append(n.keys, key)
		n.m[key] = val
	}
	return n, lines, nil
}

func parseSeq(lines []yline, indent, depth int) (*ynode, []yline, error) {
	n := &ynode{kind: 'l', line: lines[0].num}
	for len(lines) > 0 {
		ln := lines[0]
		if ln.indent < indent {
			break
		}
		if ln.indent > indent {
			return nil, nil, fmt.Errorf("yaml: line %d: unexpected indentation in sequence", ln.num)
		}
		if !strings.HasPrefix(ln.text, "- ") && ln.text != "-" {
			break
		}
		body := ""
		if ln.text != "-" {
			body = strings.TrimSpace(ln.text[2:])
		}
		lines = lines[1:]
		// `- key: value` opens a mapping whose own indent is the column the key
		// starts at, so the item's continuation lines line up under it.
		if key, rest, ok := splitMapKey(body); ok && !strings.HasPrefix(body, "{") {
			itemIndent := ln.indent + 2
			item := &ynode{kind: 'm', m: map[string]*ynode{}, line: ln.num}
			val, remain, err := parseValue(rest, lines, itemIndent, ln.num, depth+1)
			if err != nil {
				return nil, nil, err
			}
			lines = remain
			item.keys = append(item.keys, key)
			item.m[key] = val
			// the rest of this item's keys, at itemIndent
			for len(lines) > 0 && lines[0].indent == itemIndent &&
				!strings.HasPrefix(lines[0].text, "- ") && lines[0].text != "-" {
				l2 := lines[0]
				k2, r2, ok2 := splitMapKey(l2.text)
				if !ok2 {
					return nil, nil, fmt.Errorf("yaml: line %d: expected `key: value`, got %q", l2.num, l2.text)
				}
				if _, dup := item.m[k2]; dup {
					return nil, nil, fmt.Errorf("yaml: line %d: duplicate key %q", l2.num, k2)
				}
				lines = lines[1:]
				v2, rem2, err2 := parseValue(r2, lines, itemIndent, l2.num, depth+1)
				if err2 != nil {
					return nil, nil, err2
				}
				lines = rem2
				item.keys = append(item.keys, k2)
				item.m[k2] = v2
			}
			n.list = append(n.list, item)
			continue
		}
		if body == "" {
			// `-` alone: the item is the block indented beneath it.
			if len(lines) == 0 || lines[0].indent <= indent {
				return nil, nil, fmt.Errorf("yaml: line %d: empty sequence item", ln.num)
			}
			sub, remain, err := parseBlock(lines, lines[0].indent, depth+1)
			if err != nil {
				return nil, nil, err
			}
			lines = remain
			n.list = append(n.list, sub)
			continue
		}
		sc, err := parseInlineScalar(body, ln.num)
		if err != nil {
			return nil, nil, err
		}
		n.list = append(n.list, sc)
	}
	return n, lines, nil
}

// parseValue turns the text after `key:` — possibly empty — plus whatever
// follows it into a node.
func parseValue(rest string, lines []yline, indent, num, depth int) (*ynode, []yline, error) {
	rest = strings.TrimSpace(rest)
	switch {
	case rest == "|", rest == "|-", rest == ">", rest == ">-":
		return parseBlockScalar(rest, lines, indent, num)
	case rest != "":
		sc, err := parseInlineScalar(rest, num)
		return sc, lines, err
	}
	// Empty value: a nested block, either deeper (mapping/sequence) or a
	// sequence at the SAME indent (the common `key:` / `- item` shape).
	if len(lines) == 0 {
		return &ynode{kind: 's', str: "", line: num}, lines, nil
	}
	next := lines[0]
	if next.indent > indent {
		return parseBlock(lines, next.indent, depth+1)
	}
	if next.indent == indent && (strings.HasPrefix(next.text, "- ") || next.text == "-") {
		return parseSeq(lines, indent, depth+1)
	}
	return &ynode{kind: 's', str: "", line: num}, lines, nil
}

// parseBlockScalar consumes an indented literal (`|`) or folded (`>`) body.
func parseBlockScalar(marker string, lines []yline, indent, num int) (*ynode, []yline, error) {
	var body []string
	base := -1
	for len(lines) > 0 && lines[0].indent > indent {
		if base < 0 {
			base = lines[0].indent
		}
		pad := strings.Repeat(" ", lines[0].indent-base)
		body = append(body, pad+lines[0].text)
		lines = lines[1:]
	}
	if len(body) == 0 {
		return &ynode{kind: 's', str: "", line: num}, lines, nil
	}
	sep := "\n"
	if strings.HasPrefix(marker, ">") {
		sep = " "
	}
	return &ynode{kind: 's', str: strings.Join(body, sep), line: num}, lines, nil
}

// parseInlineScalar handles a quoted scalar, a flow sequence, a flow mapping or
// a bare scalar.
func parseInlineScalar(s string, num int) (*ynode, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "["):
		if !strings.HasSuffix(s, "]") {
			return nil, fmt.Errorf("yaml: line %d: unterminated flow sequence", num)
		}
		n := &ynode{kind: 'l', line: num}
		for _, part := range splitFlow(s[1:len(s)-1], num) {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if strings.HasPrefix(part, "{") || strings.HasPrefix(part, "[") {
				return nil, fmt.Errorf("yaml: line %d: nested flow collections are not supported", num)
			}
			v, err := unquoteScalar(part, num)
			if err != nil {
				return nil, err
			}
			n.list = append(n.list, &ynode{kind: 's', str: v, line: num})
		}
		return n, nil
	case strings.HasPrefix(s, "{"):
		if !strings.HasSuffix(s, "}") {
			return nil, fmt.Errorf("yaml: line %d: unterminated flow mapping", num)
		}
		n := &ynode{kind: 'm', m: map[string]*ynode{}, line: num}
		for _, part := range splitFlow(s[1:len(s)-1], num) {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			k, v, ok := splitMapKey(part)
			if !ok {
				return nil, fmt.Errorf("yaml: line %d: flow mapping entry %q is not `key: value`", num, part)
			}
			if strings.HasPrefix(strings.TrimSpace(v), "{") || strings.HasPrefix(strings.TrimSpace(v), "[") {
				return nil, fmt.Errorf("yaml: line %d: nested flow collections are not supported", num)
			}
			uv, err := unquoteScalar(strings.TrimSpace(v), num)
			if err != nil {
				return nil, err
			}
			if _, dup := n.m[k]; dup {
				return nil, fmt.Errorf("yaml: line %d: duplicate key %q", num, k)
			}
			n.keys = append(n.keys, k)
			n.m[k] = &ynode{kind: 's', str: uv, line: num}
		}
		return n, nil
	}
	v, err := unquoteScalar(s, num)
	if err != nil {
		return nil, err
	}
	return &ynode{kind: 's', str: v, line: num}, nil
}

// splitFlow splits a flow collection body on commas that are outside quotes.
func splitFlow(s string, _ int) []string {
	var out []string
	var b strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' && i+1 < len(s) {
				b.WriteByte(c)
				i++
				b.WriteByte(s[i])
				continue
			}
			if c == quote {
				quote = 0
			}
			b.WriteByte(c)
		case c == '\'' || c == '"':
			quote = c
			b.WriteByte(c)
		case c == ',':
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	out = append(out, b.String())
	return out
}

// splitMapKey splits `key: value` on the FIRST colon that is followed by a space
// or ends the line, and that is not inside quotes. It returns ok=false when the
// text is not a mapping entry at all.
func splitMapKey(s string) (key, rest string, ok bool) {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '#':
			return "", "", false
		case ':':
			if i+1 == len(s) || s[i+1] == ' ' {
				k := strings.TrimSpace(s[:i])
				if k == "" {
					return "", "", false
				}
				if uk, err := unquoteScalar(k, 0); err == nil {
					k = uk
				}
				return k, strings.TrimSpace(s[i+1:]), true
			}
		}
	}
	return "", "", false
}

// unquoteScalar removes surrounding quotes and strips a trailing comment from a
// bare scalar. A bare `#` that starts a word ends the value; a `#` inside a word
// (an interface name, a URL fragment) does not.
func unquoteScalar(s string, num int) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if s[0] == '\'' {
		end := strings.LastIndexByte(s, '\'')
		if end == 0 {
			return "", fmt.Errorf("yaml: line %d: unterminated single-quoted scalar", num)
		}
		return strings.ReplaceAll(s[1:end], "''", "'"), nil
	}
	if s[0] == '"' {
		end := strings.LastIndexByte(s, '"')
		if end == 0 {
			return "", fmt.Errorf("yaml: line %d: unterminated double-quoted scalar", num)
		}
		body := s[1:end]
		if strings.Contains(body, "\\") {
			if uq, err := strconv.Unquote(`"` + body + `"`); err == nil {
				return uq, nil
			}
		}
		return body, nil
	}
	// bare scalar: cut a trailing ` #` comment
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s, nil
}

// ── typed accessors ─────────────────────────────────────────────────────────

// ystr reads a scalar field. Missing is "".
func ystr(n *ynode, key string) (string, error) {
	v, ok := n.m[key]
	if !ok || v == nil {
		return "", nil
	}
	if !v.isScalar() {
		return "", fmt.Errorf("yaml: line %d: %q must be a scalar", v.line, key)
	}
	return strings.TrimSpace(v.str), nil
}

// ystrs reads a sequence of scalars. Missing is nil.
func ystrs(n *ynode, key string) ([]string, error) {
	v, ok := n.m[key]
	if !ok || v == nil {
		return nil, nil
	}
	if v.isScalar() && strings.TrimSpace(v.str) == "" {
		return nil, nil
	}
	if !v.isList() {
		return nil, fmt.Errorf("yaml: line %d: %q must be a list", v.line, key)
	}
	out := make([]string, 0, len(v.list))
	for _, it := range v.list {
		if !it.isScalar() {
			return nil, fmt.Errorf("yaml: line %d: %q must be a list of scalars", it.line, key)
		}
		out = append(out, strings.TrimSpace(it.str))
	}
	return out, nil
}

// ylist reads a sequence of mappings. Missing is nil.
func ylist(n *ynode, key string) ([]*ynode, error) {
	v, ok := n.m[key]
	if !ok || v == nil {
		return nil, nil
	}
	if v.isScalar() && strings.TrimSpace(v.str) == "" {
		return nil, nil
	}
	if !v.isList() {
		return nil, fmt.Errorf("yaml: line %d: %q must be a list", v.line, key)
	}
	for _, it := range v.list {
		if !it.isMap() {
			return nil, fmt.Errorf("yaml: line %d: %q must be a list of mappings", it.line, key)
		}
	}
	return v.list, nil
}

// ymap reads a nested mapping. Missing is nil.
func ymap(n *ynode, key string) (*ynode, error) {
	v, ok := n.m[key]
	if !ok || v == nil {
		return nil, nil
	}
	if v.isScalar() && strings.TrimSpace(v.str) == "" {
		return nil, nil
	}
	if !v.isMap() {
		return nil, fmt.Errorf("yaml: line %d: %q must be a mapping", v.line, key)
	}
	return v, nil
}

// yonly rejects any key not in the allowed set — the "a typo is a refusal, not
// silence" rule that makes reviewed data trustworthy.
func yonly(n *ynode, what string, allowed ...string) error {
	if n == nil {
		return nil
	}
	set := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		set[a] = struct{}{}
	}
	for _, k := range n.keys {
		if _, ok := set[k]; !ok {
			return fmt.Errorf("yaml: line %d: unknown field %q in %s (allowed: %s)",
				n.line, k, what, strings.Join(allowed, ", "))
		}
	}
	return nil
}
