package main

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// graphql_parse.go — a real (small) GraphQL document parser for the subset
// /api/graphql serves. Replaces the substring dispatch that made F-72 possible.
//
// The audit measured the old behaviour directly:
//
//	{devices{id}}                  -> 218,133 bytes  (all 512 devices, ALL fields)
//	{devices(limit:1,first:1){id}} -> 218,133 bytes  (byte-identical: args ignored)
//	{bogus}                        ->      12 bytes  ({"data":{}} with HTTP 200)
//
// `contains(q, "devices")` cannot tell a selection from a substring, an
// argument from a comment, or a field name from a typo — so it returned
// everything, ignored every argument, and answered a nonsense query with
// success. This parser makes each of those a distinguishable, reportable case.
//
// Supported subset (anything else is a NAMED error, never silence):
//   - one `query` operation, anonymous or named, with optional variable
//     definitions;
//   - selection sets with aliases, field arguments and nested selections;
//   - scalar/enum/list/object argument values and $variable references.
//
// Not supported, and refused explicitly: mutations, subscriptions, fragments,
// directives, multiple operations in one document.

// gqlValueKind enumerates the argument value forms this subset accepts.
type gqlValueKind int

const (
	gqlNull gqlValueKind = iota
	gqlInt
	gqlFloat
	gqlString
	gqlBool
	gqlEnum
	gqlList
	gqlObject
	gqlVar
)

// gqlValue is one parsed argument value (or a reference to a variable).
type gqlValue struct {
	Kind  gqlValueKind
	Int   int64
	Float float64
	Str   string // string literal, enum name, or variable name (without '$')
	Bool  bool
	List  []gqlValue
	Obj   map[string]gqlValue
}

// gqlField is one selected field.
type gqlField struct {
	Alias string // response key (== Name when no alias was given)
	Name  string
	Args  map[string]gqlValue
	Sel   []gqlField
}

// gqlOperation is the single query operation a document may contain.
type gqlOperation struct {
	Name     string
	VarNames []string // declared variable names, in declaration order
	Sel      []gqlField
}

// ---- lexer ------------------------------------------------------------------

type gqlTokenKind int

const (
	tokEOF gqlTokenKind = iota
	tokName
	tokInt
	tokFloat
	tokString
	tokPunct
)

type gqlToken struct {
	Kind gqlTokenKind
	Text string
	Pos  int
}

type gqlLexer struct {
	src string
	pos int
}

func isNameStart(r rune) bool { return r == '_' || unicode.IsLetter(r) }
func isNameCont(r rune) bool  { return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) }

// next returns the next token. Commas are insignificant in GraphQL and are
// skipped like whitespace; `#` runs to end of line.
func (l *gqlLexer) next() (gqlToken, error) {
	for l.pos < len(l.src) {
		r, w := utf8.DecodeRuneInString(l.src[l.pos:])
		switch {
		case r == utf8.RuneError && w == 1:
			return gqlToken{}, fmt.Errorf("invalid UTF-8 at offset %d", l.pos)
		case unicode.IsSpace(r) || r == ',':
			l.pos += w
		case r == '#':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		default:
			goto scan
		}
	}
scan:
	if l.pos >= len(l.src) {
		return gqlToken{Kind: tokEOF, Pos: l.pos}, nil
	}
	start := l.pos
	r, w := utf8.DecodeRuneInString(l.src[l.pos:])
	switch {
	case isNameStart(r):
		l.pos += w
		for l.pos < len(l.src) {
			r2, w2 := utf8.DecodeRuneInString(l.src[l.pos:])
			if !isNameCont(r2) {
				break
			}
			l.pos += w2
		}
		return gqlToken{Kind: tokName, Text: l.src[start:l.pos], Pos: start}, nil
	case r == '-' || unicode.IsDigit(r):
		l.pos += w
		float := false
		for l.pos < len(l.src) {
			c := l.src[l.pos]
			if c >= '0' && c <= '9' {
				l.pos++
				continue
			}
			if c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-' {
				float = true
				l.pos++
				continue
			}
			break
		}
		k := tokInt
		if float {
			k = tokFloat
		}
		return gqlToken{Kind: k, Text: l.src[start:l.pos], Pos: start}, nil
	case r == '"':
		return l.lexString()
	case strings.ContainsRune("{}()[]:$!=@|&.", r):
		l.pos += w
		return gqlToken{Kind: tokPunct, Text: l.src[start:l.pos], Pos: start}, nil
	}
	return gqlToken{}, fmt.Errorf("unexpected character %q at offset %d", string(r), start)
}

// lexString reads a single-quoted-string token, honouring the escapes the spec
// defines. Block strings (""") are not part of the supported subset.
func (l *gqlLexer) lexString() (gqlToken, error) {
	start := l.pos
	l.pos++ // opening quote
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch c {
		case '"':
			l.pos++
			return gqlToken{Kind: tokString, Text: b.String(), Pos: start}, nil
		case '\n':
			return gqlToken{}, fmt.Errorf("unterminated string at offset %d", start)
		case '\\':
			l.pos++
			if l.pos >= len(l.src) {
				return gqlToken{}, fmt.Errorf("unterminated escape at offset %d", start)
			}
			switch l.src[l.pos] {
			case '"', '\\', '/':
				b.WriteByte(l.src[l.pos])
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'u':
				if l.pos+4 >= len(l.src) {
					return gqlToken{}, fmt.Errorf("truncated \\u escape at offset %d", l.pos)
				}
				// 4 hex digits → at most 0xFFFF, so the rune conversion cannot
				// overflow; the explicit bound keeps that true if the width
				// ever changes, and refuses a surrogate half rather than
				// silently writing U+FFFD.
				n, err := strconv.ParseUint(l.src[l.pos+1:l.pos+5], 16, 32)
				if err != nil || n > 0xFFFF || (n >= 0xD800 && n <= 0xDFFF) {
					return gqlToken{}, fmt.Errorf("bad \\u escape at offset %d", l.pos)
				}
				b.WriteRune(rune(n)) //nolint:gosec // bounded to 0..0xFFFF above
				l.pos += 4
			default:
				return gqlToken{}, fmt.Errorf("unknown escape \\%c at offset %d", l.src[l.pos], l.pos)
			}
			l.pos++
		default:
			b.WriteByte(c)
			l.pos++
		}
	}
	return gqlToken{}, fmt.Errorf("unterminated string at offset %d", start)
}

// ---- parser -----------------------------------------------------------------

// gqlMaxDepth bounds selection nesting. An unbounded parser on an
// unauthenticated-adjacent endpoint is a stack-exhaustion DoS (§9: all queues
// bounded); the served schema is two levels deep, so 8 is generous.
const gqlMaxDepth = 8

// gqlMaxFields bounds the total number of selected fields in one document, so a
// pathological query cannot make the server allocate without limit.
const gqlMaxFields = 256

type gqlParser struct {
	lex    *gqlLexer
	tok    gqlToken
	fields int
}

func (p *gqlParser) advance() error {
	t, err := p.lex.next()
	if err != nil {
		return err
	}
	p.tok = t
	return nil
}

func (p *gqlParser) expectPunct(s string) error {
	if p.tok.Kind != tokPunct || p.tok.Text != s {
		return fmt.Errorf("expected %q at offset %d, found %q", s, p.tok.Pos, p.tok.Text)
	}
	return p.advance()
}

// parseGraphQL parses a document into its single query operation.
func parseGraphQL(src string) (*gqlOperation, error) {
	if strings.TrimSpace(src) == "" {
		return nil, fmt.Errorf("query is required")
	}
	p := &gqlParser{lex: &gqlLexer{src: src}}
	if err := p.advance(); err != nil {
		return nil, err
	}
	op := &gqlOperation{}
	// Optional operation type + name + variable definitions.
	if p.tok.Kind == tokName {
		switch p.tok.Text {
		case "query":
			if err := p.advance(); err != nil {
				return nil, err
			}
			if p.tok.Kind == tokName {
				op.Name = p.tok.Text
				if err := p.advance(); err != nil {
					return nil, err
				}
			}
			if p.tok.Kind == tokPunct && p.tok.Text == "(" {
				names, err := p.parseVarDefs()
				if err != nil {
					return nil, err
				}
				op.VarNames = names
			}
		case "mutation", "subscription":
			return nil, fmt.Errorf("%s operations are not supported by this endpoint (read-only GraphQL over the REST resolvers)", p.tok.Text)
		case "fragment":
			return nil, fmt.Errorf("fragments are not supported by this endpoint")
		default:
			return nil, fmt.Errorf("expected `query` or a selection set at offset %d, found %q", p.tok.Pos, p.tok.Text)
		}
	}
	sel, err := p.parseSelectionSet(1)
	if err != nil {
		return nil, err
	}
	op.Sel = sel
	if p.tok.Kind != tokEOF {
		// A second operation would make "which one runs?" ambiguous, and
		// ambiguity is how the old dispatcher answered everything at once.
		return nil, fmt.Errorf("only one operation per request is supported (unexpected %q at offset %d)", p.tok.Text, p.tok.Pos)
	}
	return op, nil
}

func (p *gqlParser) parseVarDefs() ([]string, error) {
	if err := p.expectPunct("("); err != nil {
		return nil, err
	}
	var names []string
	for !(p.tok.Kind == tokPunct && p.tok.Text == ")") {
		if p.tok.Kind == tokEOF {
			return nil, fmt.Errorf("unterminated variable definitions")
		}
		if err := p.expectPunct("$"); err != nil {
			return nil, err
		}
		if p.tok.Kind != tokName {
			return nil, fmt.Errorf("expected a variable name at offset %d", p.tok.Pos)
		}
		names = append(names, p.tok.Text)
		if err := p.advance(); err != nil {
			return nil, err
		}
		if err := p.expectPunct(":"); err != nil {
			return nil, err
		}
		if err := p.skipType(); err != nil {
			return nil, err
		}
		if p.tok.Kind == tokPunct && p.tok.Text == "=" {
			if err := p.advance(); err != nil {
				return nil, err
			}
			if _, err := p.parseValue(); err != nil {
				return nil, err
			}
		}
	}
	return names, p.advance()
}

// skipType consumes a type reference. The subset does not type-check variables
// (the resolvers validate every value they use), so the shape is consumed and
// discarded rather than half-checked.
func (p *gqlParser) skipType() error {
	if p.tok.Kind == tokPunct && p.tok.Text == "[" {
		if err := p.advance(); err != nil {
			return err
		}
		if err := p.skipType(); err != nil {
			return err
		}
		if err := p.expectPunct("]"); err != nil {
			return err
		}
	} else {
		if p.tok.Kind != tokName {
			return fmt.Errorf("expected a type name at offset %d", p.tok.Pos)
		}
		if err := p.advance(); err != nil {
			return err
		}
	}
	if p.tok.Kind == tokPunct && p.tok.Text == "!" {
		return p.advance()
	}
	return nil
}

func (p *gqlParser) parseSelectionSet(depth int) ([]gqlField, error) {
	if depth > gqlMaxDepth {
		return nil, fmt.Errorf("selection nesting exceeds the maximum depth of %d", gqlMaxDepth)
	}
	if err := p.expectPunct("{"); err != nil {
		return nil, err
	}
	var out []gqlField
	for !(p.tok.Kind == tokPunct && p.tok.Text == "}") {
		if p.tok.Kind == tokEOF {
			return nil, fmt.Errorf("unterminated selection set")
		}
		if p.tok.Kind == tokPunct && p.tok.Text == "." {
			return nil, fmt.Errorf("fragment spreads are not supported by this endpoint")
		}
		if p.tok.Kind != tokName {
			return nil, fmt.Errorf("expected a field name at offset %d, found %q", p.tok.Pos, p.tok.Text)
		}
		p.fields++
		if p.fields > gqlMaxFields {
			return nil, fmt.Errorf("query selects more than %d fields", gqlMaxFields)
		}
		f := gqlField{Name: p.tok.Text, Alias: p.tok.Text}
		if err := p.advance(); err != nil {
			return nil, err
		}
		if p.tok.Kind == tokPunct && p.tok.Text == ":" { // alias:field
			f.Alias = f.Name
			if err := p.advance(); err != nil {
				return nil, err
			}
			if p.tok.Kind != tokName {
				return nil, fmt.Errorf("expected a field name after the alias at offset %d", p.tok.Pos)
			}
			f.Name = p.tok.Text
			if err := p.advance(); err != nil {
				return nil, err
			}
		}
		if p.tok.Kind == tokPunct && p.tok.Text == "(" {
			args, err := p.parseArgs()
			if err != nil {
				return nil, err
			}
			f.Args = args
		}
		if p.tok.Kind == tokPunct && p.tok.Text == "@" {
			return nil, fmt.Errorf("directives are not supported by this endpoint")
		}
		if p.tok.Kind == tokPunct && p.tok.Text == "{" {
			sub, err := p.parseSelectionSet(depth + 1)
			if err != nil {
				return nil, err
			}
			f.Sel = sub
		}
		out = append(out, f)
	}
	if err := p.advance(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("selection set must select at least one field")
	}
	return out, nil
}

func (p *gqlParser) parseArgs() (map[string]gqlValue, error) {
	if err := p.expectPunct("("); err != nil {
		return nil, err
	}
	args := map[string]gqlValue{}
	for !(p.tok.Kind == tokPunct && p.tok.Text == ")") {
		if p.tok.Kind == tokEOF {
			return nil, fmt.Errorf("unterminated argument list")
		}
		if p.tok.Kind != tokName {
			return nil, fmt.Errorf("expected an argument name at offset %d, found %q", p.tok.Pos, p.tok.Text)
		}
		name := p.tok.Text
		if _, dup := args[name]; dup {
			return nil, fmt.Errorf("argument %q given twice", name)
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
		if err := p.expectPunct(":"); err != nil {
			return nil, err
		}
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		args[name] = v
	}
	return args, p.advance()
}

func (p *gqlParser) parseValue() (gqlValue, error) {
	switch {
	case p.tok.Kind == tokInt:
		n, err := strconv.ParseInt(p.tok.Text, 10, 64)
		if err != nil {
			return gqlValue{}, fmt.Errorf("invalid integer %q at offset %d", p.tok.Text, p.tok.Pos)
		}
		return gqlValue{Kind: gqlInt, Int: n}, p.advance()
	case p.tok.Kind == tokFloat:
		f, err := strconv.ParseFloat(p.tok.Text, 64)
		if err != nil {
			return gqlValue{}, fmt.Errorf("invalid float %q at offset %d", p.tok.Text, p.tok.Pos)
		}
		return gqlValue{Kind: gqlFloat, Float: f}, p.advance()
	case p.tok.Kind == tokString:
		// The token text MUST be captured before advance(): Go does not order
		// the evaluation of `p.tok.Text` against the `p.advance()` call in the
		// same return statement, and reading it after the advance yields the
		// NEXT token's text. That produced `$a` parsing as variable "offset".
		lit := p.tok.Text
		return gqlValue{Kind: gqlString, Str: lit}, p.advance()
	case p.tok.Kind == tokName:
		name := p.tok.Text
		switch name {
		case "true", "false":
			return gqlValue{Kind: gqlBool, Bool: name == "true"}, p.advance()
		case "null":
			return gqlValue{Kind: gqlNull}, p.advance()
		}
		return gqlValue{Kind: gqlEnum, Str: name}, p.advance()
	case p.tok.Kind == tokPunct && p.tok.Text == "$":
		if err := p.advance(); err != nil {
			return gqlValue{}, err
		}
		if p.tok.Kind != tokName {
			return gqlValue{}, fmt.Errorf("expected a variable name after $ at offset %d", p.tok.Pos)
		}
		varName := p.tok.Text
		return gqlValue{Kind: gqlVar, Str: varName}, p.advance()
	case p.tok.Kind == tokPunct && p.tok.Text == "[":
		if err := p.advance(); err != nil {
			return gqlValue{}, err
		}
		var items []gqlValue
		for !(p.tok.Kind == tokPunct && p.tok.Text == "]") {
			if p.tok.Kind == tokEOF {
				return gqlValue{}, fmt.Errorf("unterminated list value")
			}
			v, err := p.parseValue()
			if err != nil {
				return gqlValue{}, err
			}
			items = append(items, v)
		}
		return gqlValue{Kind: gqlList, List: items}, p.advance()
	case p.tok.Kind == tokPunct && p.tok.Text == "{":
		if err := p.advance(); err != nil {
			return gqlValue{}, err
		}
		obj := map[string]gqlValue{}
		for !(p.tok.Kind == tokPunct && p.tok.Text == "}") {
			if p.tok.Kind != tokName {
				return gqlValue{}, fmt.Errorf("expected an object field name at offset %d", p.tok.Pos)
			}
			k := p.tok.Text
			if err := p.advance(); err != nil {
				return gqlValue{}, err
			}
			if err := p.expectPunct(":"); err != nil {
				return gqlValue{}, err
			}
			v, err := p.parseValue()
			if err != nil {
				return gqlValue{}, err
			}
			obj[k] = v
		}
		return gqlValue{Kind: gqlObject, Obj: obj}, p.advance()
	}
	return gqlValue{}, fmt.Errorf("unexpected value token %q at offset %d", p.tok.Text, p.tok.Pos)
}

// ---- argument coercion ------------------------------------------------------

// gqlIntArg resolves an Int argument, following a $variable when one was used.
// It rejects anything that is not an integer INSTEAD of substituting a default:
// the whole point of F-72 is that `(limit: 1)` used to change nothing at all,
// and a silently ignored bound is the same defect wearing a different hat.
func gqlIntArg(v gqlValue, vars map[string]any, name string) (int, error) {
	switch v.Kind {
	case gqlInt:
		return int(v.Int), nil
	case gqlVar:
		raw, ok := vars[v.Str]
		if !ok {
			return 0, fmt.Errorf("variable $%s is referenced by argument %q but was not provided", v.Str, name)
		}
		switch n := raw.(type) {
		case float64: // encoding/json decodes every number as float64
			if n != float64(int64(n)) {
				return 0, fmt.Errorf("argument %q must be an integer (got %v)", name, raw)
			}
			return int(n), nil
		case int:
			return n, nil
		}
		return 0, fmt.Errorf("argument %q must be an integer (variable $%s is %T)", name, v.Str, raw)
	}
	return 0, fmt.Errorf("argument %q must be an integer", name)
}
