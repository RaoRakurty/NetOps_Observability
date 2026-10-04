// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package modelc

// guard.go — the model's reply is untrusted data (§3, LLM02). parseReply
// decodes it strictly; guard.check refuses what the validator cannot know is
// wrong: an entity id THIS question's resolution did not produce, a thing the
// question named that the query dropped, an incident the operator never
// pointed at, and a filter value the question never said.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/resolve"
	"netops/backend/internal/nlquery/validate"
)

// Closed repair codes for reply-shape problems (validation problems use the
// validator's own codes).
const (
	CodeNotJSON          = "reply_not_one_json_object"
	CodeBadEnvelope      = "reply_envelope_invalid"
	CodeASTNotDecodable  = "ast_not_decodable"
	CodeUnaccountedName  = "question_name_not_in_query"
	CodeNamedEntityDrop  = "named_entity_missing"
	CodeValueNotInQuery  = "filter_value_not_in_question"
	CodeIncidentNotGiven = "incident_not_in_question"
)

var (
	jsonFenceRe = regexp.MustCompile("(?s)^```(?:json)?\\s*(.*?)\\s*```$")
	uuidInText  = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	// A key that names a tenant or an organisation is an attempt to choose
	// scope; it is refused outright, never repaired.
	forbiddenKeyRe = regexp.MustCompile(`(?i)tenant|^org(?:_?id|anization|anisation)?$|customer`)
)

// parseReply decodes one reply. fatal is set for a reply that must end the
// fallback (a forbidden field, an honest "cannot", a name it could not match).
// view is the reply's optional layout suggestion (tracker 337 N-E1), RAW and
// unvalidated: it is never a reason to repair or refuse the query — a bad one
// is ignored, with a disclosure, by present.Select — so it is not decoded here.
func parseReply(reply string) (q *ast.AST, problems []validate.Error, fatal string, view json.RawMessage) {
	raw := strings.TrimSpace(reply)
	if m := jsonFenceRe.FindStringSubmatch(raw); m != nil {
		raw = m[1]
	}
	if i, j := strings.IndexByte(raw, '{'), strings.LastIndexByte(raw, '}'); i >= 0 && j > i {
		raw = raw[i : j+1]
	}
	var generic any
	if err := json.Unmarshal([]byte(raw), &generic); err != nil {
		return nil, []validate.Error{{Code: CodeNotJSON}}, "", nil
	}
	if hasForbiddenKey(generic, 0) {
		return nil, nil, RefuseForbiddenField, nil
	}
	var env struct {
		AST       json.RawMessage `json:"ast"`
		Unmatched []string        `json:"unmatched_names"`
		View      json.RawMessage `json:"view"`
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, []validate.Error{{Code: CodeBadEnvelope, Suggestions: []string{"ast", "unmatched_names", "view"}}}, "", nil
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, []validate.Error{{Code: CodeNotJSON}}, "", nil
	}
	for _, n := range env.Unmatched {
		if strings.TrimSpace(n) != "" {
			return nil, nil, RefuseUnresolvedName, nil
		}
	}
	if len(env.AST) == 0 || string(env.AST) == "null" {
		return nil, nil, RefuseModelDeclined, nil
	}
	a, err := ast.Decode(env.AST)
	if err != nil {
		p := validate.Error{Code: CodeASTNotDecodable}
		if f := unknownFieldRe.FindStringSubmatch(err.Error()); f != nil {
			p = validate.Error{Path: f[1], Code: validate.CodeUnknownField}
		}
		return nil, []validate.Error{p}, "", nil
	}
	return a, nil, "", env.View
}

var unknownFieldRe = regexp.MustCompile(`unknown field "([a-z_]{1,32})"`)

// hasForbiddenKey walks the reply's objects (depth-bounded) for a scope key.
func hasForbiddenKey(v any, depth int) bool {
	if depth > 12 {
		return true // deeper than any AST: refuse rather than walk further
	}
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if forbiddenKeyRe.MatchString(k) || hasForbiddenKey(child, depth+1) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if hasForbiddenKey(child, depth+1) {
				return true
			}
		}
	}
	return false
}

// guard holds what THIS question resolved to.
type guard struct {
	cat      *catalog.Catalog
	mentions []mention
	text     string   // the normalized question
	incident string   // the incident on screen
	idents   []string // identifier-like words the query must account for
}

// allRefs lists every entity reference in q with its path.
func allRefs(q *ast.AST) (paths []string, refs []ast.EntityRef) {
	for i, r := range q.Refs {
		paths = append(paths, "entities["+strconv.Itoa(i)+"].id")
		refs = append(refs, r)
	}
	for _, tr := range []struct {
		p string
		t *ast.TimeRange
	}{{"time_range", &q.Time}, {"compare_to", q.CompareTo}} {
		if tr.t == nil || tr.t.Anchor == nil || tr.t.Anchor.Incidents == nil {
			continue
		}
		for i, r := range tr.t.Anchor.Incidents.Refs {
			paths = append(paths, tr.p+".anchor.incidents.entities["+strconv.Itoa(i)+"].id")
			refs = append(refs, r)
		}
	}
	return paths, refs
}

// allFilters lists every filter in q with its path and entity.
func allFilters(q *ast.AST) (paths, ents []string, fs []ast.Filter) {
	for i, f := range q.Filters {
		paths, ents, fs = append(paths, "filters["+strconv.Itoa(i)+"].values"), append(ents, q.Target), append(fs, f)
	}
	for _, tr := range []struct {
		p string
		t *ast.TimeRange
	}{{"time_range", &q.Time}, {"compare_to", q.CompareTo}} {
		if tr.t == nil || tr.t.Anchor == nil || tr.t.Anchor.Incidents == nil {
			continue
		}
		for i, f := range tr.t.Anchor.Incidents.Filters {
			paths, ents, fs = append(paths, tr.p+".anchor.incidents.filters["+strconv.Itoa(i)+"].values"), append(ents, "incident"), append(fs, f)
		}
	}
	return paths, ents, fs
}

func (g guard) allowed(r ast.EntityRef) bool {
	if r.Type == "incident" {
		id := strings.TrimPrefix(r.ID, "incident:")
		return r.ID == "incident:"+id && g.incidentOK(id)
	}
	for _, m := range g.mentions {
		if m.typ == r.Type && m.id == r.ID {
			return true
		}
	}
	return false
}

func (g guard) incidentOK(id string) bool {
	if id == "" {
		return false
	}
	if id == g.incident {
		return true
	}
	for _, u := range uuidInText.FindAllString(g.text, -1) {
		if u == id {
			return true
		}
	}
	return false
}

// check returns every guard problem in q (empty = the validator decides).
func (g guard) check(q *ast.AST) []validate.Error {
	var out []validate.Error
	paths, refs := allRefs(q)
	used := map[string]bool{}
	for i, r := range refs {
		if !g.allowed(r) {
			out = append(out, validate.Error{Path: paths[i], Code: validate.CodeUnknownEntity, Suggestions: g.idsOfType(r.Type)})
			continue
		}
		used[r.Type+"|"+r.ID] = true
	}
	fpaths, fents, filters := allFilters(q)
	var values []string
	for i, f := range filters {
		d, ok := g.cat.Dimension(fents[i], f.Field)
		if !ok || d.Type != "string" {
			continue // enum / number values are checked by the validator
		}
		for _, v := range f.Values {
			nv := normalizeQuestion(v)
			values = append(values, nv)
			if nv == "" || !containsPhrase(g.text, nv) {
				out = append(out, validate.Error{Path: fpaths[i], Code: CodeValueNotInQuery})
				break
			}
		}
	}
	// Every entity the question names must narrow the query (as a reference,
	// or as the string value of a filter such as an owner): dropping one
	// widens the answer to everything.
	for _, m := range g.mentions {
		if used[m.key()] || coveredByValue(normalizeQuestion(m.input), values) {
			continue
		}
		out = append(out, validate.Error{Path: "entities", Code: CodeNamedEntityDrop, Suggestions: []string{m.id}})
	}
	for _, w := range g.idents {
		if !coveredByValue(w, values) {
			out = append(out, validate.Error{Path: "filters", Code: CodeUnaccountedName})
			break
		}
	}
	for _, x := range []struct{ p, id string }{
		{"incident_id", q.IncidentID}, {"time_range.anchor.incident_id", anchorIncident(&q.Time)}, {"compare_to.anchor.incident_id", anchorIncident(q.CompareTo)},
	} {
		if x.id != "" && !g.incidentOK(x.id) {
			out = append(out, validate.Error{Path: x.p, Code: CodeIncidentNotGiven})
		}
	}
	return out
}

func anchorIncident(t *ast.TimeRange) string {
	if t == nil || t.Anchor == nil {
		return ""
	}
	return t.Anchor.IncidentID
}

// containsPhrase reports whether phrase occurs in text on word boundaries.
func containsPhrase(text, phrase string) bool {
	return strings.Contains(" "+text+" ", " "+phrase+" ")
}

// coveredByValue reports whether phrase is (part of) one of the filter values.
func coveredByValue(phrase string, values []string) bool {
	for _, v := range values {
		if phrase != "" && containsPhrase(v, phrase) {
			return true
		}
	}
	return false
}

func (g guard) idsOfType(t string) []string {
	var out []string
	for _, m := range g.mentions {
		if m.typ == t && len(out) < 3 {
			out = append(out, m.id)
		}
	}
	return out
}

// usedRefs reports the resolved mentions the accepted query uses.
func (g guard) usedRefs(q *ast.AST) []resolve.Ref {
	_, refs := allRefs(q)
	var out []resolve.Ref
	seen := map[string]bool{}
	for _, r := range refs {
		for _, m := range g.mentions {
			if m.typ == r.Type && m.id == r.ID && !seen[m.key()] {
				seen[m.key()] = true
				out = append(out, resolve.Ref{InputText: m.input, EntityID: m.id, EntityType: m.typ, Confidence: m.conf, Method: m.method})
			}
		}
	}
	return out
}
