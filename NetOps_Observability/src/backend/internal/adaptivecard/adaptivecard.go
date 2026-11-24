// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package adaptivecard validates a Microsoft Adaptive Card against Microsoft's
// official JSON schema (testdata/adaptive-card-1.4.0.json, vendored unmodified;
// provenance in testdata/README.md).
//
// It exists so the Teams cards every Correlix sender builds (notify/teams_card.go)
// are checked against the real schema offline, in CI, without a live Teams
// tenant (tracker 455). Only tests import it.
//
// The schema is JSON Schema draft-06. No JSON-schema module is on the CLAUDE.md
// §6 allowlist, so this is a small interpreter for exactly the keywords that
// schema uses: $ref (local), allOf, anyOf, type, enum, required, properties,
// additionalProperties, items, pattern and format (uri-reference). Annotations
// (description, examples, default, version) are ignored. A keyword the schema
// starts using that this interpreter does not know is an error, not a silent
// pass (see unknownKeyword), so a schema refresh cannot weaken the check.
package adaptivecard

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

//go:embed testdata/adaptive-card-1.4.0.json
var schema14 []byte

// HostExtension is a property a host documents on top of the core schema,
// allowed at one instance path only. Microsoft Teams documents
// `msteams: {"width": "Full"}` on the root card
// (https://learn.microsoft.com/microsoftteams/platform/task-modules-and-cards/cards/cards-format),
// which the core schema's `additionalProperties: false` would otherwise refuse.
type HostExtension struct {
	Path string // JSON-pointer-like instance path of the object, "" = root
	Key  string
}

// TeamsHostExtensions are the Teams-only properties Correlix cards use.
var TeamsHostExtensions = []HostExtension{{Path: "", Key: "msteams"}}

// Validator checks instances against the vendored 1.4 schema.
type Validator struct {
	root  map[string]any
	defs  map[string]any
	ext   map[string]map[string]bool
	regex map[string]*regexp.Regexp
}

// New14 loads the vendored Adaptive Card 1.4 schema.
func New14(ext ...HostExtension) (*Validator, error) {
	var root map[string]any
	if err := json.Unmarshal(schema14, &root); err != nil {
		return nil, fmt.Errorf("adaptivecard: parse schema: %w", err)
	}
	defs, ok := root["definitions"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("adaptivecard: schema has no definitions")
	}
	v := &Validator{root: root, defs: defs, ext: map[string]map[string]bool{}, regex: map[string]*regexp.Regexp{}}
	for _, e := range ext {
		if v.ext[e.Path] == nil {
			v.ext[e.Path] = map[string]bool{}
		}
		v.ext[e.Path][e.Key] = true
	}
	return v, nil
}

// ValidateCard validates one Adaptive Card (the `content` of a Teams
// attachment) given as any JSON-marshalable value. It returns every
// violation found, sorted; nil means the card is valid.
func (v *Validator) ValidateCard(card any) []string {
	inst, err := normalise(card)
	if err != nil {
		return []string{err.Error()}
	}
	var errs []string
	v.check(v.root, inst, "", &errs)
	sort.Strings(errs)
	return dedupe(errs)
}

// normalise round-trips through JSON so the instance holds only the types
// encoding/json produces (map[string]any, []any, float64, string, bool, nil).
func normalise(x any) (any, error) {
	b, err := json.Marshal(x)
	if err != nil {
		return nil, fmt.Errorf("adaptivecard: marshal instance: %w", err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("adaptivecard: unmarshal instance: %w", err)
	}
	return out, nil
}

// known keywords: validated or deliberately ignored annotations.
var annotations = map[string]bool{"description": true, "examples": true, "example": true, "default": true, "version": true, "$schema": true, "id": true, "definitions": true, "features": true}

func (v *Validator) check(sch any, inst any, path string, errs *[]string) {
	s, ok := sch.(map[string]any)
	if !ok {
		if b, isBool := sch.(bool); isBool {
			if !b {
				*errs = append(*errs, fmt.Sprintf("%s: not allowed", at(path)))
			}
			return
		}
		*errs = append(*errs, fmt.Sprintf("%s: unreadable schema node %T", at(path), sch))
		return
	}
	for k := range s {
		if !annotations[k] && !handled[k] {
			*errs = append(*errs, fmt.Sprintf("%s: schema keyword %q is not supported by this validator", at(path), k))
		}
	}
	if ref, ok := s["$ref"].(string); ok {
		def, err := v.resolve(ref)
		if err != nil {
			*errs = append(*errs, fmt.Sprintf("%s: %v", at(path), err))
			return
		}
		v.check(def, inst, path, errs)
	}
	if all, ok := s["allOf"].([]any); ok {
		for _, sub := range all {
			v.check(sub, inst, path, errs)
		}
	}
	if anyOf, ok := s["anyOf"].([]any); ok {
		var first []string
		matched := false
		for i, sub := range anyOf {
			var e []string
			v.check(sub, inst, path, &e)
			if len(e) == 0 {
				matched = true
				break
			}
			if i == 0 || len(e) < len(first) {
				first = e
			}
		}
		if !matched {
			*errs = append(*errs, fmt.Sprintf("%s: matches none of the allowed forms; closest: %s", at(path), strings.Join(first, "; ")))
		}
	}
	if t, ok := s["type"]; ok && !typeOK(t, inst) {
		*errs = append(*errs, fmt.Sprintf("%s: want type %v, got %s", at(path), t, jsonType(inst)))
		return
	}
	if enum, ok := s["enum"].([]any); ok {
		found := false
		for _, e := range enum {
			if reflect.DeepEqual(e, inst) {
				found = true
				break
			}
		}
		if !found {
			*errs = append(*errs, fmt.Sprintf("%s: %v is not one of %v", at(path), inst, enum))
		}
	}
	if p, ok := s["pattern"].(string); ok {
		if str, isStr := inst.(string); isStr {
			re, err := v.re(p)
			if err != nil {
				*errs = append(*errs, fmt.Sprintf("%s: bad schema pattern: %v", at(path), err))
			} else if !re.MatchString(str) {
				*errs = append(*errs, fmt.Sprintf("%s: %q does not match %s", at(path), str, p))
			}
		}
	}
	if f, ok := s["format"].(string); ok && f == "uri-reference" {
		if str, isStr := inst.(string); isStr {
			if _, err := url.Parse(str); err != nil {
				*errs = append(*errs, fmt.Sprintf("%s: not a uri-reference: %v", at(path), err))
			}
		}
	}
	obj, isObj := inst.(map[string]any)
	if isObj {
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				if name, _ := r.(string); name != "" {
					if _, present := obj[name]; !present {
						*errs = append(*errs, fmt.Sprintf("%s: missing required property %q", at(path), name))
					}
				}
			}
		}
		props, _ := s["properties"].(map[string]any)
		for key, val := range obj {
			if ps, declared := props[key]; declared {
				v.check(ps, val, path+"/"+key, errs)
				continue
			}
			ap, hasAP := s["additionalProperties"]
			if !hasAP {
				continue
			}
			if b, isBool := ap.(bool); isBool {
				if !b && !v.ext[path][key] {
					*errs = append(*errs, fmt.Sprintf("%s: property %q is not allowed", at(path), key))
				}
				continue
			}
			v.check(ap, val, path+"/"+key, errs)
		}
	}
	if arr, isArr := inst.([]any); isArr {
		if items, ok := s["items"]; ok {
			for i, el := range arr {
				v.check(items, el, fmt.Sprintf("%s/%d", path, i), errs)
			}
		}
	}
}

var handled = map[string]bool{"$ref": true, "allOf": true, "anyOf": true, "type": true, "enum": true, "pattern": true, "format": true, "required": true, "properties": true, "additionalProperties": true, "items": true}

func (v *Validator) resolve(ref string) (any, error) {
	const pfx = "#/definitions/"
	if !strings.HasPrefix(ref, pfx) {
		return nil, fmt.Errorf("unsupported $ref %q", ref)
	}
	def, ok := v.defs[strings.TrimPrefix(ref, pfx)]
	if !ok {
		return nil, fmt.Errorf("unknown $ref %q", ref)
	}
	return def, nil
}

func (v *Validator) re(p string) (*regexp.Regexp, error) {
	if r, ok := v.regex[p]; ok {
		return r, nil
	}
	r, err := regexp.Compile(p)
	if err != nil {
		return nil, err
	}
	v.regex[p] = r
	return r, nil
}

func typeOK(t any, inst any) bool {
	switch tt := t.(type) {
	case string:
		return isType(tt, inst)
	case []any:
		for _, x := range tt {
			if s, _ := x.(string); isType(s, inst) {
				return true
			}
		}
	}
	return false
}

func isType(t string, inst any) bool {
	switch t {
	case "object":
		_, ok := inst.(map[string]any)
		return ok
	case "array":
		_, ok := inst.([]any)
		return ok
	case "string":
		_, ok := inst.(string)
		return ok
	case "boolean":
		_, ok := inst.(bool)
		return ok
	case "number":
		_, ok := inst.(float64)
		return ok
	case "integer":
		f, ok := inst.(float64)
		return ok && f == float64(int64(f))
	case "null":
		return inst == nil
	}
	return false
}

func jsonType(inst any) string {
	for _, t := range []string{"object", "array", "string", "boolean", "integer", "number", "null"} {
		if isType(t, inst) {
			return t
		}
	}
	return fmt.Sprintf("%T", inst)
}

func at(path string) string {
	if path == "" {
		return "card"
	}
	return "card" + path
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
