// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/gqlparse"
	"sort"

	"netops/backend/internal/httppage"
)

// graphql.go — the GraphQL endpoint, rebuilt to close audit F-72 (2026-07-21).
//
// What was wrong, measured live by the auditor:
//
//	{devices{id}}                  -> 218,133 bytes (all 512 devices, ALL fields)
//	{devices(limit:1,first:1){id}} -> 218,133 bytes (byte-identical: args ignored)
//	{bogus}                        ->      12 bytes ({"data":{}} with HTTP 200)
//
// and, the security half: the handler authenticated with
// `claims, _ := userFrom(r.Context())` and NEVER called requirePerm, while its
// REST twin handleDevices requires `infrastructure:read`. Any authenticated
// principal — including a role with no infrastructure permission at all —
// could read the entire device inventory and the alert engine through
// /api/graphql. That is a real authorization bypass, not a scaffold wart, and
// it is why this file was rewritten rather than annotated.
//
// What this endpoint now does:
//
//  1. Enforces THE SAME RBAC gate as the REST twin (infrastructure:read) before
//     any resolver runs, and the same per-field platform-owner gates the REST
//     handlers apply to rules and to fleet-wide collector/discovery health.
//  2. Parses the document (graphql_parse.go) instead of substring-matching it.
//     An unknown field is `Cannot query field "bogus" on type "Query"` in a
//     spec-shaped `errors` array with HTTP 400 — never 200 + `{"data":{}}`,
//     which every spec-compliant client reads as "success, no results".
//  3. Applies `limit`/`offset` arguments (and $variables) or refuses them by
//     name. `first:` is refused explicitly rather than ignored.
//  4. Honours the selection set: only the requested fields come back, and a
//     field that does not exist on the type is an error, not silence.
//
// Deliberately NOT implemented, and each refused with a named error rather than
// hidden: mutations, subscriptions, fragments, directives, multiple operations
// per document, and full introspection (__schema remains a small static stub).

// gqlRequest is the standard GraphQL-over-HTTP POST envelope.
type gqlRequest struct {
	Query         string         `json:"query"`
	OperationName string         `json:"operationName,omitempty"`
	Variables     map[string]any `json:"variables,omitempty"`
}

// gqlError is one spec-shaped error entry.
type gqlError struct {
	Message string   `json:"message"`
	Path    []string `json:"path,omitempty"`
}

// gqlMaxBody bounds the request body (§9: no unbounded reads).
const gqlMaxBody = 256 << 10

// writeGQLErrors emits `{"errors":[...]}` with no `data` key — the spec's
// representation of a request that could not be executed. 400, because these
// are request errors (malformed document, unknown field, bad argument), which
// graphql-over-http says SHOULD carry a 4xx status.
func writeGQLErrors(w http.ResponseWriter, status int, msgs ...string) {
	errs := make([]gqlError, 0, len(msgs))
	for _, m := range msgs {
		errs = append(errs, gqlError{Message: m})
	}
	writeJSON(w, status, map[string]any{"errors": errs})
}

func (s *server) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// F-72 (security): the SAME gate the REST twin enforces, before any
	// resolver runs. requirePerm writes the 401/403 itself.
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	var req gqlRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, gqlMaxBody))
	if err := dec.Decode(&req); err != nil {
		writeGQLErrors(w, http.StatusBadRequest, "invalid GraphQL request envelope: "+err.Error())
		return
	}
	op, err := gqlparse.Parse(req.Query)
	if err != nil {
		writeGQLErrors(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.OperationName != "" && op.Name != "" && req.OperationName != op.Name {
		writeGQLErrors(w, http.StatusBadRequest, fmt.Sprintf(
			"operationName %q does not match the operation in the document (%q)", req.OperationName, op.Name))
		return
	}
	// Variables were declared on the request struct and read at ZERO sites.
	// A variable the document declares but the request does not supply is now
	// an error the moment a resolver needs it (gqlparse.IntArg); a variable the
	// request supplies but the document never declares is refused here, so a
	// caller can never believe an input was applied when it was not.
	if err := checkGQLVariables(op, req.Variables); err != nil {
		writeGQLErrors(w, http.StatusBadRequest, err.Error())
		return
	}

	data := map[string]any{}
	var errs []gqlError
	for _, f := range op.Sel {
		v, ferr := s.resolveGQLField(f, claims, req.Variables)
		if ferr != nil {
			errs = append(errs, gqlError{Message: ferr.Error(), Path: []string{f.Alias}})
			continue
		}
		data[f.Alias] = v
	}
	if len(errs) > 0 {
		// Any field error is a request error in this subset (unknown field,
		// bad argument, refused scope) — never a partial 200 that reads as
		// success.
		writeJSON(w, http.StatusBadRequest, map[string]any{"errors": errs})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data})
}

// checkGQLVariables refuses variables the document never declares. Silently
// accepting them is the same class of defect as silently ignoring `limit`.
func checkGQLVariables(op *gqlparse.Operation, vars map[string]any) error {
	if len(vars) == 0 {
		return nil
	}
	declared := map[string]bool{}
	for _, n := range op.VarNames {
		declared[n] = true
	}
	names := make([]string, 0, len(vars))
	for k := range vars {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if !declared[k] {
			return fmt.Errorf("variable $%s was provided but is not declared by the operation", k)
		}
	}
	return nil
}

// gqlQueryFields is the whole Query type. Kept as data so the unknown-field
// error can name what IS available.
var gqlQueryFields = []string{"__schema", "__typename", "alerts", "devices", "health", "rules"}

// resolveGQLField executes one root field.
func (s *server) resolveGQLField(f gqlparse.Field, claims jwtClaims, vars map[string]any) (any, error) {
	_, cross := principalTenant(claims)
	switch f.Name {
	case "__typename":
		if err := noArgs(f); err != nil {
			return nil, err
		}
		return "Query", nil

	case "devices":
		page, err := gqlPageArgs(f, vars, deviceDefaultPage, deviceMaxPage)
		if err != nil {
			return nil, err
		}
		// Tenant isolation, identical to the REST twin: visibleDevices filters
		// to the caller's tenant (plus shared/global) before anything is paged.
		devs := s.withCredActive(withDeviceType(visibleDevices(s.discovery.Devices(), claims)))
		sort.Slice(devs, func(i, j int) bool { return devs[i].ID < devs[j].ID })
		return projectList(httppage.SliceOf(devs, page), f.Sel, "Device")

	case "alerts":
		page, err := gqlPageArgs(f, vars, deviceDefaultPage, deviceMaxPage)
		if err != nil {
			return nil, err
		}
		active := s.alerts.Active()
		if ids, crossDev := s.visibleDeviceIDs(claims); !crossDev {
			filtered := active[:0:0]
			for _, a := range active {
				if a.DeviceID == "" || ids[a.DeviceID] {
					filtered = append(filtered, a)
				}
			}
			active = filtered
		}
		sort.Slice(active, func(i, j int) bool { return active[i].ID < active[j].ID })
		return projectList(httppage.SliceOf(active, page), f.Sel, "Alert")

	case "rules":
		if err := noArgs(f); err != nil {
			return nil, err
		}
		// SR-004/SR-010: rules are platform-global (they expose infra topology
		// across tenants). The old code returned an EMPTY list to a scoped
		// caller, which reads as "there are no rules" — an honest refusal is an
		// error, not a lie shaped like data.
		if !cross {
			return nil, errors.New("rules are platform-global; requires a cross-tenant principal")
		}
		return projectList(s.alerts.Rules(), f.Sel, "Rule")

	case "health":
		if err := noArgs(f); err != nil {
			return nil, err
		}
		health := map[string]any{
			"status":  "healthy",
			"version": version,
			"alerts":  s.alerts.Health(),
		}
		if cross {
			// SR-010: fleet-wide collector/discovery health is what the REST
			// handleCollectors restricts to the platform owner.
			health["discovery"] = s.discovery.Health()
			health["collectors"] = s.collectors.Health()
		}
		return projectOne(health, f.Sel, "Health")

	case "__schema":
		if err := noArgs(f); err != nil {
			return nil, err
		}
		return staticSchema(), nil
	}
	return nil, fmt.Errorf("Cannot query field %q on type \"Query\" (available: %v)", f.Name, gqlQueryFields)
}

// noArgs refuses arguments on a field that takes none, naming the offender.
func noArgs(f gqlparse.Field) error {
	if len(f.Args) == 0 {
		return nil
	}
	names := make([]string, 0, len(f.Args))
	for k := range f.Args {
		names = append(names, k)
	}
	sort.Strings(names)
	return fmt.Errorf("Unknown argument %q on field %q", names[0], f.Name)
}

// gqlPageArgs reads limit/offset from a field's arguments and returns the same
// bounded page the REST endpoints use — including refusing an unknown argument.
// `first`/`last` are named explicitly because the audit's probe used `first:`
// and got the entire table back with no complaint.
func gqlPageArgs(f gqlparse.Field, vars map[string]any, defLimit, maxLimit int) (httppage.Request, error) {
	p := httppage.Request{Limit: defLimit, Max: maxLimit}
	names := make([]string, 0, len(f.Args))
	for k := range f.Args {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		switch k {
		case "limit", "offset":
		case "first", "last", "after", "before":
			return httppage.Request{}, fmt.Errorf(
				"Unknown argument %q on field %q — this endpoint pages with limit/offset, not Relay connections", k, f.Name)
		default:
			return httppage.Request{}, fmt.Errorf("Unknown argument %q on field %q (accepted: limit, offset)", k, f.Name)
		}
	}
	if v, ok := f.Args["limit"]; ok {
		n, err := gqlparse.IntArg(v, vars, "limit")
		if err != nil {
			return httppage.Request{}, err
		}
		if n < 1 || n > maxLimit {
			return httppage.Request{}, fmt.Errorf("argument \"limit\" must be between 1 and %d (got %d)", maxLimit, n)
		}
		p.Limit = n
		p.Explicit = true
	}
	if v, ok := f.Args["offset"]; ok {
		n, err := gqlparse.IntArg(v, vars, "offset")
		if err != nil {
			return httppage.Request{}, err
		}
		if n < 0 || n > httppage.MaxOffset {
			return httppage.Request{}, fmt.Errorf("argument \"offset\" must be between 0 and %d (got %d)", httppage.MaxOffset, n)
		}
		p.Offset = n
		p.Explicit = true
	}
	return p, nil
}

// projectList applies a selection set to every element of a typed slice. The
// old handler serialized the WHOLE struct regardless of what was selected —
// which is how `{devices{id}}` returned 218 KB of every field of every device.
func projectList[T any](rows []T, sel []gqlparse.Field, typeName string) (any, error) {
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		m, err := toFieldMap(row)
		if err != nil {
			return nil, err
		}
		projected, err := projectMap(m, sel, typeName)
		if err != nil {
			return nil, err
		}
		out = append(out, projected)
	}
	return out, nil
}

func projectOne(m map[string]any, sel []gqlparse.Field, typeName string) (any, error) {
	return projectMap(m, sel, typeName)
}

// toFieldMap converts a resolver value to its wire field map via the SAME JSON
// tags the REST surface uses, so a GraphQL field name means exactly what the
// REST field name means.
func toFieldMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// projectMap keeps only the selected fields, recursing into nested selections.
// An unselectable field is an ERROR: a client that misspells a field name must
// learn that, not receive an object silently missing the field it asked for.
//
// A field selected without a sub-selection returns the whole value — the
// pragmatic choice for the free-form maps (health, labels) this schema carries,
// and part of why the schema is documented as partial.
func projectMap(m map[string]any, sel []gqlparse.Field, typeName string) (map[string]any, error) {
	if len(sel) == 0 {
		return m, nil
	}
	out := make(map[string]any, len(sel))
	for _, f := range sel {
		if f.Name == "__typename" {
			out[f.Alias] = typeName
			continue
		}
		if len(f.Args) > 0 {
			return nil, fmt.Errorf("Unknown argument on field %q of type %q", f.Name, typeName)
		}
		v, ok := m[f.Name]
		if !ok {
			return nil, fmt.Errorf("Cannot query field %q on type %q", f.Name, typeName)
		}
		if len(f.Sel) > 0 {
			switch inner := v.(type) {
			case map[string]any:
				sub, err := projectMap(inner, f.Sel, typeName+"."+f.Name)
				if err != nil {
					return nil, err
				}
				out[f.Alias] = sub
				continue
			case []any:
				subs := make([]any, 0, len(inner))
				for _, it := range inner {
					im, isMap := it.(map[string]any)
					if !isMap {
						return nil, fmt.Errorf("Field %q of type %q has no subfields", f.Name, typeName)
					}
					sub, err := projectMap(im, f.Sel, typeName+"."+f.Name)
					if err != nil {
						return nil, err
					}
					subs = append(subs, sub)
				}
				out[f.Alias] = subs
				continue
			default:
				return nil, fmt.Errorf("Field %q of type %q has no subfields", f.Name, typeName)
			}
		}
		out[f.Alias] = v
	}
	return out, nil
}

// staticSchema is a minimal introspection stub. It is honest about being one:
// it advertises only the types this endpoint actually resolves.
func staticSchema() any {
	return map[string]any{
		"types": []map[string]any{
			{"name": "Device", "kind": "OBJECT"},
			{"name": "Alert", "kind": "OBJECT"},
			{"name": "Rule", "kind": "OBJECT"},
			{"name": "Health", "kind": "OBJECT"},
		},
		"queryType": map[string]any{"name": "Query", "fields": gqlQueryFields},
	}
}
