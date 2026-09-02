package parsercov

// openapi_test.go — the three routes are advertised, and advertised correctly.
//
// The OpenAPI document is what the Administration → API Access page renders and
// what any client codegen consumes. A route that exists and is undocumented is
// invisible; a route documented under the wrong METHOD is worse, because a
// generated client calls it and fails. Both are pinned here rather than in
// package openapi, which owns no domain knowledge about these routes.

import (
	"testing"

	"netops/backend/internal/openapi"
)

func TestOpenAPIDocumentsTheParserCoverageRoutes(t *testing.T) {
	spec := openapi.Spec("test")
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatal("spec has no paths object")
	}
	want := map[string]string{
		"/api/admin/parser/stats":                           "get",
		"/api/telemetry/unrecognized":                       "get",
		"/api/telemetry/unrecognized/{template_id}/propose": "post",
	}
	for path, method := range want {
		entry, ok := paths[path].(map[string]any)
		if !ok {
			t.Errorf("%s is not in the OpenAPI document", path)
			continue
		}
		op, ok := entry[method].(map[string]any)
		if !ok {
			t.Errorf("%s is documented, but not under %q (got %v)", path, method, keysOf(entry))
			continue
		}
		if s, _ := op["summary"].(string); s == "" {
			t.Errorf("%s %s has no summary", method, path)
		}
		tags, _ := op["tags"].([]string)
		if len(tags) != 1 || tags[0] != "Telemetry" {
			t.Errorf("%s %s tags = %v, want [Telemetry]", method, path, tags)
		}
	}
	// The propose route must NOT be advertised as a GET: it is a write-gated
	// authoring action, and a generated client that GETs it would silently do
	// nothing.
	if entry, ok := paths["/api/telemetry/unrecognized/{template_id}/propose"].(map[string]any); ok {
		if _, bad := entry["get"]; bad {
			t.Error("the propose route is advertised as a GET")
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
