package dem

// openapi_test.go — the six DEM routes are advertised, and advertised
// correctly. A route that exists and is undocumented is invisible on the API
// Access page; one documented under the wrong METHOD is worse, because a
// generated client calls it and fails. Both are pinned here rather than in
// package openapi, which owns no domain knowledge about these routes.
//
// It also pins that the route CONSTANTS this package exports and the paths the
// document advertises are the same strings — main.go registers literals so the
// route-isolation ledger's scanner can see them, and this is what stops the two
// spellings drifting apart.

import (
	"strings"
	"testing"

	"netops/backend/internal/openapi"
)

func TestOpenAPIDocumentsTheDEMRoutes(t *testing.T) {
	spec := openapi.Spec("test")
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatal("spec has no paths object")
	}
	want := map[string][]string{
		"/api/dem/targets":      {"get", "post"},
		"/api/dem/targets/{id}": {"get", "put", "delete"},
		"/api/dem/experience":   {"get"},
	}
	for path, methods := range want {
		entry, ok := paths[path].(map[string]any)
		if !ok {
			t.Errorf("%s is not in the OpenAPI document", path)
			continue
		}
		for _, m := range methods {
			op, ok := entry[m].(map[string]any)
			if !ok {
				t.Errorf("%s is documented, but not under %q", path, m)
				continue
			}
			if s, _ := op["summary"].(string); s == "" {
				t.Errorf("%s %s has no summary", m, path)
			}
			tags, _ := op["tags"].([]string)
			if len(tags) != 1 || tags[0] != "Digital Experience" {
				t.Errorf("%s %s tags = %v", m, path, tags)
			}
		}
	}
	// The experience score is a read. A generated client that POSTed it would
	// silently do nothing.
	if entry, ok := paths["/api/dem/experience"].(map[string]any); ok {
		for _, bad := range []string{"post", "put", "delete"} {
			if _, found := entry[bad]; found {
				t.Errorf("the experience route is advertised as a %s", strings.ToUpper(bad))
			}
		}
	}
}

func TestRouteConstantsMatchTheDocumentedPaths(t *testing.T) {
	if TargetsPath != "/api/dem/targets" {
		t.Fatalf("TargetsPath = %q", TargetsPath)
	}
	if TargetItemPath != TargetsPath+"/" {
		t.Fatalf("TargetItemPath = %q", TargetItemPath)
	}
	if ExperiencePath != "/api/dem/experience" {
		t.Fatalf("ExperiencePath = %q", ExperiencePath)
	}
}
