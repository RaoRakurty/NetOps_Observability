// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenantlocator_test

// openapi_test.go — the per-tenant sign-in routes are DOCUMENTED, with the right
// verbs and the right tag. Pinned here rather than in package openapi, which
// owns no domain knowledge about these routes.

import (
	"strings"
	"testing"

	"netops/backend/internal/openapi"
)

func TestOpenAPIDocumentsTheTenantSignInRoutes(t *testing.T) {
	spec := openapi.Spec("test")
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatal("spec has no paths")
	}
	want := map[string][]string{
		"/api/auth/locator":                {"get"},
		"/api/auth/sso/tenant-idp":         {"get"},
		"/api/auth/sso/tenant-idp/{alias}": {"get", "put", "delete"},
	}
	for path, methods := range want {
		item, ok := paths[path].(map[string]any)
		if !ok {
			t.Errorf("%s is not documented", path)
			continue
		}
		for _, m := range methods {
			op, ok := item[m].(map[string]any)
			if !ok {
				t.Errorf("%s: %s is not documented", path, m)
				continue
			}
			summary, _ := op["summary"].(string)
			if strings.TrimSpace(summary) == "" {
				t.Errorf("%s %s: empty summary", strings.ToUpper(m), path)
			}
			tags, _ := op["tags"].([]string)
			if len(tags) != 1 || tags[0] != "Auth" {
				t.Errorf("%s %s: tags = %v, want exactly [Auth]", strings.ToUpper(m), path, tags)
			}
		}
		// A write route must not be advertised as a read, or the generated
		// client hands callers a GET that changes state.
		if len(methods) == 1 && methods[0] == "get" {
			for _, bad := range []string{"put", "post", "delete"} {
				if _, found := item[bad]; found {
					t.Errorf("%s must be read-only, but %s is documented", path, strings.ToUpper(bad))
				}
			}
		}
	}
	// The per-tenant SSO URLs are NOT /api routes and deliberately carry no
	// OpenAPI entry: they are browser redirect targets in the sign-in flow, not
	// an API surface. Guard against someone documenting them into the client.
	for p := range paths {
		if strings.HasPrefix(p, "/t/") || strings.HasPrefix(p, "/org/") {
			t.Errorf("%s must not be in the API spec — it is a browser sign-in URL, not an API route", p)
		}
	}
}
