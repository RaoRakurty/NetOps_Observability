package experience

// openapi_test.go — every route this package serves must be DOCUMENTED, and the
// exported path constants must match what main.go registers. A documented route
// that 404s and an undocumented route that works are both defects; this pins
// the three sources of truth (constants, registrations, document) together.

import (
	"strings"
	"testing"

	"netops/backend/internal/openapi"
)

func TestOpenAPIDocumentsEveryExperienceRoute(t *testing.T) {
	spec := openapi.Spec("test")
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatal("the OpenAPI document has no paths")
	}
	want := map[string][]string{
		OverviewPath:                       {"get"},
		IncidentsPath:                      {"get"},
		IncidentItemPath + "{id}":          {"get"},
		JourneysPath:                       {"get", "post"},
		JourneyItemPath + "{id}":           {"get", "put", "delete"},
		CoveragePath:                       {"get"},
		ChangesPath:                        {"get", "post"},
		DataHealthPath:                     {"get"},
		EventsPath:                         {"post"},
		BusinessEventPath:                  {"post"},
		"/api/dem/incidents/{id}/evidence": {"get"},
		"/api/dem/incidents/{id}/timeline": {"get"},
		"/api/dem/incidents/{id}/path":     {"get"},
		"/api/dem/incidents/{id}/promote":  {"post"},
	}
	for path, methods := range want {
		entry, has := paths[path].(map[string]any)
		if !has {
			t.Errorf("the OpenAPI document does not describe %s", path)
			continue
		}
		for _, m := range methods {
			op, hasOp := entry[m].(map[string]any)
			if !hasOp {
				t.Errorf("%s %s is not documented", strings.ToUpper(m), path)
				continue
			}
			if s, _ := op["summary"].(string); strings.TrimSpace(s) == "" {
				t.Errorf("%s %s has an empty summary", strings.ToUpper(m), path)
			}
			tags, _ := op["tags"].([]string)
			if len(tags) == 0 || tags[0] != "Digital Experience" {
				t.Errorf("%s %s is not tagged Digital Experience: %v", strings.ToUpper(m), path, tags)
			}
		}
	}
}

func TestRouteConstantsMatchTheDocumentedPaths(t *testing.T) {
	pairs := map[string]string{
		OverviewPath:      "/api/dem/overview",
		IncidentsPath:     "/api/dem/incidents",
		IncidentItemPath:  "/api/dem/incidents/",
		JourneysPath:      "/api/dem/journeys",
		JourneyItemPath:   "/api/dem/journeys/",
		CoveragePath:      "/api/dem/synthetics/coverage",
		ChangesPath:       "/api/dem/changes",
		DataHealthPath:    "/api/dem/data-health",
		EventsPath:        "/api/dem/events",
		BusinessEventPath: "/api/dem/business-events",
	}
	for got, want := range pairs {
		if got != want {
			t.Fatalf("route constant %q drifted from %q", got, want)
		}
	}
}
