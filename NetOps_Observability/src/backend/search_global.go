package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Global omni-search — resolves a free-text query to jump targets across the
// product (devices, active alerts, saved objects) plus a log-search handoff.
// Powers the top-bar search dropdown so it behaves like Splunk/Datadog's
// global search rather than only running a log query.

type globalResult struct {
	Kind  string `json:"kind"`  // device | alert | saved | logs
	ID    string `json:"id"`
	Title string `json:"title"`
	Sub   string `json:"sub"`
	Route string `json:"route"` // hash route the UI should navigate to
}

const maxGlobalResults = 24

func (s *server) handleGlobalSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	results := []globalResult{}

	add := func(g globalResult) {
		if len(results) < maxGlobalResults {
			results = append(results, g)
		}
	}

	if q != "" {
		// Devices (in-memory discovery aggregator).
		for _, d := range s.discovery.Devices() {
			m := toMap(d)
			if blobContains(m, q) {
				add(globalResult{
					Kind:  "device",
					ID:    str(m["id"]),
					Title: firstNonEmpty(str(m["name"]), str(m["id"])),
					Sub:   firstNonEmpty(str(m["address"]), str(m["source"])),
					Route: "datasets/devices",
				})
			}
		}
		// Active alerts.
		for _, a := range s.alerts.Active() {
			m := toMap(a)
			if blobContains(m, q) {
				add(globalResult{
					Kind:  "alert",
					ID:    str(m["id"]),
					Title: firstNonEmpty(str(m["summary"]), str(m["rule"]), "alert"),
					Sub:   strings.TrimSpace(str(m["severity"]) + " " + str(m["device_id"])),
					Route: "alerts/triggered",
				})
			}
		}
		// Saved objects (name or body match).
		for _, o := range s.saved.List("") {
			if strings.Contains(strings.ToLower(o.Name), q) ||
				strings.Contains(strings.ToLower(string(o.Body)), q) {
				add(globalResult{
					Kind:  "saved",
					ID:    o.ID,
					Title: o.Name,
					Sub:   o.Type,
					Route: routeForSaved(o.Type),
				})
			}
		}
		// Always offer a log-search handoff for the raw query.
		add(globalResult{
			Kind:  "logs",
			Title: "Search logs for \"" + r.URL.Query().Get("q") + "\"",
			Sub:   "OpenSearch",
			Route: "search/logs",
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"query": q, "results": results})
}

func routeForSaved(typ string) string {
	switch typ {
	case "dashboard":
		return "overview/dashboards"
	case "report":
		return "reports"
	default:
		return "search/saved"
	}
}

// toMap renders any value to a generic map via JSON so handlers can read
// fields without importing each concrete type.
func toMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// blobContains reports whether the JSON of m contains the (already lowercased)
// query substring — a cheap any-field match.
func blobContains(m map[string]any, q string) bool {
	b, err := json.Marshal(m)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(b)), q)
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
