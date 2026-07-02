package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// toolspec_test.go — P2 seam tests: the manifest only ever shows a caller what
// the Policy Engine lets it run, every exposed tool is deliberately described,
// and model-supplied arguments are validated before any tool executes.

func manifestNames(specs []ToolSpec) map[string]bool {
	out := map[string]bool{}
	for _, s := range specs {
		out[s.Name] = true
	}
	return out
}

func TestManifestFiltersByPermission(t *testing.T) {
	reg := Tools(newMockDS())
	pol := NewPolicyEngine(PolicyConfig{}, func(string) bool { return false })

	// A correlations-only caller sees the RCA tools but no flow/telemetry tools.
	p := Principal{Tenant: "t-a", Perms: map[string]bool{"correlations:read": true, "events:read": true}}
	names := manifestNames(Manifest(reg, pol, p))
	if !names["get_problem"] || !names["get_active_major_incidents"] {
		t.Fatalf("correlations caller should see RCA tools, got %v", names)
	}
	if names["get_top_talkers"] || names["search_logs"] || names["get_device_health"] {
		t.Fatalf("caller without flows/infra/logs perms must not see those tools, got %v", names)
	}

	// A cross-tenant caller sees everything registered (all metas declared).
	cross := Principal{Cross: true}
	crossNames := manifestNames(Manifest(reg, pol, cross))
	for _, want := range []string{"get_problem", "get_top_talkers", "search_logs", "get_device_health"} {
		if !crossNames[want] {
			t.Fatalf("cross-tenant manifest missing %s: %v", want, crossNames)
		}
	}

	// No permissions at all → RCA/flow tools all gone.
	none := Manifest(reg, pol, Principal{Tenant: "t-a"})
	for _, s := range none {
		if len(mustTool(t, reg, s.Name).RequiredPerms()) > 0 {
			t.Fatalf("unpermissioned caller was shown %s", s.Name)
		}
	}
}

func mustTool(t *testing.T, reg *ToolRegistry, name string) AITool {
	t.Helper()
	tool, ok := reg.Get(name)
	if !ok {
		t.Fatalf("tool %s not registered", name)
	}
	return tool
}

// Every registered tool must have declared meta — an undeclared tool would be
// silently invisible to the model, which is safe but almost certainly a
// forgotten registration; keep the two tables in lockstep.
func TestEveryRegisteredToolHasMeta(t *testing.T) {
	reg := Tools(newMockDS())
	reg.AddDocsSearch(LoadDocsIndex())
	for _, n := range reg.Names() {
		if _, ok := toolMetas[n]; !ok {
			t.Errorf("registered tool %q has no toolMetas entry (invisible to the agent loop)", n)
		}
		if ToolLabel(n) == n {
			t.Errorf("registered tool %q has no customer-facing label", n)
		}
	}
}

func TestManifestSchemasAreValidFlatObjects(t *testing.T) {
	reg := Tools(newMockDS())
	reg.AddDocsSearch(LoadDocsIndex())
	pol := NewPolicyEngine(PolicyConfig{}, func(string) bool { return false })
	specs := Manifest(reg, pol, Principal{Cross: true})
	if len(specs) < 10 {
		t.Fatalf("expected a full manifest for cross principal, got %d", len(specs))
	}
	for _, s := range specs {
		if s.Description == "" {
			t.Errorf("%s: empty description", s.Name)
		}
		var schema struct {
			Type       string                       `json:"type"`
			Properties map[string]map[string]string `json:"properties"`
		}
		if err := json.Unmarshal(s.InputSchema, &schema); err != nil {
			t.Fatalf("%s: schema not valid JSON: %v", s.Name, err)
		}
		if schema.Type != "object" {
			t.Errorf("%s: schema type %q, want object", s.Name, schema.Type)
		}
		for arg, def := range schema.Properties {
			if def["type"] != "string" {
				t.Errorf("%s.%s: args must be flat strings, got %q", s.Name, arg, def["type"])
			}
		}
	}
}

func TestParseToolArgs(t *testing.T) {
	// Missing required arg errors.
	if _, err := ParseToolArgs("get_problem", json.RawMessage(`{}`)); err == nil {
		t.Fatal("missing required problem_id should error")
	}
	// Happy path + trimming.
	args, err := ParseToolArgs("get_problem", json.RawMessage(`{"problem_id":" abc "}`))
	if err != nil || args["problem_id"] != "abc" {
		t.Fatalf("got %v, %v", args, err)
	}
	// Scalar coercion (models emit numbers/bools).
	args, err = ParseToolArgs("search_logs", json.RawMessage(`{"query":42,"window":"1h"}`))
	if err != nil || args["query"] != "42" {
		t.Fatalf("number coercion: got %v, %v", args, err)
	}
	// Undeclared keys are dropped, not fatal.
	args, err = ParseToolArgs("search_logs", json.RawMessage(`{"query":"x","hax":"y"}`))
	if err != nil || args["hax"] != "" {
		t.Fatalf("undeclared key should be dropped: %v, %v", args, err)
	}
	// Nested payloads are rejected (no structured smuggling into tools).
	if _, err := ParseToolArgs("search_logs", json.RawMessage(`{"query":{"$or":[]}}`)); err == nil {
		t.Fatal("nested object arg should be rejected")
	}
	// Undeclared tool has no schema → error (fail closed).
	if _, err := ParseToolArgs("no_such_tool", json.RawMessage(`{}`)); err == nil {
		t.Fatal("undeclared tool should error")
	}
	// Empty raw payload is fine for a no-arg tool.
	if _, err := ParseToolArgs("get_active_major_incidents", nil); err != nil {
		t.Fatalf("no-arg tool with nil args: %v", err)
	}
}

func TestDocsSearchTool(t *testing.T) {
	ix := LoadDocsIndex()
	if ix.Len() == 0 {
		t.Skip("embedded docs corpus empty in this build")
	}
	reg := Tools(newMockDS())
	reg.AddDocsSearch(ix)
	tool := mustTool(t, reg, "search_docs")

	// A documented topic returns doc-cited items.
	res, err := tool.Run(context.Background(), Principal{Tenant: "t-a"}, ToolArgs{"query": "SNMP discovery scan scope"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) == 0 {
		t.Fatal("expected doc hits for a documented topic")
	}
	for _, it := range res.Items {
		if !strings.HasPrefix(it.CitationID, "doc:") || it.Kind != "doc" {
			t.Fatalf("doc item shape wrong: %+v", it)
		}
	}

	// Honesty floor: an uncovered topic yields NO items and an explicit note.
	res, err = tool.Run(context.Background(), Principal{Tenant: "t-a"}, ToolArgs{"query": "quantum flux capacitor warranty"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 0 || len(res.Notes) == 0 {
		t.Fatalf("uncovered topic must return notes only, got %+v", res)
	}

	// Missing query errors.
	if _, err := tool.Run(context.Background(), Principal{}, ToolArgs{}); err == nil {
		t.Fatal("empty query should error")
	}
}
