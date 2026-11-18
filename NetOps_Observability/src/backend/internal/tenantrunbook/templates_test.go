// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenantrunbook

import (
	"net/http"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/orgcontext"
	"netops/backend/internal/upgrademop"
)

// Every built-in procedure is a valid MOP under the very rules a customer's own
// runbook meets (the parser, the prose rule, the tool allowlist).
func TestEveryTemplateParsesAsACustomerMOP(t *testing.T) {
	for _, tpl := range upgrademop.All() {
		in, err := TemplateSource(tpl.Name, "")
		if err != nil {
			t.Fatal(err)
		}
		sk, err := Parse(tA, in.Name, in.Kind, in.Source, ai.ToolNames())
		if err != nil {
			t.Fatalf("%s does not parse as a customer runbook: %v", tpl.Name, err)
		}
		if string(sk.Kind) != string(KindMOP) || len(sk.Steps) != len(tpl.Steps) {
			t.Errorf("%s parsed as kind %s with %d steps", tpl.Name, sk.Kind, len(sk.Steps))
		}
	}
}

func TestTemplateListIsReadableByAnyMemberOfTheWorkspace(t *testing.T) {
	a := newAPI(t)
	for _, who := range []string{"alice", "key"} {
		code, m := a.call(who, http.MethodGet, apiPrefix+"/templates", "")
		if code != http.StatusOK {
			t.Fatalf("%s: %d %v", who, code, m)
		}
		list := m["templates"].([]any)
		if len(list) != len(upgrademop.All()) {
			t.Fatalf("%d templates listed", len(list))
		}
		first := list[0].(map[string]any)
		src := first["source"].(map[string]any)
		if !strings.HasPrefix(src["url"].(string), "https://") || src["version"] == "" {
			t.Errorf("a template must carry its public source: %v", src)
		}
		if len(first["checks"].([]any)) == 0 || len(first["steps"].([]any)) == 0 {
			t.Errorf("a template lists its steps and read-only checks: %v", first)
		}
	}
	if code, _ := a.call("global", http.MethodGet, apiPrefix+"/templates", ""); code != http.StatusBadRequest {
		t.Fatalf("the Global view has no workspace: %d", code)
	}
}

// Adopting makes a DRAFT in the adopter's own workspace; it reaches Iris only
// after someone else approves it, exactly like a runbook written by hand.
func TestAdoptingATemplateGoesThroughTheTwoPersonFlow(t *testing.T) {
	a := newAPI(t)
	name := upgrademop.All()[0].Name
	code, m := a.call("alice", http.MethodPost, apiPrefix+"/templates/"+name+"/adopt", "")
	if code != http.StatusCreated {
		t.Fatalf("adopt: %d %v", code, m)
	}
	id := m["id"].(string)
	v := m["versions"].([]any)[0].(map[string]any)
	if v["state"] != string(orgcontext.StateDraft) || m["kind"] != string(KindMOP) {
		t.Fatalf("an adopted template is a MOP draft: %v", m)
	}
	sha := v["body_sha256"].(string)
	if !a.audited("adopt_template", name) {
		t.Fatalf("the adoption is not audited: %v", a.audit)
	}
	for _, d := range a.audit {
		for _, val := range d {
			if s, ok := val.(string); ok && strings.Contains(s, "Performed by the engineer") {
				t.Fatalf("the audit carries runbook text: %v", d)
			}
		}
	}

	if code, m := a.call("alice", http.MethodPost, apiPrefix+"/"+id+"/submit", ""); code != http.StatusOK {
		t.Fatalf("submit: %d %v", code, m)
	}
	if code, m := a.call("alice", http.MethodPost, apiPrefix+"/"+id+"/approve", approveBody(sha)); code != http.StatusForbidden {
		t.Fatalf("the adopter approved their own copy: %d %v", code, m)
	}
	if code, m := a.call("reviewer", http.MethodPost, apiPrefix+"/"+id+"/approve", approveBody(sha)); code != http.StatusOK {
		t.Fatalf("a second person approves: %d %v", code, m)
	}

	// The copy is tenant A's alone.
	if _, m := a.call("bob", http.MethodGet, apiPrefix, ""); len(m["runbooks"].([]any)) != 0 {
		t.Fatalf("tenant B sees tenant A's adopted runbook: %v", m)
	}
	if code, _ := a.call("bob", http.MethodGet, apiPrefix+"/"+id, ""); code != http.StatusNotFound {
		t.Fatalf("tenant B reads tenant A's adopted runbook: %d", code)
	}
	// Adopting the same procedure twice under the same name is a conflict, not a
	// silent overwrite; a new name makes a second copy.
	if code, _ := a.call("alice", http.MethodPost, apiPrefix+"/templates/"+name+"/adopt", ""); code < 400 {
		t.Fatalf("a second adoption under the same name succeeded: %d", code)
	}
	if code, m := a.call("alice", http.MethodPost, apiPrefix+"/templates/"+name+"/adopt", `{"name":"core-upgrade"}`); code != http.StatusCreated || m["name"] != "core-upgrade" {
		t.Fatalf("adopt under a new name: %d %v", code, m)
	}
}

func TestAdoptRefusals(t *testing.T) {
	a := newAPI(t)
	name := upgrademop.All()[0].Name
	cases := []struct {
		who, path, body string
		want            int
	}{
		{"key", "/templates/" + name + "/adopt", "", http.StatusForbidden}, // an API key only reads
		{"global", "/templates/" + name + "/adopt", "", http.StatusBadRequest},
		{"alice", "/templates/no-such-procedure/adopt", "", http.StatusNotFound},
		{"alice", "/templates/" + name + "/adopt", `{"name":"Bad Name"}`, http.StatusBadRequest},
		{"alice", "/templates/" + name + "/adopt", `{"tenant":"t-b"}`, http.StatusBadRequest}, // no tenant in a body
		{"alice", "/templates", "", http.StatusMethodNotAllowed},                           // POST to the list
	}
	for _, c := range cases {
		method := http.MethodPost
		if code, m := a.call(c.who, method, apiPrefix+c.path, c.body); code != c.want {
			t.Errorf("%s %s %s: %d %v, want %d", c.who, c.path, c.body, code, m, c.want)
		}
	}
	if _, m := a.call("alice", http.MethodGet, apiPrefix, ""); len(m["runbooks"].([]any)) != 0 {
		t.Fatalf("a refused adoption created something: %v", m)
	}
}

func (a *api) audited(action, template string) bool {
	for _, d := range a.audit {
		if d["action"] == action && d["template"] == template && d["decision"] == "allow" {
			return true
		}
	}
	return false
}
