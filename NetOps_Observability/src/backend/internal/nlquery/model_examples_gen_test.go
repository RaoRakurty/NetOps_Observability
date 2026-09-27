// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nlquery_test

// model_examples_gen_test.go — regenerates the model fallback's example
// library (modelc/examples.v1.json) from the golden corpus. It only runs when
// asked (NLQ_WRITE_MODEL_EXAMPLES=1): the library is a curated snapshot, so a
// corpus edit never breaks another engineer's build; modelc's own test proves
// every embedded example still decodes and validates.
//
// Selection: answerable single-turn cases with no page or conversation context
// and no absolute (calendar) window — those depend on the fixture's clock.
// Every entity id becomes a per-type placeholder, so an example can teach a
// shape but never hand the model a usable id.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"netops/backend/internal/nlquery/ast"
)

func placeholderID(typ string, n int) string {
	switch typ {
	case "interface":
		return fmt.Sprintf("interface:example-%d/port-1", n)
	case "bgp_peer":
		return fmt.Sprintf("bgp_peer:example-%d/192.0.2.%d", n, n)
	case "application":
		return fmt.Sprintf("app:example-%d", n)
	case "probe_target":
		return fmt.Sprintf("probe:example-%d", n)
	}
	return fmt.Sprintf("%s:example-%d", typ, n)
}

func TestWriteModelExamples(t *testing.T) {
	if os.Getenv("NLQ_WRITE_MODEL_EXAMPLES") != "1" {
		t.Skip("set NLQ_WRITE_MODEL_EXAMPLES=1 to regenerate modelc/examples.v1.json")
	}
	type entity struct {
		Input string `json:"input"`
		Type  string `json:"type"`
		ID    string `json:"id"`
	}
	type example struct {
		ID       string          `json:"id"`
		Question string          `json:"question"`
		Resolved []entity        `json:"resolved,omitempty"`
		AST      json.RawMessage `json:"ast"`
	}
	var out []example
	for _, c := range loadCases(t) {
		cx := c.Context
		if len(c.Expect.AST) == 0 || cx.Cross || len(cx.PriorAST) > 0 || cx.IncidentID != "" || cx.Script != "" || cx.Turn > 0 ||
			bytes.Contains(c.Expect.AST, []byte(`"absolute"`)) || bytes.Contains(c.Expect.AST, []byte(`"incident:`)) {
			continue
		}
		q := decodeAST(t, c.ID, c.Expect.AST)
		repl := map[string]string{}
		n := 0
		mapID := func(r *ast.EntityRef) {
			if _, ok := repl[r.ID]; !ok {
				n++
				repl[r.ID] = placeholderID(r.Type, n)
			}
			r.ID = repl[r.ID]
		}
		for i := range q.Refs {
			mapID(&q.Refs[i])
		}
		if q.Time.Anchor != nil && q.Time.Anchor.Incidents != nil {
			for i := range q.Time.Anchor.Incidents.Refs {
				mapID(&q.Time.Anchor.Incidents.Refs[i])
			}
		}
		var res []entity
		for _, e := range c.Expect.Entities {
			if p, ok := repl[e.ID]; ok {
				res = append(res, entity{Input: e.Input, Type: e.Type, ID: p})
			}
		}
		raw, err := q.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, example{ID: c.ID, Question: c.Question, Resolved: res, AST: raw})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	var b strings.Builder
	b.WriteString("{\n \"schema\": \"correlix.nlquery.model-examples.v1\",\n \"source\": \"internal/nlquery/testdata/golden (placeholder ids)\",\n \"examples\": [\n")
	for i, e := range out {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString("  ")
		b.Write(line)
		if i < len(out)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString(" ]\n}\n")
	if err := os.WriteFile("modelc/examples.v1.json", []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d examples", len(out))
}
