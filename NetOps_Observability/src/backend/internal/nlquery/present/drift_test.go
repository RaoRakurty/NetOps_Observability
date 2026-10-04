// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package present

// drift_test.go — one source of truth for the closed enums. The Go constants
// here and the client's lists in src/frontend/src/iris/presentation.ts must be
// the same members in the same order; this test reads the TypeScript and fails
// on any difference. (presentation.test.ts reads this package's present.go in
// the other direction, so a drift breaks both CI legs.) A missing client file
// FAILS — the guard never disarms itself by skipping.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/modelc"
)

const clientContract = "../../../../frontend/src/iris/presentation.ts"

func tsConstList(t *testing.T, src, name string) []string {
	t.Helper()
	re := regexp.MustCompile(`(?s)export const ` + name + ` = \[(.*?)\] as const;`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("%s: no `export const %s = [...] as const;` — the drift guard cannot see the client enum", clientContract, name)
	}
	var out []string
	for _, s := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(m[1], -1) {
		out = append(out, s[1])
	}
	if len(out) == 0 {
		t.Fatalf("%s: %s is empty", clientContract, name)
	}
	return out
}

func readClient(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(clientContract))
	if err != nil {
		t.Fatalf("the client presentation contract must exist beside the server's: %v", err)
	}
	return string(b)
}

func sameList(t *testing.T, what string, server, client []string) {
	t.Helper()
	if strings.Join(server, ",") != strings.Join(client, ",") {
		t.Fatalf("%s drifted between Go and TypeScript:\n server: %v\n client: %v", what, server, client)
	}
}

func TestViewEnumMatchesClient(t *testing.T) {
	var server []string
	for _, v := range Views() {
		server = append(server, string(v))
	}
	sameList(t, "the view enum", server, tsConstList(t, readClient(t), "VIEW_TYPES"))
}

func TestHighlightEnumMatchesClient(t *testing.T) {
	var server []string
	for _, k := range HighlightKinds() {
		server = append(server, string(k))
	}
	sameList(t, "the highlight enum", server, tsConstList(t, readClient(t), "HIGHLIGHT_KINDS"))
}

func TestQueryTypesMatchClient(t *testing.T) {
	var server []string
	for _, k := range []ast.QueryType{ast.MetricSeries, ast.MetricTopK, ast.MetricFilter, ast.CompareWindows,
		ast.ChangeList, ast.IncidentList, ast.IncidentExplain, ast.FlowTop, ast.LogSearch} {
		if !k.Known() {
			t.Fatalf("%q is not a known query type", k)
		}
		server = append(server, string(k))
	}
	sameList(t, "the query types", server, tsConstList(t, readClient(t), "QUERY_TYPES"))
}

// The model is told the same closed list it may suggest from.
func TestModelPromptOffersTheEnum(t *testing.T) {
	var names []string
	for _, v := range Views() {
		names = append(names, `"`+string(v)+`"`)
	}
	if !strings.Contains(modelc.SystemPrompt(), strings.Join(names, ", ")) {
		t.Fatalf("the model's system prompt does not list the view enum as %s", strings.Join(names, ", "))
	}
}
