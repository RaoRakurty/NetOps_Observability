// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package fieldeval

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/iristriage"
)

func TestCLIImportAndListPrintNoQuestionText(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	exp := filepath.Join(t.TempDir(), "export.json")
	b, _ := json.Marshal(export("why is the dallas box slow"))
	if err := os.WriteFile(exp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := CLI([]string{"field-import", "--tenant", "acme", "--candidates", exp, "--root", root}, &out, &errb); code != 0 {
		t.Fatalf("import: %d %s", code, errb.String())
	}
	if strings.Contains(out.String(), "dallas") {
		t.Fatalf("import printed question text: %s", out.String())
	}
	out.Reset()
	if code := CLI([]string{"field-list", "--root", root}, &out, &errb); code != 0 {
		t.Fatalf("list: %d %s", code, errb.String())
	}
	var counts []Count
	if err := json.Unmarshal(out.Bytes(), &counts); err != nil || len(counts) != 1 || counts[0].Cases != 1 {
		t.Fatalf("list output %q %v", out.String(), err)
	}
	if strings.Contains(out.String(), "dallas") {
		t.Fatalf("list printed question text: %s", out.String())
	}
}

func TestCLIRefusesARootInsideTheRepositoryAndBadUsage(t *testing.T) {
	repo := fakeRepo(t)
	exp := filepath.Join(t.TempDir(), "export.json")
	b, _ := json.Marshal(iristriage.CandidateFile{Candidates: []iristriage.Candidate{{Question: "q one two", Source: "miss"}}})
	if err := os.WriteFile(exp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := CLI([]string{"field-import", "--tenant", "acme", "--candidates", exp, "--root", filepath.Join(repo, "src", "eval")}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "inside the repository") {
		t.Fatalf("in-repo root: %d %s", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(repo, "src")); !os.IsNotExist(err) {
		t.Fatal("a refused import still created a directory inside the repository")
	}
	for _, args := range [][]string{nil, {"nope"}, {"field-import", "--tenant", "acme"}} {
		if code := CLI(args, &out, &errb); code != 2 {
			t.Fatalf("args %v: %d", args, code)
		}
	}
}
