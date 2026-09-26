// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nlquery_test

// import_guard_test.go — the NL query packages cannot reach a backend. Every
// non-test file under internal/nlquery may import only a fixed stdlib set and
// nlquery's own packages; a network, database, filesystem or AI-package import
// fails the build. Data is reachable ONLY through the root-implemented Scope,
// which is where tenant scoping lives.

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var allowed = map[string]bool{
	"bytes": true, "context": true, "crypto/sha256": true, "embed": true, "encoding/hex": true,
	"encoding/json": true, "errors": true, "fmt": true, "io": true, "math": true, "regexp": true,
	"sort": true, "strconv": true, "strings": true, "time": true, "unicode": true,
}

func TestNLQueryImportsNoBackend(t *testing.T) {
	checked := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		checked++
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if allowed[p] || strings.HasPrefix(p, "netops/backend/internal/nlquery/") {
				continue
			}
			t.Errorf("%s imports %q — the NL query packages must reach data only through Scope", path, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 8 {
		t.Fatalf("the guard inspected only %d files — it is not looking where the code is", checked)
	}
}
