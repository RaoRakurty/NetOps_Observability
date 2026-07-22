package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// persisted_fields_test.go — the CLASS guard behind F-77.
//
// `allow_validation_scenarios` lived on the incidentPolicy struct, was accepted
// by the API, and was echoed back in the response as though it had been saved.
// It appeared in NO column list and NO migration. The in-memory store kept it —
// which is why every unit test passed — and the Postgres store silently dropped
// it on write and returned the zero value on read. Live at audit time, a policy
// named "PDI validation (confirmed-only)" reported the flag as false after an
// operator had turned it on.
//
// The audit's verdict: "An API that echoes an unsaved value is the worst
// variant of this class."
//
// This guard compares a persisted struct's JSON field names against the SQL
// column list used to read and write it. A field with no column is a field that
// cannot survive a round-trip, no matter what the response body says.
//
// Limits, stated honestly: this proves a column NAME appears in the column
// list. It cannot prove the value is bound in the right argument position, nor
// that a migration created the column. The round-trip tests in
// ticketing_store_pg_test.go cover binding; the migration is reviewed by hand.

// persistedStruct ties a Go struct to the const holding its SQL column list.
type persistedStruct struct {
	file       string // where the struct is declared
	structName string
	colsFile   string // where the column-list const lives
	colsConst  string
	// exempt maps a JSON field name to the reason it needs no column.
	exempt map[string]string
}

var persistedStructs = []persistedStruct{
	{
		file: "ticketing_model.go", structName: "incidentPolicy",
		colsFile: "ticketing_store.go", colsConst: "policyCols",
		exempt: map[string]string{},
	},
}

// jsonFieldNames returns the json tag names of a struct's exported fields.
func jsonFieldNames(t *testing.T, file, structName string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != structName {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, fld := range st.Fields.List {
			if fld.Tag == nil {
				continue
			}
			tag := strings.Trim(fld.Tag.Value, "`")
			idx := strings.Index(tag, `json:"`)
			if idx < 0 {
				continue
			}
			rest := tag[idx+len(`json:"`):]
			name := rest[:strings.Index(rest, `"`)]
			name = strings.Split(name, ",")[0]
			if name == "" || name == "-" {
				continue
			}
			out = append(out, name)
		}
		return false
	})
	if len(out) == 0 {
		t.Fatalf("no json-tagged fields found on %s in %s — did the struct move?", structName, file)
	}
	return out
}

// constValue returns the raw text of a string const declaration.
func constValue(t *testing.T, file, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	src := string(b)
	marker := "const " + name + " = `"
	i := strings.Index(src, marker)
	if i < 0 {
		t.Fatalf("const %s not found in %s", name, file)
	}
	rest := src[i+len(marker):]
	j := strings.Index(rest, "`")
	if j < 0 {
		t.Fatalf("unterminated const %s in %s", name, file)
	}
	return rest[:j]
}

func TestPersistedStructFieldsHaveColumns(t *testing.T) {
	for _, ps := range persistedStructs {
		fields := jsonFieldNames(t, ps.file, ps.structName)
		cols := constValue(t, ps.colsFile, ps.colsConst)

		for _, f := range fields {
			if reason, ok := ps.exempt[f]; ok {
				if reason == "" {
					t.Errorf("%s.%s is exempted with an empty reason", ps.structName, f)
				}
				continue
			}
			// Word-boundary match so `impact_confirmed` does not match
			// `impact_confirmed_critical` and pass for free.
			if !columnListHas(cols, f) {
				t.Errorf(`%s.%s (json:"%s") has NO column in %s.

  This is F-77 exactly: the API accepts this field and echoes it back as saved,
  the in-memory store keeps it so the unit tests pass, and the Postgres store
  drops it on write and returns the zero value on read.

  Fix it one of three ways:
    1. persist it — add the column (migration + INSERT + ON CONFLICT + scan)
    2. remove it  — from the struct AND from any API that accepts it
    3. exempt it  — add to the struct's exempt map with a reason`,
					ps.structName, f, f, ps.colsConst)
			}
		}
	}
}

// columnListHas reports whether the comma-separated SQL column list contains
// col as a whole entry.
func columnListHas(cols, col string) bool {
	for _, part := range strings.Split(cols, ",") {
		if strings.TrimSpace(strings.ReplaceAll(part, "\n", "")) == col {
			return true
		}
	}
	return false
}

// The specific field F-77 named, pinned so the regression is unmissable.
func TestF77AllowValidationScenariosIsPersisted(t *testing.T) {
	cols := constValue(t, "ticketing_store.go", "policyCols")
	if !columnListHas(cols, "allow_validation_scenarios") {
		t.Fatal("F-77 regression: allow_validation_scenarios lost its column in policyCols")
	}
	// It must also be written, not merely read.
	b, err := os.ReadFile("ticketing_store.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	src := string(b)
	if !strings.Contains(src, "allow_validation_scenarios=EXCLUDED.allow_validation_scenarios") {
		t.Error("allow_validation_scenarios is selected but never UPDATED on conflict — " +
			"an upsert would silently keep the old value")
	}
	if !strings.Contains(src, "p.AllowValidationScenarios") {
		t.Error("allow_validation_scenarios has a column but the Go value is never bound")
	}
}

// A migration must exist for the column, else a fresh deploy has the code and
// no table to put it in.
func TestF77MigrationExists(t *testing.T) {
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Clean(filepath.Join("migrations", e.Name())))
		if err != nil {
			continue
		}
		if strings.Contains(string(b), "allow_validation_scenarios") {
			return
		}
	}
	t.Fatal("no migration adds incident_policies.allow_validation_scenarios — " +
		"the column list references a column that does not exist")
}
