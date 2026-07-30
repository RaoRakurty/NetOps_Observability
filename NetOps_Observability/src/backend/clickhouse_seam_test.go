package backend

// clickhouse_seam_test.go — guards that keep ClickHouse access on one seam.
//
// These REPLACE TestClickHouseHTTPWritesCheckTheirStatus, which was the weakest
// guard in the repo and worth describing, because its failure mode is the one
// this whole audit is about.
//
// The old guard read, in full:
//
//	if !strings.Contains(src, "INSERT INTO netops.") { continue }
//	if !strings.Contains(src, "StatusCode") && !strings.Contains(src, "chExecErr") { fail }
//
// It asked whether the WORD "StatusCode" appeared somewhere in the same FILE.
// So a file with ten inserts and one unrelated status check passed clean; and
//
//	if resp.StatusCode != 200 { }   // empty body — drops the write
//
// passed too. It proved a check was WRITTEN, never that one BEHAVED. Behaviour
// is now proven where it belongs — chhttp/chhttp_test.go fires real ClickHouse
// failures at a real client — and the guards below only have to keep call sites
// ON that seam, which is a structural question a source scan answers honestly.
//
// The guards are AST-based rather than regex-based on purpose: the previous
// generation of guards in this repo were defeated by SPELLING (TestNoVoidSaveLocked
// looked for `saveLocked()` and sailed past F-78's `save()`), and an AST does not
// care how a thing is spelled or formatted.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chSeamExempt lists files permitted to address ClickHouse directly, with the
// reason. chhttp itself is the seam; anything else here is a debt marker.
var chSeamExempt = map[string]string{
	"clickhouse_client.go": "the adapter that CONSTRUCTS the chhttp client — it is the seam's own wiring",
}

// goFilesUnder returns parsed non-test Go files under root (non-recursive).
func goFilesUnder(t *testing.T, root string) map[string]*ast.File {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		p := filepath.Join(root, name)
		f, err := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
		out[p] = f
	}
	return out
}

// TestClickHouseAccessGoesThroughTheSeam fails when a file builds its own HTTP
// request against a ClickHouse endpoint instead of using chhttp.
//
// This is the structural half of the F-38/F-56 fix. Those findings existed
// because there was no ClickHouse client: a dozen call sites each resolved
// CLICKHOUSE_URL, hand-rolled a request, and invented their own idea of what
// "failed" meant. Most invented "nothing happened". One seam means one
// classifier, and one place to fix the next thing we learn about ClickHouse.
func TestClickHouseAccessGoesThroughTheSeam(t *testing.T) {
	for _, root := range []string{".", "collectors"} {
		for path, f := range goFilesUnder(t, root) {
			base := filepath.Base(path)
			if reason, ok := chSeamExempt[base]; ok {
				if reason == "" {
					t.Errorf("%s is exempted with an empty reason — state why or delete the exemption", base)
				}
				continue
			}
			// Scope the question to a FUNCTION, not a file. A file-level check
			// would flag a health probe that happens to live beside a ClickHouse
			// helper — the same per-file sloppiness that made the guard this one
			// replaces useless. The pairing that matters is: this function
			// resolves the ClickHouse endpoint AND builds its own request.
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				var resolvesCH bool
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING &&
						strings.Contains(lit.Value, "CLICKHOUSE_URL") {
						resolvesCH = true
					}
					return true
				})
				if !resolvesCH {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkg, ok := sel.X.(*ast.Ident)
					if !ok || pkg.Name != "http" {
						return true
					}
					switch sel.Sel.Name {
					case "NewRequest", "NewRequestWithContext", "Post", "PostForm":
						t.Errorf(`%s: %s() resolves CLICKHOUSE_URL and builds its own http.%s.

  Every ClickHouse call must go through the chhttp seam. A hand-rolled request
  re-invents status handling, and the audit measured how that goes: 19 of 20
  insert sites discarded the failure (F-38), and none set insert tolerance
  (F-56), because each site had to learn it independently.

    _, err := chClientFor(base).Exec(ctx, chhttp.Request{
        SQL: sql, Op: "insert netops.x", Scope: scope,
        Settings: chInsertTolerance(),
    })

  If this file genuinely must bypass the seam, add it to chSeamExempt with a
  reason.`, path, fn.Name.Name, sel.Sel.Name)
					}
					return true
				})
			}
		}
	}
}

// TestInsertToleranceMatchesTheCollectorSet keeps the two tolerance blocks
// honest about the setting they both REFUSE.
//
// input_format_allow_errors_num/ratio make ClickHouse silently discard
// malformed ROWS. Tolerating an unknown COLUMN is safe (the data is intact and
// the schema lags); tolerating a bad ROW is not (the data is gone and nothing
// says so). They read as the same kind of leniency and are opposites — which is
// exactly the sort of distinction that erodes when two copies drift.
func TestInsertToleranceMatchesTheCollectorSet(t *testing.T) {
	banned := []string{"input_format_allow_errors_num", "input_format_allow_errors_ratio"}
	for k := range chInsertTolerance() {
		for _, b := range banned {
			if k == b {
				t.Errorf(`chInsertTolerance() sets %s.

  That setting makes ClickHouse DROP malformed rows and return 200. It trades a
  loud batch failure for exactly the invisible partial loss this audit exists to
  eliminate. collectors/tunnels.go documents the same refusal — keep them agreed.`, b)
			}
		}
	}
	// The two settings we DO want must be present, or the F-56 fix is cosmetic.
	tol := chInsertTolerance()
	for _, want := range []string{"input_format_skip_unknown_fields", "date_time_input_format"} {
		if tol[want] == "" {
			t.Errorf("chInsertTolerance() is missing %s — F-56 was about insert tolerance being absent everywhere", want)
		}
	}
}
