// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// asciifold_slice_guard_test.go — the C1 invariant, made structural (tracker 299).
//
// THE DEFECT. strings.ToLower is not length-preserving:
//
//   - U+023A (Ⱥ) and U+023E (Ⱦ) each grow from two bytes to three when lowered;
//   - every byte of invalid UTF-8 becomes a three-byte U+FFFD.
//
// So an offset measured on a FOLDED COPY does not address the ORIGINAL string.
// Applied to the original it either runs past the end — a slice panic in a bare
// worker goroutine, which takes the API process, the in-process correlation
// engine and alert delivery with it — or lands the wrong number of bytes along
// and silently returns the wrong substring. Both faces have already bitten this
// repository: internal/showparse panicked the API, and internal/pipedebug wrote
// an UNREDACTED bearer token into a support bundle.
//
// THE FIX SHIPPED. internal/asciifold scans the original bytes, so the offset it
// returns is always valid for the string the caller will slice. Every site was
// converted.
//
// WHY THIS FILE EXISTS ANYWAY. "Every site is clean" is a SNAPSHOT; the guard is
// the invariant. The ClickHouse scope rule taught this the expensive way: a
// structural test that only caught CALLS stayed green while a leak was typed out
// by hand under it. So this guard keys on the SHAPE — an offset derived from a
// folded value, used to index or slice something that is not that folded value —
// and not on any identifier a new site would have to mention.
//
// It is an AST sweep, not a regex one, because the shape spans statements
// (`lower := strings.ToLower(s)` … `i := strings.Index(lower, m)` … `s[i:]`) and
// survives arbitrary renaming, line breaks and arithmetic on the offset.
//
// SCOPE, stated so the next reader does not over-trust it: it sweeps every
// non-vendor, non-test .go file in the backend module — production code in every
// package, which is where a panic of this class costs something. It does not
// read _test.go files (a fixture there is not a shipped path, and the fixtures in
// THIS file would be flagged by it). It reasons within one function body at a
// time and does not follow an offset through a function boundary or a struct
// field, so a fold in one function and a slice in another is out of its reach.

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── what the sweep looks for ────────────────────────────────────────────────

// foldFuncs are the string transforms that are NOT length-preserving. An offset
// measured on the result of any of them is valid only for that result.
// (asciifold.Index/LastIndex are deliberately absent: their whole purpose is to
// return an offset into the ORIGINAL, which is what makes them the fix.)
var foldFuncs = map[string]map[string]bool{
	"strings": {
		"ToLower": true, "ToUpper": true, "ToTitle": true, "ToValidUTF8": true,
		"ToLowerSpecial": true, "ToUpperSpecial": true, "ToTitleSpecial": true,
		"Map": true,
	},
	"bytes": {
		"ToLower": true, "ToUpper": true, "ToTitle": true, "ToValidUTF8": true,
		"ToLowerSpecial": true, "ToUpperSpecial": true, "ToTitleSpecial": true,
		"Map": true,
	},
}

// indexFuncs return a BYTE OFFSET into their first argument. Anything here,
// handed a folded haystack, produces an offset that belongs to the fold.
var indexFuncs = map[string]bool{
	"Index": true, "IndexAny": true, "IndexByte": true, "IndexRune": true, "IndexFunc": true,
	"LastIndex": true, "LastIndexAny": true, "LastIndexByte": true, "LastIndexFunc": true,
}

// foldSliceFinding is one site where an offset from a folded value indexes
// something else.
type foldSliceFinding struct {
	File    string
	Line    int
	Operand string // what is being sliced
	ValidOn string // what the offset is actually valid for
	Snippet string
}

// foldSweep is the result of one pass, counts included: the counts are what
// make the guard unable to pass by recognising nothing.
type foldSweep struct {
	Files         int
	Bodies        int // function bodies analysed
	FoldCalls     int // calls to a non-length-preserving transform
	IndexCalls    int // calls to an offset-returning function
	SliceExprs    int // slice/index expressions examined
	OffsetsOnFold int // offsets seen to be derived from a folded value
	Findings      []foldSliceFinding

	// Per-SPELLING tallies. The aggregates above are not enough on their own:
	// an earlier draft of this guard lost `strings.ToLower` from its table and
	// still passed, because the hundreds of `bytes.ToLower` calls in the tree
	// kept FoldCalls non-zero. A blind detector that reports a healthy total is
	// the exact failure this file exists to make impossible, so the two
	// load-bearing spellings — the ones the C1 defect was literally written in —
	// are counted and asserted by name.
	FoldSpellings  map[string]int
	IndexSpellings map[string]int
}

// foldSpellingC1 and indexSpellingC1 are the two halves of the idiom as it was
// actually written in showparse and pipedebug.
const (
	foldSpellingC1  = "strings.ToLower"
	indexSpellingC1 = "strings.Index"
)

// exprText renders an expression back to source, whitespace-normalised, so two
// spellings of the same operand compare equal.
func exprText(fset *token.FileSet, e ast.Expr) string {
	var b strings.Builder
	if err := printer.Fprint(&b, fset, e); err != nil {
		return ""
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// pkgSel splits a `pkg.Fn` selector into its two halves.
func pkgSel(e ast.Expr) (pkg, fn string, ok bool) {
	sel, isSel := e.(*ast.SelectorExpr)
	if !isSel {
		return "", "", false
	}
	id, isIdent := sel.X.(*ast.Ident)
	if !isIdent {
		return "", "", false
	}
	return id.Name, sel.Sel.Name, true
}

// foldArg reports whether e is a call to a non-length-preserving transform, and
// returns the ORIGINAL it was handed (the last argument, which is the string for
// every form including Map and the *Special variants).
func foldArg(e ast.Expr) (orig ast.Expr, ok bool) {
	call, isCall := e.(*ast.CallExpr)
	if !isCall || len(call.Args) == 0 {
		return nil, false
	}
	pkg, fn, isSel := pkgSel(call.Fun)
	if !isSel || !foldFuncs[pkg][fn] {
		return nil, false
	}
	return call.Args[len(call.Args)-1], true
}

// haystack reports whether e is a call that returns an offset, and returns the
// expression that offset is measured on.
func haystack(e ast.Expr) (in ast.Expr, ok bool) {
	call, isCall := e.(*ast.CallExpr)
	if !isCall || len(call.Args) == 0 {
		return nil, false
	}
	if pkg, fn, isSel := pkgSel(call.Fun); isSel && (pkg == "strings" || pkg == "bytes") && indexFuncs[fn] {
		return call.Args[0], true
	}
	// regexp's offset-returning methods: r.FindStringIndex(s) and friends. The
	// receiver is the pattern; the haystack is the sole argument.
	if sel, isSel := call.Fun.(*ast.SelectorExpr); isSel && len(call.Args) == 1 &&
		strings.HasPrefix(sel.Sel.Name, "Find") && strings.HasSuffix(sel.Sel.Name, "Index") {
		return call.Args[0], true
	}
	return nil, false
}

// sweepFoldSlices is THE detector, kept pure so it can be aimed at the real tree
// and at the known-bad fixtures below with exactly the same code.
func sweepFoldSlices(fset *token.FileSet, files map[string]*ast.File) foldSweep {
	sw := foldSweep{Files: len(files), FoldSpellings: map[string]int{}, IndexSpellings: map[string]int{}}
	for name, f := range files {
		for _, decl := range f.Decls {
			var body *ast.BlockStmt
			switch d := decl.(type) {
			case *ast.FuncDecl:
				body = d.Body
			default:
				continue
			}
			if body == nil {
				continue
			}
			sw.Bodies++
			analyseBody(fset, name, body, &sw)
		}
	}
	return sw
}

// analyseBody runs the two passes over ONE function body (nested closures
// included, because a closure can see the outer fold).
func analyseBody(fset *token.FileSet, file string, body *ast.BlockStmt, sw *foldSweep) {
	// folded: variable name → the folded value it holds, as text.
	folded := map[string]string{}
	// offsets: variable name → the text of the value its offset is valid for.
	offsets := map[string]string{}

	// Pass 1 — collect. Every `x := strings.ToLower(s)` and every
	// `i := strings.Index(<folded>, m)`.
	record := func(lhs []ast.Expr, rhs []ast.Expr) {
		for k, r := range rhs {
			if k >= len(lhs) {
				break
			}
			id, isIdent := lhs[k].(*ast.Ident)
			if !isIdent || id.Name == "_" {
				continue
			}
			if _, ok := foldArg(r); ok {
				folded[id.Name] = exprText(fset, r)
				continue
			}
			if h, ok := haystack(r); ok {
				if v, on := offsetValidOn(fset, h, folded); on {
					offsets[id.Name] = v
				}
			}
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			record(s.Lhs, s.Rhs)
		case *ast.ValueSpec:
			lhs := make([]ast.Expr, 0, len(s.Names))
			for _, nm := range s.Names {
				lhs = append(lhs, nm)
			}
			record(lhs, s.Values)
		case *ast.CallExpr:
			if _, ok := foldArg(s); ok {
				sw.FoldCalls++
				if pkg, fn, isSel := pkgSel(s.Fun); isSel {
					sw.FoldSpellings[pkg+"."+fn]++
				}
			}
			if _, ok := haystack(s); ok {
				sw.IndexCalls++
				if pkg, fn, isSel := pkgSel(s.Fun); isSel {
					sw.IndexSpellings[pkg+"."+fn]++
				}
			}
		}
		return true
	})

	// Pass 2 — check every index/slice expression.
	ast.Inspect(body, func(n ast.Node) bool {
		var operand ast.Expr
		var bounds []ast.Expr
		switch e := n.(type) {
		case *ast.SliceExpr:
			operand, bounds = e.X, []ast.Expr{e.Low, e.High, e.Max}
		case *ast.IndexExpr:
			operand, bounds = e.X, []ast.Expr{e.Index}
		default:
			return true
		}
		sw.SliceExprs++
		operandText := exprText(fset, operand)
		// Slicing the folded copy itself is correct and common.
		if fv, isFolded := folded[operandText]; isFolded {
			operandText = fv
		}
		for _, b := range bounds {
			if b == nil {
				continue
			}
			validOn, ok := boundValidOn(fset, b, folded, offsets)
			if !ok {
				continue
			}
			sw.OffsetsOnFold++
			if validOn == operandText {
				continue
			}
			pos := fset.Position(n.Pos())
			sw.Findings = append(sw.Findings, foldSliceFinding{
				File:    file,
				Line:    pos.Line,
				Operand: exprText(fset, operand),
				ValidOn: validOn,
				Snippet: exprText(fset, n.(ast.Expr)),
			})
		}
		return true
	})
}

// offsetValidOn resolves what an offset measured on haystack h is valid for:
// the folded value itself when h is one (or names one), otherwise nothing.
func offsetValidOn(fset *token.FileSet, h ast.Expr, folded map[string]string) (string, bool) {
	if _, ok := foldArg(h); ok {
		return exprText(fset, h), true
	}
	if id, isIdent := h.(*ast.Ident); isIdent {
		if v, ok := folded[id.Name]; ok {
			return v, true
		}
	}
	return "", false
}

// boundValidOn looks inside one index/slice bound for an offset that belongs to
// a folded value — a collected variable, or an inline offset call on a fold —
// and reports what that offset is valid for. Arithmetic around it (`i+len(m)`)
// does not launder it.
//
// It deliberately does NOT descend into a nested index/slice expression. In
// `byName[nm[:i]]` the offset i addresses nm, not byName: the inner `nm[:i]` is
// judged on its own terms by the caller's walk, and its VALUE is a substring,
// not an offset. Descending would report every lawful `m[lower[a:b]]` lookup —
// a guard that cries wolf is a guard that gets muted.
func boundValidOn(fset *token.FileSet, b ast.Expr, folded, offsets map[string]string) (string, bool) {
	switch b.(type) {
	case *ast.SliceExpr, *ast.IndexExpr:
		return "", false
	}
	found, ok := "", false
	ast.Inspect(b, func(n ast.Node) bool {
		if ok {
			return false
		}
		switch e := n.(type) {
		case *ast.SliceExpr, *ast.IndexExpr:
			_ = e
			return false
		case *ast.CallExpr:
			if h, is := haystack(e); is {
				if v, on := offsetValidOn(fset, h, folded); on {
					found, ok = v, true
					return false
				}
			}
		case *ast.Ident:
			if v, is := offsets[e.Name]; is {
				found, ok = v, true
				return false
			}
		}
		return true
	})
	return found, ok
}

// ── reading the tree ────────────────────────────────────────────────────────

// backendGoFiles parses every non-vendor, non-test .go file in the module.
func backendGoFiles(t *testing.T, fset *token.FileSet) map[string]*ast.File {
	t.Helper()
	out := map[string]*ast.File{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") && d.Name() != "." {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil {
			return readErr
		}
		f, parseErr := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if parseErr != nil {
			return parseErr
		}
		out[path] = f
		return nil
	})
	if err != nil {
		t.Fatalf("walk the backend tree: %v", err)
	}
	return out
}

// ── anti-vacuity ────────────────────────────────────────────────────────────

// vacuityFailures lists the reasons a sweep proves nothing. A guard whose own
// sweep matched nothing must FAIL, not pass: that is the distinction between
// "nothing is wrong" and "I recognised nothing". Returned as data rather than
// asserted inline so the assertion itself can be probed live, below.
func vacuityFailures(sw foldSweep) []string {
	var why []string
	if sw.Files == 0 {
		why = append(why, "no .go files were read — the walk found nothing to scan")
	}
	if sw.Bodies == 0 {
		why = append(why, "no function bodies were analysed — every file parsed to nothing")
	}
	if sw.SliceExprs == 0 {
		why = append(why, "no slice or index expression was examined — the shape this guard judges never came up")
	}
	if sw.FoldCalls == 0 {
		why = append(why, "no call to a non-length-preserving transform was recognised anywhere in the backend — "+
			"foldFuncs has drifted away from the code (has strings.ToLower really vanished from the tree?) and the detector is blind")
	}
	if sw.IndexCalls == 0 {
		why = append(why, "no offset-returning call was recognised anywhere in the backend — "+
			"indexFuncs has drifted away from the code (has strings.Index really vanished?) and the detector is blind")
	}
	// The two spellings the C1 defect was written in, asserted by name. Without
	// these the aggregates above can stay healthy on a sibling spelling while
	// the detector has gone blind to the one that matters.
	if sw.FoldSpellings[foldSpellingC1] == 0 {
		why = append(why, "not one "+foldSpellingC1+" call was recognised in the backend — that spelling is the C1 defect's own, "+
			"and a tree this size does not contain zero of them: foldFuncs no longer matches it and the detector is blind to the idiom")
	}
	if sw.IndexSpellings[indexSpellingC1] == 0 {
		why = append(why, "not one "+indexSpellingC1+" call was recognised in the backend — that spelling is the C1 defect's own, "+
			"and a tree this size does not contain zero of them: indexFuncs no longer matches it and the detector is blind to the idiom")
	}
	return why
}

// ── the guard ───────────────────────────────────────────────────────────────

func TestNoOffsetFromAFoldedCopyIsUsedToSliceTheOriginal(t *testing.T) {
	fset := token.NewFileSet()
	sw := sweepFoldSlices(fset, backendGoFiles(t, fset))

	for _, why := range vacuityFailures(sw) {
		t.Fatalf("this guard would have passed vacuously: %s", why)
	}

	for _, f := range sw.Findings {
		t.Errorf("%s:%d slices a value with an offset measured on a DIFFERENT, folded one.\n"+
			"  %s\n"+
			"  the offset is valid for: %s\n"+
			"  it is being applied to:  %s\n"+
			"  strings.ToLower/ToUpper are NOT length-preserving — U+023A and U+023E grow from\n"+
			"  two bytes to three, and every byte of invalid UTF-8 becomes a three-byte U+FFFD —\n"+
			"  so this offset can run past the end of the operand (a slice PANIC, which in a bare\n"+
			"  worker goroutine takes the API process, the correlation engine and alert delivery\n"+
			"  with it) or land the wrong number of bytes along and return the wrong substring.\n"+
			"  Use internal/asciifold: asciifold.Index(s, marker) / asciifold.LastIndex /\n"+
			"  asciifold.Contains scan the ORIGINAL bytes, so the offset they return is always a\n"+
			"  valid index into the string you are about to slice. If the case-insensitive match\n"+
			"  is genuinely wanted only on the folded copy, slice THAT copy — never the original.",
			f.File, f.Line, f.Snippet, f.ValidOn, f.Operand)
	}
	t.Logf("swept %d files / %d function bodies / %d slice expressions; %d fold calls (%d %s), %d offset calls (%d %s), %d offsets derived from a fold",
		sw.Files, sw.Bodies, sw.SliceExprs,
		sw.FoldCalls, sw.FoldSpellings[foldSpellingC1], foldSpellingC1,
		sw.IndexCalls, sw.IndexSpellings[indexSpellingC1], indexSpellingC1,
		sw.OffsetsOnFold)
}

// ── the guard's own proof that it can still see ─────────────────────────────

// foldGuardBad is the C1 defect in each of the arrangements it has actually been
// written in. Every one of these must be found; a detector that goes quiet on
// them is a detector that would let the next one through.
const foldGuardBad = `
package fixture

import "strings"

func inline(s, marker string) string {
	return s[strings.Index(strings.ToLower(s), marker):]
}

func viaVariable(s, marker string) string {
	lower := strings.ToLower(s)
	i := strings.Index(lower, marker)
	if i < 0 {
		return ""
	}
	return s[i+len(marker):]
}

func lastIndexForm(s, marker string) string {
	folded := strings.ToUpper(s)
	i := strings.LastIndex(folded, marker)
	return s[:i]
}

func byteIndexForm(s string) byte {
	lower := strings.ToLower(s)
	i := strings.IndexByte(lower, '=')
	return s[i]
}

func acrossTwoStrings(a, b, marker string) string {
	lower := strings.ToLower(a)
	i := strings.Index(lower, marker)
	return b[i:]
}
`

// foldGuardGood is the code the fix produced, plus the shapes that are lawful
// and must NOT be flagged — otherwise the guard becomes noise and gets muted.
const foldGuardGood = `
package fixture

import (
	"strings"

	"netops/backend/internal/asciifold"
)

func fixed(s, marker string) string {
	i := asciifold.Index(s, marker)
	if i < 0 {
		return ""
	}
	return s[i+len(marker):]
}

func sliceTheFoldedCopy(s, marker string) string {
	lower := strings.ToLower(s)
	i := strings.Index(lower, marker)
	return lower[i:]
}

func sliceTheFoldedCopyInline(s, marker string) string {
	return strings.ToLower(s)[strings.Index(strings.ToLower(s), marker):]
}

func offsetOnTheOriginal(s, marker string) string {
	i := strings.Index(s, marker)
	return s[i:]
}

func noOffsetAtAll(s string) string {
	return strings.ToLower(s)[:4]
}
`

func parseFixture(t *testing.T, fset *token.FileSet, name, src string) map[string]*ast.File {
	t.Helper()
	f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return map[string]*ast.File{name: f}
}

// The POSITIVE control: the detector must fire on every planted site. This is
// what keeps a green run on the real tree meaningful — without it, "no findings"
// and "no detector" look identical.
func TestFoldSliceDetectorCatchesThePlantedDefect(t *testing.T) {
	fset := token.NewFileSet()
	sw := sweepFoldSlices(fset, parseFixture(t, fset, "bad.go", foldGuardBad))

	wantFuncs := []string{"inline", "viaVariable", "lastIndexForm", "byteIndexForm", "acrossTwoStrings"}
	if len(sw.Findings) != len(wantFuncs) {
		t.Fatalf("the detector found %d of %d planted defects: %+v", len(sw.Findings), len(wantFuncs), sw.Findings)
	}
	for _, f := range sw.Findings {
		if f.ValidOn == "" || f.Operand == "" || f.Line == 0 {
			t.Errorf("a finding must name the site and what the offset belongs to: %+v", f)
		}
	}
}

// The NEGATIVE control: the fixed idiom and the lawful shapes must stay silent.
func TestFoldSliceDetectorDoesNotFlagTheFixedIdiom(t *testing.T) {
	fset := token.NewFileSet()
	sw := sweepFoldSlices(fset, parseFixture(t, fset, "good.go", foldGuardGood))
	if len(sw.Findings) != 0 {
		t.Fatalf("the detector flagged lawful code — it would be muted: %+v", sw.Findings)
	}
	if sw.FoldCalls == 0 || sw.IndexCalls == 0 {
		t.Fatalf("the fixture exercises both recognisers; fold=%d index=%d", sw.FoldCalls, sw.IndexCalls)
	}
}

// The anti-vacuity assertion, probed LIVE: an empty sweep must be reported as
// vacuous by every one of its five checks, and a real sweep by none. Without
// this, the vacuity check could itself rot into a no-op and nobody would know.
func TestFoldSliceVacuityCheckFiresOnAnEmptySweep(t *testing.T) {
	const checks = 7
	if got := vacuityFailures(foldSweep{}); len(got) != checks {
		t.Fatalf("an empty sweep must be reported vacuous by all %d checks, got %d: %v", checks, len(got), got)
	}
	// And each check in isolation: a sweep that is complete except for one
	// count must be reported for exactly that one.
	full := func() foldSweep {
		return foldSweep{
			Files: 1, Bodies: 1, SliceExprs: 1, FoldCalls: 1, IndexCalls: 1,
			FoldSpellings:  map[string]int{foldSpellingC1: 1},
			IndexSpellings: map[string]int{indexSpellingC1: 1},
		}
	}
	for _, tc := range []struct {
		name string
		mut  func(*foldSweep)
	}{
		{"files", func(s *foldSweep) { s.Files = 0 }},
		{"bodies", func(s *foldSweep) { s.Bodies = 0 }},
		{"slices", func(s *foldSweep) { s.SliceExprs = 0 }},
		{"folds", func(s *foldSweep) { s.FoldCalls = 0 }},
		{"indexes", func(s *foldSweep) { s.IndexCalls = 0 }},
		{"the C1 fold spelling", func(s *foldSweep) { delete(s.FoldSpellings, foldSpellingC1) }},
		{"the C1 index spelling", func(s *foldSweep) { delete(s.IndexSpellings, indexSpellingC1) }},
	} {
		sw := full()
		tc.mut(&sw)
		if got := vacuityFailures(sw); len(got) != 1 {
			t.Errorf("%s: want exactly one vacuity reason, got %d: %v", tc.name, len(got), got)
		}
	}
	if got := vacuityFailures(full()); len(got) != 0 {
		t.Fatalf("a complete sweep must not be reported vacuous, got %v", got)
	}
}
