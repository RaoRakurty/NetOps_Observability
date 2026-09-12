// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// architecture_guards_test.go — MECHANICAL enforcement of the CLAUDE.md rules
// that the 2026-07-21 audit found violated at class scale.
//
// Why source scanning rather than prose. The audit's one-line diagnosis was
// "remediation was applied to the instance and not the class": the flows lane
// learned type coercion and applogs did not; one ClickHouse write learned to
// check its result and nineteen did not. Prose in CLAUDE.md did not stop that,
// and a reviewer cannot hold 20 sibling call sites in their head. These tests
// fail the build on the NEXT instance of each class, which is the only thing
// that actually holds a line.
//
// These run inside `go test ./...`, which is already merge-blocking in
// .github/workflows/backend-ci.yml — so adding a guard here IS adding a gate.
// See kv_paths_test.go for the first guard in this family (absolute store keys).
//
// If a guard below fires on a legitimate new pattern, fix the pattern. If the
// pattern is genuinely correct, add it to the guard's allowlist WITH a reason —
// never delete the guard.

// stripComments removes // line comments so a guard never fires on the prose
// that EXPLAINS the banned pattern — these tests document the defect they
// prevent, and quoting it must not trip them.
func stripComments(src string) string {
	lines := strings.Split(src, "\n")
	for i, l := range lines {
		if idx := strings.Index(l, "//"); idx >= 0 {
			lines[i] = l[:idx]
		}
	}
	return strings.Join(lines, "\n")
}

// goSourcesRaw returns every non-test .go file in the backend module UNMODIFIED.
//
// AST-based guards must use this, never goSources: stripComments truncates each
// line at the first "//", so any line containing a URL literal ("https://…")
// becomes syntactically broken, parser.ParseFile fails, and a guard that skips
// unparseable files silently stops covering them. That hid 54 files — 8 with
// live findings — from the conflation guard until 2026-07-27. go/parser handles
// comments natively, so there is no reason to pre-strip for an AST scan.
// (Text/regex guards still want the stripped form: a pattern in a comment is
// not a finding.)
func goSourcesRaw(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	skipDir := map[string]bool{"vendor": true, "testdata": true, "node_modules": true}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir[d.Name()] || (strings.HasPrefix(d.Name(), ".") && d.Name() != ".") {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(filepath.Clean(path))
		if rerr != nil {
			return rerr
		}
		out[filepath.ToSlash(path)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk backend module: %v", err)
	}
	if len(out) < 400 {
		t.Fatalf("only %d source files scanned — the guard is not seeing the whole module", len(out))
	}
	return out
}

// goSources returns every non-test .go file in the backend module — the root
// package AND its subpackages — with comments stripped.
//
// SCOPE (2026-07-27): this used to be os.ReadDir(".") — the root package only.
// That left 201 subpackage files (alerts/, notify/, collectors/, nms/, ai/,
// cloudconn/, appid/ …) outside EVERY structural guard in this repo, and the
// vacuity tripwire below passed comfortably on the root package's ~296 files,
// so the blind scope certified itself as healthy. Three void persist functions
// (notify/jira.go, notify/servicenow.go) and the alert engine's
// error-conflated evaluate loop all lived in that gap. The walk now descends,
// and the floor is raised so a regression to the root-only scope FAILS instead
// of silently narrowing coverage again.
func goSources(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	skipDir := map[string]bool{"vendor": true, "testdata": true, "node_modules": true}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir[d.Name()] || strings.HasPrefix(d.Name(), ".") && d.Name() != "." {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(filepath.Clean(path))
		if rerr != nil {
			return rerr
		}
		out[filepath.ToSlash(path)] = stripComments(string(b))
		return nil
	})
	if err != nil {
		t.Fatalf("walk backend module: %v", err)
	}
	// Floor set above the root-package-only count (296 as of this change) so a
	// silent narrowing of scope trips the guard rather than shrinking coverage.
	if len(out) < 400 {
		t.Fatalf("only %d source files scanned — the guard is not seeing the whole module "+
			"(root package alone is ~296; subpackages must be included)", len(out))
	}
	return out
}

// TestNoVoidSaveLocked guards F-62/F-63: a persist function that returns nothing
// makes every handler above it STRUCTURALLY unable to report a failed write, so
// the API answers 200 for data that was never stored. Nine stores shipped that
// way. A save must return an error.
func TestNoVoidSaveLocked(t *testing.T) {
	voidSave := regexp.MustCompile(`func \([^)]+\) saveLocked\(\) \{`)
	for name, src := range goSources(t) {
		if loc := voidSave.FindString(src); loc != "" {
			t.Errorf("%s: %q returns nothing.\n"+
				"A persist function that cannot fail makes its handler unable to report a failed "+
				"write — the API returns 200 for data that never reached the store (audit F-62/F-63). "+
				"Return error, roll the in-memory change back, and propagate to a 5xx.", name, loc)
		}
	}
}

// TestNoVoidPersistFuncs widens the guard above to the OTHER spellings of the
// same function.
//
// F-78 slipped past TestNoVoidSaveLocked for a purely lexical reason: the
// method was called `save()`, not `saveLocked()`. The guard had been written
// against the instance the audit happened to name. `notifyConfigStore.save()`
// returned nothing and swallowed three distinct failures — encrypt, marshal and
// kvSave — so every notification-channel PUT answered 200 for a config that was
// never written. An operator wired up paging during an incident, saw it saved,
// and lost it at the next restart.
//
// Fixing the guard is the actual lesson of the audit: fix the generator, not
// the instance. If a persist method genuinely cannot fail, add it to
// voidPersistAllowed WITH a reason.
// Keyed by METHOD NAME. Each entry was read end-to-end and is a prefix-match
// false positive, not a persist function — the verb list matches leading verbs,
// which is what makes it spelling-proof and also what makes it over-fire.
var voidPersistAllowed = map[string]string{
	"storeSession": "nms_scheduler.go — writes an in-memory map (rt.sessions) under a mutex. " +
		"'store' here means 'put in the map'; there is no durable write and nothing that can fail.",
	"storeErr": "ticketing_worker.go — a LOGGING helper that records a store error. " +
		"It is the thing that reports failures, not one that can have them.",
	"saveConnectorAndRespond": "cloud_connectors_handlers.go — an HTTP handler. It delegates the " +
		"write to persistConnector, which returns ok=false and writes the error response itself; " +
		"the handler returns early on failure. Returning nothing is correct for a handler that owns its own response.",
}

// The two ClickHouse guards that used to live here — TestClickHouseReadsCarryExecutionGuards
// and TestClickHouseHTTPWritesCheckTheirStatus — have been REPLACED by
// clickhouse_seam_test.go + chhttp/chhttp_test.go.
//
// They are worth a note because of HOW they died. Both asked whether a token
// ("chApplyGuards", "StatusCode") appeared somewhere in the same FILE. When the
// ClickHouse calls moved behind the chhttp seam — which applies execution
// guards and classifies every status, for every caller, unconditionally — both
// guards FAILED. Not on a regression: on the fix. A token-presence guard cannot
// tell "this file stopped checking" from "this file stopped needing to check",
// so it opposes the very refactor that makes the check universal.
//
// What replaces them is stronger on both axes: chhttp_test.go proves the
// BEHAVIOUR by firing real ClickHouse failures at a real client, and
// clickhouse_seam_test.go proves the STRUCTURE with an AST walk that no
// spelling change can slip past.

// persistVerbs name a method whose job is to make data durable. Matched on the
// leading verb, case-insensitively, so Save/save/SaveLocked/saveToDisk all land.
var persistVerbs = []string{"save", "persist", "flush", "store", "commit", "sync", "writeall", "writefile"}

// TestNoVoidPersistFuncs fails on any METHOD whose name starts with a persist
// verb and which returns nothing.
//
// Rewritten from a regex to an AST walk, because the regex had inherited the
// exact weakness it was created to fix. It read:
//
//	func \([^)]+\) (save|persist|flush|writeAll)(Locked)?\(\) \{
//
// which matches only zero-argument, lowercase, four-specific-verb methods on
// one line. `func (s *x) save(ctx context.Context) {`, `func (s *x) Save() {`
// and `func (s *x) commit() {` all sail past — the same lexical blind spot that
// let F-78's `save()` past TestNoVoidSaveLocked, one level up. A guard written
// against a spelling is itself an instance fix.
//
// The AST does not care about spelling, argument lists, or line breaks.
func TestNoVoidPersistFuncs(t *testing.T) {
	for path, f := range goFilesUnder(t, ".") {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue // methods only: a bare function has no store to persist to
			}
			lower := strings.ToLower(fn.Name.Name)
			matched := false
			for _, v := range persistVerbs {
				if strings.HasPrefix(lower, v) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			// Does it return anything at all?
			if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 {
				continue
			}
			if reason, ok := voidPersistAllowed[fn.Name.Name]; ok {
				if reason == "" {
					t.Errorf("%s: %s is exempted with an empty reason — state why or delete the exemption",
						path, fn.Name.Name)
				}
				continue
			}
			t.Errorf(`%s: %s() returns nothing.

  A persist function that cannot fail makes its caller unable to report a failed
  write, so the API returns 2xx for data that never reached the store (F-62,
  F-63, F-78). Return error and propagate it.

  If it genuinely cannot fail, add its NAME to voidPersistAllowed with a reason.`,
				path, fn.Name.Name)
		}
	}
}

// TestSaveResultsAreChecked guards the other half of the same class: converting
// saveLocked to return an error achieves nothing if callers drop it on the
// floor. Go permits ignoring a returned error in statement position, so the
// compiler will not catch this — only this test will.
func TestSaveResultsAreChecked(t *testing.T) {
	// A bare `s.saveLocked()` on its own line, not part of `if err := ...`.
	unchecked := regexp.MustCompile(`(?m)^\s*[a-zA-Z_][a-zA-Z0-9_.]*\.saveLocked\(\)\s*$`)
	for name, src := range goSources(t) {
		for _, m := range unchecked.FindAllString(src, -1) {
			t.Errorf("%s: %q discards the persist result.\n"+
				"Check it and propagate: `if err := s.saveLocked(); err != nil { ... }`. "+
				"An unchecked save is the F-62 defect with extra steps.", name, strings.TrimSpace(m))
		}
	}
}

// TestNoSscanfIntParsing guards the parseIntStrict trap found 2026-07-21.
//
// fmt.Sscanf("%d") is NOT strict despite how it reads: it stops at the first
// character that does not fit the verb and reports success for what it
// consumed. "1e3" parsed as 1, "100x" as 100, "5 OR 1=1" as 5 — each silently
// becoming a DIFFERENT number than the caller sent, with no error. Use
// strconv.Atoi/ParseInt, which consume the whole string or fail.
func TestNoSscanfIntParsing(t *testing.T) {
	sscanfInt := regexp.MustCompile(`Sscanf\([^)]*"%d"`)
	for name, src := range goSources(t) {
		if m := sscanfInt.FindString(src); m != "" {
			t.Errorf("%s: %q — Sscanf(\"%%d\") accepts trailing garbage and reports success, "+
				"silently yielding a different number than the caller sent. Use strconv.Atoi.", name, m)
		}
	}
}

// TestNoUnboundedResponseBodyReads guards F-27: `io.ReadAll(resp.Body)` with no
// limit reads a remote peer's response — whose size is a function of THEIR table
// / dataset, not of anything we control — straight into the heap of the process
// that also serves the API. That is the client-side shape of the #100 incident.
//
// The correct form is io.ReadAll(io.LimitReader(resp.Body, N)), which is already
// used at 25 sites in this tree. The four that were not are what this guard
// stops coming back — and it also catches the sibling-inconsistency pattern the
// audit found twice, where a capped read sits three lines above an uncapped one.
func TestNoUnboundedResponseBodyReads(t *testing.T) {
	// io.ReadAll( <something>.Body ) — with no LimitReader between them.
	unbounded := regexp.MustCompile(`io\.ReadAll\(\s*[a-zA-Z_][a-zA-Z0-9_]*\.Body\s*\)`)
	for name, src := range goSources(t) {
		for _, m := range unbounded.FindAllString(src, -1) {
			t.Errorf("%s: %q reads a response body with NO size limit.\n"+
				"Response size is controlled by the peer, not by us: an 8 GiB ClickHouse "+
				"result or a hostile endpoint becomes an OOM in the API process (audit F-27). "+
				"Use io.ReadAll(io.LimitReader(resp.Body, N)) and treat hitting N as an ERROR, "+
				"not as a short result.", name, m)
		}
	}
}

// TestWriteJSONMarshalsBeforeCommittingTheStatus guards F-21 at the shape level.
//
// `w.WriteHeader(status)` followed by `json.NewEncoder(w).Encode(body)` cannot
// report an encode failure: the status line is already on the wire, so a NaN
// produced 200 OK with an empty body at ~400 call sites and no signal anywhere.
// Marshalling first is the only ordering that keeps the failure reportable.
func TestWriteJSONMarshalsBeforeCommittingTheStatus(t *testing.T) {
	src, ok := goSources(t)["main.go"]
	if !ok {
		t.Fatal("main.go not found")
	}
	start := strings.Index(src, "func writeJSON(")
	if start == -1 {
		t.Fatal("writeJSON has moved — update this guard")
	}
	body := src[start:]
	if end := strings.Index(body, "\nfunc "); end != -1 {
		body = body[:end]
	}
	if strings.Contains(body, "json.NewEncoder(w)") {
		t.Error("writeJSON encodes straight to the ResponseWriter again.\n" +
			"Encode() marshals to an internal buffer first, so an unencodable body (NaN, ±Inf, " +
			"a broken MarshalJSON) yields a 200 with ZERO bytes and no error anywhere — the F-21 " +
			"silent empty-200. Marshal first, then WriteHeader.")
	}
	if !strings.Contains(body, "json.Marshal(body)") {
		t.Error("writeJSON no longer marshals before writing the status line (F-21)")
	}
	if !strings.Contains(body, "jsonEncodeFailures.Add(1)") {
		t.Error("writeJSON no longer counts encode failures — the defect was that they were invisible (§10)")
	}
}

// TestPreAuthRoutesAreBodyCapped guards F-32: the routes reachable with no
// credentials at all must not ride only the 50 MiB global backstop, which
// amplifies 3-5× in a struct decode and can be sent concurrently by anyone.
// Capping by ROUTE CLASS (rather than per handler) is what makes the NEXT
// public route safe without its author remembering.
func TestPreAuthRoutesAreBodyCapped(t *testing.T) {
	src, ok := goSources(t)["main.go"]
	if !ok {
		t.Fatal("main.go not found")
	}
	if !strings.Contains(src, "func requestBodyLimit(") {
		t.Fatal("requestBodyLimit is gone — the per-route body cap has been removed (F-32)")
	}
	if !strings.Contains(src, "requestBodyLimit(r.URL.Path") {
		t.Error("withBodyLimit no longer consults requestBodyLimit, so every public route is back " +
			"on the 50 MiB global cap (F-32)")
	}
	if preAuthMaxBodyBytes > 1<<20 {
		t.Errorf("preAuthMaxBodyBytes = %d — an unauthenticated body cap above 1 MiB defeats the point", preAuthMaxBodyBytes)
	}
}

// TestBoundedQueryParamsFailClosed guards F-71 at the contract level: the
// shared bounded-int query parser must reject out-of-range and malformed input
// rather than substituting the default.
//
// The behavioural cases live in flows_test.go; this asserts the SIGNATURE,
// because reverting to a single return value is exactly how the fail-open
// behaviour would come back — and it would come back silently, since every
// existing call site would still compile if the error return were dropped.
func TestBoundedQueryParamsFailClosed(t *testing.T) {
	src, ok := goSources(t)["flows.go"]
	if !ok {
		t.Fatal("flows.go not found — intQuery may have moved; update this guard")
	}
	if !strings.Contains(src, "func intQuery(r *http.Request, key string, def, min, max int) (int, error)") {
		t.Error("intQuery must return (int, error) and fail closed on out-of-range/malformed input.\n" +
			"Returning only int means an out-of-range value silently becomes the default: measured " +
			"on /api/flows/top, limit=501 returned 20 rows and never an error, so a client " +
			"paginating by doubling renders a fraction of the traffic as the whole picture (F-71).")
	}
}

// TestNoDiscardedIntParseInQueryHandling guards F-57/F-74 at the class level.
//
// Both endpoints parsed a query parameter with strconv.Atoi and DISCARDED the
// error — `if n, err := strconv.Atoi(v); err == nil { q.Limit = n }`. The
// caller's `?limit=abc` then silently became the default, and `?limit=100000`
// was silently clamped, so a client asking for MORE quietly received FEWER with
// a 200. intQuery/parsePage exist precisely so this never has to be hand-rolled
// again; a handler that hand-rolls it is reintroducing the class.
func TestNoDiscardedIntParseInQueryHandling(t *testing.T) {
	// `strconv.Atoi(...); err == nil` is the discard-the-error idiom. It is
	// only a DEFECT when the parsed string is a caller's query parameter:
	// falling back to a default for an env var or a stored cursor is correct,
	// but falling back for `?limit=` means the caller's request was not
	// honoured and they were told 200. So the guard fires only when a
	// `r.URL.Query().Get(...)` appears in the same short window.
	discarded := regexp.MustCompile(`strconv\.Atoi\([^)]*\);\s*err\s*==\s*nil`)
	const window = 3 // lines of context above the parse
	for name, src := range goSources(t) {
		lines := strings.Split(src, "\n")
		for i, l := range lines {
			m := discarded.FindString(l)
			if m == "" {
				continue
			}
			fromQuery := false
			for j := i; j >= 0 && j > i-window; j-- {
				if strings.Contains(lines[j], "r.URL.Query().Get(") {
					fromQuery = true
					break
				}
			}
			if !fromQuery {
				continue
			}
			t.Errorf("%s:%d: %q parses a QUERY PARAMETER and discards the error.\n"+
				"The caller's `?limit=abc` then silently becomes the default and they get a 200 "+
				"for a request that was never honoured (audit F-57/F-74). "+
				"Use intQuery/parsePage, which fail closed, and answer 400.", name, i+1, strings.TrimSpace(m))
		}
	}
}

// TestPaginatedReadsReportTheirTotal guards the other half of the bounded-read
// contract: an endpoint that BOUNDS a read must also state the true total, or
// the caller cannot tell a page from the whole set.
//
// Asserted at the contract level (the behavioural cases are in
// pagination_test.go) because dropping the total is exactly the change that
// would compile fine and silently reintroduce F-61/F-79.
func TestPaginatedReadsReportTheirTotal(t *testing.T) {
	// The contract moved to internal/httppage (Phase-2 W4.1); the guard follows it.
	raw, err := os.ReadFile("internal/httppage/page.go")
	if err != nil {
		t.Fatal("internal/httppage/page.go not found — the bounded-read contract may have moved; update this guard")
	}
	src := string(raw)
	for _, want := range []string{
		"func WriteHeaders(w http.ResponseWriter, p Request, returned, total int)",
		"func Complete(p Request, returned, total int) bool",
		"func RejectUnknownQuery(r *http.Request, allowed ...string) error",
		`HeaderTotalCount = "X-Total-Count"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("httppage no longer declares %q.\n"+
				"Every bounded read must report the caller's TRUE total and refuse unknown "+
				"parameters by name; without both, a truncated answer is indistinguishable "+
				"from a complete one (audit F-57/F-61/F-74/F-79).", want)
		}
	}
	// pageSliceOf must return an EMPTY page past the end, never a clamped one.
	if !strings.Contains(src, "if p.Offset >= len(rows) {") {
		t.Error("pageSliceOf must return an empty slice when the offset is past the end. " +
			"A clamped last page re-serves rows the caller already walked, so a sequential " +
			"walk never terminates.")
	}
}

// TestBlankDiscardsCarryJustification makes CLAUDE.md §5 self-enforcing:
// "no ignored errors — `_ = err` is forbidden unless justified".
//
// The 2026-08 standards audit found ~268 bare `_ =` discards of call results in
// non-test code, almost all unjustified — among them the report pipeline's
// RecordEvent phase events and the inbound-integration ledger verdicts, which
// vanished silently on store failure (fixed alongside this guard). Prose did
// not hold that line; this does.
//
// The rule: any assignment — `=` OR `:=` — whose LAST result from a CALL is an
// ERROR discarded through a blank identifier (`_ = f()`, `_, _ = f()`,
// `x, _ := f()`) must carry a REAL justification marker on the SAME line or the
// line DIRECTLY above (`// best-effort: <why>` is the house format; `discard:`,
// `//nolint`, `// #nosec`, "cannot fail" / "never fails" / "never returns an
// error" also count). If it is NOT safe to drop, do not write the comment —
// check the error and log/propagate it. The LAST position is the test because
// Go convention puts the error there: `_, err = f()` keeps the error and is
// fine; `x, _ = f()` throws it away.
//
// Two weaknesses the first version shipped with (M22), both closed here:
//   - it checked only token.ASSIGN, so the ~215 `x, _ := f()` DEFINE sites —
//     the more common way to throw an error away — were invisible; and
//   - ANY comment on/above the line counted as justification, so a section
//     header or an unrelated note silently satisfied it.
//
// Error-ness is decided WITHOUT a type-checker (a full go/types load of the
// module costs minutes and needs the go tool): the guard builds a name→
// signature map from every FuncDecl it parses (unanimous verdicts only) and
// falls back to a table of well-known stdlib callables and io-convention
// method names. Anything it cannot prove is an error (comma-ok bools like
// principalTenant/userFrom, ambiguous names) is deliberately out of scope —
// under-coverage is acceptable, spamming markers onto bool discards is not.
//
// Deliberate scope boundaries: `_ = ident` (keeping a symbol referenced) has
// no result to lose; non-call RHS (map/type-assert comma-ok) are different
// idioms with their own guards. No file allowlist: every site can carry a
// one-line comment.

// discardMarkerRe accepts the justification vocabularies in use in this repo.
// A bare unrelated comment must NOT satisfy the guard.
var discardMarkerRe = regexp.MustCompile(`(?i)(best-effort|discard:|nolint|#nosec|cannot fail|never fails|never returns an error)`)

// stdlibErrCallables maps qualified stdlib calls whose last result is an error.
// Fallback only — in-repo declarations are resolved from their own FuncDecls.
var stdlibErrCallables = map[string]bool{
	"json.Marshal": true, "json.MarshalIndent": true, "json.Unmarshal": true,
	"strconv.Atoi": true, "strconv.ParseInt": true, "strconv.ParseUint": true,
	"strconv.ParseFloat": true, "strconv.ParseBool": true,
	"io.ReadAll": true, "io.Copy": true, "io.WriteString": true,
	"time.Parse": true, "time.ParseDuration": true, "time.ParseInLocation": true,
	"os.Setenv": true, "os.Unsetenv": true, "os.Remove": true, "os.RemoveAll": true,
	"os.MkdirAll": true, "os.WriteFile": true, "os.ReadFile": true, "os.Hostname": true,
	"fmt.Sscanf": true, "fmt.Fscanf": true, "fmt.Fprintf": true, "fmt.Fprintln": true, "fmt.Fprint": true,
	"url.Parse": true, "url.QueryUnescape": true, "url.PathUnescape": true,
	"hex.DecodeString": true, "rand.Read": true,
	"net.SplitHostPort": true, "net.ParseMAC": true,
	"filepath.Rel": true, "filepath.Abs": true, "filepath.Glob": true, "filepath.Walk": true,
	"fs.WalkDir": true, "filepath.WalkDir": true,
	"mime.ParseMediaType": true,
}

// errMethodNames are io-convention method names whose last result is an error
// on every implementation this module touches (receiver-blind fallback).
var errMethodNames = map[string]bool{
	"Write": true, "Read": true, "Close": true, "Flush": true, "Decode": true,
	"Encode": true, "Rollback": true, "Commit": true, "Shutdown": true,
	"WriteString": true, "WriteByte": true, "ReadFrom": true, "WriteTo": true,
	"Sync": true, "Exec": true,
}

// lastResultIsError reports whether a FuncType's final result is literally
// `error`.
func lastResultIsError(ft *ast.FuncType) bool {
	if ft == nil || ft.Results == nil || len(ft.Results.List) == 0 {
		return false
	}
	lastField := ft.Results.List[len(ft.Results.List)-1]
	id, ok := lastField.Type.(*ast.Ident)
	return ok && id.Name == "error"
}

func TestBlankDiscardsCarryJustification(t *testing.T) {
	fset := token.NewFileSet()
	skipDir := map[string]bool{"vendor": true, "testdata": true, "node_modules": true}
	files := map[string]*ast.File{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir[d.Name()] || (strings.HasPrefix(d.Name(), ".") && d.Name() != ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			return perr // an unparseable file must FAIL the guard, not shrink its scope (see goSourcesRaw)
		}
		files[filepath.ToSlash(path)] = f
		return nil
	})
	if err != nil {
		t.Fatalf("walk backend module: %v", err)
	}
	if len(files) < 400 {
		t.Fatalf("only %d source files scanned — the guard is not seeing the whole module", len(files))
	}

	// Pass 1: name→verdict for every function/method declared in the module.
	// Receiver-blind by design: if EVERY decl sharing a name agrees on whether
	// its last result is an error, the name carries that verdict; a split name
	// is ambiguous and proves nothing.
	type verdict struct{ errLast, other int }
	sigs := map[string]*verdict{}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			v := sigs[fd.Name.Name]
			if v == nil {
				v = &verdict{}
				sigs[fd.Name.Name] = v
			}
			if lastResultIsError(fd.Type) {
				v.errLast++
			} else {
				v.other++
			}
		}
	}
	// discardedErrProven: does this call's last result provably carry an error?
	// importedAs maps a file's package qualifiers to their import paths so a
	// package-qualified call is never mistaken for a method call: `pem.Decode`
	// (last result []byte) must not match the io-convention "Decode" fallback.
	discardedErrProven := func(call *ast.CallExpr, importedAs map[string]string) bool {
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if v, ok := sigs[fn.Name]; ok {
				return v.errLast > 0 && v.other == 0
			}
			return false
		case *ast.SelectorExpr:
			if pkg, ok := fn.X.(*ast.Ident); ok {
				if path, isPkg := importedAs[pkg.Name]; isPkg {
					if is, ok := stdlibErrCallables[pkg.Name+"."+fn.Sel.Name]; ok {
						return is
					}
					// In-repo packages are covered by the parsed FuncDecls;
					// unknown external/stdlib callables prove nothing.
					if strings.HasPrefix(path, "netops/backend") {
						if v, ok := sigs[fn.Sel.Name]; ok {
							return v.errLast > 0 && v.other == 0
						}
					}
					return false
				}
			}
			if v, ok := sigs[fn.Sel.Name]; ok && (v.errLast > 0 || v.other > 0) {
				return v.errLast > 0 && v.other == 0
			}
			return errMethodNames[fn.Sel.Name]
		default:
			return false
		}
	}

	// Pass 2: find the discards.
	for path, f := range files {
		// This file's package qualifiers (import basename or alias → path).
		importedAs := map[string]string{}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			name := p[strings.LastIndex(p, "/")+1:]
			if imp.Name != nil && imp.Name.Name != "_" && imp.Name.Name != "." {
				name = imp.Name.Name
			}
			importedAs[name] = p
		}
		// Justification lines: a marker comment at the end of the discard line
		// or filling the line above it.
		justified := map[int]bool{}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if !discardMarkerRe.MatchString(c.Text) {
					continue
				}
				start := fset.Position(c.Pos()).Line
				end := fset.Position(c.End()).Line
				for l := start; l <= end; l++ {
					justified[l] = true
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || (as.Tok != token.ASSIGN && as.Tok != token.DEFINE) || len(as.Rhs) != 1 {
				return true
			}
			call, isCall := as.Rhs[0].(*ast.CallExpr)
			if !isCall {
				return true
			}
			last, ok := as.Lhs[len(as.Lhs)-1].(*ast.Ident)
			if !ok || last.Name != "_" {
				return true // the error-position result is kept
			}
			if !discardedErrProven(call, importedAs) {
				return true // not provably an error (comma-ok bool, ambiguous name)
			}
			line := fset.Position(as.Pos()).Line
			if justified[line] || justified[line-1] {
				return true
			}
			t.Errorf("%s:%d: an ERROR result is discarded with `_` and NO justification marker.\n"+
				"  CLAUDE.md §5: ignored errors are forbidden unless justified. Either check the\n"+
				"  error (log at minimum, propagate where the contract expects it), or state on\n"+
				"  this line or the line above why the failure is safe to drop, using a marker\n"+
				"  the guard recognizes (`// best-effort: <why>` is the house format).", path, line)
			return true
		})
	}
}

// TestGraphQLDoesNotDispatchOnSubstrings guards F-72's correctness half at the
// source level: the endpoint must PARSE the document. Substring dispatch cannot
// tell a selection from a comment, an argument from a typo, or a field name from
// a substring — which is how `{devices(limit:1,first:1){id}}` returned the whole
// 512-device inventory and `{bogus}` returned 200.
func TestGraphQLDoesNotDispatchOnSubstrings(t *testing.T) {
	src, ok := goSources(t)["graphql.go"]
	if !ok {
		t.Fatal("graphql.go not found — update this guard")
	}
	if !strings.Contains(src, "gqlparse.Parse(req.Query)") {
		t.Error("handleGraphQL must parse the document (gqlparse.Parse), not pattern-match it (F-72).")
	}
	// The security half: the same RBAC gate as the REST twin, which the old
	// handler skipped entirely with `claims, _ := userFrom(r.Context())`.
	if !strings.Contains(src, `s.requirePerm(w, r, "infrastructure", LevelRead)`) {
		t.Error("handleGraphQL must enforce infrastructure:read — the SAME gate handleDevices " +
			"enforces. Without it /api/graphql is a second, ungated door into the device " +
			"inventory for any authenticated principal (audit F-72, authorization bypass).")
	}
	if strings.Contains(src, "claims, _ := userFrom(") {
		t.Error("handleGraphQL is authenticating without authorizing again (F-72).")
	}
}

// TestNoFixedNameTempFileWrites guards the tracker-229 class: an "atomic" write
// that stages its data in a temp file named after the TARGET —
// `tmp := path + ".tmp"` — and then renames it into place.
//
// The rename is atomic; the temp NAME is the defect. Two writers of the same
// target share one temp path, so the loser either loses its write outright (its
// rename hits ENOENT because the winner already renamed the shared file away)
// or has its half-written bytes committed by the winner's rename. The audit
// trail lost writes this way on every restart until 7ec92152 gave
// platformdb.FileKV.Save a unique name — and eleven sibling call sites kept the
// fixed name for another year because the fix was applied to the instance and
// not to the class. This guard is the class.
//
// The house primitive is platformdb.WriteFileAtomic (os.CreateTemp in the
// target's own directory, chmod, write, rename, unlink on every failure path).
// If a store genuinely needs its own copy — a different directory mode, a
// streamed body — it must still take the temp name from os.CreateTemp.
func TestNoFixedNameTempFileWrites(t *testing.T) {
	// `<anything> + ".tmp"` / ".part" / ".new" — the target-derived temp name.
	fixedTemp := regexp.MustCompile(`\+\s*"\.(tmp|part|new)"`)
	for name, src := range goSources(t) {
		for _, m := range fixedTemp.FindAllString(src, -1) {
			t.Errorf("%s: %q derives a temp file name from its target.\n"+
				"Two concurrent writers then share one temp path: one write is LOST "+
				"(rename → ENOENT) or the two interleave into a file that is neither. "+
				"Use platformdb.WriteFileAtomic(path, data, perm), or os.CreateTemp in "+
				"the target's directory if this site needs its own copy.", name, strings.TrimSpace(m))
		}
	}
}
