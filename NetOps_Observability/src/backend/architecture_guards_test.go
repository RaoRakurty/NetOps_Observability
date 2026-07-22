package main

import (
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

// goSources returns every non-test .go file in this package directory, with
// comments stripped.
func goSources(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		out[name] = stripComments(string(b))
	}
	if len(out) < 50 {
		t.Fatalf("only %d source files scanned — the guard is not seeing the package", len(out))
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

// TestClickHouseReadsCarryExecutionGuards guards the other half of F-27: a Go
// client timeout does NOT stop a ClickHouse query. Without max_execution_time
// and cancel_http_readonly_queries_on_client_close, every abandoned read keeps
// running server-side, holding memory, while the caller retries on the next
// poll — the compounding shape of the 2026-07-09 incident.
//
// Rather than trying to match every call site, this asserts the shared helper
// exists and that the read paths route through it.
func TestClickHouseReadsCarryExecutionGuards(t *testing.T) {
	srcs := goSources(t)
	guard, ok := srcs["ch_workload.go"]
	if !ok || !strings.Contains(guard, "func chApplyGuards(") {
		t.Fatal("chApplyGuards is gone from ch_workload.go — without it no ClickHouse read carries " +
			"max_execution_time / cancel_http_readonly_queries_on_client_close, and an abandoned query " +
			"runs to completion server-side (F-27)")
	}
	for _, want := range []string{"max_execution_time", "cancel_http_readonly_queries_on_client_close"} {
		if !strings.Contains(guard, want) {
			t.Errorf("chApplyGuards no longer sets %s", want)
		}
	}
	// Every file that builds a ClickHouse read URL must stamp the guards.
	for _, name := range []string{"correlations.go", "report_scheduler.go", "appid_fusion_store.go"} {
		if src, ok := srcs[name]; ok && !strings.Contains(src, "chApplyGuards(") {
			t.Errorf("%s builds a ClickHouse query but never calls chApplyGuards — "+
				"its queries outlive the caller that gave up on them (F-27)", name)
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
	src, ok := goSources(t)["pagination.go"]
	if !ok {
		t.Fatal("pagination.go not found — the bounded-read contract may have moved; update this guard")
	}
	for _, want := range []string{
		"func writePageHeaders(w http.ResponseWriter, p pageRequest, returned, total int)",
		"func pageComplete(p pageRequest, returned, total int) bool",
		"func rejectUnknownQuery(r *http.Request, allowed ...string) error",
		`headerTotalCount = "X-Total-Count"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("pagination.go no longer declares %q.\n"+
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

// TestClickHouseHTTPWritesCheckTheirStatus guards F-56. A ClickHouse write that
// builds an INSERT and never looks at resp.StatusCode discards 400/401/500
// identically to success — no log, no counter, no retry.
func TestClickHouseHTTPWritesCheckTheirStatus(t *testing.T) {
	roots := []string{".", "collectors"}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("read %s: %v", root, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			b, err := os.ReadFile(filepath.Clean(filepath.Join(root, name)))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			src := stripComments(string(b))
			if !strings.Contains(src, "INSERT INTO netops.") {
				continue
			}
			if !strings.Contains(src, "StatusCode") && !strings.Contains(src, "chExecErr") {
				t.Errorf("%s/%s builds an `INSERT INTO netops.*` but never inspects the "+
					"response status (nor delegates to chExecErr).\n"+
					"A 400 from one unknown key, a 401 from a rotated password and a 500 all "+
					"look exactly like success — the write vanishes with no log and no counter "+
					"(audit F-56).", root, name)
			}
		}
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
	if !strings.Contains(src, "parseGraphQL(req.Query)") {
		t.Error("handleGraphQL must parse the document (parseGraphQL), not pattern-match it (F-72).")
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
