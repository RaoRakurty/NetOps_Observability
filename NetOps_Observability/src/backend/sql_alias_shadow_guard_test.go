package backend

// sql_alias_shadow_guard_test.go — the STRUCTURAL guard for the alias-shadowing
// class (tracker 200; the bug fixed twice by hand in dda24f37 and 1c402b5c).
//
// THE CLASS. ClickHouse resolves a SELECT alias INSIDE the WHERE / PREWHERE /
// GROUP BY / HAVING / ORDER BY / LIMIT n BY of the SAME statement, and the alias
// WINS over a real column of that name. So a projection that aliases a CONVERTED
// expression back onto the column it converted —
//
//	SELECT toString(window_start) AS window_start ... WHERE window_start >= now()
//
// silently re-points every such clause at the converted value. Two outcomes:
// a hard `Code: 386 NO_COMMON_TYPE` / `Code: 43 ILLEGAL_TYPE_OF_ARGUMENT` when
// the types cannot be reconciled (the undetermined-frequency endpoint answered
// 502 for its whole life this way), or — worse — a SILENT mis-sort when the
// converted text happens to order like the typed column today and stops doing so
// tomorrow.
//
// WHY A GUARD AND NOT THREE UNIT TESTS. Both hand fixes were found only after the
// server refused a statement in production. The three per-site regressions below
// pin the sites we know about; THIS test finds the ones nobody has looked at yet,
// including in SQL built by concatenation (a plain string-literal scan cannot see
// `SELECT ` + chschema.ISO("ts") + ` AS ts`, which is exactly how every site in
// this repo is written).
//
// HOW. The scanner parses each non-test .go file, folds every string-concatenation
// chain into ONE rendered statement (literals verbatim; chschema.ISO(<literal>)
// expanded to the real SQL it emits; every other runtime piece replaced by an
// opaque placeholder), and applies ClickHouse's resolution rule to the result. An
// alias is a violation only when its defining expression is NOT the bare column of
// the same name — `evidence_missing AS evidence_missing` and `o.ts AS ts` are
// type-preserving no-ops and stay legal — and the name is then referenced
// UNQUALIFIED in a clause aliases resolve in. A table-qualified reference
// (`f.ts`) is never resolved through an alias, which is the sanctioned fix where
// the alias name is also the served wire field.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// sqlPlaceholder stands in for a runtime fragment (a variable, a helper call, a
// formatted literal). It is deliberately not a legal identifier, so it can never
// be mistaken for "the bare column of the same name".
const sqlPlaceholder = "<<expr>>"

// renderSQLExpr folds a Go expression into the SQL text it contributes.
// Concatenation chains are joined; string literals are unquoted verbatim;
// chschema.ISO("x") is expanded to what it actually emits (so the guard sees the
// real conversion, not a placeholder); anything else becomes sqlPlaceholder.
func renderSQLExpr(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			return renderSQLExpr(v.X) + renderSQLExpr(v.Y)
		}
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			if s, err := strconv.Unquote(v.Value); err == nil {
				return s
			}
		}
	case *ast.ParenExpr:
		return renderSQLExpr(v.X)
	case *ast.CallExpr:
		// chschema.ISO(<string literal>) → the exact SQL the helper emits.
		if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ISO" && len(v.Args) == 1 {
			if lit, ok := v.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if arg, err := strconv.Unquote(lit.Value); err == nil {
					return "concat(replaceOne(toString(" + arg + ", 'UTC'), ' ', 'T'), 'Z')"
				}
			}
		}
	}
	return sqlPlaceholder
}

// renderedSQLStatements returns every folded string-concatenation chain (and
// standalone raw literal) in a file that looks like a SELECT statement. Only the
// TOP of a chain is rendered, so a 6-literal query yields one statement, not six.
func renderedSQLStatements(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Clean(path), nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	inner := map[ast.Expr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if b, ok := n.(*ast.BinaryExpr); ok && b.Op == token.ADD {
			inner[b.X], inner[b.Y] = true, true
		}
		return true
	})
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		e, ok := n.(ast.Expr)
		if !ok || inner[e] {
			return true
		}
		switch e.(type) {
		case *ast.BinaryExpr, *ast.BasicLit:
		default:
			return true
		}
		s := renderSQLExpr(e)
		if strings.Contains(s, "SELECT") {
			out = append(out, s)
		}
		return true
	})
	return out
}

// projectionAliases returns the `<expr> AS <name>` pairs of ONE scope's SELECT
// list. The list is delimited by the scope's first SELECT and its matching
// top-level FROM, then split on DEPTH-0 commas — a line-anchored regex cannot do
// this (`... AS ts, id, kind` puts three columns on one line, and
// `concat(a, b) AS x` puts commas inside one).
func projectionAliases(scope string) [][2]string {
	upper := strings.ToUpper(scope)
	sel := regexp.MustCompile(`(?i)\bSELECT\b`).FindStringIndex(scope)
	if sel == nil {
		return nil
	}
	start := sel[1]
	end := len(scope)
	depth := 0
	for i := start; i < len(scope); i++ {
		switch scope[i] {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth == 0 && strings.HasPrefix(upper[i:], "FROM") &&
			(i == 0 || !isWordByte(scope[i-1])) &&
			(i+4 >= len(scope) || !isWordByte(scope[i+4])) {
			end = i
			break
		}
	}
	var out [][2]string
	depth = 0
	item := strings.Builder{}
	flush := func() {
		txt := strings.TrimSpace(item.String())
		item.Reset()
		if txt == "" {
			return
		}
		m := regexp.MustCompile(`(?is)^(.+?)\s+AS\s+([A-Za-z_][A-Za-z0-9_]*)$`).FindStringSubmatch(txt)
		if m == nil {
			return
		}
		out = append(out, [2]string{strings.Join(strings.Fields(m[1]), " "), m[2]})
	}
	for i := start; i < end; i++ {
		switch scope[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				flush()
				continue
			}
		}
		item.WriteByte(scope[i])
	}
	flush()
	return out
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// aliasResolvingClauses are the clauses ClickHouse resolves SELECT aliases in.
var aliasResolvingClauses = []string{"WHERE", "PREWHERE", "GROUP BY", "HAVING", "ORDER BY", "LIMIT 1 BY", "LIMIT 2 BY"}

// clauseKeyword ends a clause as reliably as it starts one.
var reClauseBoundary = regexp.MustCompile(`(?i)\b(SELECT|FROM|WHERE|PREWHERE|GROUP BY|HAVING|ORDER BY|LIMIT|SETTINGS|FORMAT|UNION|WITH|JOIN|ON)\b`)

// splitSQLScopes returns one text per QUERY SCOPE. Alias resolution is
// per-scope: an alias defined in an outer projection is NOT visible inside a
// derived table / CTE / IN-subquery, and vice versa. So each parenthesised group
// that contains a SELECT is lifted out as its own scope and BLANKED from its
// parent. Parens that are not subqueries (function calls, tuple predicates such
// as the `(created_at, correlation_id) > (...)` cursor) are left intact — they
// are part of their scope's clause text and must stay checkable.
func splitSQLScopes(sql string) []string {
	out := []string{}
	var walk func(string)
	walk = func(text string) {
		var b strings.Builder
		for i := 0; i < len(text); i++ {
			if text[i] != '(' {
				b.WriteByte(text[i])
				continue
			}
			depth, j := 1, i+1
			for ; j < len(text) && depth > 0; j++ {
				switch text[j] {
				case '(':
					depth++
				case ')':
					depth--
				}
			}
			if depth != 0 { // unbalanced (a fragment); keep the tail as-is
				b.WriteString(text[i:])
				break
			}
			body := text[i+1 : j-1]
			if strings.Contains(strings.ToUpper(body), "SELECT") {
				walk(body)         // the subquery is its own scope
				b.WriteString(" ") // and is invisible to its parent's aliases
			} else {
				b.WriteString(text[i:j])
			}
			i = j - 1
		}
		out = append(out, b.String())
	}
	walk(sql)
	return out
}

// aliasResolvingText returns the concatenation of every alias-resolving clause in
// the statement — the text an alias would be substituted into.
func aliasResolvingText(sql string) string {
	var b strings.Builder
	upper := strings.ToUpper(sql)
	for _, kw := range aliasResolvingClauses {
		for i := 0; ; {
			j := strings.Index(upper[i:], kw)
			if j < 0 {
				break
			}
			start := i + j + len(kw)
			rest := sql[start:]
			if m := reClauseBoundary.FindStringIndex(rest); m != nil {
				rest = rest[:m[0]]
			}
			b.WriteString(" " + rest + " ")
			i = start
		}
	}
	return b.String()
}

// bareRef reports whether name appears in text as an UNQUALIFIED column
// reference — not `t.name`, not part of a longer identifier, and not inside a
// single-quoted SQL string literal.
func bareRef(text, name string) bool {
	stripped := regexp.MustCompile(`'[^']*'`).ReplaceAllString(text, "''")
	re := regexp.MustCompile(`(^|[^.\w])` + regexp.QuoteMeta(name) + `\b`)
	return re.MatchString(stripped)
}

// refsColumn reports whether the defining expression reads a column CALLED name
// — bare (`toString(ts)`) or table-qualified (`any(o.created_at)`). Both make the
// alias a re-use of that column's name; only a qualifier in the CLAUSE escapes
// alias resolution, never one in the projection.
func refsColumn(expr, name string) bool {
	stripped := regexp.MustCompile(`'[^']*'`).ReplaceAllString(expr, "''")
	return regexp.MustCompile(`(^|[^\w])([A-Za-z_][A-Za-z0-9_]*\.)?` + regexp.QuoteMeta(name) + `\b`).MatchString(stripped)
}

// aliasShadowFindings applies ClickHouse's resolution rule to one rendered
// statement and returns a message per violating alias.
func aliasShadowFindings(sql string) []string {
	var all []string
	for _, scope := range splitSQLScopes(sql) {
		all = append(all, aliasShadowFindingsInScope(scope)...)
	}
	return all
}

func aliasShadowFindingsInScope(sql string) []string {
	clauses := aliasResolvingText(sql)
	if strings.TrimSpace(clauses) == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, pair := range projectionAliases(sql) {
		expr, alias := pair[0], pair[1]
		if seen[alias] {
			continue
		}
		// A no-op self-alias preserves the type and is legal: `x AS x`, and the
		// qualified rename `o.x AS x` (still the raw column, still typed).
		if expr == alias || strings.HasSuffix(expr, "."+alias) {
			continue
		}
		// THE class is narrow: an alias re-using the name of the column it
		// CONVERTS. A freshly-named computed column (`sum(bytes) AS bytes_total`,
		// `least(a,b) AS lo`) introduces a name no column has, so a clause that
		// references it could never have meant anything else — that is ordinary
		// SQL, not shadowing. Require the alias to appear as a bare identifier
		// INSIDE its own defining expression.
		if !refsColumn(expr, alias) {
			continue
		}
		if bareRef(clauses, alias) {
			seen[alias] = true
			out = append(out, "SELECT alias `"+alias+"` re-uses the name of the column it converts (`"+
				collapse(expr)+"`) and is referenced UNQUALIFIED in a clause ClickHouse resolves aliases in — "+
				"the clause binds the CONVERTED value, not the typed column")
		}
	}
	return out
}

func collapse(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 90 {
		s = s[:90] + "…"
	}
	return s
}

// backendGoTrees are the source roots the guard sweeps: the flat backend package
// and every ClickHouse-touching subpackage under it.
func backendGoTrees(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "vendor" || info.Name() == "testdata" || info.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 50 {
		t.Fatalf("the alias-shadow sweep found only %d sources — the walk is broken, not the code", len(files))
	}
	return files
}

// TestNoSQLBuilderShadowsATypedColumn is the generic guard. It must find NOTHING:
// every alias-shadowing site in the tree is either fixed or, if a new one is
// genuinely safe, must be made safe by TABLE-QUALIFYING the clause reference
// (which alias resolution does not touch) rather than by exempting it here.
func TestNoSQLBuilderShadowsATypedColumn(t *testing.T) {
	total := 0
	for _, path := range backendGoTrees(t) {
		for _, sql := range renderedSQLStatements(t, path) {
			for _, msg := range aliasShadowFindings(sql) {
				total++
				t.Errorf("%s: %s\n\nrendered statement:\n%s", path, msg, sql)
			}
		}
	}
	if total > 0 {
		t.Logf("%d alias-shadowing site(s) — see dda24f37 / 1c402b5c for the two sanctioned fixes "+
			"(rename the alias when the name is internal; table-qualify the clause when the name is the wire field)", total)
	}
}

// TestAliasShadowGuardCatchesTheKnownBugs is the guard's own self-check: it is
// fed the EXACT projections the live ClickHouse server rejected, and must flag
// every one of them. Without this, a guard that silently goes blind (a regex
// drifts, the folding stops folding) reports a clean tree forever.
func TestAliasShadowGuardCatchesTheKnownBugs(t *testing.T) {
	mutants := map[string]string{
		"1c402b5c undetermined-frequency (386)": `
SELECT toString(correlation_id) AS correlation_id,
       concat(replaceOne(toString(window_start, 'UTC'), ' ', 'T'), 'Z') AS window_start,
       evidence_missing AS evidence_missing
  FROM netops.corr_objects_latest
 WHERE verdict_tier = 'undetermined'
   AND window_start >= now() - INTERVAL 604800 SECOND
 ORDER BY window_start DESC`,
		"dda24f37 timeintel pick (43)": `
SELECT toString(correlation_id) AS correlation_id,
       concat(replaceOne(toString(created_at, 'UTC'), ' ', 'T'), 'Z') AS created_at
  FROM netops.corr_current FINAL
 WHERE (created_at, correlation_id) > (toDateTime64('x',3), toUUID('y'))
 ORDER BY created_at ASC, correlation_id ASC`,
		"tracker 200 findings (latent mis-sort)": `
SELECT concat(replaceOne(toString(ts, 'UTC'), ' ', 'T'), 'Z') AS ts, id, kind
  FROM netops.findings
 ORDER BY ts DESC`,
		"tracker 200 pathgraph observations": `
SELECT observation_id, concat(replaceOne(toString(observed_at, 'UTC'), ' ', 'T'), 'Z') AS observed_at, method
  FROM netops.path_observations FINAL
 WHERE observation_id = 'x'
 ORDER BY observed_at DESC`,
		"tracker 200 app-correlations aggregate": `
SELECT toString(o.correlation_id) AS correlation_id,
       concat(replaceOne(toString(any(o.created_at), 'UTC'), ' ', 'T'), 'Z') AS created_at
  FROM picked AS o
 GROUP BY o.correlation_id
 ORDER BY created_at DESC`,
	}
	for name, sql := range mutants {
		if got := aliasShadowFindings(sql); len(got) == 0 {
			t.Errorf("the guard is BLIND to %s — it would not have caught the bug it exists for:\n%s", name, sql)
		}
	}

	// And it must NOT fire on the sanctioned fixes, or the next author will
	// "fix" the fix.
	safe := map[string]string{
		"non-shadowing rename (1c402b5c shape)": `
SELECT toString(correlation_id) AS correlation_id_s,
       concat(replaceOne(toString(window_start, 'UTC'), ' ', 'T'), 'Z') AS window_start_iso,
       evidence_missing AS evidence_missing
  FROM netops.corr_current FINAL
 WHERE verdict_tier = 'undetermined'
   AND window_start >= now() - INTERVAL 604800 SECOND
 ORDER BY window_start DESC`,
		"table-qualified clause (tracker 200 findings fix)": `
SELECT concat(replaceOne(toString(f.ts, 'UTC'), ' ', 'T'), 'Z') AS ts, id, kind
  FROM netops.findings AS f
 ORDER BY f.ts DESC`,
		"aggregate ORDER BY (tracker 200 app-correlations fix)": `
SELECT concat(replaceOne(toString(any(o.created_at), 'UTC'), ' ', 'T'), 'Z') AS created_at
  FROM picked AS o
 GROUP BY o.correlation_id
 ORDER BY any(o.created_at) DESC`,
		"alias not referenced in a resolving clause (hopsOf)": `
SELECT hop_index, concat(replaceOne(toString(observed_at, 'UTC'), ' ', 'T'), 'Z') AS observed_at
  FROM netops.path_hops FINAL
 WHERE observation_id = 'x'
 ORDER BY hop_index ASC`,
	}
	for name, sql := range safe {
		if got := aliasShadowFindings(sql); len(got) > 0 {
			t.Errorf("the guard false-positives on %s: %v\n%s", name, got, sql)
		}
	}
}

// ── tracker 200: the four named sites, pinned individually ───────────────────
//
// The generic sweep above would catch a regression at any of these, but it
// reports "an alias shadows a column" — these say WHICH fix each site carries
// and why, so a future edit that reverts one fails with the reason attached.
// (The sites are handler-inline SQL, not lifted builders, so each is asserted
// against the statement the source actually renders — the same folding the
// sweep uses.)

// fileStatements renders one source file's SQL and returns the statements that
// mention a marker, failing loudly if the marker is gone (a moved query must
// re-point its test, never silently stop being covered).
func fileStatements(t *testing.T, path, marker string) []string {
	t.Helper()
	var out []string
	for _, sql := range renderedSQLStatements(t, path) {
		if strings.Contains(sql, marker) {
			out = append(out, sql)
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s: no rendered SQL contains %q — the query moved and this regression stopped covering it", path, marker)
	}
	return out
}

func TestTracker200FindingsOrdersTheTypedColumn(t *testing.T) {
	for _, sql := range fileStatements(t, "flows.go", "netops.findings") {
		if !strings.Contains(sql, "FROM netops.findings AS f") || !strings.Contains(sql, "ORDER BY f.ts DESC") {
			t.Errorf("findings read must sort the TABLE-QUALIFIED ts (the alias `ts` is the wire field and cannot be renamed):\n%s", sql)
		}
		if strings.Contains(sql, "ORDER BY ts DESC") {
			t.Errorf("findings read sorts the ISO String alias, not the DateTime column:\n%s", sql)
		}
		if len(aliasShadowFindings(sql)) != 0 {
			t.Errorf("findings read still shadows: %v", aliasShadowFindings(sql))
		}
	}
}

func TestTracker200TunnelsOrdersTheTypedColumn(t *testing.T) {
	for _, sql := range fileStatements(t, "flows.go", "netops.tunnels") {
		if !strings.Contains(sql, "FROM netops.tunnels AS t") || !strings.Contains(sql, "ORDER BY t.ts DESC") {
			t.Errorf("tunnels read must sort the TABLE-QUALIFIED ts:\n%s", sql)
		}
		if !strings.Contains(sql, "LIMIT 1 BY id") {
			t.Errorf("tunnels read lost its per-id fold:\n%s", sql)
		}
		if len(aliasShadowFindings(sql)) != 0 {
			t.Errorf("tunnels read still shadows: %v", aliasShadowFindings(sql))
		}
	}
}

func TestTracker200PathObservationsUseANonShadowingAlias(t *testing.T) {
	stmts := fileStatements(t, "pathgraph/store.go", "FROM netops.path_observations FINAL")
	for _, sql := range stmts {
		if !strings.Contains(sql, "AS observed_at_iso") {
			t.Errorf("path_observations read must project the ISO conversion under a DISTINCT name:\n%s", sql)
		}
		if !strings.Contains(sql, "ORDER BY observed_at DESC") {
			t.Errorf("path_observations read must sort the raw DateTime64 column:\n%s", sql)
		}
		if len(aliasShadowFindings(sql)) != 0 {
			t.Errorf("path_observations read still shadows: %v", aliasShadowFindings(sql))
		}
	}
	// The OTHER half of a half-done fix: renaming the projection while the row
	// scan still reads the old key serves a zero time for every observation.
	src, err := os.ReadFile(filepath.Clean("pathgraph/store.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `parseCHTime(r["observed_at_iso"])`) {
		t.Error("pathgraph/store.go: the observation row scan does not read observed_at_iso — the rename is half done and every ObservedAt decodes to the zero time")
	}
}

func TestTracker200AppCorrelationsOrdersTheTypedAggregate(t *testing.T) {
	for _, sql := range fileStatements(t, "cloud_handlers.go", "corr_signals_archive") {
		if !strings.Contains(sql, "ORDER BY any(o.created_at) DESC") {
			t.Errorf("app-correlations read must sort the raw DateTime64 aggregate, not the ISO String alias `created_at` (which is the wire field):\n%s", sql)
		}
		if strings.Contains(sql, "\n ORDER BY created_at DESC") {
			t.Errorf("app-correlations read sorts the ISO String alias:\n%s", sql)
		}
		if len(aliasShadowFindings(sql)) != 0 {
			t.Errorf("app-correlations read still shadows: %v", aliasShadowFindings(sql))
		}
	}
}
