package chschema

// corr_merge_budget_test.go — the merge budget (P2,
// docs/scale/P2_CLICKHOUSE_MEMFLAT_2026-08-29.md) is a MEASURED number, not a
// preference. These tests pin it against the three places it has to agree:
// the emitted converge ALTERs, the CREATE TABLE list it must cover completely,
// and init.sql (the fresh-install authority).

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	wantCapObjects = "2147483648" // 2 GiB
	wantCapDefault = "1073741824" // 1 GiB
)

// TestCorrMergeBudgetValues: the exact measured settings, per table. A change
// to any one of them is a change to the merge cost the 2.5K leg measured, so
// it must be a deliberate edit here too.
func TestCorrMergeBudgetValues(t *testing.T) {
	want := map[string]string{
		"corr_objects":          wantCapObjects,
		"corr_signals":          wantCapDefault,
		"corr_signals_archive":  wantCapDefault,
		"corr_current":          wantCapDefault,
		"corr_edges":            wantCapDefault,
		"corr_evidence":         wantCapDefault,
		"corr_tenant_write_amp": wantCapDefault,
		"corr_path_edges":       wantCapDefault,
	}
	re := regexp.MustCompile(`^ALTER TABLE netops\.(\w+) MODIFY SETTING ` +
		`max_bytes_to_merge_at_max_space_in_pool = (\d+), ` +
		`min_age_to_force_merge_seconds = (\d+), ` +
		`min_age_to_force_merge_on_partition_only = 1$`)

	seen := map[string]bool{}
	for _, s := range CorrMergeBudgetDDL() {
		m := re.FindStringSubmatch(s)
		if m == nil {
			t.Fatalf("merge-budget statement does not match the contract shape: %q", s)
		}
		table, capBytes, age := m[1], m[2], m[3]
		if want[table] == "" {
			t.Errorf("merge budget applied to unexpected table %q", table)
			continue
		}
		if capBytes != want[table] {
			t.Errorf("%s: max_bytes_to_merge_at_max_space_in_pool = %s, want %s",
				table, capBytes, want[table])
		}
		if age != "600" {
			t.Errorf("%s: min_age_to_force_merge_seconds = %s, want 600", table, age)
		}
		if seen[table] {
			t.Errorf("%s: emitted twice", table)
		}
		seen[table] = true
	}
	for table := range want {
		if !seen[table] {
			t.Errorf("no merge budget emitted for netops.%s", table)
		}
	}
}

// TestCorrMergeBudgetCoversEveryCorrTable: the budget list may not fall behind
// the schema. A new corr_* MergeTree table with no cap can grow the same
// level-30,000 accumulated part the P2 run measured.
func TestCorrMergeBudgetCoversEveryCorrTable(t *testing.T) {
	created := regexp.MustCompile(`CREATE TABLE IF NOT EXISTS netops\.(corr_\w+)`)
	covered := corrMergeBudgetTables()
	for _, s := range CorrSchemaDDL() {
		for _, m := range created.FindAllStringSubmatch(s, -1) {
			if _, ok := covered[m[1]]; !ok {
				t.Errorf("netops.%s is created by CorrSchemaDDL but has NO merge "+
					"budget — add it to corrMergeBudgetTables()", m[1])
			}
		}
	}
}

// TestCorrMergeBudgetMatchesInitSQL: init.sql is the fresh-install authority
// and this file converges live deployments. If they disagree, a fresh install
// and an upgraded one merge differently — which is exactly the class of drift
// the 2026-07-04 virgin-host 500 came from.
func TestCorrMergeBudgetMatchesInitSQL(t *testing.T) {
	raw, err := os.ReadFile(repoFile(t, "deployment/docker/clickhouse/init.sql"))
	if err != nil {
		t.Fatalf("read init.sql: %v", err)
	}
	// Strip `--` line comments BEFORE splitting on `;`: several column comments
	// contain a semicolon, and a naive split would truncate the statement
	// before its SETTINGS clause (corr_current, corr_path_edges).
	var b strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	sql := b.String()

	// Per-table CREATE ... SETTINGS blocks, matched from the table name to the
	// statement terminator.
	for table, capBytes := range corrMergeBudgetTables() {
		start := strings.Index(sql, "CREATE TABLE IF NOT EXISTS netops."+table+"\n")
		if start < 0 {
			t.Errorf("init.sql has no CREATE for netops.%s", table)
			continue
		}
		end := strings.Index(sql[start:], ";")
		if end < 0 {
			t.Fatalf("init.sql: unterminated CREATE for netops.%s", table)
		}
		stmt := sql[start : start+end]
		wantCap := "max_bytes_to_merge_at_max_space_in_pool = " + strconv.FormatInt(capBytes, 10)
		for _, want := range []string{
			wantCap,
			"min_age_to_force_merge_seconds = 600",
			"min_age_to_force_merge_on_partition_only = 1",
		} {
			if !strings.Contains(stmt, want) {
				t.Errorf("init.sql netops.%s: missing %q (init.sql and "+
					"corr_merge_budget.go must carry identical values)", table, want)
			}
		}
	}
}

// TestCorrMergeBudgetRunsAfterItsCreates: an ALTER that precedes its CREATE
// fails on a fresh volume and stalls the converge list behind it (the
// 2026-07-09 shape). Same ordering invariant the F-58 TTL test asserts.
func TestCorrMergeBudgetRunsAfterItsCreates(t *testing.T) {
	stmts := ConvergeStmts()
	createAt := map[string]int{}
	created := regexp.MustCompile(`CREATE TABLE IF NOT EXISTS netops\.(corr_\w+)`)
	for i, s := range stmts {
		for _, m := range created.FindAllStringSubmatch(s, -1) {
			if _, seen := createAt[m[1]]; !seen {
				createAt[m[1]] = i
			}
		}
	}
	alter := regexp.MustCompile(`^ALTER TABLE netops\.(corr_\w+) MODIFY SETTING max_bytes_to_merge`)
	found := 0
	for i, s := range stmts {
		m := alter.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		found++
		c, ok := createAt[m[1]]
		if !ok {
			t.Errorf("merge-budget ALTER for netops.%s has no CREATE in the converge list", m[1])
			continue
		}
		if i < c {
			t.Errorf("netops.%s: merge-budget ALTER at %d runs BEFORE its CREATE at %d", m[1], i, c)
		}
	}
	if found != len(corrMergeBudgetTables()) {
		t.Errorf("boot converge emits %d merge-budget ALTERs, want %d — "+
			"CorrMergeBudgetDDL is not wired into ConvergeStmts",
			found, len(corrMergeBudgetTables()))
	}
}
