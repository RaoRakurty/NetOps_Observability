package incident

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Moved from the integrator with the store (filterSQL is package contract).
func TestIncidentSeverityFilterRejectsUnknownInsteadOfSubstituting(t *testing.T) {
	// Every value the audit probed with. None is on the ladder; each used to
	// become the `info` predicate.
	for _, bad := range []string{"warning", "WARN", "bogus", "warn", "sev1", "0", " "} {
		if ValidSeverity(bad) {
			t.Errorf("ValidSeverity(%q) = true — it is not on the ladder %v", bad, Severities)
		}
		if _, _, err := filterSQL(Query{Severity: bad}); err == nil {
			t.Errorf("filterSQL(severity=%q) built a predicate instead of failing — "+
				"this is the F-74 substitution: the caller's filter silently becomes a DIFFERENT one", bad)
		}
	}
	// The ladder itself still works, case-insensitively, and canonicalises.
	for _, good := range []string{"info", "LOW", "Medium", "high", "CRITICAL"} {
		if !ValidSeverity(good) {
			t.Fatalf("ValidSeverity(%q) = false", good)
		}
		where, args, err := filterSQL(Query{Severity: good})
		if err != nil {
			t.Fatalf("severity=%q: %v", good, err)
		}
		if !strings.Contains(where, "severity = $1") {
			t.Fatalf("severity=%q produced WHERE %q", good, where)
		}
		if got := fmt.Sprint(args[0]); got != strings.ToLower(good) {
			t.Fatalf("severity=%q bound %q, want the canonical lowercase form", good, got)
		}
	}
	// The status filter had the same shape of hole: an unknown status was
	// passed straight into SQL and silently matched nothing.
	if _, _, err := filterSQL(Query{Status: "in-progress"}); err == nil {
		t.Error("an unknown status must fail closed, not silently match zero rows")
	}
}

// TestIncidentFilterSQLSharedByListAndCount pins the invariant that makes the
// reported total trustworthy: the page and its total are built from the SAME
// predicate.
func TestIncidentFilterSQLSharedByListAndCount(t *testing.T) {
	q := Query{Status: StatusOpen, Severity: "high", Before: time.Now().UTC(), Limit: 10, Offset: 20}
	where, args, err := filterSQL(q)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 3 || !strings.Contains(where, "status = $1") ||
		!strings.Contains(where, "severity = $2") || !strings.Contains(where, "last_seen_at < $3") {
		t.Fatalf("filter = %q args=%d", where, len(args))
	}
	// Limit/offset must NOT be part of the shared filter — that is precisely
	// what would make Count return the page size instead of the total.
	if strings.Contains(strings.ToUpper(where), "LIMIT") || strings.Contains(strings.ToUpper(where), "OFFSET") {
		t.Fatalf("the shared filter leaked paging into the count: %q", where)
	}
}

// ── the HTTP boundary ────────────────────────────────────────────────────────
