package ai

// investigation_memory_test.go — the IRIS Phase B store contract. The
// invariants pinned here are the ones a leak or an unbounded growth would break:
//
//   - tenant A never observes tenant B's memory, and the cross-tenant flag is
//     the ONLY way to see across (§3a rule 1/4);
//   - a recall with NO entity key returns nothing — there is no unscoped list;
//   - the per-tenant retention cap evicts OLDEST-FIRST and is enforced per
//     tenant, so one busy tenant cannot evict another's memory;
//   - every field is clipped at write, and a row without a key or a verdict is
//     REFUSED rather than stored unrecallable;
//   - the file backend round-trips through disk with its owner intact.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func memDay(n int) time.Time {
	return time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, n)
}

func mustRecord(t *testing.T, st InvestigationStore, row InvestigationRow) InvestigationRow {
	t.Helper()
	if err := st.Record(context.Background(), row); err != nil {
		t.Fatalf("record %+v: %v", row, err)
	}
	return row
}

func TestInvestigationMemoryIsolatesTenants(t *testing.T) {
	st := NewInvestigationFileStore("")
	ctx := context.Background()
	mustRecord(t, st, InvestigationRow{
		TenantID: "acme", DeviceName: "edge-1", Verdict: "optic degraded",
		Outcome: OutcomeConfirmed, ResolvedAt: memDay(1),
	})
	mustRecord(t, st, InvestigationRow{
		// SAME device name, other tenant — the case a leak would expose.
		TenantID: "globex", DeviceName: "edge-1", Verdict: "peer misconfigured",
		Outcome: OutcomeWrong, ResolvedAt: memDay(2),
	})

	got, err := st.Recall(ctx, "acme", false, InvestigationQuery{Device: "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].TenantID != "acme" || got[0].Verdict != "optic degraded" {
		t.Fatalf("LEAK: acme's recall of a shared device name = %+v", got)
	}
	got, err = st.Recall(ctx, "globex", false, InvestigationQuery{Device: "EDGE-1"}) // case-insensitive
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].TenantID != "globex" {
		t.Fatalf("LEAK: globex's recall = %+v", got)
	}
	// An unknown tenant sees nothing at all.
	if got, _ = st.Recall(ctx, "nobody", false, InvestigationQuery{Device: "edge-1"}); len(got) != 0 {
		t.Fatalf("LEAK: an unrelated tenant recalled %+v", got)
	}
	// Cross-tenant (platform owner) sees both, newest conclusion first.
	got, err = st.Recall(ctx, "", true, InvestigationQuery{Device: "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].TenantID != "globex" {
		t.Fatalf("cross recall = %+v, want both newest-first", got)
	}
}

func TestInvestigationMemoryHasNoUnscopedList(t *testing.T) {
	st := NewInvestigationFileStore("")
	mustRecord(t, st, InvestigationRow{
		TenantID: "acme", DeviceName: "edge-1", Verdict: "optic degraded", ResolvedAt: memDay(1),
	})
	for _, q := range []InvestigationQuery{{}, {Since: memDay(0)}, {Limit: 100}} {
		got, err := st.Recall(context.Background(), "acme", false, q)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("an unkeyed recall %+v returned %d rows — there must be no unscoped list", q, len(got))
		}
	}
	// Even a CROSS-tenant caller cannot dump memory without a key.
	if got, _ := st.Recall(context.Background(), "", true, InvestigationQuery{}); len(got) != 0 {
		t.Fatalf("cross-tenant unkeyed recall returned %d rows", len(got))
	}
}

func TestInvestigationMemoryMatchesEveryEntityKey(t *testing.T) {
	st := NewInvestigationFileStore("")
	ctx := context.Background()
	mustRecord(t, st, InvestigationRow{TenantID: "acme", DeviceID: "dev-a", Verdict: "v1", ResolvedAt: memDay(1)})
	mustRecord(t, st, InvestigationRow{TenantID: "acme", Peer: "10.0.0.1", Verdict: "v2", ResolvedAt: memDay(2)})
	mustRecord(t, st, InvestigationRow{TenantID: "acme", Prefix: "203.0.113.0/24", Verdict: "v3", ResolvedAt: memDay(3)})
	mustRecord(t, st, InvestigationRow{TenantID: "acme", CorrelationID: "case-1", Verdict: "v4", ResolvedAt: memDay(4)})

	for _, tc := range []struct {
		q    InvestigationQuery
		want string
	}{
		{InvestigationQuery{Device: "dev-a"}, "v1"},
		{InvestigationQuery{Peer: "10.0.0.1"}, "v2"},
		{InvestigationQuery{Prefix: "203.0.113.0/24"}, "v3"},
		{InvestigationQuery{CorrelationID: "case-1"}, "v4"},
	} {
		got, err := st.Recall(ctx, "acme", false, tc.q)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Verdict != tc.want {
			t.Fatalf("recall %+v = %+v, want the row with verdict %q", tc.q, got, tc.want)
		}
	}
	// Keys are OR-ed and the result is newest-conclusion first.
	got, err := st.Recall(ctx, "acme", false, InvestigationQuery{Device: "dev-a", CorrelationID: "case-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Verdict != "v4" || got[1].Verdict != "v1" {
		t.Fatalf("OR-ed recall = %+v, want [v4 v1]", got)
	}
	// The window excludes older conclusions.
	got, _ = st.Recall(ctx, "acme", false, InvestigationQuery{Device: "dev-a", Since: memDay(3)})
	if len(got) != 0 {
		t.Fatalf("a conclusion older than the window was recalled: %+v", got)
	}
}

func TestInvestigationMemoryRetentionCapEvictsOldestFirst(t *testing.T) {
	st := NewInvestigationFileStore("")
	ctx := context.Background()
	total := MaxInvestigationsPerTenant + 20
	for i := 0; i < total; i++ {
		mustRecord(t, st, InvestigationRow{
			TenantID: "acme", DeviceName: "edge-1",
			Verdict:    "conclusion " + strings.Repeat("x", 1) + itoa(i),
			ResolvedAt: memDay(i),
		})
	}
	// One row for another tenant, written last: the cap is PER TENANT, so it
	// must survive acme's eviction untouched.
	mustRecord(t, st, InvestigationRow{
		TenantID: "globex", DeviceName: "edge-1", Verdict: "globex row", ResolvedAt: memDay(0),
	})

	st.mu.RLock()
	held := len(st.rows["acme"])
	other := len(st.rows["globex"])
	oldest := st.rows["acme"][0]
	st.mu.RUnlock()
	if held != MaxInvestigationsPerTenant {
		t.Fatalf("acme holds %d rows, want the cap of %d", held, MaxInvestigationsPerTenant)
	}
	if other != 1 {
		t.Fatalf("globex holds %d rows — one tenant's eviction must never touch another's", other)
	}
	if !oldest.ResolvedAt.Equal(memDay(total - MaxInvestigationsPerTenant)) {
		t.Fatalf("eviction was not oldest-first: the oldest retained row concluded %s", oldest.ResolvedAt)
	}
	// The newest conclusion is still recallable.
	got, _ := st.Recall(ctx, "acme", false, InvestigationQuery{Device: "edge-1", Limit: 1})
	if len(got) != 1 || !got[0].ResolvedAt.Equal(memDay(total-1)) {
		t.Fatalf("newest conclusion = %+v", got)
	}
}

func TestNormalizeInvestigationClipsAndRefuses(t *testing.T) {
	// Refusals: a row with no entity key, and a row with no verdict, could never
	// be recalled or narrated — both are errors, not silently stored.
	if _, err := NormalizeInvestigation(InvestigationRow{TenantID: "acme", Verdict: "v"}); err == nil {
		t.Error("a row with no entity key must be refused")
	}
	if _, err := NormalizeInvestigation(InvestigationRow{TenantID: "acme", DeviceID: "d"}); err == nil {
		t.Error("a row with no verdict must be refused")
	}

	row, err := NormalizeInvestigation(InvestigationRow{
		TenantID:   "  ACME ",
		DeviceID:   strings.Repeat("d", maxInvestigationKeyChars+50),
		Verdict:    strings.Repeat("v", maxInvestigationVerdictChars+200),
		Skills:     []string{"a", "b", "c", "d", "e", "f", ""},
		Citations:  make([]string, maxInvestigationCitations+5),
		Outcome:    InvestigationOutcome("something-else"),
		ResolvedAt: memDay(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if row.TenantID != "acme" {
		t.Errorf("tenant not normalized: %q", row.TenantID)
	}
	if len(row.DeviceID) != maxInvestigationKeyChars {
		t.Errorf("device id not clipped: %d chars", len(row.DeviceID))
	}
	if len(row.Verdict) > maxInvestigationVerdictChars+len(" …") { // clampText marks the clip
		t.Errorf("verdict not clipped: %d chars", len(row.Verdict))
	}
	if len(row.Skills) != maxInvestigationSkills {
		t.Errorf("skills not clipped: %v", row.Skills)
	}
	if row.Citations != nil {
		t.Errorf("blank citations should drop out entirely, got %v", row.Citations)
	}
	if row.Outcome != OutcomeUnknown {
		t.Errorf("an unrecognized outcome must fail CLOSED to unknown, got %q", row.Outcome)
	}
	if row.ID == "" || len(row.ID) != 36 {
		t.Errorf("a row must be stamped with a uuid, got %q", row.ID)
	}
	if row.CreatedAt.IsZero() {
		t.Error("created_at must be stamped")
	}
}

func TestOutcomePhraseWording(t *testing.T) {
	// The exact operator wording is a product contract: "confirmed" must never
	// read as "verified", and an unrated memory must never read as either.
	for outcome, want := range map[InvestigationOutcome]string{
		OutcomeConfirmed:                "operator confirmed",
		OutcomeWrong:                    "operator marked wrong",
		OutcomeUnknown:                  "unverified",
		InvestigationOutcome("garbage"): "unverified",
	} {
		if got := OutcomePhrase(outcome); got != want {
			t.Errorf("OutcomePhrase(%q) = %q, want %q", outcome, got, want)
		}
	}
}

func TestInvestigationFileStoreRoundTripsThroughDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "iris_investigations.json")
	st := NewInvestigationFileStore(path)
	mustRecord(t, st, InvestigationRow{
		TenantID: "acme", DeviceName: "edge-1", Peer: "10.0.0.1",
		Skills: []string{"bgp-session-down"}, Verdict: "hold timer expired",
		Citations: []string{"diagsig:sig-1"}, Outcome: OutcomeConfirmed, ResolvedAt: memDay(1),
	})
	mustRecord(t, st, InvestigationRow{
		TenantID: "globex", DeviceName: "edge-1", Verdict: "unrelated", ResolvedAt: memDay(1),
	})
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the store did not persist: %v", err)
	}

	reloaded := NewInvestigationFileStore(path)
	got, err := reloaded.Recall(context.Background(), "acme", false, InvestigationQuery{Device: "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Verdict != "hold timer expired" || got[0].Peer != "10.0.0.1" {
		t.Fatalf("reload lost the row: %+v", got)
	}
	if got[0].Outcome != OutcomeConfirmed || len(got[0].Skills) != 1 || len(got[0].Citations) != 1 {
		t.Fatalf("reload lost provenance: %+v", got[0])
	}
	// Ownership survives the round trip — the file holds every tenant, so a lost
	// tenant_id would be a cross-tenant leak on the next boot.
	if got[0].TenantID != "acme" {
		t.Fatalf("reloaded row lost its owner: %+v", got[0])
	}
	if other, _ := reloaded.Recall(context.Background(), "globex", false, InvestigationQuery{Device: "edge-1"}); len(other) != 1 || other[0].Verdict != "unrelated" {
		t.Fatalf("globex's own row did not survive: %+v", other)
	}
}

// itoa keeps the retention test readable without pulling strconv into it.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
