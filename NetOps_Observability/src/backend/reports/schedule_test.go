package reports

import (
	"testing"
	"time"
)

func mustLoad(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Skipf("tz database unavailable for %s: %v", name, err)
	}
	return loc
}

func TestNextFireDaily(t *testing.T) {
	utc := time.UTC
	r := Recurrence{Hour: 7, Minute: 0} // daily 07:00 UTC
	// Before today's fire -> today 07:00.
	after := time.Date(2026, 6, 2, 3, 0, 0, 0, utc)
	got, ok := r.NextFire(after)
	if !ok || !got.Equal(time.Date(2026, 6, 2, 7, 0, 0, 0, utc)) {
		t.Fatalf("daily before-fire: got %v ok=%v", got, ok)
	}
	// Exactly at the fire instant -> strictly after, so next day.
	got, _ = r.NextFire(time.Date(2026, 6, 2, 7, 0, 0, 0, utc))
	if !got.Equal(time.Date(2026, 6, 3, 7, 0, 0, 0, utc)) {
		t.Fatalf("daily at-fire: got %v", got)
	}
	// After today's fire -> tomorrow, including month rollover.
	got, _ = r.NextFire(time.Date(2026, 6, 30, 9, 0, 0, 0, utc))
	if !got.Equal(time.Date(2026, 7, 1, 7, 0, 0, 0, utc)) {
		t.Fatalf("daily month-rollover: got %v", got)
	}
}

func TestNextFireWeekly(t *testing.T) {
	utc := time.UTC
	r := Recurrence{Hour: 7, Minute: 0, Weekday: "mon"} // Mondays 07:00 UTC
	// 2026-06-02 is a Tuesday -> next Monday is 2026-06-08.
	got, ok := r.NextFire(time.Date(2026, 6, 2, 12, 0, 0, 0, utc))
	if !ok || !got.Equal(time.Date(2026, 6, 8, 7, 0, 0, 0, utc)) {
		t.Fatalf("weekly: got %v ok=%v", got, ok)
	}
	if got.Weekday() != time.Monday {
		t.Fatalf("weekly weekday: got %v", got.Weekday())
	}
	// On the target weekday but before the time -> same day.
	got, _ = r.NextFire(time.Date(2026, 6, 8, 3, 0, 0, 0, utc))
	if !got.Equal(time.Date(2026, 6, 8, 7, 0, 0, 0, utc)) {
		t.Fatalf("weekly same-day-before: got %v", got)
	}
	// On the target weekday after the time -> next week.
	got, _ = r.NextFire(time.Date(2026, 6, 8, 8, 0, 0, 0, utc))
	if !got.Equal(time.Date(2026, 6, 15, 7, 0, 0, 0, utc)) {
		t.Fatalf("weekly same-day-after: got %v", got)
	}
}

func TestNextFireMonthly(t *testing.T) {
	utc := time.UTC
	r := Recurrence{Hour: 9, Minute: 30, DOM: 15} // 15th of month 09:30 UTC
	got, ok := r.NextFire(time.Date(2026, 6, 2, 0, 0, 0, 0, utc))
	if !ok || !got.Equal(time.Date(2026, 6, 15, 9, 30, 0, 0, utc)) {
		t.Fatalf("monthly: got %v ok=%v", got, ok)
	}
	// After this month's day -> next month.
	got, _ = r.NextFire(time.Date(2026, 6, 20, 0, 0, 0, 0, utc))
	if !got.Equal(time.Date(2026, 7, 15, 9, 30, 0, 0, utc)) {
		t.Fatalf("monthly next-month: got %v", got)
	}
}

func TestNextFireMonthlyClampShortMonth(t *testing.T) {
	utc := time.UTC
	r := Recurrence{Hour: 0, Minute: 0, DOM: 31} // "end of month"
	// February 2026 has 28 days -> clamp to the 28th.
	got, ok := r.NextFire(time.Date(2026, 2, 1, 0, 0, 0, 0, utc))
	if !ok || !got.Equal(time.Date(2026, 2, 28, 0, 0, 0, 0, utc)) {
		t.Fatalf("monthly clamp Feb: got %v ok=%v", got, ok)
	}
	// April has 30 days -> clamp to the 30th.
	got, _ = r.NextFire(time.Date(2026, 4, 1, 0, 0, 0, 0, utc))
	if !got.Equal(time.Date(2026, 4, 30, 0, 0, 0, 0, utc)) {
		t.Fatalf("monthly clamp Apr: got %v", got)
	}
}

func TestNextFireDSTSpringForward(t *testing.T) {
	chi := mustLoad(t, "America/Chicago")
	// 2026-03-08 is US spring-forward: clocks jump 02:00 -> 03:00 CST->CDT, so the
	// wall-clock hour 02:00-03:00 does not exist. A daily 02:30 schedule lands in
	// that gap. The evaluator builds the candidate via time.Date with the configured
	// H:M, so it inherits Go's deterministic gap normalization (the nonexistent
	// 02:30 resolves using the pre-transition CST offset, instant 07:30 UTC). The
	// contract we guarantee: a single real instant, strictly after `after`, on the
	// scheduled date — the report still fires exactly once that day.
	r := Recurrence{TZ: "America/Chicago", Hour: 2, Minute: 30}
	after := time.Date(2026, 3, 8, 0, 0, 0, 0, chi)
	got, ok := r.NextFire(after)
	if !ok {
		t.Fatalf("DST spring-forward: not ok")
	}
	if got.Location() != time.UTC {
		t.Fatalf("NextFire must return UTC, got %v", got.Location())
	}
	if y, m, d := got.In(chi).Date(); y != 2026 || m != time.March || d != 8 {
		t.Fatalf("DST spring-forward date: got %v", got.In(chi))
	}
	if !got.After(after) {
		t.Fatalf("DST spring-forward not after: got %v", got)
	}
	// Faithful to time.Date's gap normalization (guards against a construction change).
	want := time.Date(2026, 3, 8, 2, 30, 0, 0, chi).UTC()
	if !got.Equal(want) {
		t.Fatalf("DST spring-forward instant: got %v want %v", got, want)
	}
}

func TestNextFireDSTFallBack(t *testing.T) {
	chi := mustLoad(t, "America/Chicago")
	// 2026-11-01 is US fall-back: 02:00 CDT -> 01:00 CST (01:00-02:00 repeats).
	// A daily 01:30 schedule is ambiguous; time.Date resolves it deterministically.
	r := Recurrence{TZ: "America/Chicago", Hour: 1, Minute: 30}
	after := time.Date(2026, 11, 1, 0, 0, 0, 0, chi)
	got, ok := r.NextFire(after)
	if !ok {
		t.Fatalf("DST fall-back: not ok")
	}
	want := time.Date(2026, 11, 1, 1, 30, 0, 0, chi)
	if !got.Equal(want.UTC()) {
		t.Fatalf("DST fall-back instant: got %v want %v", got.In(chi), want)
	}
}

func TestNextFireTimezoneConversion(t *testing.T) {
	chi := mustLoad(t, "America/Chicago")
	// Weekly Monday 07:00 America/Chicago. 2026-06-08 is a Monday; CDT = UTC-5.
	r := Recurrence{TZ: "America/Chicago", Hour: 7, Minute: 0, Weekday: "mon"}
	after := time.Date(2026, 6, 8, 0, 0, 0, 0, chi)
	got, ok := r.NextFire(after)
	if !ok {
		t.Fatalf("tz weekly: not ok")
	}
	if got.Location() != time.UTC {
		t.Fatalf("NextFire must return UTC, got %v", got.Location())
	}
	want := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC) // 07:00 CDT == 12:00 UTC
	if !got.Equal(want) {
		t.Fatalf("tz weekly instant: got %v want %v", got, want)
	}
}

func TestInvalidRecurrence(t *testing.T) {
	cases := []Recurrence{
		{Hour: 24, Minute: 0},
		{Hour: 1, Minute: 60},
		{Hour: 1, Minute: 0, DOM: 32},
		{Hour: 1, Minute: 0, Weekday: "funday"},
		{Hour: 1, Minute: 0, TZ: "Mars/Phobos"},
	}
	for i, r := range cases {
		if r.Valid() {
			t.Errorf("case %d: expected invalid", i)
		}
		if _, ok := r.NextFire(time.Now().UTC()); ok {
			t.Errorf("case %d: invalid recurrence must not fire", i)
		}
	}
}

func TestBetweenCatchup(t *testing.T) {
	utc := time.UTC
	r := Recurrence{Hour: 0, Minute: 0} // daily midnight UTC
	after := time.Date(2026, 6, 1, 0, 0, 0, 0, utc)
	until := time.Date(2026, 6, 5, 12, 0, 0, 0, utc)
	// Fires strictly after `after`: Jun 2,3,4,5 (00:00) — 4 fires, within (after, until].
	got := r.Between(after, until, 50)
	if len(got) != 4 {
		t.Fatalf("between count: got %d (%v)", len(got), got)
	}
	if !got[0].Equal(time.Date(2026, 6, 2, 0, 0, 0, 0, utc)) || !got[3].Equal(time.Date(2026, 6, 5, 0, 0, 0, 0, utc)) {
		t.Fatalf("between bounds: got %v", got)
	}
	// max cap is honored.
	if capped := r.Between(after, until, 2); len(capped) != 2 {
		t.Fatalf("between cap: got %d", len(capped))
	}
}
