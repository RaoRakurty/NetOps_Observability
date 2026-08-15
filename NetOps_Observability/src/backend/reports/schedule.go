// Package reports holds the dependency-light core of the asynchronous reporting
// pipeline: the calendar/timezone schedule evaluator, the render view-model and
// renderer seam, and the queue/execution/artifact interfaces. It imports no
// database or transport code so it stays unit-testable in isolation; the
// Postgres-backed repositories and HTTP wiring live in package main.
package reports

import (
	"strings"
	"time"
)

// Recurrence is a calendar + timezone schedule for a report. It is intentionally
// small and declarative — enough for the daily / weekly / monthly cadences an
// executive reporting product needs, without a full cron grammar (which the
// guided UI would only hide anyway).
//
// Precedence when fields overlap: DOM (monthly) > Weekday (weekly) > daily.
// All times are wall-clock in TZ; NextFire returns the resolved instant in UTC.
type Recurrence struct {
	TZ      string `json:"tz"`      // IANA location, e.g. "America/Chicago"; "" => UTC
	Hour    int    `json:"hour"`    // 0..23 wall-clock in TZ
	Minute  int    `json:"minute"`  // 0..59
	Weekday string `json:"weekday"` // "" or mon|tue|wed|thu|fri|sat|sun => weekly
	DOM     int    `json:"dom"`     // 0 => none; 1..31 => monthly on this day-of-month
}

var weekdays = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday,
	"wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// Valid reports whether the recurrence is well-formed. An invalid recurrence
// never fires (NextFire returns ok=false) — callers treat that as "unscheduled".
func (r Recurrence) Valid() bool {
	if r.Hour < 0 || r.Hour > 23 || r.Minute < 0 || r.Minute > 59 {
		return false
	}
	if r.DOM < 0 || r.DOM > 31 {
		return false
	}
	if r.Weekday != "" {
		if _, ok := weekdays[strings.ToLower(strings.TrimSpace(r.Weekday))]; !ok {
			return false
		}
	}
	if _, err := r.location(); err != nil {
		return false
	}
	return true
}

func (r Recurrence) location() (*time.Location, error) {
	tz := strings.TrimSpace(r.TZ)
	if tz == "" || strings.EqualFold(tz, "utc") {
		return time.UTC, nil
	}
	return time.LoadLocation(tz)
}

// NextFire returns the first scheduled instant strictly after `after`, in UTC.
// ok is false if the recurrence is invalid. DST is handled by time.Date, which
// normalizes a wall-clock time that doesn't exist (spring-forward gap) to the
// adjacent valid instant; ambiguous fall-back times resolve to the earlier one.
func (r Recurrence) NextFire(after time.Time) (time.Time, bool) {
	if !r.Valid() {
		return time.Time{}, false
	}
	loc, _ := r.location() // discard: Valid() has already vetted the timezone
	a := after.In(loc)
	switch {
	case r.DOM > 0:
		return r.nextMonthly(a, loc)
	case r.Weekday != "":
		return r.nextWeekly(a, loc)
	default:
		return r.nextDaily(a, loc)
	}
}

func (r Recurrence) nextDaily(a time.Time, loc *time.Location) (time.Time, bool) {
	cand := time.Date(a.Year(), a.Month(), a.Day(), r.Hour, r.Minute, 0, 0, loc)
	if !cand.After(a) {
		cand = time.Date(a.Year(), a.Month(), a.Day()+1, r.Hour, r.Minute, 0, 0, loc)
	}
	return cand.UTC(), true
}

func (r Recurrence) nextWeekly(a time.Time, loc *time.Location) (time.Time, bool) {
	target := weekdays[strings.ToLower(strings.TrimSpace(r.Weekday))]
	// Scan the next 8 calendar days; the target weekday appears once in 0..6 and
	// again at 7, so the first candidate strictly after `a` is the answer.
	for offset := 0; offset <= 7; offset++ {
		cand := time.Date(a.Year(), a.Month(), a.Day()+offset, r.Hour, r.Minute, 0, 0, loc)
		if cand.Weekday() == target && cand.After(a) {
			return cand.UTC(), true
		}
	}
	return time.Time{}, false // unreachable for a valid weekday
}

func (r Recurrence) nextMonthly(a time.Time, loc *time.Location) (time.Time, bool) {
	y, m := a.Year(), a.Month()
	// Walk up to 12 months so a too-large DOM (e.g. 31 in a 30-day month) still
	// resolves: it is clamped to the month's last day, so a monthly report always
	// fires once per month rather than skipping short months.
	for i := 0; i < 13; i++ {
		day := r.DOM
		if last := daysIn(y, m); day > last {
			day = last
		}
		cand := time.Date(y, m, day, r.Hour, r.Minute, 0, 0, loc)
		if cand.After(a) {
			return cand.UTC(), true
		}
		if m++; m > time.December {
			m = time.January
			y++
		}
	}
	return time.Time{}, false // unreachable
}

func daysIn(y int, m time.Month) int {
	// Day 0 of the following month is the last day of month m.
	return time.Date(y, m+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// Between returns every fire instant in the half-open window (after, until],
// capped at max entries (oldest first). The scheduler uses it for bounded
// missed-run catch-up after an outage. A non-positive max or invalid recurrence
// yields nil.
func (r Recurrence) Between(after, until time.Time, max int) []time.Time {
	if max <= 0 || !r.Valid() {
		return nil
	}
	var out []time.Time
	cur := after
	for len(out) < max {
		next, ok := r.NextFire(cur)
		if !ok || next.After(until) {
			break
		}
		out = append(out, next)
		cur = next
	}
	return out
}
