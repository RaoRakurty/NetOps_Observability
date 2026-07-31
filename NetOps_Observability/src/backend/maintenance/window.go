// Package maintenance holds tenant-scoped maintenance windows (tracker item
// 121, the #53 remnant): declared periods of planned work during which alert
// NOTIFICATIONS for the covered scope are paused and incidents are stamped as
// planned maintenance so the reliability rollups (MTBF, chronic offenders)
// separate planned from unplanned downtime.
//
// Like episode mute/snooze, a window suppresses notifications ONLY — alerts
// still fire, episodes still fold, incidents still ingest; the UI shows the
// paused state honestly. The window additionally feeds the timeintel
// Maintenance stamp, which nothing set before this package existed.
//
// The schedule evaluator is purpose-built and dependency-free (the reports
// Recurrence models fire INSTANTS; a maintenance window is an interval with a
// duration, possibly spanning midnight, on a set of weekdays).
package maintenance

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// MaxOneShotSpan bounds a one-shot window (a "window" that lasts months is
	// a config error, not planned work).
	MaxOneShotSpan = 90 * 24 * time.Hour
	// MaxDurationMinutes bounds a recurring occurrence (7 days — beyond that a
	// weekly window would overlap itself).
	MaxDurationMinutes = 7 * 24 * 60
	// MaxScopeEntries bounds each scope list.
	MaxScopeEntries = 200
	// MaxScopeEntryLen bounds one scope entry (device id / site slug / rule name).
	MaxScopeEntryLen = 128
)

// Schedule is a recurring occurrence: every listed weekday (empty = every day)
// at StartHour:StartMinute wall-clock in TZ, lasting DurationMinutes. An
// occurrence may span midnight; ActiveAt checks yesterday's start too.
type Schedule struct {
	TZ              string   `json:"tz,omitempty"`       // IANA location; "" => UTC
	Weekdays        []string `json:"weekdays,omitempty"` // mon|tue|...|sun; empty = daily
	StartHour       int      `json:"start_hour"`
	StartMinute     int      `json:"start_minute"`
	DurationMinutes int      `json:"duration_minutes"`
}

var weekdayNames = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday,
	"wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

func (sc Schedule) location() (*time.Location, error) {
	tz := strings.TrimSpace(sc.TZ)
	if tz == "" || strings.EqualFold(tz, "utc") {
		return time.UTC, nil
	}
	return time.LoadLocation(tz)
}

func (sc Schedule) validate() error {
	if sc.StartHour < 0 || sc.StartHour > 23 || sc.StartMinute < 0 || sc.StartMinute > 59 {
		return errors.New("schedule start must be a valid wall-clock time")
	}
	if sc.DurationMinutes < 1 || sc.DurationMinutes > MaxDurationMinutes {
		return fmt.Errorf("schedule duration_minutes must be 1..%d", MaxDurationMinutes)
	}
	for _, d := range sc.Weekdays {
		if _, ok := weekdayNames[strings.ToLower(strings.TrimSpace(d))]; !ok {
			return fmt.Errorf("unknown weekday %q (use mon..sun)", d)
		}
	}
	if _, err := sc.location(); err != nil {
		return fmt.Errorf("unknown timezone %q", sc.TZ)
	}
	return nil
}

// dayAllowed reports whether an occurrence may START on this weekday.
func (sc Schedule) dayAllowed(d time.Weekday) bool {
	if len(sc.Weekdays) == 0 {
		return true
	}
	for _, name := range sc.Weekdays {
		if weekdayNames[strings.ToLower(strings.TrimSpace(name))] == d {
			return true
		}
	}
	return false
}

// Window is one declared maintenance period, owned by a tenant. Exactly one of
// the two shapes is set: one-shot ([StartsAt, EndsAt)) or recurring (Schedule,
// optionally bounded by StartsAt/Until). Scope lists are AND-ed across
// dimensions and OR-ed within one: an empty list matches everything of that
// dimension; a non-empty list requires the alert/incident's value to be listed
// (so a sites-scoped window never covers an alert whose site is unknown).
type Window struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`

	DeviceIDs []string `json:"device_ids,omitempty"`
	Sites     []string `json:"sites,omitempty"`
	Rules     []string `json:"rules,omitempty"`

	StartsAt *time.Time `json:"starts_at,omitempty"`
	EndsAt   *time.Time `json:"ends_at,omitempty"`
	Schedule *Schedule  `json:"schedule,omitempty"`
	Until    *time.Time `json:"until,omitempty"` // recurring: last instant the series may cover

	Enabled   bool      `json:"enabled"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Validate checks and normalizes the operator-supplied fields (zero-trust on
// the payload). It does NOT touch server-owned stamps (id/tenant/created_*).
func (w *Window) Validate() error {
	w.Name = strings.TrimSpace(w.Name)
	if w.Name == "" || len(w.Name) > MaxScopeEntryLen || !printable(w.Name) {
		return errors.New("name is required (single line, max 128 chars)")
	}
	w.Description = strings.TrimSpace(w.Description)
	if len(w.Description) > 1024 || !printable(w.Description) {
		return errors.New("description is capped at 1024 printable chars")
	}
	var err error
	if w.DeviceIDs, err = normScope("device_ids", w.DeviceIDs); err != nil {
		return err
	}
	if w.Sites, err = normScope("sites", w.Sites); err != nil {
		return err
	}
	if w.Rules, err = normScope("rules", w.Rules); err != nil {
		return err
	}
	oneShot := w.StartsAt != nil || w.EndsAt != nil
	if w.Schedule == nil && !oneShot {
		return errors.New("a window needs either starts_at/ends_at or a schedule")
	}
	if w.Schedule != nil {
		if w.EndsAt != nil {
			return errors.New("a recurring window uses until, not ends_at")
		}
		if err := w.Schedule.validate(); err != nil {
			return err
		}
		if w.Until != nil && w.StartsAt != nil && !w.Until.After(*w.StartsAt) {
			return errors.New("until must be after starts_at")
		}
		return nil
	}
	if w.StartsAt == nil || w.EndsAt == nil {
		return errors.New("a one-shot window needs both starts_at and ends_at")
	}
	if !w.EndsAt.After(*w.StartsAt) {
		return errors.New("ends_at must be after starts_at")
	}
	if w.EndsAt.Sub(*w.StartsAt) > MaxOneShotSpan {
		return errors.New("a one-shot window is capped at 90 days")
	}
	if w.Until != nil {
		return errors.New("a one-shot window uses ends_at, not until")
	}
	return nil
}

func printable(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func normScope(field string, in []string) ([]string, error) {
	if len(in) > MaxScopeEntries {
		return nil, fmt.Errorf("%s is capped at %d entries", field, MaxScopeEntries)
	}
	out := in[:0]
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if len(v) > MaxScopeEntryLen || !printable(v) {
			return nil, fmt.Errorf("%s entries are single-line, max %d chars", field, MaxScopeEntryLen)
		}
		out = append(out, v)
	}
	return out, nil
}

// ActiveAt reports whether the window covers instant t (scope aside).
func (w *Window) ActiveAt(t time.Time) bool {
	if !w.Enabled {
		return false
	}
	if w.Schedule == nil {
		return w.StartsAt != nil && w.EndsAt != nil &&
			!t.Before(*w.StartsAt) && t.Before(*w.EndsAt)
	}
	if w.StartsAt != nil && t.Before(*w.StartsAt) {
		return false
	}
	if w.Until != nil && t.After(*w.Until) {
		return false
	}
	loc, err := w.Schedule.location()
	if err != nil {
		return false // an invalid stored TZ never covers (fail toward noisy)
	}
	lt := t.In(loc)
	dur := time.Duration(w.Schedule.DurationMinutes) * time.Minute
	// An occurrence that started yesterday may span midnight into now.
	for _, dayOff := range []int{-1, 0} {
		day := lt.AddDate(0, 0, dayOff)
		start := time.Date(day.Year(), day.Month(), day.Day(),
			w.Schedule.StartHour, w.Schedule.StartMinute, 0, 0, loc)
		if !w.Schedule.dayAllowed(start.Weekday()) {
			continue
		}
		if !t.Before(start) && t.Before(start.Add(dur)) {
			return true
		}
	}
	return false
}

// Matches reports whether the (device, site, rule) triple is inside the
// window's scope. Empty scope lists match everything; a non-empty list with an
// empty candidate value does NOT match (a sites-scoped window never covers an
// alert whose site is unknown — conservative, never over-suppresses).
func (w *Window) Matches(device, site, rule string) bool {
	return scopeMatch(w.DeviceIDs, device) &&
		scopeMatch(w.Sites, site) &&
		scopeMatch(w.Rules, rule)
}

func scopeMatch(scope []string, v string) bool {
	if len(scope) == 0 {
		return true
	}
	for _, s := range scope {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

// Covers is the one predicate suppression and the timeintel stamp share.
func (w *Window) Covers(t time.Time, device, site, rule string) bool {
	return w.ActiveAt(t) && w.Matches(device, site, rule)
}
