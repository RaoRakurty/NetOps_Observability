// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package iristrigger holds a workspace's triggered Iris investigations
// (tracker 337 N-I2, design of record D16): a tenant admin asks Iris to run
// its read-only Investigator (N-I1) on its own — when a new incident matches a
// filter, or on a schedule — and the result is attached to the incident and
// announced on the workspace's own Slack lane.
//
// What lives here is the pure part: the trigger and run model, validation,
// matching, the schedule's due rule, the daily caps, and the stores. The
// server runs the investigation (as a system principal bound to the trigger's
// tenant, read-only role, never platform-wide) and decides whether AI
// investigations are licensed and switched on.
//
// Default-closed throughout: a workspace has no triggers until an admin
// creates one, the workspace switch starts OFF, and a run that cannot be
// admitted (a cap, a switch, no usable model) is RECORDED as skipped with its
// reason — never silently dropped, never retried behind the operator's back.
package iristrigger

import (
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Kind is what starts a trigger.
type Kind string

// Trigger kinds.
const (
	KindIncident Kind = "incident" // a new incident that matches the filter
	KindSchedule Kind = "schedule" // every N minutes
)

// Run statuses.
const (
	RunRunning = "running"
	RunDone    = "done"
	RunSkipped = "skipped"
	RunFailed  = "failed"
)

// Skip reasons — closed, and each says what an operator can do about it.
const (
	SkipWorkspaceOff     = "workspace_off"     // the workspace switch for triggered investigations is off
	SkipNotEntitled      = "not_entitled"      // AI investigations are not licensed / switched on for this workspace
	SkipModelUnavailable = "model_unavailable" // no AI model could be reached (overloaded, down, or none set up)
	SkipRunCap           = "daily_run_cap"     // the workspace's triggered runs for today are used up
	SkipTokenCap         = "daily_token_cap"   // the workspace's token allowance for triggered runs (or overall) is used up
	SkipDuplicate        = "duplicate"         // this trigger already ran for this incident / this slot
)

// Bounds.
const (
	MaxTriggersPerTenant = 20
	MaxName              = 80
	MaxSignature         = 100
	MaxQuestion          = 300
	MaxLabel             = 100
	MinEveryMinutes      = 15
	MaxEveryMinutes      = 24 * 60
	DefaultRunsPerDay    = 20
	MaxRunsPerDayCap     = 100
	DefaultTokensPerDay  = 200_000
	MaxTokensPerDayCap   = 1_000_000
	MaxRunSummary        = 500
	MaxRunsListed        = 50
)

// Errors.
var (
	ErrNotFound  = errors.New("iristrigger: not found")
	ErrInvalid   = errors.New("iristrigger: invalid")
	ErrTooMany   = errors.New("iristrigger: too many triggers")
	ErrDuplicate = errors.New("iristrigger: duplicate run")
)

// Severities, lowest first — the incident system's own vocabulary.
var severities = []string{"info", "notice", "warning", "error", "critical"}

// SeverityRank returns the rank of a severity (-1 when unknown).
func SeverityRank(s string) int {
	s = strings.ToLower(strings.TrimSpace(s))
	for i, v := range severities {
		if v == s {
			return i
		}
	}
	return -1
}

// Filter narrows which new incidents start an incident trigger. Every set
// field must hold; an empty filter is refused (it would investigate every
// incident and spend the day's cap on noise).
type Filter struct {
	MinSeverity string `json:"min_severity,omitempty"` // info…critical
	Signature   string `json:"signature,omitempty"`    // case-insensitive text in the incident's title or rule
	Site        string `json:"site,omitempty"`         // the firing device's site
	Role        string `json:"role,omitempty"`         // the firing device's role (wan_edge, core, …)
}

// Schedule is when a schedule trigger runs: every N minutes (15 minimum, once
// a day maximum), its first run one interval after it is created.
type Schedule struct {
	EveryMinutes int `json:"every_minutes"`
}

// Trigger is one triggered investigation a workspace asked for.
type Trigger struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"-"`
	Name      string     `json:"name"`
	Kind      Kind       `json:"kind"`
	Enabled   bool       `json:"enabled"`
	Filter    Filter     `json:"filter"`
	Schedule  Schedule   `json:"schedule"`
	Question  string     `json:"question,omitempty"` // what to investigate; empty → the kind's default
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	LastRunAt *time.Time `json:"last_run_at,omitempty"`
}

// Settings is the workspace's own control over triggered investigations.
type Settings struct {
	Enabled         bool `json:"enabled"`          // the workspace switch; default OFF
	MaxRunsPerDay   int  `json:"max_runs_per_day"` // triggered runs per UTC day
	MaxTokensPerDay int  `json:"max_tokens_per_day"`
}

// DefaultSettings is what a workspace with no stored row reads: off, with the
// default caps ready for when an admin turns it on.
func DefaultSettings() Settings {
	return Settings{MaxRunsPerDay: DefaultRunsPerDay, MaxTokensPerDay: DefaultTokensPerDay}
}

// Run is one triggered investigation, admitted or skipped.
type Run struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"-"`
	TriggerID       string     `json:"trigger_id"`
	TriggerName     string     `json:"trigger_name"`
	IncidentID      string     `json:"incident_id,omitempty"`
	DedupeKey       string     `json:"-"`
	Status          string     `json:"status"`
	Reason          string     `json:"reason,omitempty"` // skip reason, or the investigation's status when done
	InvestigationID string     `json:"investigation_id,omitempty"`
	Tokens          int        `json:"tokens"`
	Summary         string     `json:"summary,omitempty"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
}

// IncidentEvent is what the server knows about a new incident when it asks
// which triggers match: the incident's own fields plus the firing device's
// inventory facts (empty when the incident has no device).
type IncidentEvent struct {
	IncidentID string
	Severity   string
	Title      string
	Rule       string
	DeviceID   string
	Site       string
	Role       string
}

var reID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidID reports whether id is a lowercase UUID — the only id shape a trigger
// or run is stored under.
func ValidID(id string) bool { return reID.MatchString(id) }

// cleanText trims, collapses whitespace and refuses control and invisible
// characters (a trigger name is shown to other admins and in Slack).
func cleanText(s string, max int) (string, bool) {
	s = strings.Join(strings.Fields(s), " ")
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", false
		}
	}
	return s, true
}

var reLabel = regexp.MustCompile(`^[A-Za-z0-9 ._:/-]*$`)

// Validate normalises t in place and reports the first problem in plain
// words. It never trusts the caller: ids, tenant, author and timestamps are
// set by the store, not here.
func Validate(t *Trigger) error {
	name, ok := cleanText(t.Name, MaxName)
	if !ok || name == "" {
		return invalid("give the trigger a name of up to 80 characters")
	}
	t.Name = name
	q, ok := cleanText(t.Question, MaxQuestion)
	if !ok {
		return invalid("the question can be up to 300 characters, with no control characters")
	}
	t.Question = q
	switch t.Kind {
	case KindIncident:
		t.Schedule = Schedule{}
		f := &t.Filter
		f.MinSeverity = strings.ToLower(strings.TrimSpace(f.MinSeverity))
		if f.MinSeverity != "" && SeverityRank(f.MinSeverity) < 0 {
			return invalid("severity must be info, notice, warning, error or critical")
		}
		sig, ok := cleanText(f.Signature, MaxSignature)
		if !ok {
			return invalid("the signature text can be up to 100 characters")
		}
		f.Signature = sig
		for _, v := range []*string{&f.Site, &f.Role} {
			*v = strings.TrimSpace(*v)
			if len(*v) > MaxLabel || !reLabel.MatchString(*v) {
				return invalid("site and role are names of up to 100 letters, digits and . _ : / -")
			}
		}
		if f.MinSeverity == "" && f.Signature == "" && f.Site == "" && f.Role == "" {
			return invalid("set at least one condition — a severity, a signature, a site or a device role")
		}
	case KindSchedule:
		t.Filter = Filter{}
		if t.Schedule.EveryMinutes < MinEveryMinutes || t.Schedule.EveryMinutes > MaxEveryMinutes {
			return invalid("a schedule runs every 15 minutes at most and once a day at least")
		}
	default:
		return invalid("a trigger runs on a new incident or on a schedule")
	}
	return nil
}

// ValidateSettings clamps nothing silently: an out-of-range cap is refused.
func ValidateSettings(s *Settings) error {
	if s.MaxRunsPerDay < 1 || s.MaxRunsPerDay > MaxRunsPerDayCap {
		return invalid("triggered runs per day must be between 1 and 100")
	}
	if s.MaxTokensPerDay < 1000 || s.MaxTokensPerDay > MaxTokensPerDayCap {
		return invalid("the daily token allowance must be between 1,000 and 1,000,000")
	}
	return nil
}

func invalid(msg string) error { return &validationError{msg: msg} }

type validationError struct{ msg string }

func (e *validationError) Error() string { return e.msg }
func (e *validationError) Unwrap() error { return ErrInvalid }

// Matches reports whether a new incident starts t. Disabled and schedule
// triggers never match.
func (t Trigger) Matches(ev IncidentEvent) bool {
	if !t.Enabled || t.Kind != KindIncident {
		return false
	}
	f := t.Filter
	if f.MinSeverity != "" && SeverityRank(ev.Severity) < SeverityRank(f.MinSeverity) {
		return false
	}
	if f.Signature != "" {
		needle := strings.ToLower(f.Signature)
		if !strings.Contains(strings.ToLower(ev.Title), needle) && !strings.Contains(strings.ToLower(ev.Rule), needle) {
			return false
		}
	}
	if f.Site != "" && !strings.EqualFold(f.Site, strings.TrimSpace(ev.Site)) {
		return false
	}
	if f.Role != "" && !strings.EqualFold(f.Role, strings.TrimSpace(ev.Role)) {
		return false
	}
	return true
}

// Due reports whether a schedule trigger should run at now. Its first run is
// one interval after it was created (never on creation), then one interval
// after the last run started.
func (t Trigger) Due(now time.Time) bool {
	if !t.Enabled || t.Kind != KindSchedule || t.Schedule.EveryMinutes < MinEveryMinutes {
		return false
	}
	every := time.Duration(t.Schedule.EveryMinutes) * time.Minute
	from := t.CreatedAt
	if t.LastRunAt != nil && t.LastRunAt.After(from) {
		from = *t.LastRunAt
	}
	return !now.Before(from.Add(every))
}

// ScheduleSlot is the dedupe key of a schedule run: the interval it belongs
// to, so two scheduler ticks (or two replicas) in the same interval run once.
func (t Trigger) ScheduleSlot(now time.Time) string {
	every := int64(t.Schedule.EveryMinutes) * 60
	if every <= 0 {
		every = 60
	}
	return "slot:" + time.Unix((now.Unix()/every)*every, 0).UTC().Format(time.RFC3339)
}

// IncidentKey is the dedupe key of an incident run: one run per trigger per
// incident, however many times the incident is re-detected.
func IncidentKey(incidentID string) string { return "incident:" + incidentID }

// DefaultQuestion is what a trigger investigates when its admin left the
// question empty.
func DefaultQuestion(t Trigger, ev *IncidentEvent) string {
	if t.Question != "" {
		return t.Question
	}
	if t.Kind == KindIncident && ev != nil {
		title := strings.TrimSpace(ev.Title)
		if title == "" {
			title = "this incident"
		}
		return "Investigate the new incident: " + title
	}
	return "Check the network for anything that needs attention right now"
}

// Day is the UTC day a time falls in — the caps reset at UTC midnight, like
// the AI token budget.
func Day(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// SkipText is the operator's sentence for a skip reason.
func SkipText(reason string) string {
	switch reason {
	case SkipWorkspaceOff:
		return "Triggered investigations are switched off for this workspace."
	case SkipNotEntitled:
		return "AI investigations are not available for this workspace (licence, Features page or workspace access)."
	case SkipModelUnavailable:
		return "Skipped: no AI model could be reached (it may be overloaded or down). Nothing was retried."
	case SkipRunCap:
		return "Skipped: this workspace's triggered investigations for today are used up."
	case SkipTokenCap:
		return "Skipped: this workspace's AI token allowance for today is used up."
	case SkipDuplicate:
		return "Already investigated."
	}
	return "Skipped."
}
