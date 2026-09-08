// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// caselink.go — the case comes BACK to the incident.
//
// Opening a case is half the job. The other half is the owner's, verbatim
// (2026-09-07): "finally display message on Correlix with case number and its
// status, update the status of the case with a refresh interval that is
// reasonable for case management" — and then: "For an emergency case, refresh
// should be more often."
//
// So a case is recorded on the incident as {connector, case_id, case_url,
// opened_at, status}, and its status is re-read on a SEVERITY-TIERED schedule.
// Three rules shape the schedule and all three are the owner's:
//
//  1. Emergencies refresh often. A Sev 1 is a network that is down and a person
//     watching the screen; a Sev 4 is a question someone will answer next week.
//     One cadence for both would either hammer the vendor or leave the P1
//     operator refreshing by hand.
//  2. The vendor's limits are the OUTER bound, not a suggestion. Juniper
//     publishes 1000 invocations an hour; a tenant with several Sev 1 Juniper
//     cases must degrade to the next tier and SAY SO on the chip, rather than
//     trip a limit and lose status for every case at once.
//  3. A failed read is never a stale green. "Status unknown since 09:41 —
//     the vendor returned 503" is the honest chip; showing yesterday's "Open" as
//     if it were current is the failure mode this file exists to prevent.

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// SeverityTier is the closed cadence class. It is derived from the severity
// ACTUALLY SENT TO THE VENDOR, not from Correlix's own incident severity: the
// vendor's queue is what the poll is watching, and a case downgraded on their
// side must re-tier on ours.
type SeverityTier string

const (
	// TierEmergency is Sev 1 / P1 / S1 / Critical — a network that is down.
	TierEmergency SeverityTier = "emergency"
	// TierHigh is Sev 2 / P2 / S2.
	TierHigh SeverityTier = "high"
	// TierRoutine is Sev 3-4 / P3-P4 / S3-S4 and anything unrecognised. An
	// unknown severity tiers DOWN, never up: guessing "emergency" from a token
	// nobody recognises would spend a tenant's whole vendor budget on it.
	TierRoutine SeverityTier = "routine"
)

// PollStage is one leg of a tier's schedule: an interval that applies until the
// case is `Until` old, and then the next leg.
type PollStage struct {
	// Until is the case age this leg covers. Zero means "for ever after".
	Until time.Duration
	// Every is the interval between status reads during this leg.
	Every time.Duration
}

// pollSchedule is the owner's table, verbatim, in one place with one test.
//
//	Sev 1 / P1 : every 2 minutes for the first 4 hours, then every 5 until closed
//	Sev 2 / P2 : every 5 minutes for the first 24 hours, then every 15
//	Sev 3-4    : every 15 minutes for the first 24 hours, then hourly
func pollSchedule() map[SeverityTier][]PollStage {
	return map[SeverityTier][]PollStage{
		TierEmergency: {{Until: 4 * time.Hour, Every: 2 * time.Minute}, {Every: 5 * time.Minute}},
		TierHigh:      {{Until: 24 * time.Hour, Every: 5 * time.Minute}, {Every: 15 * time.Minute}},
		TierRoutine:   {{Until: 24 * time.Hour, Every: 15 * time.Minute}, {Every: time.Hour}},
	}
}

// PollStages exposes one tier's schedule (the settings screen renders it, and
// the cadence test reads it rather than restating it).
func PollStages(tier SeverityTier) []PollStage {
	return append([]PollStage(nil), pollSchedule()[normalizeTier(tier)]...)
}

func normalizeTier(t SeverityTier) SeverityTier {
	switch t {
	case TierEmergency, TierHigh, TierRoutine:
		return t
	}
	return TierRoutine
}

// ManualRefreshFloor is the shortest gap between two operator-driven refreshes
// of one case. A person hammering the button must not be the thing that trips a
// vendor's rate limit for their whole tenant.
const ManualRefreshFloor = 60 * time.Second

// TierForSeverity maps a severity token — in whatever vocabulary the vendor
// uses — onto the cadence tier.
//
// It reads the DIGIT, because every vendor's vocabulary is a number with a
// prefix: Cisco S1-S4, Fortinet P1-P4, Palo Alto Sev 1-4, ServiceNow 1-4,
// Jira's own priority names. Words are handled for the vocabularies that use
// them. Anything unrecognised is routine, deliberately.
func TierForSeverity(severity string) SeverityTier {
	s := strings.ToLower(strings.TrimSpace(severity))
	if s == "" {
		return TierRoutine
	}
	switch {
	case strings.Contains(s, "critical"), strings.Contains(s, "emergency"),
		strings.Contains(s, "system down"), strings.Contains(s, "network down"):
		return TierEmergency
	case strings.Contains(s, "highest"), strings.Contains(s, "blocker"):
		return TierEmergency
	case strings.Contains(s, "major"), strings.Contains(s, "high"):
		return TierHigh
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '1' || s[i] > '4' {
			continue
		}
		// A digit is a severity only when it is not part of a larger number
		// (a case id, a version). The tokens are short and shaped `s1`, `p2`,
		// `sev 3`, `priority 4`, so a neighbouring digit means this is not one.
		if i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
			continue
		}
		if i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
			continue
		}
		switch s[i] {
		case '1':
			return TierEmergency
		case '2':
			return TierHigh
		default:
			return TierRoutine
		}
	}
	return TierRoutine
}

// CaseStatusClosed reports whether a vendor's status string means the case is
// finished, so polling stops. It is deliberately generous about vocabulary and
// deliberately conservative about the answer: a status it does not recognise is
// OPEN, and an open case keeps being watched.
func CaseStatusClosed(status string) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	if s == "" {
		return false
	}
	for _, closed := range []string{"closed", "resolved", "complete", "cancelled", "canceled", "done"} {
		if strings.Contains(s, closed) {
			return true
		}
	}
	return false
}

// CaseLink is the case as the incident records it. It is the chip's content.
type CaseLink struct {
	// Connector is the path the case was opened through.
	Connector string `json:"connector"`
	// Vendor groups it for the UI.
	Vendor string `json:"vendor,omitempty"`
	// CaseID is the vendor's own case number. It is empty on a path that cannot
	// return one — an email-opened Arista case until the mailbox connector can
	// read the reply — and the chip says "opened by email · number pending"
	// rather than inventing one.
	CaseID string `json:"case_id,omitempty"`
	// CaseURL is the deep link, when the vendor publishes one.
	CaseURL string `json:"case_url,omitempty"`
	// OpenedAt is when the human pressed the button.
	OpenedAt time.Time `json:"opened_at"`
	// Status is the vendor's own last-read status string.
	Status string `json:"status,omitempty"`
	// Severity is what was sent to the vendor; Tier is the cadence it earns.
	Severity string       `json:"severity,omitempty"`
	Tier     SeverityTier `json:"tier"`
	// AuthMode is how the connector authenticated, shown on the chip's tooltip.
	AuthMode string `json:"auth_mode,omitempty"`
	// Attached records whether the bundle went with the case.
	Attached bool `json:"attached"`
	// AttachNote is why it did not, when it did not.
	AttachNote string `json:"attach_note,omitempty"`
	// LastCheckedAt is when the status was last READ SUCCESSFULLY. It is the
	// timestamp the chip shows, so "last refreshed" never means "last tried".
	LastCheckedAt time.Time `json:"last_checked_at,omitzero"`
	// LastError is the cause of the most recent FAILED read. While it is set the
	// chip reads "status unknown since <LastCheckedAt>" with this cause — never
	// a stale green.
	LastError string `json:"last_error,omitempty"`
	// NextCheckAt is when the poller will try again.
	NextCheckAt time.Time `json:"next_check_at,omitzero"`
	// Cadence is the interval currently in force, and CadenceNote says why when
	// it is not the tier's own ("vendor rate limit", "closed").
	Cadence     time.Duration `json:"-"`
	CadenceNote string        `json:"cadence_note,omitempty"`
	// CadenceLabel is Cadence rendered for the chip's tooltip.
	CadenceLabel string `json:"cadence_label,omitempty"`
	// Pollable reports that this connector can read a status back at all. A
	// path that cannot says so once, instead of showing a refresh control that
	// could only ever fail.
	Pollable bool `json:"pollable"`
	// Closed stops the schedule. A reopened case (a status that stops meaning
	// closed) starts it again, which is why this is derived on every read rather
	// than latched.
	Closed bool `json:"closed"`
}

// StatusLine is the chip's sentence: what to show, in one place, so the panel,
// the incident list and the answer card cannot word it differently.
func (c CaseLink) StatusLine(now time.Time) string {
	switch {
	case c.CaseID == "" && c.Connector != "" && strings.HasPrefix(c.Connector, "email-"):
		return "opened by email · number pending"
	case c.CaseID == "":
		return "prepared · not yet opened"
	case c.LastError != "":
		since := "just now"
		if !c.LastCheckedAt.IsZero() {
			since = c.LastCheckedAt.UTC().Format("15:04 MST on 2 Jan")
		}
		return c.CaseID + " · status unknown since " + since + " — " + clip(c.LastError, 120)
	case c.Status == "":
		return c.CaseID + " · opened"
	default:
		return c.CaseID + " · " + c.Status
	}
}

// Tooltip is the chip's hover text: how it authenticated and how often it
// refreshes, which is exactly what an operator asks when the number stops moving.
func (c CaseLink) Tooltip() string {
	parts := []string{}
	if c.Connector != "" {
		parts = append(parts, "via "+c.Connector)
	}
	if c.AuthMode != "" {
		parts = append(parts, "authenticated with "+c.AuthMode)
	}
	switch {
	case c.Closed:
		parts = append(parts, "closed — no longer refreshing")
	case !c.Pollable:
		parts = append(parts, "this path publishes no status read; refresh it in the vendor's portal")
	case c.CadenceLabel != "":
		line := "refreshing every " + c.CadenceLabel
		if c.CadenceNote != "" {
			line += " · " + c.CadenceNote
		}
		parts = append(parts, line)
	}
	if !c.LastCheckedAt.IsZero() {
		parts = append(parts, "last refreshed "+c.LastCheckedAt.UTC().Format("15:04 MST on 2 Jan"))
	}
	return strings.Join(parts, " · ")
}

// CaseSyncStatus renders a case link as the incident record's sync status.
//
// A FAILED status read is "unknown", never the last known value: the incident
// list must not show a stale green any more than the chip may. It is here rather
// than at the call site because the chip and the list must say the same thing
// about the same case.
func CaseSyncStatus(link CaseLink) string {
	switch {
	case link.LastError != "":
		return "unknown"
	case strings.TrimSpace(link.Status) != "":
		return link.Status
	default:
		return "opened"
	}
}

// ── the schedule ────────────────────────────────────────────────────────────

// PollBudget is the outer bound: what a tenant may spend against one vendor in
// an hour, so a tenant with many emergency cases degrades gracefully instead of
// tripping the vendor's limit for all of them.
type PollBudget struct {
	// PerHour is the vendor's published invocation limit. Juniper publishes
	// 1000/hour; a vendor that publishes none gets DefaultVendorBudget, which is
	// a Correlix guard rather than a vendor claim.
	PerHour int
}

// DefaultVendorBudget is the per-tenant, per-vendor hourly ceiling used when a
// vendor publishes none. It is deliberately well under any plausible limit.
const DefaultVendorBudget = 600

// vendorBudgets is the published-limit table. A vendor absent from it is not
// unlimited — it gets DefaultVendorBudget.
func vendorBudgets() map[string]PollBudget {
	return map[string]PollBudget{
		// Juniper's Service Case API publishes 1000 invocations per hour
		// (docs/design/TAC_CASE_FIELDS_2026-09-07.md, Juniper row). Correlix
		// spends at most half of it on status polling, so a customer's own
		// integrations are not crowded out by ours.
		"juniper": {PerHour: 500},
	}
}

// BudgetFor returns the hourly poll budget for one vendor.
func BudgetFor(vendor string) PollBudget {
	if b, ok := vendorBudgets()[strings.ToLower(strings.TrimSpace(vendor))]; ok {
		return b
	}
	return PollBudget{PerHour: DefaultVendorBudget}
}

// NextPoll returns when a case should next be read, the interval in force and
// the reason when it is not the tier's own.
//
// degrade is how many tiers the budget forced this case down. It comes from the
// tracker, which is the only thing that can see a tenant's whole vendor load.
func NextPoll(link CaseLink, now time.Time, degrade int) (time.Time, time.Duration, string) {
	if link.Closed || CaseStatusClosed(link.Status) {
		return time.Time{}, 0, "closed"
	}
	if !link.Pollable {
		return time.Time{}, 0, "this path publishes no status read"
	}
	tier := normalizeTier(link.Tier)
	stages := pollSchedule()[tier]
	age := now.Sub(link.OpenedAt)
	every := stages[len(stages)-1].Every
	for _, st := range stages {
		if st.Until == 0 || age < st.Until {
			every = st.Every
			break
		}
	}
	note := ""
	for i := 0; i < degrade; i++ {
		next, ok := degradedInterval(every)
		if !ok {
			break
		}
		every = next
		note = "vendor rate limit"
	}
	// A read that FAILED backs off on top of the cadence, with jitter, so a
	// vendor having a bad minute is not met by every case at once (§9).
	if link.LastError != "" {
		every = backoffFor(every, link)
		if note == "" {
			note = "backing off after a failed read"
		}
	}
	return now.Add(every), every, note
}

// degradedInterval is the next-slower cadence, one step. It is the ladder the
// budget walks down, and it stops at an hour: a case still open after that is
// not something a tighter loop would help with.
func degradedInterval(d time.Duration) (time.Duration, bool) {
	ladder := []time.Duration{2 * time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour}
	for i, step := range ladder {
		if d <= step && i+1 < len(ladder) {
			return ladder[i+1], true
		}
	}
	return d, false
}

// backoffFor widens the interval after a failed read, bounded and jittered.
func backoffFor(base time.Duration, link CaseLink) time.Duration {
	d := base * 2
	if d > time.Hour {
		d = time.Hour
	}
	// Deterministic jitter from the case id: no global RNG (§5), no thundering
	// herd, and the same case gets the same offset so a test can assert it.
	var sum int
	for i := 0; i < len(link.CaseID); i++ {
		sum += int(link.CaseID[i])
	}
	jitter := time.Duration(sum%20) * d / 100 // 0-19% of the interval
	return d + jitter
}

// ── the tracker ─────────────────────────────────────────────────────────────

// CaseTracker is the bounded, per-tenant register of OPEN cases and the poll
// budget they share. It is the only thing that can see a tenant's whole vendor
// load, which is why the degrade decision lives here and not in NextPoll.
type CaseTracker struct {
	now func() time.Time

	mu sync.Mutex
	// links is tenant → incident → the case.
	links map[string]map[string]*CaseLink
	// spend is tenant\x00vendor → the reads made in the current hour window.
	spend map[string]*spendWindow
	// manual is tenant\x00incident → when the last operator refresh happened.
	manual map[string]time.Time
}

type spendWindow struct {
	since time.Time
	count int
}

// maxTrackedCasesPerTenant bounds the register (§9). A tenant past it stops
// tracking the OLDEST closed case first, and never a case that is still open.
const maxTrackedCasesPerTenant = 500

// NewCaseTracker builds the register.
func NewCaseTracker(now func() time.Time) *CaseTracker {
	if now == nil {
		now = time.Now
	}
	return &CaseTracker{
		now:    now,
		links:  map[string]map[string]*CaseLink{},
		spend:  map[string]*spendWindow{},
		manual: map[string]time.Time{},
	}
}

// Record files a newly-opened (or re-read) case and returns it with its
// schedule filled in.
func (t *CaseTracker) Record(tenant, incident string, link CaseLink) CaseLink {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now().UTC()
	if link.OpenedAt.IsZero() {
		link.OpenedAt = now
	}
	if link.Tier == "" {
		link.Tier = TierForSeverity(link.Severity)
	}
	link.Closed = CaseStatusClosed(link.Status)
	next, every, note := NextPoll(link, now, t.degradeLocked(tenant, link.Vendor))
	link.NextCheckAt, link.Cadence, link.CadenceNote = next, every, note
	link.CadenceLabel = humanInterval(every)
	byInc := t.links[tenant]
	if byInc == nil {
		byInc = map[string]*CaseLink{}
		t.links[tenant] = byInc
	}
	t.evictLocked(byInc)
	stored := link
	byInc[incident] = &stored
	return stored
}

// Get returns a copy of one incident's case link.
func (t *CaseTracker) Get(tenant, incident string) (CaseLink, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	l, ok := t.links[tenant][incident]
	if !ok {
		return CaseLink{}, false
	}
	return *l, true
}

// Due returns the cases whose next read has come, oldest deadline first and
// bounded by the caller's batch size, spending the tenant's vendor budget as it
// goes. A case the budget cannot afford this round is simply not returned; its
// next Record will carry the degraded cadence and say so.
func (t *CaseTracker) Due(limit int) []DueCase {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now().UTC()
	var out []DueCase
	for tenant, byInc := range t.links {
		for incident, l := range byInc {
			if l.Closed || !l.Pollable || l.NextCheckAt.IsZero() || now.Before(l.NextCheckAt) {
				continue
			}
			out = append(out, DueCase{Tenant: tenant, Incident: incident, Link: *l})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Link.NextCheckAt.Equal(out[j].Link.NextCheckAt) {
			return out[i].Incident < out[j].Incident
		}
		return out[i].Link.NextCheckAt.Before(out[j].Link.NextCheckAt)
	})
	kept := out[:0]
	for _, d := range out {
		if limit > 0 && len(kept) >= limit {
			break
		}
		if !t.spendLocked(d.Tenant, d.Link.Vendor) {
			continue
		}
		kept = append(kept, d)
	}
	return kept
}

// DueCase is one case the poller should read now.
type DueCase struct {
	Tenant   string
	Incident string
	Link     CaseLink
}

// AllowManual applies the 60-second floor to an operator-driven refresh. It
// returns the wait when the refresh is too soon, so the caller can say how long
// rather than silently doing nothing.
func (t *CaseTracker) AllowManual(tenant, incident string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now().UTC()
	key := tenant + "\x00" + incident
	if last, ok := t.manual[key]; ok {
		if wait := ManualRefreshFloor - now.Sub(last); wait > 0 {
			return false, wait
		}
	}
	t.manual[key] = now
	return true, 0
}

// degradeLocked reports how many cadence steps this tenant's load against this
// vendor has earned. Caller holds t.mu.
func (t *CaseTracker) degradeLocked(tenant, vendor string) int {
	budget := BudgetFor(vendor).PerHour
	if budget <= 0 {
		return 0
	}
	// The projected hourly cost of every open case this tenant has against this
	// vendor, at each one's own cadence.
	var perHour float64
	for _, l := range t.links[tenant] {
		if l.Closed || !l.Pollable || !strings.EqualFold(l.Vendor, vendor) {
			continue
		}
		if l.Cadence > 0 {
			perHour += float64(time.Hour) / float64(l.Cadence)
		}
	}
	steps := 0
	for perHour > float64(budget) && steps < 3 {
		perHour /= 2.5 // one ladder step is roughly a 2.5x widening
		steps++
	}
	return steps
}

// spendLocked charges one read against the tenant's hourly window for a vendor.
// Caller holds t.mu.
func (t *CaseTracker) spendLocked(tenant, vendor string) bool {
	now := t.now().UTC()
	key := tenant + "\x00" + strings.ToLower(vendor)
	w := t.spend[key]
	if w == nil || now.Sub(w.since) >= time.Hour {
		w = &spendWindow{since: now}
		t.spend[key] = w
	}
	if w.count >= BudgetFor(vendor).PerHour {
		return false
	}
	w.count++
	return true
}

// evictLocked keeps the register bounded, dropping CLOSED cases first and never
// an open one. Caller holds t.mu.
func (t *CaseTracker) evictLocked(byInc map[string]*CaseLink) {
	for len(byInc) >= maxTrackedCasesPerTenant {
		var oldestID string
		var oldest time.Time
		for id, l := range byInc {
			if !l.Closed {
				continue
			}
			if oldestID == "" || l.OpenedAt.Before(oldest) {
				oldestID, oldest = id, l.OpenedAt
			}
		}
		if oldestID == "" {
			return // everything is open; refuse to forget a live case
		}
		delete(byInc, oldestID)
	}
}

// humanInterval renders a cadence for the chip.
func humanInterval(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d < time.Hour:
		return itoaTAC(int(d/time.Minute)) + " min"
	case d == time.Hour:
		return "hour"
	default:
		return itoaTAC(int(d/time.Hour)) + " h"
	}
}

// ── the poller ──────────────────────────────────────────────────────────────

// StatusReader reads one case's status back. It is the CaseOpener's PollStatus,
// narrowed to what the poller needs and injected so the loop is testable with no
// connectors at all.
type StatusReader func(ctx context.Context, tenant, connectorID, caseID string) (CaseResult, error)

// CaseRecorder persists a status update — onto the incident record, and into
// whatever the caller wants to notify.
type CaseRecorder func(ctx context.Context, tenant, incident string, link CaseLink) error

// CasePoller re-reads open cases on their schedule. It is a bounded loop with a
// timeout on every call, a batch cap per round and the tracker's budget behind
// it (§9: timeout, backoff, jitter, bounded queue).
type CasePoller struct {
	tracker  *CaseTracker
	read     StatusReader
	record   CaseRecorder
	warn     func(msg string, fields map[string]any)
	interval time.Duration
	batch    int
	timeout  time.Duration
	now      func() time.Time
}

// NewCasePoller builds the loop. read and tracker are required; record and warn
// may be nil (nothing is persisted, nothing is logged), which is the honest
// no-op wiring rather than a crash.
func NewCasePoller(tracker *CaseTracker, read StatusReader, record CaseRecorder,
	warn func(string, map[string]any)) (*CasePoller, error) {
	if tracker == nil {
		return nil, errors.New("tac: nil case tracker")
	}
	if read == nil {
		return nil, errors.New("tac: nil status reader")
	}
	return &CasePoller{
		tracker: tracker, read: read, record: record, warn: warn,
		interval: 30 * time.Second, batch: 25, timeout: 20 * time.Second, now: tracker.now,
	}, nil
}

// Run drives the loop until the context ends. The TICK is short and the
// SCHEDULE is long: the tick only asks "is anything due", and the tracker's
// per-case NextCheckAt is what decides.
func (p *CasePoller) Run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Round(ctx)
		}
	}
}

// Round polls everything due once. It is exported so a test drives it directly
// and so an operator's "Refresh now" can reuse exactly the same path.
func (p *CasePoller) Round(ctx context.Context) int {
	due := p.tracker.Due(p.batch)
	for _, d := range due {
		p.Poll(ctx, d.Tenant, d.Incident, d.Link)
	}
	return len(due)
}

// Poll reads ONE case and records the outcome. A failed read is recorded as a
// failure — the link keeps its last known status AND carries the error, so the
// chip can say "status unknown since" instead of showing a stale green.
func (p *CasePoller) Poll(ctx context.Context, tenant, incident string, link CaseLink) CaseLink {
	callCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	res, err := p.read(callCtx, tenant, link.Connector, link.CaseID)
	now := p.now().UTC()
	switch {
	case err != nil && errors.Is(err, ErrCapabilityUnsupported):
		// The connector cannot read a status back. Stop asking, and say so.
		link.Pollable = false
		link.LastError = ""
	case err != nil:
		link.LastError = clip(err.Error(), 200)
		if p.warn != nil {
			p.warn("a TAC case status could not be read", map[string]any{
				"tenant": tenant, "incident_id": incident, "connector": link.Connector,
				"case_id": link.CaseID, "error": link.LastError,
			})
		}
	default:
		link.LastError = ""
		link.LastCheckedAt = now
		if s := strings.TrimSpace(res.Status); s != "" {
			link.Status = s
		}
		if u := strings.TrimSpace(res.CaseURL); u != "" {
			link.CaseURL = u
		}
		if id := strings.TrimSpace(res.CaseID); id != "" {
			link.CaseID = id
		}
	}
	out := p.tracker.Record(tenant, incident, link)
	if p.record != nil {
		if rerr := p.record(ctx, tenant, incident, out); rerr != nil && p.warn != nil {
			p.warn("a TAC case status could not be written to the incident", map[string]any{
				"tenant": tenant, "incident_id": incident, "error": rerr.Error(),
			})
		}
	}
	return out
}
