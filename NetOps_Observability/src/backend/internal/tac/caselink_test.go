// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// caselink_test.go — the case coming back to the incident, and the cadence it
// comes back on.
//
// The owner's schedule is a product decision, so it is asserted as data rather
// than reasoned about in prose: an emergency case is read every two minutes for
// four hours and then every five; a P2 every five for a day and then every
// fifteen; everything else fifteen then hourly. Around that: closed stops,
// reopened resumes, the vendor's limit degrades a whole tenant gracefully and
// SAYS SO, a manual refresh has a floor, and a failed read is never a stale
// green.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func at(h, m int) time.Time {
	return time.Date(2026, 9, 7, h, m, 0, 0, time.UTC)
}

func TestTierForSeverityReadsEveryVendorVocabulary(t *testing.T) {
	cases := []struct {
		in   string
		want SeverityTier
	}{
		// Cisco S1-S4.
		{"S1 — Critical impact (system down)", TierEmergency},
		{"S2", TierHigh},
		{"S3", TierRoutine},
		{"S4 — No impact (informational)", TierRoutine},
		// Fortinet P1-P4 and Palo Alto Sev 1-4.
		{"P1", TierEmergency},
		{"P2", TierHigh},
		{"Sev 1", TierEmergency},
		{"Sev 4", TierRoutine},
		// ServiceNow / Jira words.
		{"1 - Critical", TierEmergency},
		{"Highest", TierEmergency},
		{"Blocker", TierEmergency},
		{"Major", TierHigh},
		{"High", TierHigh},
		{"Medium", TierRoutine},
		{"Low", TierRoutine},
		// The honest defaults: unknown and blank tier DOWN, never up.
		{"", TierRoutine},
		{"urgent-ish", TierRoutine},
		// A case number must not be read as a severity.
		{"688123456", TierRoutine},
	}
	for _, tc := range cases {
		if got := TierForSeverity(tc.in); got != tc.want {
			t.Errorf("TierForSeverity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestPollScheduleIsTheOwnersTable states the cadence table as an assertion, so
// changing it is a deliberate act with a failing test attached.
func TestPollScheduleIsTheOwnersTable(t *testing.T) {
	want := map[SeverityTier][]PollStage{
		TierEmergency: {{Until: 4 * time.Hour, Every: 2 * time.Minute}, {Every: 5 * time.Minute}},
		TierHigh:      {{Until: 24 * time.Hour, Every: 5 * time.Minute}, {Every: 15 * time.Minute}},
		TierRoutine:   {{Until: 24 * time.Hour, Every: 15 * time.Minute}, {Every: time.Hour}},
	}
	for tier, stages := range want {
		got := PollStages(tier)
		if len(got) != len(stages) {
			t.Fatalf("%s: %d stages, want %d", tier, len(got), len(stages))
		}
		for i := range stages {
			if got[i] != stages[i] {
				t.Fatalf("%s stage %d = %+v, want %+v", tier, i, got[i], stages[i])
			}
		}
	}
	// An unknown tier reads as routine rather than as nothing at all: a case
	// with no schedule would silently never refresh.
	if len(PollStages("nonsense")) == 0 {
		t.Fatal("an unrecognised tier must still get the routine schedule")
	}
}

func TestNextPollWalksTheStages(t *testing.T) {
	opened := at(9, 0)
	cases := []struct {
		tier SeverityTier
		age  time.Duration
		want time.Duration
	}{
		{TierEmergency, 0, 2 * time.Minute},
		{TierEmergency, 3 * time.Hour, 2 * time.Minute},
		{TierEmergency, 5 * time.Hour, 5 * time.Minute},
		{TierHigh, time.Hour, 5 * time.Minute},
		{TierHigh, 30 * time.Hour, 15 * time.Minute},
		{TierRoutine, time.Hour, 15 * time.Minute},
		{TierRoutine, 48 * time.Hour, time.Hour},
	}
	for _, tc := range cases {
		link := CaseLink{CaseID: "C1", OpenedAt: opened, Tier: tc.tier, Pollable: true, Status: "Open"}
		now := opened.Add(tc.age)
		next, every, note := NextPoll(link, now, 0)
		if every != tc.want {
			t.Errorf("%s at age %s: cadence %s, want %s", tc.tier, tc.age, every, tc.want)
		}
		if !next.Equal(now.Add(tc.want)) {
			t.Errorf("%s at age %s: next %s", tc.tier, tc.age, next)
		}
		if note != "" {
			t.Errorf("%s: unexpected note %q", tc.tier, note)
		}
	}
}

func TestNextPollStopsOnAClosedCaseAndResumesOnReopen(t *testing.T) {
	opened := at(9, 0)
	for _, status := range []string{"Closed", "resolved", "Complete", "Cancelled"} {
		link := CaseLink{CaseID: "C1", OpenedAt: opened, Tier: TierEmergency, Pollable: true, Status: status}
		next, every, note := NextPoll(link, opened.Add(time.Hour), 0)
		if !next.IsZero() || every != 0 {
			t.Fatalf("%q must stop the schedule, got next=%s every=%s", status, next, every)
		}
		if note != "closed" {
			t.Fatalf("%q: note = %q", status, note)
		}
	}
	// Reopened: the status no longer says closed, so the schedule resumes. It is
	// derived on every read rather than latched, which is what makes this work.
	link := CaseLink{CaseID: "C1", OpenedAt: opened, Tier: TierEmergency, Pollable: true, Status: "Reopened"}
	if next, _, _ := NextPoll(link, opened.Add(time.Hour), 0); next.IsZero() {
		t.Fatal("a reopened case must be watched again")
	}
}

func TestNextPollSaysWhenAPathCannotReportStatus(t *testing.T) {
	link := CaseLink{CaseID: "C1", OpenedAt: at(9, 0), Tier: TierEmergency, Pollable: false, Status: "Open"}
	next, _, note := NextPoll(link, at(9, 30), 0)
	if !next.IsZero() {
		t.Fatal("a path with no status read must not be scheduled")
	}
	if !strings.Contains(note, "no status read") {
		t.Fatalf("note = %q", note)
	}
}

func TestNextPollDegradesUnderTheVendorLimitAndSaysSo(t *testing.T) {
	link := CaseLink{CaseID: "C1", OpenedAt: at(9, 0), Tier: TierEmergency, Pollable: true, Status: "Open"}
	_, every, note := NextPoll(link, at(9, 30), 1)
	if every != 5*time.Minute {
		t.Fatalf("one degrade step from 2 min should be 5 min, got %s", every)
	}
	if note != "vendor rate limit" {
		t.Fatalf("the chip must say why it slowed down, got %q", note)
	}
	_, every2, _ := NextPoll(link, at(9, 30), 2)
	if every2 != 15*time.Minute {
		t.Fatalf("two steps should be 15 min, got %s", every2)
	}
	// The ladder stops at an hour rather than running away.
	_, every5, _ := NextPoll(link, at(9, 30), 9)
	if every5 != time.Hour {
		t.Fatalf("the ladder must bottom out at an hour, got %s", every5)
	}
}

func TestNextPollBacksOffAfterAFailedRead(t *testing.T) {
	link := CaseLink{
		CaseID: "C1", OpenedAt: at(9, 0), Tier: TierEmergency, Pollable: true,
		Status: "Open", LastError: "the vendor returned 503",
	}
	_, every, note := NextPoll(link, at(9, 30), 0)
	if every < 4*time.Minute {
		t.Fatalf("a failed read must widen the interval, got %s", every)
	}
	if !strings.Contains(note, "backing off") {
		t.Fatalf("note = %q", note)
	}
	// Jitter is deterministic per case, so two cases do not line up and one case
	// is reproducible.
	other := link
	other.CaseID = "C2"
	_, otherEvery, _ := NextPoll(other, at(9, 30), 0)
	if otherEvery == every {
		t.Skip("this pair of ids happens to jitter identically; the property is that it is derived from the id, not that it always differs")
	}
	_, again, _ := NextPoll(link, at(9, 30), 0)
	if again != every {
		t.Fatalf("the same case must jitter the same way: %s then %s", every, again)
	}
}

// ── the tracker ─────────────────────────────────────────────────────────────

func testTracker(now *time.Time) *CaseTracker {
	return NewCaseTracker(func() time.Time { return *now })
}

func TestTrackerRecordsAndSchedules(t *testing.T) {
	now := at(9, 0)
	tr := testTracker(&now)
	link := tr.Record("t1", "inc-1", CaseLink{
		Connector: "juniper", Vendor: "juniper", CaseID: "2026-0907-1234",
		Severity: "P1", Status: "Open", Pollable: true, AuthMode: "oauth",
	})
	if link.Tier != TierEmergency {
		t.Fatalf("tier = %q", link.Tier)
	}
	if link.Cadence != 2*time.Minute || link.CadenceLabel != "2 min" {
		t.Fatalf("cadence = %s / %q", link.Cadence, link.CadenceLabel)
	}
	if !link.NextCheckAt.Equal(now.Add(2 * time.Minute)) {
		t.Fatalf("next check = %s", link.NextCheckAt)
	}
	if got, ok := tr.Get("t1", "inc-1"); !ok || got.CaseID != "2026-0907-1234" {
		t.Fatalf("the case was not stored: %+v %v", got, ok)
	}
	if _, ok := tr.Get("t2", "inc-1"); ok {
		t.Fatal("another tenant must not see this case")
	}
}

func TestTrackerDueRespectsTheSchedule(t *testing.T) {
	now := at(9, 0)
	tr := testTracker(&now)
	tr.Record("t1", "inc-1", CaseLink{Connector: "juniper", Vendor: "juniper", CaseID: "C1",
		Severity: "P1", Status: "Open", Pollable: true})
	if due := tr.Due(10); len(due) != 0 {
		t.Fatalf("nothing is due yet, got %d", len(due))
	}
	now = at(9, 3)
	due := tr.Due(10)
	if len(due) != 1 || due[0].Incident != "inc-1" {
		t.Fatalf("the case should be due: %+v", due)
	}
}

func TestTrackerDegradesAWholeTenantUnderTheVendorBudget(t *testing.T) {
	now := at(9, 0)
	tr := testTracker(&now)
	// Juniper's budget is 500/hour in the table. An emergency case at 2 minutes
	// costs 30/hour, so 20 of them cost 600 — over the line.
	var last CaseLink
	for i := 0; i < 20; i++ {
		last = tr.Record("t1", "inc-"+itoaTAC(i), CaseLink{
			Connector: "juniper", Vendor: "juniper", CaseID: "C" + itoaTAC(i),
			Severity: "P1", Status: "Open", Pollable: true,
		})
	}
	if last.Cadence <= 2*time.Minute {
		t.Fatalf("a tenant over the vendor budget must slow down, cadence %s", last.Cadence)
	}
	if last.CadenceNote != "vendor rate limit" {
		t.Fatalf("the chip must say why: %q", last.CadenceNote)
	}
	if !strings.Contains(last.Tooltip(), "vendor rate limit") {
		t.Fatalf("the tooltip must carry it: %q", last.Tooltip())
	}
}

func TestTrackerManualRefreshHasAFloor(t *testing.T) {
	now := at(9, 0)
	tr := testTracker(&now)
	if ok, _ := tr.AllowManual("t1", "inc-1"); !ok {
		t.Fatal("the first manual refresh must be allowed")
	}
	ok, wait := tr.AllowManual("t1", "inc-1")
	if ok {
		t.Fatal("a second refresh inside the floor must be refused")
	}
	if wait <= 0 || wait > ManualRefreshFloor {
		t.Fatalf("the caller must be told how long to wait, got %s", wait)
	}
	now = at(9, 2)
	if ok, _ := tr.AllowManual("t1", "inc-1"); !ok {
		t.Fatal("after the floor the refresh must be allowed again")
	}
}

func TestTrackerNeverEvictsAnOpenCase(t *testing.T) {
	now := at(9, 0)
	tr := testTracker(&now)
	for i := 0; i < maxTrackedCasesPerTenant+10; i++ {
		tr.Record("t1", "inc-"+itoaTAC(i), CaseLink{
			Connector: "juniper", Vendor: "juniper", CaseID: "C" + itoaTAC(i),
			Severity: "P3", Status: "Open", Pollable: true,
		})
	}
	// Everything is open, so nothing may be forgotten even past the bound.
	for i := 0; i < maxTrackedCasesPerTenant+10; i++ {
		if _, ok := tr.Get("t1", "inc-"+itoaTAC(i)); !ok {
			t.Fatalf("open case inc-%d was evicted", i)
		}
	}
}

// ── the chip ────────────────────────────────────────────────────────────────

func TestStatusLineNeverShowsAStaleGreen(t *testing.T) {
	link := CaseLink{
		Connector: "juniper", CaseID: "2026-0907-1234", Status: "Open",
		LastCheckedAt: at(9, 41), LastError: "the vendor returned 503",
	}
	line := link.StatusLine(at(10, 15))
	if strings.Contains(line, "Open") {
		t.Fatalf("a failed read must not render the last known status as current: %q", line)
	}
	if !strings.Contains(line, "status unknown since") || !strings.Contains(line, "503") {
		t.Fatalf("the chip must say what is wrong and since when: %q", line)
	}
}

func TestStatusLineIsHonestAboutAnEmailOpenedCase(t *testing.T) {
	link := CaseLink{Connector: "email-arista", OpenedAt: at(9, 0)}
	if got := link.StatusLine(at(9, 5)); got != "opened by email · number pending" {
		t.Fatalf("status line = %q", got)
	}
}

func TestStatusLineRendersTheCaseAndItsStatus(t *testing.T) {
	link := CaseLink{Connector: "juniper", CaseID: "2026-0907-1234", Status: "In Progress"}
	if got := link.StatusLine(at(9, 5)); got != "2026-0907-1234 · In Progress" {
		t.Fatalf("status line = %q", got)
	}
	bare := CaseLink{Connector: "juniper", CaseID: "2026-0907-1234"}
	if got := bare.StatusLine(at(9, 5)); got != "2026-0907-1234 · opened" {
		t.Fatalf("status line = %q", got)
	}
}

func TestTooltipShowsAuthModeAndCadence(t *testing.T) {
	now := at(9, 0)
	tr := testTracker(&now)
	link := tr.Record("t1", "inc-1", CaseLink{
		Connector: "cisco-smart-bonding", Vendor: "cisco", CaseID: "689123456",
		Severity: "S1", Status: "Open", Pollable: true, AuthMode: "oauth",
	})
	tip := link.Tooltip()
	for _, want := range []string{"cisco-smart-bonding", "oauth", "refreshing every 2 min"} {
		if !strings.Contains(tip, want) {
			t.Fatalf("tooltip %q is missing %q", tip, want)
		}
	}
	closed := link
	closed.Closed = true
	if !strings.Contains(closed.Tooltip(), "no longer refreshing") {
		t.Fatalf("a closed case's tooltip: %q", closed.Tooltip())
	}
	unpollable := link
	unpollable.Pollable = false
	if !strings.Contains(unpollable.Tooltip(), "publishes no status read") {
		t.Fatalf("an unpollable case's tooltip: %q", unpollable.Tooltip())
	}
}

// ── the poller ──────────────────────────────────────────────────────────────

func TestPollerReadsStatusAndRecordsIt(t *testing.T) {
	now := at(9, 0)
	tr := testTracker(&now)
	var recorded []CaseLink
	p, err := NewCasePoller(tr,
		func(context.Context, string, string, CaseHandle) (CaseResult, error) {
			return CaseResult{Status: "In Progress", CaseURL: "https://vendor.example/case/1"}, nil
		},
		func(_ context.Context, _, _ string, l CaseLink) error {
			recorded = append(recorded, l)
			return nil
		}, nil)
	if err != nil {
		t.Fatalf("poller: %v", err)
	}
	tr.Record("t1", "inc-1", CaseLink{Connector: "juniper", Vendor: "juniper", CaseID: "C1",
		Severity: "P1", Status: "Open", Pollable: true})
	now = at(9, 3)
	if n := p.Round(context.Background()); n != 1 {
		t.Fatalf("polled %d cases", n)
	}
	if len(recorded) != 1 {
		t.Fatalf("the status was not recorded onto the incident: %+v", recorded)
	}
	got := recorded[0]
	if got.Status != "In Progress" || got.CaseURL == "" {
		t.Fatalf("the vendor's answer was not kept: %+v", got)
	}
	if got.LastError != "" || got.LastCheckedAt.IsZero() {
		t.Fatalf("a successful read must clear the error and stamp the time: %+v", got)
	}
}

func TestPollerRecordsAFailureWithoutLosingTheLastKnownStatus(t *testing.T) {
	now := at(9, 0)
	tr := testTracker(&now)
	var warned int
	p, err := NewCasePoller(tr,
		func(context.Context, string, string, CaseHandle) (CaseResult, error) {
			return CaseResult{}, errors.New("the vendor returned 503")
		}, nil, func(string, map[string]any) { warned++ })
	if err != nil {
		t.Fatalf("poller: %v", err)
	}
	tr.Record("t1", "inc-1", CaseLink{Connector: "juniper", Vendor: "juniper", CaseID: "C1",
		Severity: "P1", Status: "Open", Pollable: true})
	now = at(9, 3)
	p.Round(context.Background())
	got, _ := tr.Get("t1", "inc-1")
	if got.Status != "Open" {
		t.Fatalf("the last known status must be kept: %+v", got)
	}
	if !strings.Contains(got.LastError, "503") {
		t.Fatalf("the cause must be kept: %+v", got)
	}
	if warned != 1 {
		t.Fatalf("a failed read must be logged exactly once, got %d", warned)
	}
	if strings.Contains(got.StatusLine(now), "Open") {
		t.Fatalf("the chip must not render the stale status: %q", got.StatusLine(now))
	}
}

func TestPollerStopsAskingAPathThatCannotAnswer(t *testing.T) {
	now := at(9, 0)
	tr := testTracker(&now)
	p, err := NewCasePoller(tr,
		func(context.Context, string, string, CaseHandle) (CaseResult, error) {
			return CaseResult{}, ErrCapabilityUnsupported
		}, nil, nil)
	if err != nil {
		t.Fatalf("poller: %v", err)
	}
	tr.Record("t1", "inc-1", CaseLink{Connector: "portal-nokia", Vendor: "nokia", CaseID: "C1",
		Severity: "P1", Status: "Open", Pollable: true})
	now = at(9, 3)
	p.Round(context.Background())
	got, _ := tr.Get("t1", "inc-1")
	if got.Pollable {
		t.Fatal("a connector that cannot poll must be marked unpollable, not retried for ever")
	}
	if got.LastError != "" {
		t.Fatalf("an unsupported capability is not an error to show: %q", got.LastError)
	}
	now = at(9, 30)
	if n := p.Round(context.Background()); n != 0 {
		t.Fatalf("an unpollable case must not be scheduled again, polled %d", n)
	}
}

func TestPollerNeedsATrackerAndAReader(t *testing.T) {
	if _, err := NewCasePoller(nil, func(context.Context, string, string, CaseHandle) (CaseResult, error) {
		return CaseResult{}, nil
	}, nil, nil); err == nil {
		t.Fatal("a poller with no tracker must be refused")
	}
	if _, err := NewCasePoller(NewCaseTracker(nil), nil, nil, nil); err == nil {
		t.Fatal("a poller with no reader must be refused")
	}
}
