// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// mailbox_reply_test.go — the reply read answers for ONE case.
//
// An email-created case has no number at send time: the vendor assigns one and
// puts it in the subject of their reply. Reading "the newest reply from this
// vendor" out of the tenant's mailbox answers the same string for every
// unnumbered case they have open, so two escalations get one case number and one
// of them is filed against the wrong incident. The reply has to be tied to the
// message that opened THIS case.
//
// The second rule here is about honesty: a Graph read that FAILED is a failure.
// Reporting it as an unsupported capability tells the poller to stop asking
// forever over what may be a five-minute outage.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/tac"
)

// sentAt is when both test cases were opened.
var sentAt = time.Date(2026, 9, 5, 9, 0, 0, 0, time.UTC)

// replyMailbox is a vendor mailbox holding the given raw Graph message list.
func replyMailbox(t *testing.T, messages string) (*fakeMailbox, *EmailCaseConnector, TACConnectorConfig) {
	t.Helper()
	f := newFakeMailbox(t)
	if messages != "" {
		f.reply["/messages"] = messages
	}
	c := f.connector(t, "cisco")
	e := graphCfg()
	e.ReadReplies = true
	return f, c, TACConnectorConfig{Email: e}
}

// TestTwoUnnumberedCasesToOneVendorDoNotShareANumber is the finding, stated as
// the rule it broke. Two cases are open with Cisco; only one has been answered.
// The answered case gets its number and the other gets nothing — never the same
// number twice.
func TestTwoUnnumberedCasesToOneVendorDoNotShareANumber(t *testing.T) {
	_, c, cfg := replyMailbox(t, `{"value":[
		{"subject":"RE: SR 123456789 - BGP session down on edge1","receivedDateTime":"2026-09-06T10:00:00Z"}]}`)

	answered, found, err := c.LookupCaseNumber(context.Background(), cfg, "BGP session down on edge1", sentAt)
	if err != nil || !found {
		t.Fatalf("the answered case: err=%v found=%v", err, found)
	}
	if answered.Number != "123456789" {
		t.Fatalf("the answered case took %q, want 123456789", answered.Number)
	}

	other, found, err := c.LookupCaseNumber(context.Background(), cfg, "OSPF adjacency flapping on core2", sentAt)
	if err != nil {
		t.Fatalf("the unanswered case: %v", err)
	}
	if found {
		t.Fatalf("a case nobody answered was handed %q — the number belongs to another case", other.Number)
	}
}

// TestEachCaseTakesTheNumberFromItsOwnReply — both cases answered, in one
// mailbox, and each takes its own number rather than the newest one.
func TestEachCaseTakesTheNumberFromItsOwnReply(t *testing.T) {
	_, c, cfg := replyMailbox(t, `{"value":[
		{"subject":"RE: SR 111111111 - BGP session down on edge1","receivedDateTime":"2026-09-06T10:00:00Z"},
		{"subject":"RE: SR 222222222 - OSPF adjacency flapping on core2","receivedDateTime":"2026-09-07T10:00:00Z"}]}`)

	for _, tc := range []struct{ subject, want string }{
		{"BGP session down on edge1", "111111111"},
		{"OSPF adjacency flapping on core2", "222222222"},
	} {
		ref, found, err := c.LookupCaseNumber(context.Background(), cfg, tc.subject, sentAt)
		if err != nil || !found {
			t.Fatalf("%s: err=%v found=%v", tc.subject, err, found)
		}
		if ref.Number != tc.want {
			t.Fatalf("%q took case number %q, want its own %q", tc.subject, ref.Number, tc.want)
		}
	}
}

// TestAReplyThatPredatesTheCaseIsNotItsAnswer — a case number that arrived
// before the case was opened answers some earlier message, not this one.
func TestAReplyThatPredatesTheCaseIsNotItsAnswer(t *testing.T) {
	_, c, cfg := replyMailbox(t, `{"value":[
		{"subject":"RE: SR 999999999 - BGP session down on edge1","receivedDateTime":"2026-08-01T10:00:00Z"}]}`)

	ref, found, err := c.LookupCaseNumber(context.Background(), cfg, "BGP session down on edge1", sentAt)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if found {
		t.Fatalf("a reply older than the case it supposedly answers gave it %q", ref.Number)
	}
}

// TestTwoCaseNumbersForOneMessageAreRefusedRatherThanGuessed — when the mailbox
// cannot be read unambiguously, nothing is filed and the reason is stated.
func TestTwoCaseNumbersForOneMessageAreRefusedRatherThanGuessed(t *testing.T) {
	_, c, cfg := replyMailbox(t, `{"value":[
		{"subject":"RE: SR 111111111 - BGP session down on edge1","receivedDateTime":"2026-09-06T10:00:00Z"},
		{"subject":"RE: SR 222222222 - BGP session down on edge1","receivedDateTime":"2026-09-07T10:00:00Z"}]}`)

	ref, found, err := c.LookupCaseNumber(context.Background(), cfg, "BGP session down on edge1", sentAt)
	if found || err == nil {
		t.Fatalf("an ambiguous mailbox produced %q (found=%v, err=%v)", ref.Number, found, err)
	}
	if !strings.Contains(err.Error(), "more than one case number") {
		t.Fatalf("the refusal does not say what was ambiguous: %v", err)
	}
}

// TestALookupWithNoSentSubjectRefusesRatherThanGuessing — with nothing to match
// against there is no honest answer, and "the newest reply" is a guess.
func TestALookupWithNoSentSubjectRefusesRatherThanGuessing(t *testing.T) {
	f, c, cfg := replyMailbox(t, `{"value":[
		{"subject":"RE: SR 123456789 - some case","receivedDateTime":"2026-09-06T10:00:00Z"}]}`)

	if _, found, err := c.LookupCaseNumber(context.Background(), cfg, "  ", sentAt); found || err == nil {
		t.Fatalf("a lookup with no subject answered anyway (found=%v, err=%v)", found, err)
	}
	if got := f.seen(); len(got) != 0 {
		t.Fatalf("a mailbox was read for a lookup that could not be answered: %v", got)
	}
}

// ── through the adapter ─────────────────────────────────────────────────────

// emailOpener builds the seam adapter over the mailbox-backed email connector.
func emailOpener(t *testing.T, messages string) (*fakeMailbox, *TACOpener) {
	t.Helper()
	f, c, cfg := replyMailbox(t, messages)
	o := NewTACOpener(c, "cisco", "Cisco by email", testResolver(cfg), nil)
	o.Now = func() time.Time { return time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC) }
	return f, o
}

// TestPollByReplyAnswersForTheCaseItWasAskedAbout — the same rule one level up,
// where the case handle is what carries the identity.
func TestPollByReplyAnswersForTheCaseItWasAskedAbout(t *testing.T) {
	_, o := emailOpener(t, `{"value":[
		{"subject":"RE: SR 111111111 - BGP session down on edge1","receivedDateTime":"2026-09-06T10:00:00Z"},
		{"subject":"RE: SR 222222222 - OSPF adjacency flapping on core2","receivedDateTime":"2026-09-07T10:00:00Z"}]}`)

	mine, err := o.PollStatus(context.Background(), "org-a-tenant", tac.CaseHandle{
		ThreadSubject: "BGP session down on edge1", OpenedAt: sentAt,
	})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if mine.CaseID != "111111111" {
		t.Fatalf("case id = %q, want this case's own number", mine.CaseID)
	}
	if mine.Status != EmailOpenedStatus {
		t.Fatalf("status = %q, want %q", mine.Status, EmailOpenedStatus)
	}

	theirs, err := o.PollStatus(context.Background(), "org-a-tenant", tac.CaseHandle{
		ThreadSubject: "OSPF adjacency flapping on core2", OpenedAt: sentAt,
	})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if theirs.CaseID == mine.CaseID {
		t.Fatalf("two cases were handed the same number %q", theirs.CaseID)
	}
	if theirs.CaseID != "222222222" {
		t.Fatalf("case id = %q, want its own number", theirs.CaseID)
	}
}

// TestAGraphReadFailureIsNotAnUnsupportedCapability — §10. A read that failed
// must not retire the case's refresh schedule.
func TestAGraphReadFailureIsNotAnUnsupportedCapability(t *testing.T) {
	f, o := emailOpener(t, "")
	f.status["/messages"] = http.StatusInternalServerError

	_, err := o.PollStatus(context.Background(), "org-a-tenant", tac.CaseHandle{
		ThreadSubject: "BGP session down on edge1", OpenedAt: sentAt,
	})
	if err == nil {
		t.Fatal("a failed mailbox read reported success")
	}
	if errors.Is(err, tac.ErrCapabilityUnsupported) {
		t.Fatalf("a failed read was reported as an unsupported capability: %v", err)
	}
}

// TestAReplyThatHasNotArrivedYetLeavesTheScheduleAlone — no reply is not an
// error and not an unsupported capability. It is "not yet".
func TestAReplyThatHasNotArrivedYetLeavesTheScheduleAlone(t *testing.T) {
	_, o := emailOpener(t, `{"value":[]}`)

	res, err := o.PollStatus(context.Background(), "org-a-tenant", tac.CaseHandle{
		ThreadSubject: "BGP session down on edge1", OpenedAt: sentAt,
	})
	if err != nil {
		t.Fatalf("an unanswered case is not an error: %v", err)
	}
	if res.CaseID != "" || res.Status != "" {
		t.Fatalf("an unanswered case produced %+v", res)
	}
}

// TestACaseWithNoSentSubjectIsNotPollable — nothing here can ever answer, so it
// says so once instead of asking forever.
func TestACaseWithNoSentSubjectIsNotPollable(t *testing.T) {
	f, o := emailOpener(t, `{"value":[
		{"subject":"RE: SR 123456789 - someone else's case","receivedDateTime":"2026-09-06T10:00:00Z"}]}`)

	_, err := o.PollStatus(context.Background(), "org-a-tenant", tac.CaseHandle{OpenedAt: sentAt})
	if !errors.Is(err, tac.ErrCapabilityUnsupported) {
		t.Fatalf("err = %v, want ErrCapabilityUnsupported", err)
	}
	if got := f.seen(); len(got) != 0 {
		t.Fatalf("a mailbox was read for a case that cannot be matched: %v", got)
	}
}

// TestAnEmailCreateCarriesItsSubjectBackToTheCaseRecord — the plumbing that
// makes all of the above possible: the subject that went on the wire comes back
// on the result, so the case record can keep it.
func TestAnEmailCreateCarriesItsSubjectBackToTheCaseRecord(t *testing.T) {
	f := newFakeMailbox(t)
	c := f.connector(t, "arista")
	o := NewTACOpener(c, "arista", "Arista by email", testResolver(TACConnectorConfig{Email: graphCfg()}), nil)

	res, err := o.SubmitCase(context.Background(), tac.CaseRequest{
		TenantID: "org-a-tenant", IncidentID: "P-000123", Actor: "user:42",
		Form: tac.CaseForm{Title: "BGP session down on edge1", Description: "the DIA edge lost its session",
			ContactName: "Jane Doe", ContactEmail: "jane.doe@acme.example", Severity: "3"},
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.CaseID != "" {
		t.Fatalf("an email create invented a case id: %q", res.CaseID)
	}
	if !strings.Contains(res.ThreadSubject, "BGP session down on edge1") {
		t.Fatalf("the sent subject did not reach the result: %q", res.ThreadSubject)
	}
}
