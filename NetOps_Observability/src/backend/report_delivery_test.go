package backend

import (
	"context"
	"errors"
	"testing"
	"time"

	"netops/backend/models"
	"netops/backend/notify"
)

type fakeDoc struct {
	err         error
	called      bool
	body        string
	ctype       string
	attachments []notify.Attachment
}

func (f *fakeDoc) SendDocument(subject, contentType, body string) error {
	f.called = true
	f.body = body
	f.ctype = contentType
	return f.err
}

func (f *fakeDoc) SendReport(subject, htmlBody string, attachments []notify.Attachment) error {
	f.called = true
	f.body = htmlBody
	f.ctype = "text/html; charset=UTF-8"
	f.attachments = attachments
	return f.err
}

// fixed clock for deterministic timestamps.
func fixedNow() time.Time { return time.Date(2026, 6, 2, 7, 0, 0, 0, time.UTC) }

func TestDeliverEmailSuccess(t *testing.T) {
	doc := &fakeDoc{}
	d := &reportDelivery{
		resolveEmail: func(ids []string, tenant string, cross bool) []string {
			if tenant != "acme" {
				t.Errorf("expected tenant scope acme, got %q", tenant)
			}
			return []string{"a@x.com", "b@x.com"}
		},
		emailSender: func(r []string) (docSender, bool) { return doc, true },
		dispatch:    func(a models.Alert, names []string) []notify.SendResult { return nil },
		now:         fixedNow,
	}
	got := d.Deliver(context.Background(), deliverReq{
		Tenant: "acme", ContactPoints: []string{"cp1"},
		Subject: "Weekly", ContentType: "text/html; charset=utf-8", Body: []byte("<html>hi</html>"),
	})
	if !doc.called || doc.body != "<html>hi</html>" || doc.ctype != "text/html; charset=utf-8" {
		t.Fatalf("doc not sent with HTML body: %+v", doc)
	}
	if len(got) != 2 {
		t.Fatalf("delivery statuses = %d, want 2", len(got))
	}
	for _, ds := range got {
		if !ds.OK || ds.Channel != "email" || ds.Error != "" || !ds.At.Equal(fixedNow()) {
			t.Errorf("bad status: %+v", ds)
		}
	}
}

func TestDeliverEmailFailureRecordedPerRecipient(t *testing.T) {
	doc := &fakeDoc{err: errors.New("smtp 550")}
	d := &reportDelivery{
		resolveEmail: func(ids []string, tenant string, cross bool) []string { return []string{"a@x.com", "b@x.com"} },
		emailSender:  func(r []string) (docSender, bool) { return doc, true },
		dispatch:     func(a models.Alert, names []string) []notify.SendResult { return nil },
		now:          fixedNow,
	}
	got := d.Deliver(context.Background(), deliverReq{ContactPoints: []string{"cp1"}})
	if len(got) != 2 {
		t.Fatalf("statuses = %d, want 2", len(got))
	}
	for _, ds := range got {
		if ds.OK || ds.Error != "smtp 550" {
			t.Errorf("expected failure recorded: %+v", ds)
		}
	}
}

func TestDeliverSMTPNotConfigured(t *testing.T) {
	d := &reportDelivery{
		resolveEmail: func(ids []string, tenant string, cross bool) []string { return []string{"a@x.com"} },
		emailSender:  func(r []string) (docSender, bool) { return nil, false },
		dispatch:     func(a models.Alert, names []string) []notify.SendResult { return nil },
		now:          fixedNow,
	}
	got := d.Deliver(context.Background(), deliverReq{ContactPoints: []string{"cp1"}})
	if len(got) != 1 || got[0].OK || got[0].Error != "SMTP not configured" {
		t.Fatalf("expected SMTP-not-configured status, got %+v", got)
	}
}

func TestDeliverNamedChannelsRecordPerChannel(t *testing.T) {
	d := &reportDelivery{
		resolveEmail: func(ids []string, tenant string, cross bool) []string { return nil }, // no contact points
		emailSender:  func(r []string) (docSender, bool) { return nil, false },
		dispatch: func(a models.Alert, names []string) []notify.SendResult {
			return []notify.SendResult{
				{Channel: "slack", Err: nil},
				{Channel: "pagerduty", Err: errors.New("503")},
			}
		},
		now: fixedNow,
	}
	got := d.Deliver(context.Background(), deliverReq{Cross: true, Channels: []string{"slack", "pagerduty"}, Alert: models.Alert{Rule: "report"}}) // Cross: named-channel dispatch is platform-owned (M15)
	if len(got) != 2 {
		t.Fatalf("statuses = %d, want 2", len(got))
	}
	byCh := map[string]bool{}
	for _, ds := range got {
		byCh[ds.Channel] = ds.OK
	}
	if !byCh["slack"] || byCh["pagerduty"] {
		t.Fatalf("per-channel status wrong: %+v", got)
	}
}

func TestDeliverSkipsAlreadyDelivered(t *testing.T) {
	var sentTo []string
	d := &reportDelivery{
		resolveEmail: func(ids []string, tenant string, cross bool) []string {
			return []string{"a@x.com", "b@x.com", "c@x.com"}
		},
		emailSender: func(r []string) (docSender, bool) { sentTo = append(sentTo, r[0]); return &fakeDoc{}, true },
		dispatch:    func(a models.Alert, names []string) []notify.SendResult { return nil },
		now:         fixedNow,
	}
	got := d.Deliver(context.Background(), deliverReq{
		ContactPoints:  []string{"cp"},
		Attempt:        2,
		SkipRecipients: map[string]bool{"b@x.com": true},
	})
	// b@x.com was already delivered -> not re-sent, but still reported ok.
	if len(sentTo) != 2 {
		t.Fatalf("expected 2 sends (a,c), got %v", sentTo)
	}
	for _, s := range sentTo {
		if s == "b@x.com" {
			t.Fatalf("b@x.com should have been skipped, not re-sent")
		}
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 statuses, got %d", len(got))
	}
	for _, ds := range got {
		if !ds.OK || ds.Attempt != 2 {
			t.Errorf("status should be ok/attempt2: %+v", ds)
		}
	}
}

func TestDeliverEmptyChannelsNoFanout(t *testing.T) {
	dispatched := false
	d := &reportDelivery{
		resolveEmail: func(ids []string, tenant string, cross bool) []string { return nil },
		emailSender:  func(r []string) (docSender, bool) { return nil, false },
		dispatch: func(a models.Alert, names []string) []notify.SendResult {
			dispatched = true
			return nil
		},
		now: fixedNow,
	}
	got := d.Deliver(context.Background(), deliverReq{Channels: nil})
	if dispatched {
		t.Fatalf("empty Channels must NOT fan out to all channels")
	}
	if len(got) != 0 {
		t.Fatalf("expected no deliveries, got %+v", got)
	}
}

// TestAsyncDeliveryRefusesNamedChannelsForTenantReport pins the M15/§3a.3 gate on
// the ASYNC (Postgres, default backend) delivery path: notify channels are
// platform-global resources, so a TENANT-owned report (Cross=false) must never
// fan out to named channels — even though its saved body may carry a channel
// list. Only a platform-owned (Cross=true) report may. Mirrors the file-backend
// reportScheduler.deliver gate. Before the fix, the tenant report dispatched
// every named channel.
func TestAsyncDeliveryRefusesNamedChannelsForTenantReport(t *testing.T) {
	var dispatched [][]string
	d := &reportDelivery{
		// No email / webhook destinations — this test is only about named channels.
		resolveEmail:    func(ids []string, tenant string, cross bool) []string { return nil },
		resolveWebhooks: func(ids []string, tenant string, cross bool) []ContactPoint { return nil },
		dispatch: func(a models.Alert, names []string) []notify.SendResult {
			dispatched = append(dispatched, names)
			out := make([]notify.SendResult, 0, len(names))
			for _, n := range names {
				out = append(out, notify.SendResult{Channel: n})
			}
			return out
		},
		now: fixedNow,
	}

	// Tenant-owned report (Cross=false) naming platform-global channels: refused.
	tenantReq := deliverReq{
		Tenant:   "acme",
		Cross:    false,
		Channels: []string{"ops-slack", "pagerduty-critical"},
	}
	if got := d.Deliver(context.Background(), tenantReq); len(got) != 0 {
		t.Fatalf("tenant-owned report must produce NO channel deliveries, got %+v", got)
	}
	if len(dispatched) != 0 {
		t.Fatalf("CHANNEL LEAK: tenant-owned report dispatched to platform channels %v", dispatched)
	}

	// Platform-owned report (Cross=true) with the same channels: still delivered,
	// so the refusal above is the gate, not a broken dispatch path.
	platformReq := tenantReq
	platformReq.Cross = true
	if got := d.Deliver(context.Background(), platformReq); len(got) != 2 {
		t.Fatalf("platform-owned report should dispatch both channels, got %+v", got)
	}
	if len(dispatched) != 1 || len(dispatched[0]) != 2 {
		t.Fatalf("platform-owned report should dispatch exactly the 2 named channels, got %v", dispatched)
	}
}
