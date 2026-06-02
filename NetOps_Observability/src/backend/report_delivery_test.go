package main

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
	got := d.Deliver(context.Background(), deliverReq{Channels: []string{"slack", "pagerduty"}, Alert: models.Alert{Rule: "report"}})
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
