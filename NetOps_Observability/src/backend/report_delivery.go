package main

import (
	"context"
	"time"

	"netops/backend/models"
	"netops/backend/notify"
	"netops/backend/reports"
)

// report_delivery.go — the delivery adapter for the reporting pipeline.
//
// It routes a rendered artifact to its recipients and returns a per-recipient /
// per-channel reports.DeliveryStatus list, which the worker records on the
// execution row. That durable receipt — who received the report, which sends
// failed — is the capability the old fire-and-forget path never had.
//
// Two destination types:
//   - Email contact points get the rendered HTML artifact as the message body.
//   - Named notify channels (slack/pagerduty/...) get the alert-shaped summary.
//
// Phase-1 semantics: named-channel delivery happens ONLY for channels explicitly
// listed on the report. An empty Channels list means "contact points only" — it
// does NOT fan out to every configured channel (the old behavior, which produced
// surprise double-sends now that contact points are the primary recipient model).
type reportDelivery struct {
	resolveEmail    func(ids []string, tenant string, cross bool) []string
	resolveWebhooks func(ids []string, tenant string, cross bool) []ContactPoint
	emailSender     func(recipients []string) (docSender, bool)
	dispatch        func(a models.Alert, names []string) []notify.SendResult
	postWebhook     func(url, text string) error
	now             func() time.Time
}

// docSender is the slice of *notify.Email the adapter needs (HTML-capable one-off
// sends, with and without attachments), kept as an interface so tests can fake it.
type docSender interface {
	SendDocument(subject, contentType, body string) error
	SendReport(subject, htmlBody string, attachments []notify.Attachment) error
}

func newReportDelivery(s *server) *reportDelivery {
	return &reportDelivery{
		resolveEmail:    s.contactPoints.resolveEmailRecipients,
		resolveWebhooks: s.contactPoints.resolveWebhookPoints,
		emailSender: func(recipients []string) (docSender, bool) {
			e, ok := s.notifyCfg.emailSenderTo(recipients)
			if !ok {
				return nil, false
			}
			return e, true
		},
		dispatch:    s.notifier.DispatchToResults,
		postWebhook: notify.PostWebhook,
		now:         func() time.Time { return time.Now().UTC() },
	}
}

// deliverReq is one report fire's delivery instruction.
type deliverReq struct {
	Tenant         string
	Cross          bool
	ContactPoints  []string
	Channels       []string
	Subject        string             // artifact summary -> email subject
	ContentType    string             // artifact content type (text/html...)
	Body           []byte             // rendered HTML artifact (the email body)
	Attachments    []reports.Artifact // non-HTML artifacts (xlsx/pdf) attached to the email
	Alert          models.Alert
	Mode           string // "body" (default) or "link"
	ReportName     string
	ExecutionID    string          // for building the secure link in "link" mode
	Attempt        int             // current job attempt (stamped on delivery rows)
	SkipRecipients map[string]bool // recipients already delivered on a prior attempt
}

// Deliver sends to all configured destinations and returns one DeliveryStatus per
// recipient/channel. It never returns an error — partial failures are recorded
// individually so the execution record reflects exactly what happened.
func (d *reportDelivery) Deliver(_ context.Context, req deliverReq) []reports.DeliveryStatus {
	at := d.now()
	attempt := req.Attempt
	if attempt < 1 {
		attempt = 1
	}
	var out []reports.DeliveryStatus

	// ---- email contact points: one send PER recipient so a retry can resend
	// only the failures (recipients already delivered on a prior attempt are
	// skipped and recorded as ok without resending). ----
	recipients := d.resolveEmail(req.ContactPoints, req.Tenant, req.Cross)
	for _, rcpt := range recipients {
		if req.SkipRecipients[rcpt] {
			out = append(out, reports.DeliveryStatus{Channel: "email", Recipient: rcpt, OK: true, Attempt: attempt, At: at})
			continue
		}
		sender, ok := d.emailSender([]string{rcpt})
		if !ok {
			out = append(out, reports.DeliveryStatus{Channel: "email", Recipient: rcpt, Attempt: attempt, At: at, Error: "SMTP not configured"})
			continue
		}
		var err error
		switch {
		case req.Mode == "link":
			err = sender.SendDocument(req.Subject, "text/html; charset=UTF-8", buildLinkEmail(req.ReportName, reportViewLink(req.ExecutionID, req.Tenant, "html")))
		case len(toAttachments(req.Attachments)) > 0:
			err = sender.SendReport(req.Subject, string(req.Body), toAttachments(req.Attachments))
		default:
			err = sender.SendDocument(req.Subject, req.ContentType, string(req.Body))
		}
		ds := reports.DeliveryStatus{Channel: "email", Recipient: rcpt, OK: err == nil, Attempt: attempt, At: at}
		if err != nil {
			ds.Error = err.Error()
		}
		out = append(out, ds)
	}

	// ---- slack/webhook contact points: post a summary + a secure link (a
	// webhook can't carry the HTML body/attachment, so it always links out). ----
	if d.resolveWebhooks != nil {
		for _, cp := range d.resolveWebhooks(req.ContactPoints, req.Tenant, req.Cross) {
			if req.SkipRecipients[cp.Name] {
				out = append(out, reports.DeliveryStatus{Channel: cp.Type, Recipient: cp.Name, OK: true, Attempt: attempt, At: at})
				continue
			}
			text := req.ReportName + ": " + req.Subject
			if req.ExecutionID != "" {
				text += "\n" + reportViewLink(req.ExecutionID, req.Tenant, "html")
			}
			err := d.postWebhook(cp.Target, text)
			ds := reports.DeliveryStatus{Channel: cp.Type, Recipient: cp.Name, OK: err == nil, Attempt: attempt, At: at}
			if err != nil {
				ds.Error = err.Error()
			}
			out = append(out, ds)
		}
	}

	// ---- named notify channels (only when explicitly requested) ----
	if len(req.Channels) > 0 {
		for _, res := range d.dispatch(req.Alert, req.Channels) {
			ds := reports.DeliveryStatus{Channel: res.Channel, Recipient: res.Channel, Attempt: attempt, At: at, OK: res.Err == nil}
			if res.Err != nil {
				ds.Error = res.Err.Error()
			}
			out = append(out, ds)
		}
	}

	return out
}

// toAttachments turns rendered non-HTML artifacts into email attachments with a
// sensible filename per format.
func toAttachments(arts []reports.Artifact) []notify.Attachment {
	if len(arts) == 0 {
		return nil
	}
	out := make([]notify.Attachment, 0, len(arts))
	for _, a := range arts {
		ext := a.Format
		if ext == "" {
			ext = "bin"
		}
		out = append(out, notify.Attachment{
			Filename:    "report." + ext,
			ContentType: a.ContentType,
			Bytes:       a.Bytes,
		})
	}
	return out
}
