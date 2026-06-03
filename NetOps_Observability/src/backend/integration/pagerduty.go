package integration

import (
	"encoding/json"
	"net/http"
	"strings"
)

// pagerduty.go — PagerDuty inbound translator. PagerDuty v3 webhooks are signed
// with HMAC-SHA256 over the raw body; the X-PagerDuty-Signature header carries one
// or more comma-separated "v1=<hex>" values (key rotation) — we accept if any
// matches.

type pagerDutyProvider struct{}

// NewPagerDutyProvider returns the PagerDuty inbound translator.
func NewPagerDutyProvider() Provider { return pagerDutyProvider{} }

func (pagerDutyProvider) Type() string { return "pagerduty" }
func (pagerDutyProvider) Capabilities() Capabilities {
	// On-call routing, not a ticket store; supports ack via webhooks.
	return Capabilities{Ticketing: false, Webhooks: true, Polling: true, Interactive: true}
}

func (pagerDutyProvider) VerifyWebhook(r *http.Request, body []byte, secret string) error {
	if secret == "" {
		return ErrSignatureInvalid
	}
	expected := "v1=" + hmacSHA256Hex([]byte(secret), body)
	for _, tok := range strings.Split(r.Header.Get("X-PagerDuty-Signature"), ",") {
		if constEq(strings.TrimSpace(tok), expected) {
			return nil
		}
	}
	return ErrSignatureInvalid
}

type pdWebhook struct {
	Event struct {
		ID         string `json:"id"`
		EventType  string `json:"event_type"` // incident.triggered|acknowledged|resolved|reassigned|annotated
		OccurredAt string `json:"occurred_at"`
		Agent      *struct {
			Summary string `json:"summary"`
		} `json:"agent"`
		Data struct {
			ID        string `json:"id"`
			Status    string `json:"status"`
			Assignees []struct {
				Summary string `json:"summary"`
			} `json:"assignees"`
		} `json:"data"`
	} `json:"event"`
}

func (pagerDutyProvider) Normalize(tenant string, body []byte) ([]IntegrationEvent, error) {
	var p pdWebhook
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, err
	}
	e := p.Event
	ev := IntegrationEvent{
		Provider:      "pagerduty",
		Tenant:        tenant,
		ProviderEvtID: e.ID,
		ExternalID:    e.Data.ID,
		OccurredAt:    parseLooseTime(e.OccurredAt),
		ExternalState: e.Data.Status,
		Type:          pdEventType(e.EventType),
		Raw:           body,
	}
	if e.Agent != nil {
		ev.Actor = e.Agent.Summary
	}
	if len(e.Data.Assignees) > 0 {
		ev.Assignee = e.Data.Assignees[0].Summary
	}
	return []IntegrationEvent{ev}, nil
}

func pdEventType(t string) EventType {
	switch t {
	case "incident.acknowledged":
		return EventAcknowledged
	case "incident.resolved":
		return EventResolved
	case "incident.triggered":
		return EventCreated
	case "incident.reassigned":
		return EventAssigned
	case "incident.annotated":
		return EventCommentAdded
	default:
		return EventUpdated
	}
}
