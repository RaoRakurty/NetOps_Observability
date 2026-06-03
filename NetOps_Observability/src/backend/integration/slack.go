package integration

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// slack.go — Slack inbound translator. Slack is NOT a ticket store: it's a
// notification + ACTION source. Its Interactivity webhook (Block Kit buttons:
// Acknowledge / Resolve / Escalate) lets a responder drive incident state from a
// channel. Requests are signed with the v0 scheme: HMAC-SHA256 over
// "v0:{timestamp}:{body}" keyed by the signing secret, with a 5-minute replay
// window. The payload is form-encoded: body = "payload=<url-encoded JSON>".

type slackProvider struct{}

// NewSlackProvider returns the Slack inbound (interactivity) translator.
func NewSlackProvider() Provider { return slackProvider{} }

func (slackProvider) Type() string { return "slack" }
func (slackProvider) Capabilities() Capabilities {
	return Capabilities{Ticketing: false, Webhooks: true, Polling: false, Interactive: true}
}

const slackReplayWindow = 5 * time.Minute

func (slackProvider) VerifyWebhook(r *http.Request, body []byte, secret string) error {
	if secret == "" {
		return ErrSignatureInvalid
	}
	tsHdr := r.Header.Get("X-Slack-Request-Timestamp")
	ts, err := strconv.ParseInt(tsHdr, 10, 64)
	if err != nil || !withinSkew(ts, slackReplayWindow) {
		return ErrSignatureInvalid
	}
	base := append([]byte("v0:"+tsHdr+":"), body...)
	expected := "v0=" + hmacSHA256Hex([]byte(secret), base)
	if !constEq(r.Header.Get("X-Slack-Signature"), expected) {
		return ErrSignatureInvalid
	}
	return nil
}

type slackInteraction struct {
	Type    string `json:"type"` // block_actions
	User    struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	} `json:"user"`
	TriggerID string `json:"trigger_id"`
	Actions   []struct {
		ActionID string `json:"action_id"` // ack_incident | resolve_incident | escalate_incident
		Value    string `json:"value"`     // our internal incident/alert id (embedded outbound)
	} `json:"actions"`
}

func (slackProvider) Normalize(tenant string, body []byte) ([]IntegrationEvent, error) {
	// Interactivity bodies are form-encoded with a single `payload` field.
	raw := string(body)
	if vals, err := url.ParseQuery(raw); err == nil {
		if p := vals.Get("payload"); p != "" {
			raw = p
		}
	}
	var p slackInteraction
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, err
	}
	out := make([]IntegrationEvent, 0, len(p.Actions))
	for _, a := range p.Actions {
		et, ext := slackAction(a.ActionID)
		if et == "" {
			continue // non-state action (open modal, etc.) — ignore
		}
		out = append(out, IntegrationEvent{
			Provider:      "slack",
			Tenant:        tenant,
			ProviderEvtID: firstNonEmpty(p.TriggerID+":"+a.ActionID, a.ActionID+":"+a.Value),
			AlertID:       a.Value, // the internal id our outbound message embedded
			ExternalID:    a.Value,
			OccurredAt:    timeNow().UTC(),
			Type:          et,
			ExternalState: ext,
			Actor:         firstNonEmpty(p.User.Username, p.User.ID),
			Raw:           body,
		})
	}
	return out, nil
}

// slackAction maps a Block Kit action_id to a canonical event + external state.
func slackAction(actionID string) (EventType, string) {
	switch actionID {
	case "ack_incident", "acknowledge":
		return EventAcknowledged, "acknowledged"
	case "resolve_incident", "resolve":
		return EventResolved, "resolved"
	case "escalate_incident", "escalate":
		return EventUpdated, "escalated"
	default:
		return "", ""
	}
}
