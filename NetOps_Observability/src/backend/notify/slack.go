package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"netops/backend/models"
	"netops/backend/safehttp"
)

// Slack posts incident messages to an Incoming Webhook URL.
type Slack struct {
	webhookURL string
	client     *http.Client
}

func NewSlack(webhookURL string) *Slack {
	return &Slack{
		webhookURL: webhookURL,
		client:     safehttp.Client(10 * time.Second),
	}
}

func (s *Slack) Name() string { return "slack" }

func (s *Slack) Send(a models.Alert) error {
	if s.webhookURL == "" {
		return errors.New("slack webhook url not configured")
	}
	body := map[string]string{
		"text": fmt.Sprintf("[%s] %s — %s", a.Severity, a.Rule, a.Summary),
	}
	buf, _ := json.Marshal(body)
	resp, err := s.client.Post(s.webhookURL, "application/json", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned %d", resp.StatusCode)
	}
	return nil
}

// IncidentNotice is an incident summary posted to Slack with interactive action
// buttons. The buttons are the OUTBOUND half of the bidirectional loop (#43):
// each carries action_id + value, and a click POSTs back to the integration
// webhook, whose Slack translator maps action_id→event and value→our incident id
// (see integration/slack.go: ack_incident/resolve_incident/escalate_incident).
type IncidentNotice struct {
	IncidentID string
	// DisplayID is the human handle shown in the message text (INC-XXXXXX,
	// #103 UX-2 — no raw hex in operator-facing copy). The buttons' value stays
	// IncidentID: that is the inbound translator's contract.
	DisplayID string
	Title     string
	Severity  string
	Status    string
	URL       string // optional deep link into the NetOps UI
}

// SendIncident posts an interactive incident message (Block Kit) to the webhook.
// Acknowledge/Resolve/Escalate buttons carry the incident id so an operator's
// click drives the incident's lifecycle back through the inbound webhook.
func (s *Slack) SendIncident(n IncidentNotice) error {
	if s.webhookURL == "" {
		return errors.New("slack webhook url not configured")
	}
	buf, _ := json.Marshal(BuildIncidentBlocks(n))
	resp, err := s.client.Post(s.webhookURL, "application/json", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned %d", resp.StatusCode)
	}
	return nil
}

// BuildIncidentBlocks builds the Slack Block Kit payload for an incident notice.
// Exported so the action_id/value contract with the inbound translator can be
// unit-tested directly. action_ids MUST match integration/slack.go's slackAction.
func BuildIncidentBlocks(n IncidentNotice) map[string]any {
	headline := fmt.Sprintf("*[%s] %s*", strings.ToUpper(n.Severity), n.Title)
	// Show the human handle when the caller supplies one; the raw id stays in
	// the button values (the inbound translator's correlation contract).
	shownID := n.DisplayID
	if shownID == "" {
		shownID = n.IncidentID
	}
	statusLine := fmt.Sprintf("Status: `%s`  ·  Incident `%s`", n.Status, shownID)

	button := func(text, actionID, style string) map[string]any {
		b := map[string]any{
			"type":      "button",
			"text":      map[string]any{"type": "plain_text", "text": text},
			"action_id": actionID,
			"value":     n.IncidentID, // the internal id the inbound translator reads
		}
		if style != "" {
			b["style"] = style
		}
		return b
	}

	blocks := []map[string]any{
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": headline + "\n" + statusLine}},
		{"type": "actions", "elements": []map[string]any{
			button("Acknowledge", "ack_incident", ""),
			button("Resolve", "resolve_incident", "primary"),
			button("Escalate", "escalate_incident", "danger"),
		}},
	}
	if n.URL != "" {
		blocks = append(blocks, map[string]any{"type": "context", "elements": []map[string]any{
			{"type": "mrkdwn", "text": "<" + n.URL + "|Open in NetOps>"}}})
	}
	// `text` is the notification fallback shown in the Slack list/preview.
	return map[string]any{"text": headline, "blocks": blocks}
}
