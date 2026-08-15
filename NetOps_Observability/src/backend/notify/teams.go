package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"netops/backend/models"
	"netops/backend/safehttp"
)

// Teams posts to a Microsoft Teams Incoming Webhook using the MessageCard
// (Office 365 connector) format, which Teams renders with a colored title bar.
type Teams struct {
	webhookURL string
	client     *http.Client
}

func NewTeams(webhookURL string) *Teams {
	return &Teams{webhookURL: webhookURL, client: safehttp.Client(10 * time.Second)}
}

func (t *Teams) Name() string { return "teams" }

// teamsThemeColor maps severity to a hex bar color.
func teamsThemeColor(sev string) string {
	switch sev {
	case "critical":
		return "E11D48"
	case "error":
		return "EA580C"
	case "warning":
		return "D97706"
	case "ok", "info":
		return "2563EB"
	default:
		return "5B5BD6"
	}
}

func (t *Teams) Send(a models.Alert) error {
	if t.webhookURL == "" {
		return errors.New("teams webhook url not configured")
	}
	text := a.Summary
	if a.Description != "" {
		text = a.Summary + "\n\n" + a.Description
	}
	card := map[string]any{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"summary":    a.Rule,
		"themeColor": teamsThemeColor(a.Severity),
		"title":      fmt.Sprintf("[%s] %s", a.Severity, a.Rule),
		"text":       text,
	}
	buf, _ := json.Marshal(card) // discard: marshalling an in-memory value cannot fail
	resp, err := t.client.Post(t.webhookURL, "application/json", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("teams webhook returned %d", resp.StatusCode)
	}
	return nil
}

// PostWebhook sends a simple text payload to an arbitrary incoming webhook
// (Slack/Teams/generic). The reporting pipeline uses it to deliver to
// slack/webhook-type contact points. text-only keeps it compatible with the
// widest set of webhook receivers.
func PostWebhook(url, text string) error {
	if url == "" {
		return errors.New("webhook url is empty")
	}
	buf, _ := json.Marshal(map[string]string{"text": text}) // discard: marshalling an in-memory value cannot fail
	c := safehttp.Client(10 * time.Second)
	resp, err := c.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
