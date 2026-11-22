// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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

// Teams is the PLATFORM-GLOBAL Microsoft Teams channel: the operator's own,
// configured under Settings -> Notification channels, not a tenant's. It posts
// the same Adaptive Card message the tenant Teams destinations send
// (teams_card.go: TeamsAlertMessage + PostTeamsMessage), so it renders on both
// kinds of Teams webhook an operator can paste: a Workflows ("When a Teams
// webhook request is received") URL and a classic Incoming Webhook. The legacy
// MessageCard it used to post rendered only on the classic kind (tracker 455).
//
// Egress is the SSRF-hardened safehttp client; the severity floor is the
// SeverityGate that BuildTeamsChannel wraps around it. The webhook URL is a
// bearer credential, and no error returned from here ever carries it.
type Teams struct {
	webhookURL string
	client     *http.Client
}

// NewTeams builds the channel over the SSRF-hardened egress client.
func NewTeams(webhookURL string) *Teams {
	return &Teams{webhookURL: webhookURL, client: safehttp.Client(10 * time.Second)}
}

func (t *Teams) Name() string { return "teams" }

// Send posts one alert as an Adaptive Card. Any non-2xx is an error so the
// delivery layer retries and counts it; the error carries the status only.
func (t *Teams) Send(a models.Alert) error {
	if strings.TrimSpace(t.webhookURL) == "" {
		return errors.New("teams webhook url not configured")
	}
	return sendTeamsAlert(t.client, t.webhookURL, a)
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
