package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"netops/backend/models"
)

// Slack posts incident messages to an Incoming Webhook URL.
type Slack struct {
	webhookURL string
	client     *http.Client
}

func NewSlack(webhookURL string) *Slack {
	return &Slack{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 10 * time.Second},
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
