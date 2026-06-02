package notify

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"netops/backend/models"
)

// Ntfy publishes alerts to an ntfy.sh topic — free push notifications to phone
// and desktop. A no-cost alternative to Twilio for testing critical-alert pushes
// (Twilio is metered/paid; ntfy is free for public topics). Same wiring: gate it
// to "critical" via a SeverityGate to get phone pushes only for critical alerts.
//
// API: POST https://<server>/<topic> with the message as the body; Title,
// Priority (1-5) and Tags as headers. Public topics need no auth; protected
// topics take a bearer token.
type Ntfy struct {
	server string
	topic  string
	token  string
	client *http.Client
}

func NewNtfy(server, topic, token string) *Ntfy {
	if server == "" {
		server = "https://ntfy.sh"
	}
	return &Ntfy{
		server: strings.TrimRight(server, "/"),
		topic:  topic,
		token:  token,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *Ntfy) Name() string { return "ntfy" }

func (n *Ntfy) Send(a models.Alert) error {
	if n.topic == "" {
		return errors.New("ntfy: no topic configured")
	}
	req, err := http.NewRequest(http.MethodPost, n.server+"/"+n.topic, strings.NewReader(smsBody(a)))
	if err != nil {
		return err
	}
	req.Header.Set("Title", fmt.Sprintf("[%s] %s", strings.ToUpper(a.Severity), a.Rule))
	req.Header.Set("Priority", ntfyPriority(a.Severity))
	req.Header.Set("Tags", "rotating_light")
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy: status %d", resp.StatusCode)
	}
	return nil
}

func ntfyPriority(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "5"
	case "error":
		return "4"
	case "warning":
		return "3"
	default:
		return "2"
	}
}
