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

// pagerDutyEventsV2URL is the Events API v2 endpoint. A var (not const) so tests
// can point it at a local fake server; never reassigned in production.
var pagerDutyEventsV2URL = "https://events.pagerduty.com/v2/enqueue"

// PagerDuty fires events via the Events API v2.
type PagerDuty struct {
	routingKey string
	client     *http.Client
}

func NewPagerDuty(routingKey string) *PagerDuty {
	return &PagerDuty{
		routingKey: routingKey,
		client:     safehttp.Client(10 * time.Second),
	}
}

func (p *PagerDuty) Name() string { return "pagerduty" }

// pdSeverity maps platform severities onto the Events API v2 enum
// (critical | error | warning | info) — anything else is rejected with a 400.
func pdSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit":
		return "critical"
	case "error", "err", "major":
		return "error"
	case "warning", "warn", "minor", "high":
		return "warning"
	case "info", "notice", "":
		return "info"
	}
	return "warning"
}

func (p *PagerDuty) Send(a models.Alert) error {
	if p.routingKey == "" {
		return errors.New("pagerduty routing key not configured")
	}
	// Events v2 rejects the whole event (400) on an empty source or a severity
	// outside its enum — normalize both here so every caller (alert engine,
	// channel test, future paths) sends a valid event.
	source := a.DeviceID
	if source == "" {
		source = "correlix"
	}
	payload := map[string]any{
		"routing_key":  p.routingKey,
		"event_action": "trigger",
		"dedup_key":    a.ID,
		"payload": map[string]any{
			"summary":  a.Summary,
			"severity": pdSeverity(a.Severity),
			"source":   source,
			"custom_details": map[string]any{
				"rule":   a.Rule,
				"labels": a.Labels,
			},
		},
	}
	buf, _ := json.Marshal(payload)
	resp, err := p.client.Post(pagerDutyEventsV2URL, "application/json", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("pagerduty returned %d", resp.StatusCode)
	}
	return nil
}
