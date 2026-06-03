package integration

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// servicenow.go — ServiceNow inbound translator. ServiceNow has no standard
// webhook HMAC, so a Business Rule / Scripted REST posts a shared secret in the
// X-NetOps-Webhook-Secret header (per-tenant token); we compare it constant-time.
// (HMAC can be added later if the instance computes one.)

type serviceNowProvider struct{}

// NewServiceNowProvider returns the ServiceNow inbound translator.
func NewServiceNowProvider() Provider { return serviceNowProvider{} }

func (serviceNowProvider) Type() string { return "servicenow" }
func (serviceNowProvider) Capabilities() Capabilities {
	return Capabilities{Ticketing: true, Webhooks: true, Polling: true, Interactive: false}
}

const headerWebhookSecret = "X-NetOps-Webhook-Secret"

func (serviceNowProvider) VerifyWebhook(r *http.Request, _ []byte, secret string) error {
	if secret == "" || !constEq(r.Header.Get(headerWebhookSecret), secret) {
		return ErrSignatureInvalid
	}
	return nil
}

// snWebhook is the payload a ServiceNow Business Rule posts on incident change.
type snWebhook struct {
	Number      string `json:"number"`
	SysID       string `json:"sys_id"`
	State       string `json:"state"`         // numeric ServiceNow state
	SysModCount int64  `json:"sys_mod_count"` // monotonic version → ExternalSeq
	AssignedTo  string `json:"assigned_to"`
	Comments    string `json:"comments"`
	UpdatedBy   string `json:"sys_updated_by"`
	UpdatedOn   string `json:"sys_updated_on"` // "2006-01-02 15:04:05" (instance TZ)
	EventID     string `json:"event_id"`       // optional delivery id
	AlertID     string `json:"u_nms_alert_id"` // optional back-reference our payload set
}

func (serviceNowProvider) Normalize(tenant string, body []byte) ([]IntegrationEvent, error) {
	var p snWebhook
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, err
	}
	state := snStateWord(p.State)
	ev := IntegrationEvent{
		Provider:      "servicenow",
		Tenant:        tenant,
		ProviderEvtID: firstNonEmpty(p.EventID, p.SysID+":"+strconv.FormatInt(p.SysModCount, 10)),
		ExternalID:    firstNonEmpty(p.SysID, p.Number),
		AlertID:       p.AlertID,
		ExternalSeq:   p.SysModCount,
		OccurredAt:    parseLooseTime(p.UpdatedOn),
		Type:          stateToEventType(state),
		ExternalState: state,
		Actor:         p.UpdatedBy,
		Comment:       p.Comments,
		Assignee:      p.AssignedTo,
		Raw:           body,
	}
	return []IntegrationEvent{ev}, nil
}

// snStateWord maps ServiceNow's numeric incident state to a canonical token the
// MappingEngine understands. Unknown → the raw value (lets a tenant override map it).
func snStateWord(s string) string {
	switch s {
	case "1":
		return "new"
	case "2":
		return "in progress"
	case "3":
		return "on hold"
	case "6":
		return "resolved"
	case "7":
		return "closed"
	case "8":
		return "cancelled"
	default:
		return s
	}
}
