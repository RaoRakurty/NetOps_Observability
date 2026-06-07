package integration

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// servicenow.go — ServiceNow inbound translator. ServiceNow has no standard
// webhook HMAC. PREFERRED (SR-019): a Business Rule sends a request timestamp
// (X-NetOps-Webhook-Timestamp) and HMAC-SHA256 over "{ts}.{body}" in
// X-NetOps-Webhook-Signature — giving authenticity + replay protection like the
// other providers. FALLBACK (legacy): a static shared secret in
// X-NetOps-Webhook-Secret, compared constant-time (no replay protection).

type serviceNowProvider struct{}

// NewServiceNowProvider returns the ServiceNow inbound translator.
func NewServiceNowProvider() Provider { return serviceNowProvider{} }

func (serviceNowProvider) Type() string { return "servicenow" }
func (serviceNowProvider) Capabilities() Capabilities {
	return Capabilities{Ticketing: true, Webhooks: true, Polling: true, Interactive: false}
}

const (
	headerWebhookSecret    = "X-NetOps-Webhook-Secret"    // #nosec G101 -- HTTP header NAME, not a credential value
	headerWebhookTimestamp = "X-NetOps-Webhook-Timestamp" // #nosec G101 -- HTTP header NAME
	headerWebhookSignature = "X-NetOps-Webhook-Signature" // #nosec G101 -- HTTP header NAME
)

const serviceNowReplayWindow = 5 * time.Minute

func (serviceNowProvider) VerifyWebhook(r *http.Request, body []byte, secret string) error {
	if secret == "" {
		return ErrSignatureInvalid
	}
	// Preferred: signed + replay-protected (SR-019).
	if sig := r.Header.Get(headerWebhookSignature); sig != "" {
		tsHdr := r.Header.Get(headerWebhookTimestamp)
		ts, err := strconv.ParseInt(tsHdr, 10, 64)
		if err != nil || !withinSkew(ts, serviceNowReplayWindow) {
			return ErrSignatureInvalid
		}
		expected := hmacSHA256Hex([]byte(secret), append([]byte(tsHdr+"."), body...))
		if !constEq(sig, expected) {
			return ErrSignatureInvalid
		}
		return nil
	}
	// Fallback: legacy static shared-secret header (no replay protection).
	if !constEq(r.Header.Get(headerWebhookSecret), secret) {
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
		// ExternalID correlates to the incident's external_ticket_id, which we
		// store as the SN NUMBER (INC00…) on outbound. Prefer number; fall back to
		// sys_id if a webhook omits it.
		ExternalID:    firstNonEmpty(p.Number, p.SysID),
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
