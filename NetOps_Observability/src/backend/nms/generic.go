package nms

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

// generic.go — the generic REST/Webhook connector: the escape hatch for any
// controller not yet first-classed. It accepts a payload already shaped to the
// canonical field names (or a batch of them), so an operator can integrate an
// unlisted vendor by mapping to the canonical schema without new code.

// GenericTransformer normalizes a canonical-shaped event (or array of events).
type GenericTransformer struct{}

type genericEvent struct {
	EventID     string `json:"event_id"`
	EventType   string `json:"event_type"`
	Normalized  string `json:"normalized_event_type"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	DeviceID    string `json:"device_id"`
	DeviceName  string `json:"device_name"`
	SiteID      string `json:"site_id"`
	SiteName    string `json:"site_name"`
	Interface   string `json:"interface_name"`
	TunnelID    string `json:"tunnel_id"`
	Application string `json:"application"`
	Message     string `json:"message"`
	EventTime   string `json:"event_time"`
}

func (GenericTransformer) Transform(tenant, integrationID string, raw []byte) (Batch, error) {
	// Accept a single object or an array.
	var evs []genericEvent
	if err := json.Unmarshal(raw, &evs); err != nil {
		var one genericEvent
		if err2 := json.Unmarshal(raw, &one); err2 != nil {
			return Batch{}, err2
		}
		evs = []genericEvent{one}
	}
	var b Batch
	for _, g := range evs {
		net := firstNonEmpty(g.Normalized, "controller_alarm")
		e := ControllerEvent{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "generic",
			Vendor: "generic", Product: "Generic REST/Webhook",
			EventID:             g.EventID,
			EventTime:           parseTime(g.EventTime),
			IngestTime:          time.Now().UTC(),
			EventType:           g.EventType,
			NormalizedEventType: net,
			Severity:            normSeverity(g.Severity),
			Category:            firstNonEmpty(g.Category, "generic"),
			DeviceID:            g.DeviceID,
			DeviceName:          g.DeviceName,
			SiteID:              g.SiteID,
			SiteName:            g.SiteName,
			InterfaceName:       g.Interface,
			TunnelID:            g.TunnelID,
			Application:         g.Application,
			Message:             g.Message,
			RawPayload:          mustJSON(g),
			EvidenceRole:        roleForEventType(net),
		}
		e.DedupeKey = DedupeKey(e)
		b.Events = append(b.Events, e)
	}
	return b, nil
}

// GenericWebhook verifies an HMAC-SHA256 shared-secret signature (header
// X-Correlix-Signature) — the recommended pattern for the generic receiver.
type GenericWebhook struct{}

func (GenericWebhook) Verify(r *http.Request, body, secret []byte) error {
	sig := r.Header.Get("X-Correlix-Signature")
	if sig == "" {
		return ErrSignatureInvalid
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) == 1 {
		return nil
	}
	return ErrSignatureInvalid
}

func (GenericWebhook) Extract(body []byte) ([][]byte, error) { return [][]byte{body}, nil }
