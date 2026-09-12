// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// meraki.go — Cisco Meraki Dashboard connector: webhook receiver + transformer.
// Webhook archetype (auth = API key / OAuth). A Meraki alert webhook is a single
// discrete event → one ControllerEvent (§3.3).

// MerakiTransformer normalizes a Meraki webhook alert.
type MerakiTransformer struct{}

func (MerakiTransformer) Transform(tenant, integrationID string, raw []byte) (Batch, error) {
	var a struct {
		SentAt           string `json:"sentAt"`
		OrganizationName string `json:"organizationName"`
		NetworkID        string `json:"networkId"`
		NetworkName      string `json:"networkName"`
		DeviceSerial     string `json:"deviceSerial"`
		DeviceName       string `json:"deviceName"`
		AlertID          string `json:"alertId"`
		AlertType        string `json:"alertType"`
		AlertTypeID      string `json:"alertTypeId"`
		OccurredAt       string `json:"occurredAt"`
		AlertLevel       string `json:"alertLevel"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return Batch{}, err
	}
	net := merakiNormType(a.AlertTypeID, a.AlertType)
	e := ControllerEvent{
		TenantID: tenant, IntegrationID: integrationID, SourceSystem: "meraki",
		Vendor: "cisco", Product: "Meraki Dashboard",
		EventID:             a.AlertID,
		EventTime:           parseTime(a.OccurredAt),
		IngestTime:          time.Now().UTC(),
		EventType:           a.AlertType,
		NormalizedEventType: net,
		Severity:            normSeverity(a.AlertLevel),
		Category:            "meraki_alert",
		DeviceID:            a.DeviceSerial, // Meraki keys devices by serial
		DeviceName:          a.DeviceName,
		SiteID:              a.NetworkID, // a Meraki network ≈ a site
		SiteName:            a.NetworkName,
		Message:             a.AlertType,
		RawPayload:          raw,
		EvidenceRole:        roleForEventType(net),
		CorrelationHints:    map[string]string{"org": a.OrganizationName, "network_id": a.NetworkID},
	}
	if e.EventTime.IsZero() {
		e.EventTime = parseTime(a.SentAt)
	}
	e.DedupeKey = DedupeKey(e)
	return Batch{Events: []ControllerEvent{e}}, nil
}

// merakiNormType maps Meraki alertTypeId to a normalized kind.
func merakiNormType(typeID, typeText string) string {
	t := strings.ToLower(typeID + " " + typeText)
	switch {
	case strings.Contains(t, "wan") && (strings.Contains(t, "down") || strings.Contains(t, "lost")):
		return "controller_device_unreachable"
	case strings.Contains(t, "down") || strings.Contains(t, "unreachable") || strings.Contains(t, "went down"):
		return "controller_device_unreachable"
	case strings.Contains(t, "config") || strings.Contains(t, "settings changed"):
		return "controller_policy_change"
	default:
		return "controller_alarm"
	}
}

// MerakiWebhook verifies the Meraki webhook shared secret (constant-time) and
// extracts the payload. Meraki posts a `sharedSecret` in the body; some setups
// also HMAC-sign. We accept either: exact shared-secret match OR HMAC-SHA256.
type MerakiWebhook struct{}

func (MerakiWebhook) Verify(r *http.Request, body, secret []byte) error {
	// HMAC header form (X-Cisco-Meraki-Signature), if present.
	if sig := r.Header.Get("X-Cisco-Meraki-Signature"); sig != "" {
		mac := hmac.New(sha256.New, secret)
		mac.Write(body)
		want := hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) == 1 {
			return nil
		}
		return ErrSignatureInvalid
	}
	// Shared-secret-in-body form.
	var probe struct {
		SharedSecret string `json:"sharedSecret"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return ErrSignatureInvalid
	}
	if subtle.ConstantTimeCompare([]byte(probe.SharedSecret), secret) == 1 {
		return nil
	}
	return ErrSignatureInvalid
}

func (MerakiWebhook) Extract(body []byte) ([][]byte, error) { return [][]byte{body}, nil }
