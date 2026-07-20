package nms

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"time"
)

// prime.go — Cisco Prime Infrastructure transformer (LEGACY). Prime returns
// XML or JSON; this handles both (§7 requirement). Device alarms → event
// (+ reachability state). Conservative by design.

// PrimeTransformer normalizes a Prime alarm response (XML or JSON).
type PrimeTransformer struct{}

// primeAlarm is the normalized shape we pull from either encoding.
type primeAlarm struct {
	ObjectID   string `xml:"objectId" json:"objectId"`
	Severity   string `xml:"severity" json:"severity"`
	Category   string `xml:"category" json:"category"`
	Source     string `xml:"source" json:"source"`
	DeviceName string `xml:"deviceName" json:"deviceName"`
	DeviceIP   string `xml:"deviceIpAddress" json:"deviceIpAddress"`
	EventType  string `xml:"eventType" json:"eventType"`
	Message    string `xml:"message" json:"message"`
	TimeStamp  int64  `xml:"timeStamp" json:"timeStamp"`
}

func (PrimeTransformer) Transform(tenant, integrationID string, raw []byte) (Batch, error) {
	alarms, err := parsePrime(raw)
	if err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, a := range alarms {
		net, stateKind := primeNormType(a.EventType, a.Category)
		et := msToTime(a.TimeStamp)
		e := ControllerEvent{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "prime",
			Vendor: "cisco", Product: "Prime Infrastructure",
			EventID:             a.ObjectID,
			EventTime:           et,
			IngestTime:          time.Now().UTC(),
			EventType:           a.EventType,
			NormalizedEventType: net,
			Severity:            normSeverity(a.Severity),
			Category:            strings.ToLower(firstNonEmpty(a.Category, "device")),
			DeviceID:            firstNonEmpty(a.DeviceIP, a.Source),
			DeviceName:          firstNonEmpty(a.DeviceName, a.Source),
			Message:             a.Message,
			RawPayload:          mustJSON(a),
			EvidenceRole:        roleForEventType(net),
			CorrelationHints:    map[string]string{"device_ip": a.DeviceIP},
		}
		e.DedupeKey = DedupeKey(e)
		b.Events = append(b.Events, e)

		if stateKind == "reachability" {
			b.States = append(b.States, ControllerState{
				TenantID: tenant, IntegrationID: integrationID, SourceSystem: "prime",
				EntityKey: firstNonEmpty(a.DeviceIP, a.Source), StateKind: "reachability",
				CurrentState: "down", DeviceID: firstNonEmpty(a.DeviceIP, a.Source), Time: et,
			})
		}
	}
	return b, nil
}

// parsePrime detects XML vs JSON and extracts the alarms.
func parsePrime(raw []byte) ([]primeAlarm, error) {
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "<") {
		var q struct {
			Entities []struct {
				Alarm primeAlarm `xml:"alarmDTO"`
			} `xml:"entity"`
		}
		if err := xml.Unmarshal(raw, &q); err != nil {
			return nil, err
		}
		out := make([]primeAlarm, 0, len(q.Entities))
		for _, e := range q.Entities {
			out = append(out, e.Alarm)
		}
		return out, nil
	}
	// JSON form: either a bare array or {"queryResponse":{"entity":[{"alarmDTO":…}]}}.
	var arr []primeAlarm
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return arr, nil
	}
	var wrapped struct {
		QueryResponse struct {
			Entity []struct {
				AlarmDTO primeAlarm `json:"alarmDTO"`
			} `json:"entity"`
		} `json:"queryResponse"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	out := make([]primeAlarm, 0, len(wrapped.QueryResponse.Entity))
	for _, e := range wrapped.QueryResponse.Entity {
		out = append(out, e.AlarmDTO)
	}
	return out, nil
}

func primeNormType(eventType, category string) (string, string) {
	t := strings.ToLower(eventType + " " + category)
	switch {
	case strings.Contains(t, "unreach") || strings.Contains(t, "reachab"):
		return "controller_device_unreachable", "reachability"
	case strings.Contains(t, "config") || strings.Contains(t, "change"):
		return "controller_policy_change", ""
	default:
		return "controller_alarm", ""
	}
}
