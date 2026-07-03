package nms

import (
	"encoding/json"
	"strings"
	"time"
)

// ndfc.go — Cisco Nexus Dashboard / NDFC transformer. Fabric alarms → event
// (+ interface/link state). Carries fabric/VRF/tenant context in hints.

// NDFCTransformer normalizes an NDFC fabric-alarms response.
type NDFCTransformer struct{}

func (NDFCTransformer) Transform(tenant, integrationID string, raw []byte) (Batch, error) {
	var resp struct {
		Alarms []struct {
			ID           string `json:"id"`
			FabricName   string `json:"fabricName"`
			SourceName   string `json:"sourceName"`
			SwitchSerial string `json:"switchSerial"`
			ModuleName   string `json:"moduleName"`
			VRF          string `json:"vrf"`
			Tenant       string `json:"tenant"`
			Severity     string `json:"severity"`
			Category     string `json:"category"`
			PolicyChange bool   `json:"policyChange"`
			Message      string `json:"message"`
			EventType    string `json:"eventType"`
			CreatedTime  int64  `json:"createdTime"`
		} `json:"alarms"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, a := range resp.Alarms {
		net, stateKind := ndfcNormType(a.EventType, a.Category, a.PolicyChange)
		et := msToTime(a.CreatedTime)
		e := ControllerEvent{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "ndfc",
			Vendor: "cisco", Product: "Nexus Dashboard / NDFC",
			EventID:             a.ID,
			EventTime:           et,
			IngestTime:          time.Now().UTC(),
			EventType:           a.EventType,
			NormalizedEventType: net,
			Severity:            normSeverity(a.Severity),
			Category:            strings.ToLower(firstNonEmpty(a.Category, "fabric")),
			DeviceID:            firstNonEmpty(a.SwitchSerial, a.SourceName),
			DeviceName:          a.SourceName,
			InterfaceName:       a.ModuleName,
			Message:             a.Message,
			RawPayload:          mustJSON(a),
			EvidenceRole:        roleForEventType(net),
			CorrelationHints: map[string]string{
				"fabric": a.FabricName, "vrf": a.VRF, "controller_tenant": a.Tenant,
			},
		}
		e.DedupeKey = DedupeKey(e)
		b.Events = append(b.Events, e)

		if stateKind == "intf_oper" {
			b.States = append(b.States, ControllerState{
				TenantID: tenant, IntegrationID: integrationID, SourceSystem: "ndfc",
				EntityKey: a.SourceName + ":" + a.ModuleName, StateKind: "intf_oper",
				CurrentState: "down", DeviceID: firstNonEmpty(a.SwitchSerial, a.SourceName), Time: et,
				Data: map[string]any{"fabric": a.FabricName, "vrf": a.VRF},
			})
		}
	}
	return b, nil
}

func ndfcNormType(eventType, category string, policyChange bool) (string, string) {
	if policyChange {
		return "controller_policy_change", ""
	}
	t := strings.ToLower(eventType + " " + category)
	switch {
	case strings.Contains(t, "link") && strings.Contains(t, "down"):
		return "controller_alarm", "intf_oper"
	case strings.Contains(t, "deploy") || strings.Contains(t, "config"):
		return "controller_policy_change", ""
	default:
		return "controller_alarm", ""
	}
}
