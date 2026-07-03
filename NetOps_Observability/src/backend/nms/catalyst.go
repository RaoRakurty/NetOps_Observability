package nms

import (
	"encoding/json"
	"strings"
	"time"
)

// catalyst.go — Cisco Catalyst Center (DNA Center) transformer. Assurance
// issues (poll or webhook). Each issue → one ControllerEvent; an interface/
// reachability issue also carries a STATE fact.

// CatalystTransformer normalizes a Catalyst Center assurance-issues response.
type CatalystTransformer struct{}

func (CatalystTransformer) Transform(tenant, integrationID string, raw []byte) (Batch, error) {
	var resp struct {
		Response []struct {
			IssueID     string `json:"issueId"`
			Name        string `json:"name"`
			Priority    string `json:"priority"`
			Severity    string `json:"severity"`
			Category    string `json:"category"`
			Status      string `json:"status"`
			DeviceID    string `json:"deviceId"`
			DeviceName  string `json:"deviceName"`
			SiteID      string `json:"siteId"`
			SiteName    string `json:"siteName"`
			EntityType  string `json:"entityType"`
			Entity      string `json:"entity"`
			LastOccTime int64  `json:"lastOccurenceTime"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, iss := range resp.Response {
		net, stateKind := catalystNormType(iss.Category, iss.Name, iss.EntityType)
		et := msToTime(iss.LastOccTime)
		e := ControllerEvent{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "catalyst_center",
			Vendor: "cisco", Product: "Catalyst Center",
			EventID:             iss.IssueID,
			EventTime:           et,
			IngestTime:          time.Now().UTC(),
			EventType:           iss.Category,
			NormalizedEventType: net,
			Severity:            normSeverity(firstNonEmpty(iss.Priority, iss.Severity)),
			Category:            "assurance_issue",
			DeviceID:            iss.DeviceID,
			DeviceName:          iss.DeviceName,
			SiteID:              iss.SiteID,
			SiteName:            iss.SiteName,
			InterfaceName:       ifaceIfIntf(iss.EntityType, iss.Entity),
			Message:             iss.Name,
			RawPayload:          mustJSON(iss),
			EvidenceRole:        roleForEventType(net),
			CorrelationHints:    map[string]string{"entity_type": iss.EntityType, "entity": iss.Entity},
		}
		e.DedupeKey = DedupeKey(e)
		b.Events = append(b.Events, e)

		if stateKind != "" && strings.EqualFold(iss.Status, "active") {
			b.States = append(b.States, ControllerState{
				TenantID: tenant, IntegrationID: integrationID, SourceSystem: "catalyst_center",
				EntityKey: firstNonEmpty(iss.Entity, iss.DeviceName), StateKind: stateKind,
				CurrentState: "down", DeviceID: iss.DeviceID, SiteID: iss.SiteID, Time: et,
			})
		}
	}
	return b, nil
}

func ifaceIfIntf(entityType, entity string) string {
	if strings.EqualFold(entityType, "interface") {
		return entity
	}
	return ""
}

func catalystNormType(category, name, entityType string) (string, string) {
	t := strings.ToLower(category + " " + name + " " + entityType)
	switch {
	case strings.Contains(t, "interface") && strings.Contains(t, "down"):
		return "controller_alarm", "intf_oper"
	case strings.Contains(t, "reachab") || strings.Contains(t, "unreachable") || strings.Contains(t, "down") && strings.Contains(t, "device"):
		return "controller_device_unreachable", "reachability"
	case strings.Contains(t, "onboarding") || strings.Contains(t, "config") || strings.Contains(t, "provision"):
		return "controller_policy_change", ""
	default:
		return "controller_alarm", ""
	}
}
