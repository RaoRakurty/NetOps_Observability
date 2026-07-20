package nms

import (
	"encoding/json"
	"strings"
	"time"
)

// versa.go — Versa Director + Concerto transformers. Director: SD-WAN tunnel/
// path/SLA alarms (event + tunnel state). Concerto: SASE/policy/security events.

// VersaDirectorTransformer normalizes a Versa Director alarms response.
type VersaDirectorTransformer struct{}

func (VersaDirectorTransformer) Transform(tenant, integrationID string, raw []byte) (Batch, error) {
	var resp struct {
		Alarms []struct {
			ID            string `json:"id"`
			Type          string `json:"type"`
			Severity      string `json:"severity"`
			Organization  string `json:"organization"`
			ApplianceName string `json:"applianceName"`
			SiteName      string `json:"siteName"`
			LocalSite     string `json:"localSite"`
			RemoteSite    string `json:"remoteSite"`
			TunnelName    string `json:"tunnelName"`
			Transport     string `json:"transport"`
			SLAViolation  bool   `json:"slaViolation"`
			EventTime     string `json:"eventTime"`
			Description   string `json:"description"`
		} `json:"alarms"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, a := range resp.Alarms {
		net, stateKind := versaNormType(a.Type)
		et := parseTime(a.EventTime)
		e := ControllerEvent{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "versa_director",
			Vendor: "versa", Product: "Versa Director",
			EventID:             a.ID,
			EventTime:           et,
			IngestTime:          time.Now().UTC(),
			EventType:           a.Type,
			NormalizedEventType: net,
			Severity:            normSeverity(a.Severity),
			Category:            "sdwan",
			DeviceID:            a.ApplianceName,
			DeviceName:          a.ApplianceName,
			SiteName:            a.SiteName,
			TunnelID:            a.TunnelName,
			Message:             a.Description,
			RawPayload:          mustJSON(a),
			EvidenceRole:        roleForEventType(net),
			CorrelationHints: map[string]string{
				"org": a.Organization, "transport": a.Transport,
				"local_site": a.LocalSite, "remote_site": a.RemoteSite,
				"sla_violation": boolStr(a.SLAViolation),
			},
		}
		e.DedupeKey = DedupeKey(e)
		b.Events = append(b.Events, e)

		if stateKind == "tunnel" {
			b.States = append(b.States, ControllerState{
				TenantID: tenant, IntegrationID: integrationID, SourceSystem: "versa_director",
				EntityKey: a.TunnelName, StateKind: "tunnel", CurrentState: "down",
				DeviceID: a.ApplianceName, Time: et,
				Data: map[string]any{"transport": a.Transport, "remote_site": a.RemoteSite},
			})
		}
	}
	return b, nil
}

func versaNormType(typ string) (string, string) {
	t := strings.ToLower(typ)
	switch {
	case strings.Contains(t, "tunnel"):
		return "controller_tunnel_state", "tunnel"
	case strings.Contains(t, "sla"):
		return "controller_health_score", ""
	case strings.Contains(t, "policy"):
		return "controller_policy_change", ""
	case strings.Contains(t, "path"):
		return "controller_alarm", ""
	default:
		return "controller_alarm", ""
	}
}

// VersaConcertoTransformer normalizes Versa Concerto SASE/policy/security events.
type VersaConcertoTransformer struct{}

func (VersaConcertoTransformer) Transform(tenant, integrationID string, raw []byte) (Batch, error) {
	var resp struct {
		Events []struct {
			ID          string `json:"id"`
			Tenant      string `json:"tenant"`
			Site        string `json:"site"`
			Type        string `json:"type"`
			Category    string `json:"category"`
			Severity    string `json:"severity"`
			PolicyName  string `json:"policyName"`
			Application string `json:"application"`
			EventTime   string `json:"eventTime"`
			Description string `json:"description"`
		} `json:"events"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, ev := range resp.Events {
		net := "controller_alarm"
		if strings.Contains(strings.ToLower(ev.Type+" "+ev.Category), "policy") {
			net = "controller_policy_change"
		}
		e := ControllerEvent{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "versa_concerto",
			Vendor: "versa", Product: "Versa Concerto",
			EventID:             ev.ID,
			EventTime:           parseTime(ev.EventTime),
			IngestTime:          time.Now().UTC(),
			EventType:           ev.Type,
			NormalizedEventType: net,
			Severity:            normSeverity(ev.Severity),
			Category:            firstNonEmpty(ev.Category, "sase"),
			SiteID:              ev.Site,
			Application:         ev.Application,
			Message:             ev.Description,
			RawPayload:          mustJSON(ev),
			EvidenceRole:        roleForEventType(net),
			CorrelationHints:    map[string]string{"controller_tenant": ev.Tenant, "policy": ev.PolicyName},
		}
		e.DedupeKey = DedupeKey(e)
		b.Events = append(b.Events, e)
	}
	return b, nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
