package nms

import (
	"encoding/json"
	"strings"
	"time"
)

// vmanage.go — Cisco Catalyst SD-WAN Manager (vManage) transformer. Poll
// archetype. A vManage alarm carries BOTH a discrete alarm (event) AND an
// operational state (BFD/tunnel/control-connection up/down) — so it emits into
// TWO classes (§3.2 + §3.3), the canonical example of "not everything is an
// event."

// VManageTransformer normalizes a vManage /dataservice/alarms response.
type VManageTransformer struct{}

func (VManageTransformer) Transform(tenant, integrationID string, raw []byte) (Batch, error) {
	var resp struct {
		Data []struct {
			UUID       string `json:"uuid"`
			EventName  string `json:"eventname"`
			Type       string `json:"type"`
			RuleDisp   string `json:"rule_name_display"`
			Component  string `json:"component"`
			Severity   string `json:"severity"`
			EntryTime  int64  `json:"entry_time"`
			SystemIP   string `json:"system_ip"`
			HostName   string `json:"host_name"`
			SiteID     string `json:"site_id"`
			Active     bool   `json:"active"`
			Values     []map[string]any `json:"values"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, a := range resp.Data {
		net, stateKind := vmanageNormType(a.Type, a.Component, a.EventName)
		et := msToTime(a.EntryTime)
		e := ControllerEvent{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
			Vendor: "cisco", Product: "Catalyst SD-WAN Manager",
			EventID:             a.UUID,
			EventTime:           et,
			IngestTime:          time.Now().UTC(),
			EventType:           firstNonEmpty(a.Type, a.EventName),
			NormalizedEventType: net,
			Severity:            normSeverity(a.Severity),
			Category:            strings.ToLower(a.Component),
			DeviceID:            a.SystemIP,
			DeviceName:          a.HostName,
			SiteID:              a.SiteID,
			Message:             firstNonEmpty(a.RuleDisp, a.EventName),
			RawPayload:          mustJSON(a),
			EvidenceRole:        roleForEventType(net),
			CorrelationHints:    map[string]string{"component": a.Component, "system_ip": a.SystemIP},
		}
		e.DedupeKey = DedupeKey(e)
		b.Events = append(b.Events, e)

		// The same alarm is also a STATE fact when it's up/down-shaped.
		if stateKind != "" {
			cur := "down"
			if !a.Active { // an inactive/cleared alarm means the state recovered
				cur = "up"
			}
			b.States = append(b.States, ControllerState{
				TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
				EntityKey: firstNonEmpty(a.SystemIP, a.HostName), StateKind: stateKind,
				CurrentState: cur, DeviceID: a.SystemIP, SiteID: a.SiteID, Time: et,
				Data: map[string]any{"component": a.Component},
			})
		}
	}
	return b, nil
}

// vmanageNormType returns (normalized_event_type, stateKind). stateKind is ""
// when the alarm is not an operational up/down state.
func vmanageNormType(typ, component, eventName string) (string, string) {
	t := strings.ToLower(typ + " " + component + " " + eventName)
	switch {
	case strings.Contains(t, "bfd"):
		return "controller_bfd_down", "bfd"
	case strings.Contains(t, "control") && strings.Contains(t, "conn"):
		return "controller_control_connection_loss", "control_conn"
	case strings.Contains(t, "omp"):
		// OMP is SD-WAN's overlay control-plane routing — its own state kind.
		return "controller_control_connection_loss", "omp"
	case strings.Contains(t, "tunnel") || strings.Contains(t, "tloc"):
		return "controller_tunnel_state", "tunnel"
	case strings.Contains(t, "bgp"):
		return "controller_alarm", "bgp"
	case strings.Contains(t, "reachab") || strings.Contains(t, "unreach"):
		return "controller_device_unreachable", "reachability"
	case strings.Contains(t, "policy") || strings.Contains(t, "template"):
		return "controller_policy_change", ""
	default:
		return "controller_alarm", ""
	}
}
