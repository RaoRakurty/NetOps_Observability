// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"encoding/json"
	"net"
	"strings"
	"time"
)

// vmanage_events.go — the /dataservice/event and /dataservice/device streams.
//
// Until 2026-10-18 both fell into the ALARMS parser (VManageAutoTransformer
// sniffed payload keys): event rows carry `id`/`severity_level`, not
// `uuid`/`severity`, and no `active` flag — so a "bgp-peer-state-change" to
// idle was stored as a bgp state of UP, and every inventory row became an empty
// controller_alarm. Field names below are the 20.x wire names, sampled from a
// live 20.6.1.

// TransformStream routes by the stream that was polled (StreamTransformer).
func (t VManageAutoTransformer) TransformStream(tenant, integrationID, stream string, raw []byte) (Batch, error) {
	switch stream {
	case "alarms":
		return VManageTransformer{}.Transform(tenant, integrationID, raw)
	case "events":
		return vmanageEventsTransform(tenant, integrationID, raw)
	case "inventory":
		return vmanageInventoryTransform(tenant, integrationID, raw)
	case "approute", "statistics":
		return vmanageAppRouteAggTransform(tenant, integrationID, raw)
	case "qos":
		return vmanageQoSAggTransform(tenant, integrationID, raw)
	case "hardware":
		return vmanageHardwareTransform(tenant, integrationID, raw)
	case "audit":
		return vmanageAuditTransform(tenant, integrationID, raw)
	case "interfaces":
		return vmanageInterfaceAggTransform(tenant, integrationID, raw)
	case "system":
		return vmanageSystemAggTransform(tenant, integrationID, raw)
	case "counters":
		return vmanageCountersTransform(tenant, integrationID, raw)
	case "certs":
		return vmanageCertsTransform(tenant, integrationID, raw)
	case "bfd":
		return vmanageBFDTransform(tenant, integrationID, raw)
	case "control_connections":
		return vmanageControlTransform(tenant, integrationID, raw)
	case "tunnels":
		return vmanageTunnelStatsTransform(tenant, integrationID, raw)
	}
	return t.Transform(tenant, integrationID, raw)
}

// vmDetails parses the event `details` string: "k=v; k2=v2;".
func vmDetails(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && k != "" {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// vmEventSeverity maps vManage severity_level (critical|major|minor|medium|low).
func vmEventSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "major":
		return "major"
	case "minor", "medium":
		return "minor"
	default:
		return "info"
	}
}

// vmBGPState: only "established" is up; idle/active/connect/… are not.
func vmBGPState(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), "established") {
		return "up"
	}
	return "down"
}

func vmanageEventsTransform(tenant, integrationID string, raw []byte) (Batch, error) {
	var resp struct {
		Data []struct {
			ID        string `json:"id"`
			EventName string `json:"eventname"`
			Component string `json:"component"`
			Severity  string `json:"severity_level"`
			EntryTime vmNum  `json:"entry_time"`
			SystemIP  string `json:"system_ip"`
			HostName  string `json:"host_name"`
			Details   string `json:"details"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, r := range resp.Data {
		if r.ID == "" || net.ParseIP(r.SystemIP) == nil {
			continue // controller output is untrusted: no id or no valid device → not an event
		}
		et := vmTime(int64(r.EntryTime))
		det := vmDetails(r.Details)
		normType, stateKind := vmanageNormType(r.EventName, r.Component, r.EventName)
		e := ControllerEvent{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
			Vendor: "cisco", Product: "Catalyst SD-WAN Manager",
			EventID: r.ID, EventTime: et, IngestTime: time.Now().UTC(),
			EventType: r.EventName, NormalizedEventType: normType, Severity: vmEventSeverity(r.Severity),
			Category: strings.ToLower(r.Component), DeviceID: r.SystemIP, DeviceName: r.HostName,
			Message: r.EventName + " " + strings.TrimSpace(r.Details), EvidenceRole: roleForEventType(normType),
			CorrelationHints: map[string]string{"component": r.Component, "system_ip": r.SystemIP},
		}
		e.DedupeKey = DedupeKey(e)
		b.Events = append(b.Events, e)
		// A BGP peer change is also a STATE fact — taken from the event's own
		// new state, never inferred from a missing `active` flag.
		if stateKind == "bgp" && det["peer"] != "" && det["bgp-new-state"] != "" {
			b.States = append(b.States, ControllerState{
				TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
				EntityKey: r.SystemIP + "|bgp|" + det["peer"], StateKind: "bgp",
				CurrentState: vmBGPState(det["bgp-new-state"]), DeviceID: r.SystemIP, Time: et,
				Data: map[string]any{"device_name": r.HostName, "peer": det["peer"], "bgp_state": det["bgp-new-state"]},
			})
		}
	}
	return b, nil
}

// vmanageInventoryTransform: /dataservice/device → reachability + health states,
// and the device snapshot (inventory.go). Inventory is not an alarm source; it
// produces no events. Every row is a device the fabric knows; the edges
// (device-type "vedge" — cEdges report it too) are the MANAGED ones, and
// vManage / vSmart / vBond are the controller's own nodes (Managed=false).
func vmanageInventoryTransform(tenant, integrationID string, raw []byte) (Batch, error) {
	var resp struct {
		Data []struct {
			SystemIP     string `json:"system-ip"`
			HostName     string `json:"host-name"`
			DeviceType   string `json:"device-type"`
			Reachability string `json:"reachability"`
			State        string `json:"state"`
			StateDesc    string `json:"state_description"`
			SiteID       vmStr  `json:"site-id"`
			Version      string `json:"version"`
			LastUpd      vmNum  `json:"lastupdated"`
			Model        string `json:"device-model"`
			BoardSerial  string `json:"board-serial"`
			UUID         string `json:"uuid"`
			Personality  string `json:"personality"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Batch{}, err
	}
	b := Batch{Devices: make([]ControllerDevice, 0, len(resp.Data))} // non-nil: this IS an inventory snapshot
	for _, d := range resp.Data {
		if net.ParseIP(d.SystemIP) == nil {
			continue
		}
		ts := vmTime(int64(d.LastUpd))
		edge := strings.EqualFold(d.DeviceType, "vedge")
		role := "controller"
		if edge {
			role = "edge"
		}
		b.Devices = append(b.Devices, ControllerDevice{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
			KeyKind: KeySystemIP, Key: d.SystemIP,
			Name: d.HostName,
			// The system-ip is the address vManage and every SD-WAN signal name
			// the device by; an SNMP twin of the same box is often reached at it
			// too, which is what lets the two de-duplicate.
			MgmtAddr: d.SystemIP,
			// board-serial is the board/SUDI identity on a cEdge, not necessarily
			// the chassis serial a support case asks for — an alias, not a claim.
			Vendor: "cisco", Model: d.Model, OS: "Catalyst SD-WAN", OSVersion: d.Version,
			SiteID: string(d.SiteID), Role: role, Managed: edge,
			Reachable: strings.ToLower(d.Reachability),
			Aliases:   map[string]string{"system_ip": d.SystemIP, "uuid": d.UUID, "board_serial": d.BoardSerial, "personality": d.Personality},
			LastSeen:  ts,
		})
		reach := "unreachable"
		if strings.EqualFold(d.Reachability, "reachable") {
			reach = "reachable"
		}
		data := map[string]any{"device_name": d.HostName, "device_type": d.DeviceType, "version": d.Version}
		b.States = append(b.States, ControllerState{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
			EntityKey: d.SystemIP, StateKind: "reachability", CurrentState: reach,
			DeviceID: d.SystemIP, SiteID: string(d.SiteID), Time: ts, Data: data,
		})
		if h := strings.ToLower(strings.TrimSpace(d.State)); h == "green" || h == "yellow" || h == "red" {
			b.States = append(b.States, ControllerState{
				TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
				EntityKey: d.SystemIP, StateKind: "device_health", CurrentState: h,
				DeviceID: d.SystemIP, SiteID: string(d.SiteID), Time: ts,
				Data: map[string]any{"device_name": d.HostName, "description": d.StateDesc},
			})
		}
	}
	return b, nil
}

// vmanageAuditTransform: /dataservice/auditlog → change events.
//
// Template attaches, policy pushes, config syncs and certificate installs are
// CHANGES — the evidence an RCA asks for first ("what changed before it
// broke?"). They become controller_policy_change on the device they touched.
// A successful login is not a change and is dropped; a failed one is kept as
// an alarm on the manager. Entries without a device system-ip (a template
// edited but not yet pushed, a push keyed by chassis UUID) are dropped: the
// same push also logs one entry per device by system-ip.
func vmanageAuditTransform(tenant, integrationID string, raw []byte) (Batch, error) {
	var resp struct {
		Data []struct {
			ID        string `json:"logid"`
			EntryTime vmNum  `json:"entry_time"`
			Module    string `json:"logmodule"`
			Feature   string `json:"logfeature"`
			User      string `json:"loguser"`
			Message   string `json:"logmessage"`
			Device    string `json:"logdeviceid"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, r := range resp.Data {
		if r.ID == "" || net.ParseIP(r.Device) == nil {
			continue
		}
		module := strings.ToLower(strings.TrimSpace(r.Module))
		normType, severity := "controller_policy_change", "info"
		if module == "user" {
			if !strings.Contains(strings.ToLower(r.Message), "fail") {
				continue // a successful login changes nothing
			}
			normType, severity = "controller_alarm", "minor"
		}
		e := ControllerEvent{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
			Vendor: "cisco", Product: "Catalyst SD-WAN Manager",
			EventID: "audit:" + r.ID, EventTime: vmTime(int64(r.EntryTime)), IngestTime: time.Now().UTC(),
			EventType: "audit_" + module, NormalizedEventType: normType, Severity: severity,
			Category: "audit", DeviceID: r.Device, Message: strings.TrimSpace(r.Message),
			EvidenceRole:     roleForEventType(normType),
			CorrelationHints: map[string]string{"audit_module": r.Module, "audit_feature": r.Feature, "user": r.User},
		}
		e.DedupeKey = DedupeKey(e)
		b.Events = append(b.Events, e)
	}
	return b, nil
}
