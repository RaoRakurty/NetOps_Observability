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
	case "statistics":
		return VManageStatsTransformer{}.Transform(tenant, integrationID, raw)
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

// vmanageInventoryTransform: /dataservice/device → reachability + health states.
// Inventory is not an alarm source; it produces no events.
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
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, d := range resp.Data {
		if net.ParseIP(d.SystemIP) == nil {
			continue
		}
		ts := vmTime(int64(d.LastUpd))
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
