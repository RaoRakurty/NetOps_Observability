// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"encoding/json"
	"net"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/bgpfsm"
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
		return vmanageEventsTransform(tenant, integrationID, raw, t.bgp)
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
	case "interface_realtime":
		return vmanageInterfaceRealtimeTransform(tenant, integrationID, raw)
	case "system_realtime":
		return vmanageSystemRealtimeTransform(tenant, integrationID, raw)
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

// vmEventSeverity maps vManage severity_level (critical|major|minor|medium|low)
// onto the canonical contract info|warn|high|crit (model.go). It used to pass
// vManage's own words through, and the engine reads only the canonical four:
// "major" fell to WARN, below severity_open_floor="high", so no polled vManage
// event could open an incident on its own (2026-10-24). An absent level is info.
func vmEventSeverity(s string) string {
	if strings.TrimSpace(s) == "" {
		return "info"
	}
	return normSeverity(s)
}

// vmPeerType: a control session's far-end role (vsmart | vbond | vmanage | …),
// lower-cased. Controller output is untrusted, so anything that is not one short
// word is no role at all ("").
func vmPeerType(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 24 {
		return ""
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return ""
		}
	}
	return s
}

// vmBGPState: only "established" is up; idle/active/connect/… are not.
func vmBGPState(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), "established") {
		return "up"
	}
	return "down"
}

// vManage's bgp-peer-state-change bases for the `bgp_transition_basis` hint: where
// the transition's prior state, or the fact that it had none, came from.
const (
	vmBGPBasisPeerHistory = "peer_history" // the peer's previous report, this poll or remembered
	vmBGPBasisNewState    = "new_state"    // the new state alone
)

// vmBGPReport is one bgp-peer-state-change of one device|peer.
type vmBGPReport struct {
	at    int64 // entry_time, ms
	state string
}

// vmBGPPrevState is the state the peer's latest report STRICTLY before `at` moved
// to, or "" when there is none, or when two reports at that same instant disagree
// (the order is not evidenced). reports is sorted by at.
func vmBGPPrevState(reports []vmBGPReport, at int64) string {
	i := sort.Search(len(reports), func(i int) bool { return reports[i].at >= at })
	if i == 0 {
		return ""
	}
	prev := reports[i-1]
	for j := i - 2; j >= 0 && reports[j].at == prev.at; j-- {
		if reports[j].state != prev.state {
			return ""
		}
	}
	return prev.state
}

// vmBGPTransition names one vManage bgp-peer-state-change with the classifier the
// trap receiver uses (internal/bgpfsm; tracker 387). Owner rule: only an
// ESTABLISHED session going down is a session failure. vManage reports only the
// NEW state, so the prior one comes from the same peer's previous report — in
// this poll, or remembered across polls (vmBGPMemory) — and bgpfsm names the
// move (peer_history). With no such report the new state alone decides
// (new_state): session_up, or unknown, which reads as a down (fail-open).
//
// peer-routerid 0.0.0.0 decides NOTHING: IOS / IOS-XE clears the remote
// router-id on teardown, so an established session that drops reports exactly
// that (P-424934 review). It is carried as an annotation only.
//
// class "" when the new state is not an FSM state.
func vmBGPTransition(prev, newState string) (class, basis string) {
	if prev != "" {
		if c := bgpfsm.Classify(prev, newState); c != "" {
			return c, vmBGPBasisPeerHistory
		}
	}
	if _, ok := bgpfsm.Rank(newState); !ok {
		return "", ""
	}
	return bgpfsm.Classify("", newState), vmBGPBasisNewState
}

// vmanageEventsTransform maps /dataservice/event rows. mem (nil = none) carries
// each BGP peer's reports across polls; the reports of this batch are added to it.
func vmanageEventsTransform(tenant, integrationID string, raw []byte, mem *vmBGPMemory) (Batch, error) {
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
	// Each BGP peer's reports in this poll, oldest first, so a report's prior
	// state can be read from the one before it (vmBGPTransition).
	bgpHistory := map[string][]vmBGPReport{}
	for _, r := range resp.Data {
		if r.ID == "" || net.ParseIP(r.SystemIP) == nil {
			continue
		}
		det := vmDetails(r.Details)
		if k, _, ok := vmanageEventKind(r.EventName, det); ok && k.StateKind == "bgp" && det["peer"] != "" && det[k.StateKey] != "" {
			key := r.SystemIP + "|" + det["peer"]
			bgpHistory[key] = append(bgpHistory[key], vmBGPReport{at: int64(r.EntryTime), state: strings.ToLower(strings.TrimSpace(det[k.StateKey]))})
		}
	}
	// Each peer's history = what the memory remembers (within its TTL of this
	// batch's earliest report) ∪ this batch, sorted and de-duplicated, so a
	// report re-polled in the overlap is one report. This batch is then
	// remembered for the next poll.
	for key, reports := range bgpHistory {
		earliest := reports[0].at
		for _, r := range reports {
			if r.at < earliest {
				earliest = r.at
			}
		}
		memKey := vmBGPMemoryKey(tenant, integrationID, key)
		bgpHistory[key] = mergeVMBGPReports(mem.recall(memKey, earliest), reports)
		mem.remember(memKey, reports)
	}
	var b Batch
	for _, r := range resp.Data {
		if r.ID == "" || net.ParseIP(r.SystemIP) == nil {
			continue // controller output is untrusted: no id or no valid device → not an event
		}
		et := vmTime(int64(r.EntryTime))
		det := vmDetails(r.Details)
		normType, stateKind := vmanageNormType(r.EventName, r.Component, r.EventName)
		severity := vmEventSeverity(r.Severity)
		recovery := false
		// Canonical kind from the event name (vmanage_kinds.go); direction from
		// the event's own new-state detail, never from polling.
		if k, rec, ok := vmanageEventKind(r.EventName, det); ok {
			normType, stateKind, recovery = k.Kind, k.StateKind, rec
			if !recovery && k.StateKey != "" {
				severity = "high" // a session / link going down — the trap rules' severity
			}
		}
		e := ControllerEvent{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
			Vendor: "cisco", Product: "Catalyst SD-WAN Manager",
			EventID: r.ID, EventTime: et, IngestTime: time.Now().UTC(),
			EventType: r.EventName, NormalizedEventType: normType, Severity: severity,
			Category: strings.ToLower(r.Component), DeviceID: r.SystemIP, DeviceName: r.HostName,
			InterfaceName: firstNonEmpty(det["if-name"], det["interface"]),
			// A control-connection / OMP transition names the far end as
			// `peer-system-ip` (BGP uses `peer`): without it the engine could
			// not tell which controller several edges lost together.
			PeerID:  firstNonEmpty(det["peer"], det["neighbor"], det["peer-system-ip"]),
			Message: r.EventName + " " + strings.TrimSpace(r.Details), EvidenceRole: roleForEventType(normType),
			CorrelationHints: map[string]string{"component": r.Component, "system_ip": r.SystemIP},
		}
		// Tracker 387 on the controller lane: what the BGP transition MEANS. The
		// engine builds no session failure from never_established / progressing
		// (controller_events.bgp_not_a_session_failure) and counts it; the event
		// itself is kept, as it is.
		if stateKind == "bgp" && det["peer"] != "" && det["bgp-new-state"] != "" {
			newState := strings.ToLower(strings.TrimSpace(det["bgp-new-state"]))
			prev := vmBGPPrevState(bgpHistory[r.SystemIP+"|"+det["peer"]], int64(r.EntryTime))
			if class, basis := vmBGPTransition(prev, newState); class != "" {
				e.CorrelationHints["bgp_transition_class"] = class
				e.CorrelationHints["bgp_transition_basis"] = basis
			}
			if strings.TrimSpace(det["peer-routerid"]) == "0.0.0.0" {
				// Annotation only: no OPEN in the CURRENT session, which is also
				// what a just-torn-down established session reports.
				e.CorrelationHints["bgp_peer_routerid"] = "unset"
			}
		}
		if pt := vmPeerType(det["peer-type"]); pt != "" {
			// vsmart | vbond | vmanage — which controller role the lost session ran to.
			e.CorrelationHints["peer_type"] = pt
		}
		if recovery {
			e.NormalizedEventType += "_clear"
			e.Severity = "info"
			e.EvidenceRole = RoleSupporting
			e.CorrelationHints["transition"] = "recovery"
		}
		e.DedupeKey = DedupeKey(e)
		b.Events = append(b.Events, e)
		// A BGP peer change is also a STATE fact — taken from the event's own
		// new state, never inferred from a missing `active` flag.
		if stateKind == "bgp" && det["peer"] != "" && det["bgp-new-state"] != "" {
			b.States = append(b.States, ControllerState{
				TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
				EntityKey: r.SystemIP + "|bgp|" + det["peer"], StateKind: "bgp",
				CurrentState: vmBGPState(det["bgp-new-state"]), DeviceID: r.SystemIP, PeerID: det["peer"], Time: et,
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
		// The vendor-neutral facts come from the vManage mapper (facts.go).
		facts := VManageFacts{}.MapFacts(NativeDeviceFacts{Model: d.Model, SiteID: string(d.SiteID), DeviceType: d.DeviceType})
		edge := facts.Role == RoleEdge
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
			Vendor: "cisco", Model: facts.Model, OS: "Catalyst SD-WAN", OSVersion: d.Version,
			SiteID: facts.Site, Role: facts.Role, Managed: edge,
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
			normType, severity = "controller_alarm", "warn"
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
