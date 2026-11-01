// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import "strings"

// vmanage_kinds.go — vManage alarms and device events → the correlation
// engine's CANONICAL kinds (source-equivalence E2a, plan of record
// docs/design/NMS_DEVICE_IDENTITY_2026-11-01.md §7a/§7b).
//
// Until E2a the connector guessed a kind from substrings of type + component +
// eventname and sent every BGP, OSPF, interface, reboot and transceiver alarm
// as `controller_alarm` — a kind no template, producer registry or modality
// table names, so the engine received the alarm and could do nothing with it.
// The RCA templates key on canonical kinds (`link_state_change`,
// `bgp_adjacency_change`, …) that the device's own traps and syslog already
// produce; a vManage-only customer could not match them.
//
// Alarms are keyed on `rule_name_display` — the release's stable rule key (the
// 20.6 vocabulary, 99 rules, is recorded in testdata/vmanage_20.6/
// alarm_rules.json). Every rule is either mapped below or listed in
// vmanageUnclassifiedAlarms with the reason it is not state evidence; the test
// over the recorded vocabulary fails on a rule that is neither, so a new
// release's new rule is noticed instead of falling silently to
// `controller_alarm`. Modality is unchanged (management_plane): a relayed
// observation names the right hypothesis, it does not by itself confirm one.

// vmAlarmKind is one rule's canonical mapping. Recovery marks a rule that
// reports a return to a good state (the *_Up rules): it is emitted under the
// engine's clear convention (`<kind>_clear`), never as fault evidence.
type vmAlarmKind struct {
	Kind      string
	StateKind string // the ControllerState kind it also feeds ("" = none)
	Recovery  bool
}

func down(kind, state string) vmAlarmKind { return vmAlarmKind{Kind: kind, StateKind: state} }
func up(kind, state string) vmAlarmKind {
	return vmAlarmKind{Kind: kind, StateKind: state, Recovery: true}
}

// vmanageAlarmKinds maps a vManage alarm rule to its canonical kind.
var vmanageAlarmKinds = map[string]vmAlarmKind{
	// Overlay tunnels (BFD) — PATH kinds; both ends share the TLOC-pair id.
	"BFD_Node_Down":          down("controller_bfd_down", "bfd"),
	"BFD_Node_Up":            up("controller_bfd_down", "bfd"),
	"BFD_Site_Down":          down("controller_bfd_down", "bfd"),
	"BFD_Site_Up":            up("controller_bfd_down", "bfd"),
	"BFD_TLOC_Down":          down("controller_bfd_down", "bfd"),
	"BFD_TLOC_Up":            up("controller_bfd_down", "bfd"),
	"BFD_Between_Sites_Down": down("controller_bfd_down", "bfd"),
	"BFD_Between_Sites_Up":   up("controller_bfd_down", "bfd"),
	// Control plane (DTLS/TLS control connections to vSmart/vManage/vBond).
	// "Control_Node_Down" fell through to controller_alarm under the substring
	// guess ("control" without "conn"): a node that lost its control
	// connections is exactly control-connection loss.
	"Control_Node_Down":          down("controller_control_connection_loss", "control_conn"),
	"Control_Node_Up":            up("controller_control_connection_loss", "control_conn"),
	"Control_Site_Down":          down("controller_control_connection_loss", "control_conn"),
	"Control_Site_Up":            up("controller_control_connection_loss", "control_conn"),
	"Control_TLOC_Down":          down("controller_control_connection_loss", "control_conn"),
	"Control_TLOC_Up":            up("controller_control_connection_loss", "control_conn"),
	"Control_Vsmart_Down":        down("controller_control_connection_loss", "control_conn"),
	"Control_Vsmart_Up":          up("controller_control_connection_loss", "control_conn"),
	"Control_Vsmarts_Up":         up("controller_control_connection_loss", "control_conn"),
	"Control_All_Vsmarts_Down":   down("controller_control_connection_loss", "control_conn"),
	"Control_Vmanage_Down":       down("controller_control_connection_loss", "control_conn"),
	"Control_Vmanage_Up":         up("controller_control_connection_loss", "control_conn"),
	"Control_No_Active_vBond":    down("controller_control_connection_loss", "control_conn"),
	"Control_vBond_State_Change": down("controller_control_connection_loss", "control_conn"),
	// OMP — the overlay's control-plane routing protocol.
	"OMP_Node_Down":        down("controller_control_connection_loss", "omp"),
	"OMP_Node_Up":          up("controller_control_connection_loss", "omp"),
	"OMP_Site_Down":        down("controller_control_connection_loss", "omp"),
	"OMP_Site_Up":          up("controller_control_connection_loss", "omp"),
	"OMP_All_Vsmarts_Down": down("controller_control_connection_loss", "omp"),
	"OMP_Vsmarts_Up":       up("controller_control_connection_loss", "omp"),
	"OMP_State_Change":     down("controller_control_connection_loss", "omp"),
	// Routing adjacencies — the same canonical kinds the device's own traps and
	// syslog produce (events.yaml), bound to the same entity shape.
	"BGP_Router_Down":  down("bgp_adjacency_change", "bgp"),
	"BGP_Router_Up":    up("bgp_adjacency_change", "bgp"),
	"OSPF_Router_Down": down("ospf_adjacency_change", "ospf"),
	"OSPF_Router_Up":   up("ospf_adjacency_change", "ospf"),
	// Interfaces: direction comes from the alarm's new-state value, not the
	// rule name (one rule covers both directions).
	"Interface_State_Change":       down("link_state_change", "interface"),
	"Interface_Admin_State_Change": down("link_state_change", "interface"),
	// Device lifecycle and configuration.
	"System_Reboot_Issued": down("device_restart", ""),
	"Template_Rollback":    down("controller_policy_change", ""),
	"Pseudo_Commit_Status": down("controller_policy_change", ""),
	"System-IP_Change":     down("controller_policy_change", ""),
	"Site-ID_Change":       down("controller_policy_change", ""),
	"Domain-ID_Change":     down("controller_policy_change", ""),
	"Org_Name_Change":      down("controller_policy_change", ""),
	// Physical layer.
	"Unsupported_SFP_Detected": down("transceiver_unsupported", ""),
}

// vmanageUnclassifiedAlarms are the rules that stay `controller_alarm` on
// purpose, each with the reason it is not (yet) canonical state evidence.
var vmanageUnclassifiedAlarms = map[string]string{
	"CPU_Usage":                                 "resource threshold — canonical resource evidence is the metric episode (E3)",
	"Memory_Usage":                              "resource threshold — canonical resource evidence is the metric episode (E3)",
	"Disk_Usage":                                "resource threshold — canonical resource evidence is the metric episode (E3)",
	"Vmanage_Critical_Space_Usage":              "the controller's own disk, not the managed network",
	"vManage_Queue_State":                       "the controller's own processing queue",
	"SLA_Violation":                             "app-route SLA — tunnel_degraded is a NORMALIZATION_PENDING kind with no engine binding yet",
	"SLA_Violation_Packet_Drop":                 "app-route SLA — tunnel_degraded is a NORMALIZATION_PENDING kind with no engine binding yet",
	"Tracker_State_Change":                      "endpoint/interface tracker: the tracked object is not identified in the alarm",
	"Pim_Interface_State_Change":                "multicast PIM interface state — no canonical multicast kind",
	"DHCP_Server_State_Change":                  "DHCP server state — no canonical kind",
	"Process_Restart":                           "a process restarted, not the device (device_restart would be wrong)",
	"System_IP_Reuse":                           "identity conflict — a fabric configuration fault, no canonical kind",
	"Cloned_Vedge_Detected":                     "identity conflict — a fabric configuration fault, no canonical kind",
	"Geo_Fence_Alert_Status":                    "location policy — not network state",
	"Cloud On Ramp":                             "cloud on-ramp orchestration status — no canonical kind",
	"Multicloud":                                "multicloud orchestration status — no canonical kind",
	"APPQOE_ALARM":                              "AppQoE service — no canonical kind",
	"AppQoe service node state":                 "AppQoE service — no canonical kind",
	"AppQoe site id mismatch":                   "AppQoE configuration — no canonical kind",
	"Default App List Update":                   "application catalogue update — not network state",
	"Renamed_Apps_Detected_Notification":        "application catalogue — not network state",
	"Unsupported_Apps_Detected_Notification":    "application catalogue — not network state",
	"SD-AVC Cloud Connector Credentials Error":  "controller credential — not network state",
	"Container App installation failed":         "software lifecycle — not network state",
	"Container activate failed":                 "software lifecycle — not network state",
	"Container reload failed":                   "software lifecycle — not network state",
	"Container reset failed":                    "software lifecycle — not network state",
	"Container upgrade failed":                  "software lifecycle — not network state",
	"Device Activation Failed":                  "software lifecycle — not network state",
	"Device Upgrade Failed":                     "software lifecycle — not network state",
	"ZTP Upgrade Failed":                        "software lifecycle — not network state",
	"Clear_Installed_Certificate":               "certificate lifecycle — not network state",
	"New_CSR_Generated":                         "certificate lifecycle — not network state",
	"Root_Cert_Chain_Installed":                 "certificate lifecycle — not network state",
	"Root_Cert_Chain_Uninstalled":               "certificate lifecycle — not network state",
	"Acknowledgement file not uploaded":         "licensing / serial-file administration — not network state",
	"Devices Have No License Associated":        "licensing — not network state",
	"System_License_Mismatch":                   "licensing — not network state",
	"license-is-out-of-compliance":              "licensing — not network state",
	"vEdge_Serial_File_Uploaded":                "licensing / serial-file administration — not network state",
	"vSmart/vManage_Serial_File_Uploaded":       "licensing / serial-file administration — not network state",
	"aaa_Admin_Password_Change":                 "administrative audit — not network state",
	"UTD signature package installation failed": "security service lifecycle — routes to the security lane, not network state",
	"UTD_File_Analysis_Status_Event":            "security service — routes to the security lane",
	"UTD_File_Analysis_Upload_Status":           "security service — routes to the security lane",
	"UTD_File_Reputation_Alert":                 "security finding — routes to the security lane",
	"UTD_File_Reputation_Retrospective_Alert":   "security finding — routes to the security lane",
	"UTD_File_Reputation_Status_Event":          "security service — routes to the security lane",
	"UTD_IPS_Alert":                             "security finding — routes to the security lane",
	"UTD_Notification":                          "security service — routes to the security lane",
	"UTD_Update":                                "security service lifecycle — routes to the security lane",
	"UTD_Version_Mismatch":                      "security service lifecycle — routes to the security lane",
	"ZBFW_Half_Open_Limit_Hit":                  "firewall session limit — routes to the security lane",
	"ZBFW_Session_Maximum":                      "firewall session limit — routes to the security lane",
	"ZBFW_Session_Rate_Alert_Off":               "firewall session rate — routes to the security lane",
	"ZBFW_Session_Rate_Alert_On":                "firewall session rate — routes to the security lane",
}

// vmanageAlarmKind returns the canonical mapping for a vManage alarm rule.
func vmanageAlarmKind(rule string) (vmAlarmKind, bool) {
	k, ok := vmanageAlarmKinds[strings.TrimSpace(rule)]
	return k, ok
}

// vmEventKind maps one vManage device-event name to its canonical kind. The
// direction comes from a detail key: a value in Up is a recovery.
type vmEventKind struct {
	Kind      string
	StateKind string
	StateKey  string   // the details key carrying the new state ("" = no direction)
	Up        []string // new-state values that mean "recovered"
}

// vmanageEventKinds maps /dataservice/event names to canonical kinds.
//
// bgp-peer-state-change is lab-recorded (testdata/vmanage_20.6/events.json);
// the others follow the same documented `<subject>-state-change` naming and
// detail grammar — doc_claimed until a lab capture shows each one.
var vmanageEventKinds = map[string]vmEventKind{
	"bgp-peer-state-change":           {Kind: "bgp_adjacency_change", StateKind: "bgp", StateKey: "bgp-new-state", Up: []string{"established"}},
	"ospf-neighbor-state-change":      {Kind: "ospf_adjacency_change", StateKind: "ospf", StateKey: "new-state", Up: []string{"full"}},
	"interface-state-change":          {Kind: "link_state_change", StateKind: "interface", StateKey: "new-state", Up: []string{"up"}},
	"interface-admin-state-change":    {Kind: "link_state_change", StateKind: "interface", StateKey: "new-state", Up: []string{"up"}},
	"bfd-state-change":                {Kind: "controller_bfd_down", StateKind: "bfd", StateKey: "new-state", Up: []string{"up"}},
	"control-connection-state-change": {Kind: "controller_control_connection_loss", StateKind: "control_conn", StateKey: "new-state", Up: []string{"up"}},
	"omp-peer-state-change":           {Kind: "controller_control_connection_loss", StateKind: "omp", StateKey: "new-state", Up: []string{"up"}},
	"system-reboot-complete":          {Kind: "device_restart"},
	"system-reboot-issued":            {Kind: "device_restart"},
}

// vmanageEventKind returns the canonical kind for a device event and whether
// the event reports a recovery.
func vmanageEventKind(name string, det map[string]string) (vmEventKind, bool, bool) {
	k, ok := vmanageEventKinds[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return vmEventKind{}, false, false
	}
	recovery := false
	if k.StateKey != "" {
		st := strings.ToLower(strings.TrimSpace(det[k.StateKey]))
		for _, u := range k.Up {
			if st == u {
				recovery = true
			}
		}
	}
	return k, recovery, true
}

// vmValue returns the first non-empty string value for any of keys across a
// vManage alarm's `values` objects.
func vmValue(values []map[string]any, keys ...string) string {
	for _, v := range values {
		for _, k := range keys {
			if s, ok := v[k].(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}
