// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package showparse

// types.go — the typed evidence rows every parser produces.
//
// EVERY optional field is a POINTER. That is not style, it is the package's
// central safety property: a nil MTU means "this capture did not report an MTU",
// which a downstream rule must treat as unknown, while an int MTU of 0 would
// read as "MTU zero" and could fire an MTU-mismatch verdict on a device that
// never told us anything. Absent means absent (design §3.2, "0 fabricated
// fields").

// InterfaceState is one interface's state, counters and (where the same command
// carries them) transceiver digital-diagnostics readings.
type InterfaceState struct {
	// Name is the interface name exactly as the device printed it.
	Name string
	// Admin is the administrative state ("up", "down",
	// "administratively down", "Enabled"/"Disabled" on Junos) verbatim.
	Admin *string
	// Oper is the operational/line-protocol state verbatim.
	Oper *string
	// Description is the configured interface description.
	Description *string
	// IPv4 is the interface's IPv4 address (with mask where printed).
	IPv4 *string
	// SpeedMbps is the negotiated/configured speed in megabits per second.
	SpeedMbps *int64
	// Duplex is the duplex mode verbatim ("Full", "half", …).
	Duplex *string
	// MTU is the interface MTU in bytes, as the device reports it. Note the
	// dialects do not agree on whether this is the L3 or the L2 MTU — the value
	// is reported, not reinterpreted.
	MTU *int
	// InErrors is the total input-error counter.
	InErrors *int64
	// CRC is the CRC/FCS/framing error counter.
	CRC *int64
	// InDrops is the input drop counter.
	InDrops *int64
	// OutErrors is the total output-error counter.
	OutErrors *int64
	// OutDrops is the output drop counter.
	OutDrops *int64
	// CarrierTransitions is the link up/down transition counter where the
	// platform exposes one (Junos, Nokia). Cisco IOS reports "interface resets",
	// which is NOT the same counter and is deliberately not mapped here.
	CarrierTransitions *int64
	// LastFlap is the platform's own last-flap text, verbatim. Classic Cisco IOS
	// `show interfaces` does not report one — the field stays nil there rather
	// than being synthesized from "last input".
	LastFlap *string
	// RxPowerDbm / TxPowerDbm are transceiver optical power in dBm.
	RxPowerDbm *float64
	TxPowerDbm *float64
	// BiasCurrentMa is the laser bias current in milliamps.
	BiasCurrentMa *float64
	// VoltageV is the transceiver supply voltage in volts.
	VoltageV *float64
	// TempC is the transceiver (or interface module) temperature in Celsius.
	TempC *float64
}

// IGPNeighbor is one OSPF or IS-IS adjacency row.
type IGPNeighbor struct {
	// Proto is "ospf" or "isis".
	Proto string
	// ID is the neighbor router-id (OSPF) or system-id / hostname (IS-IS).
	ID string
	// Address is the neighbor's interface address where the table carries one.
	Address *string
	// Iface is the local interface the adjacency runs over.
	Iface string
	// State is the adjacency state verbatim ("FULL/DR", "EXSTART/DROTHER",
	// "Up", "Init", …). It is NOT normalized: the operator's tell is the exact
	// string the device printed.
	State string
	// Level is the IS-IS level ("L1", "L2", "L1L2") where reported.
	Level *string
	// Area is the OSPF area where the table carries one.
	Area *string
	// Priority is the OSPF neighbor priority.
	Priority *int
	// DeadTime is the OSPF dead-timer countdown text where the table shows one.
	DeadTime *string
	// Holdtime is the IS-IS holdtime (seconds, as text) where reported.
	Holdtime *string
	// Uptime is the adjacency uptime text where the table shows one. Cisco's
	// classic OSPF table shows DEAD TIME, not uptime — the two are never mixed.
	Uptime *string
}

// BGPPeer is one BGP neighbor summary row.
type BGPPeer struct {
	// Peer is the neighbor address verbatim.
	Peer string
	// AS is the remote autonomous-system number.
	AS *int64
	// State is the FSM state / state column verbatim ("Idle", "Active",
	// "Establ", "Established", "Idle (Admin)", …).
	State string
	// Established reports whether State names the Established FSM state, or the
	// row's state column carried a prefix count (which only an established
	// session has). It is a DERIVED convenience, never a substitute for State.
	Established bool
	// PrefixesRx is the accepted/received prefix count where the row carries one.
	PrefixesRx *int64
	// UpDown is the session up/down timer text where the row carries one.
	UpDown *string
	// MsgRcvd / MsgSent are the message counters where the row carries them.
	MsgRcvd *int64
	MsgSent *int64
	// VRF is the routing instance where the table names one per row.
	VRF *string
}

// RouteEntry is one routing-table entry.
type RouteEntry struct {
	// Prefix is the destination prefix verbatim.
	Prefix string
	// Protocol is the source protocol verbatim ("ospf 1", "OSPF", "bgp", "C").
	Protocol *string
	// Preference is the administrative distance / route preference.
	Preference *int64
	// Metric is the protocol metric.
	Metric *int64
	// NextHop is the next-hop address.
	NextHop *string
	// Iface is the outgoing interface.
	Iface *string
	// Age is the route age text.
	Age *string
	// Active reports whether the entry is the active/selected route, where the
	// dialect marks it. nil = the output does not say.
	Active *bool
}

// ARPEntry is one ARP / neighbor-cache row.
type ARPEntry struct {
	// Address is the L3 address.
	Address string
	// MAC is the hardware address verbatim (vendor formatting preserved).
	MAC *string
	// Iface is the interface the entry was learned on.
	Iface *string
	// Age is the age/expiry text verbatim (units differ per dialect, so it is
	// never converted).
	Age *string
	// Type is the entry type where reported ("ARPA", "Dynamic", …).
	Type *string
}

// MACEntry is one MAC forwarding-table row.
type MACEntry struct {
	// MAC is the hardware address verbatim.
	MAC string
	// VLAN is the VLAN id where the table is VLAN-keyed.
	VLAN *int
	// Iface is the egress port.
	Iface *string
	// Type is the entry type ("DYNAMIC", "dynamic", "static", …).
	Type *string
}

// SensorReading is one environmental sensor.
type SensorReading struct {
	// Name is the sensor/slot label verbatim.
	Name string
	// ValueC is a temperature in Celsius, where the reading is a temperature.
	ValueC *float64
	// Status is the reported status verbatim ("OK", "Normal", "Faulty", …).
	Status *string
}

// PlatformHealth is a device's control-plane health snapshot. Each field is
// populated only by a command that actually reports it.
type PlatformHealth struct {
	// CPUPercent is the headline CPU utilization percentage.
	CPUPercent *float64
	// CPU5Sec / CPU1Min / CPU5Min are the Cisco-style utilization windows.
	CPU5Sec *float64
	CPU1Min *float64
	CPU5Min *float64
	// MemUsedPercent is memory utilization as a percentage.
	MemUsedPercent *float64
	// MemTotalKB / MemUsedKB / MemFreeKB are absolute memory figures in KiB.
	MemTotalKB *int64
	MemUsedKB  *int64
	MemFreeKB  *int64
	// Temps / Fans / PSUs are environmental readings.
	Temps []SensorReading
	Fans  []SensorReading
	PSUs  []SensorReading
	// Uptime is the device uptime text verbatim.
	Uptime *string
	// LastReload is the last reload/reboot reason text verbatim.
	LastReload *string
	// Version is the software version string.
	Version *string
}

// LogLine is one parsed device log-buffer line.
type LogLine struct {
	// Raw is the whole line, verbatim (already redacted upstream by the
	// collector — this package never redacts and never logs).
	Raw string
	// Timestamp is the leading timestamp text verbatim; it is NOT converted to
	// a time.Time because device buffers routinely omit the year and the zone,
	// and inventing either would be a fabricated field.
	Timestamp *string
	// Facility is the vendor log facility / module ("OSPF", "LINK", "rpd").
	Facility *string
	// Severity is the numeric severity where the grammar carries one.
	Severity *int
	// Mnemonic is the event mnemonic / tag ("ADJCHG", "UPDOWN",
	// "RPD_OSPF_NBRUP").
	Mnemonic *string
	// Message is the message body after the grammar prefix.
	Message string
}
