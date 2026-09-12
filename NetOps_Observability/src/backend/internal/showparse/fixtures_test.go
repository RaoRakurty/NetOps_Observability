// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package showparse

// fixtures_test.go — captured-output fixtures, one per (command, dialect) the
// library binds a parser for, authored against the real command output formats
// of each platform.
//
// Where a dialect's exact output could not be pinned down with confidence, the
// rule the design sets is followed literally: the parser is written
// conservatively and the fixture proves it SKIPS rather than guesses. Those
// cases are named *SkipFixture and are asserted in
// TestConservative_SkipRatherThanGuess.

// ── interfaces: Cisco family ────────────────────────────────────────────────

const ciscoShowInterfaces = `GigabitEthernet0/0 is up, line protocol is up
  Hardware is CSR vNIC, address is 000c.29ab.cdef (bia 000c.29ab.cdef)
  Description: uplink to core-02
  Internet address is 10.0.0.1/30
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  Full Duplex, 1000Mbps, link type is auto, media type is RJ45
  output flow-control is unsupported, input flow-control is unsupported
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:00:01, output 00:00:01, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/375/0/0 (size/max/drops/flushes); Total output drops: 4
  Queueing strategy: fifo
  5 minute input rate 1000 bits/sec, 1 packets/sec
  5 minute output rate 2000 bits/sec, 2 packets/sec
     1234567 packets input, 987654321 bytes, 0 no buffer
     Received 1000 broadcasts (0 IP multicasts)
     0 runts, 0 giants, 0 throttles
     12 input errors, 7 CRC, 0 frame, 0 overrun, 0 ignored
     0 watchdog, 0 multicast, 0 pause input
     2345678 packets output, 876543210 bytes, 0 underruns
     0 output errors, 0 collisions, 3 interface resets
GigabitEthernet0/1 is administratively down, line protocol is down
  Hardware is CSR vNIC, address is 000c.29ab.cdf0 (bia 000c.29ab.cdf0)
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
  Full Duplex, 1000Mbps, link type is auto, media type is RJ45
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
`

// FIXTURE PROVENANCE: SYNTHETIC, authored 2026-09-10. Not a device capture.
// It is the shape review 3.5-03 names: an operator DESCRIPTION carrying the
// very tokens the position-independent parameter scan reads, sitting above the
// device's own parameter lines, which carry DIFFERENT values. Every number in
// the description is deliberately unlike the device's own, so a reading taken
// from the wrong line cannot be mistaken for the right one. GigabitEthernet0/1
// carries NO description and is the guard that refusing the free-text line
// costs an ordinary record nothing.
const ciscoInterfacesDescriptionTrap = `GigabitEthernet0/0 is up, line protocol is up
  Hardware is CSR vNIC, address is 000c.29ab.cdef (bia 000c.29ab.cdef)
  Description: MTU 9000 to core-02, 1Gbps uplink, Half Duplex, Last flapped never
  Internet address is 10.0.0.1/30
  MTU 1500 bytes, BW 100000 Kbit/sec, DLY 100 usec,
  Full Duplex, 100Mbps, link type is auto, media type is RJ45
GigabitEthernet0/1 is up, line protocol is up
  Internet address is 10.0.0.5/30
  MTU 1500 bytes, BW 100000 Kbit/sec, DLY 100 usec,
  Full Duplex, 100Mbps, link type is auto, media type is RJ45
`

// FIXTURE PROVENANCE: SYNTHETIC, authored 2026-09-10. Not a device capture.
// It is the Junos form of the shape review 3.5-03 names, and the worst one in
// the package: an operator DESCRIPTION carrying the very "Key: value" tokens the
// comma-split parameter loop reads AND the words the Last-flapped scan reads,
// printed ABOVE the device's own link-level and Last-flapped lines. Every value
// in the description is deliberately unlike the device's own, so a reading taken
// from the wrong line cannot be mistaken for the right one: the description says
// MTU 9000 / 10000mbps / Half-duplex / "yesterday", the device says MTU 1514 /
// 1000mbps / no duplex at all / a real flap timestamp. ge-0/0/1 carries NO
// description and is the guard that refusing the free-text line costs an
// ordinary record nothing.
const junosInterfacesDescriptionTrap = `Physical interface: ge-0/0/0, Enabled, Physical link is Up
  Interface index: 148, SNMP ifIndex: 526, Generation: 151
  Description: core uplink, MTU: 9000, Speed: 10000mbps, Link-mode: Half-duplex, Last flapped: yesterday
  Link-level type: Ethernet, MTU: 1514, MRU: 1522, LAN-PHY mode, Speed: 1000mbps, BPDU Error: None
  Last flapped   : 2026-08-30 12:11:03 UTC (2d 03:12:44 ago)
  Input errors:
    Errors: 12, Drops: 3, Framing errors: 7, Runts: 0, Policed discards: 0
  Output errors:
    Carrier transitions: 5, Errors: 0, Drops: 4, Collisions: 0, Aged packets: 0
Physical interface: ge-0/0/1, Enabled, Physical link is Up
  Interface index: 149, SNMP ifIndex: 527, Generation: 152
  Link-level type: Ethernet, MTU: 1514, MRU: 1522, LAN-PHY mode, Speed: 1000mbps, BPDU Error: None
  Last flapped   : 2026-08-30 12:11:05 UTC (2d 03:12:42 ago)
  Input errors:
    Errors: 0, Drops: 0, Framing errors: 0, Runts: 0, Policed discards: 0
  Output errors:
    Carrier transitions: 1, Errors: 0, Drops: 0, Collisions: 0, Aged packets: 0
`

const junosShowInterfacesExtensive = `Physical interface: ge-0/0/0, Enabled, Physical link is Up
  Interface index: 148, SNMP ifIndex: 526, Generation: 151
  Description: uplink to core-02
  Link-level type: Ethernet, MTU: 1514, MRU: 1522, LAN-PHY mode, Speed: 1000mbps, BPDU Error: None
  Device flags   : Present Running
  Interface flags: SNMP-Traps Internal: 0x4000
  Link flags     : None
  CoS queues     : 8 supported, 8 maximum usable queues
  Hold-times     : Up 0 ms, Down 0 ms
  Current address: 00:05:86:71:c2:00, Hardware address: 00:05:86:71:c2:00
  Last flapped   : 2026-08-30 12:11:03 UTC (2d 03:12:44 ago)
  Input rate     : 1000 bps (1 pps)
  Output rate    : 2000 bps (2 pps)
  Input errors:
    Errors: 12, Drops: 3, Framing errors: 7, Runts: 0, Policed discards: 0, L3 incompletes: 0
  Output errors:
    Carrier transitions: 5, Errors: 0, Drops: 4, Collisions: 0, Aged packets: 0
`

// FIXTURE PROVENANCE: SYNTHETIC, authored 2026-09-10. Not a device capture.
// It is the VRP form of the shape review 3.5-03 names: an operator DESCRIPTION
// carrying both the comma-separated "Key: value" tokens the parameter loop reads
// AND the two distinct phrases VRP prints for MTU and for the interface address,
// sitting above the device's own lines, which carry DIFFERENT values. The
// description says speed 10000, duplex HALF, MTU 9000 and 192.0.2.99/32; the
// device says 1000, FULL, 1500 and 10.0.0.1/30. GigabitEthernet0/0/2 carries NO
// description and is the guard that refusing the free-text line costs an
// ordinary record nothing.
const vrpInterfaceDescriptionTrap = `GigabitEthernet0/0/1 current state : UP
Line protocol current state : UP
Description:core uplink, Speed : 10000, Duplex: HALF, The Maximum Transmit Unit is 9000, Internet Address is 192.0.2.99/32
Route Port,The Maximum Transmit Unit is 1500
Internet Address is 10.0.0.1/30
IP Sending Frames' Format is PKTFMT_ETHNT_2, Hardware address is 00e0-fc12-3456
Port Mode: FORCE COPPER
Speed : 1000,  Loopback: NONE
Duplex: FULL,  Negotiation: ENABLE
    Input:
      Unicast: 1234567, Multicast: 1000
      CRC: 7, Overrun: 0, Fragment: 0
      Total Error: 12, Drop: 3
    Output:
      Unicast: 2345678, Multicast: 500
      Total Error: 0, Drop: 4
GigabitEthernet0/0/2 current state : UP
Line protocol current state : UP
Route Port,The Maximum Transmit Unit is 1500
Internet Address is 10.0.0.5/30
Port Mode: FORCE COPPER
Speed : 1000,  Loopback: NONE
Duplex: FULL,  Negotiation: ENABLE
    Input:
      Unicast: 10, Multicast: 1
      CRC: 0, Overrun: 0, Fragment: 0
      Total Error: 0, Drop: 0
    Output:
      Unicast: 20, Multicast: 2
      Total Error: 0, Drop: 0
`

// FIXTURE PROVENANCE: SYNTHETIC, authored 2026-09-10. Not a device capture.
// The second VRP form of the class: a description that forges a RECORD BOUNDARY
// rather than a value. vrpHeaderShape treats the words "current state" followed
// by a colon as the start of a new interface wherever they appear, and this
// description carries them. The device's own MTU, speed, duplex and address
// lines follow the description, so if the description ends the record they are
// filed under no interface at all. GigabitEthernet0/0/2 carries NO description
// and is the guard that the boundary itself still works.
const vrpInterfaceDescriptionBoundaryTrap = `GigabitEthernet0/0/1 current state : UP
Line protocol current state : UP
Description:core uplink to spine-01, peer current state : UP
Route Port,The Maximum Transmit Unit is 1500
Internet Address is 10.0.0.1/30
Port Mode: FORCE COPPER
Speed : 1000,  Loopback: NONE
Duplex: FULL,  Negotiation: ENABLE
    Input:
      CRC: 7, Overrun: 0, Fragment: 0
      Total Error: 12, Drop: 3
    Output:
      Total Error: 0, Drop: 4
GigabitEthernet0/0/2 current state : UP
Line protocol current state : DOWN
Route Port,The Maximum Transmit Unit is 1500
Internet Address is 10.0.0.5/30
Speed : 1000,  Loopback: NONE
Duplex: FULL,  Negotiation: ENABLE
    Input:
      CRC: 0, Overrun: 0, Fragment: 0
      Total Error: 0, Drop: 0
    Output:
      Total Error: 0, Drop: 0
`

const vrpDisplayInterface = `GigabitEthernet0/0/1 current state : UP
Line protocol current state : UP
Description:uplink to core-02
Route Port,The Maximum Transmit Unit is 1500
Internet Address is 10.0.0.1/30
IP Sending Frames' Format is PKTFMT_ETHNT_2, Hardware address is 00e0-fc12-3456
Port Mode: FORCE COPPER
Speed : 1000,  Loopback: NONE
Duplex: FULL,  Negotiation: ENABLE
    Last 300 seconds input rate 1000 bits/sec, 1 packets/sec
    Last 300 seconds output rate 2000 bits/sec, 2 packets/sec
    Input:
      Unicast: 1234567, Multicast: 1000
      CRC: 7, Overrun: 0, Fragment: 0
      Total Error: 12, Drop: 3
    Output:
      Unicast: 2345678, Multicast: 500
      Total Error: 0, Drop: 4
`

// FIXTURE PROVENANCE: SYNTHETIC, authored 2026-09-10. Not a device capture.
// It is the SR OS form of the shape review 3.5-03 names. This table has no
// "Key: value" scan to fall through into — its keys come from a closed switch —
// but the COLUMNS are found by shape, so free text in the description that
// carries a column gap and a colon becomes a key of its own. The description
// here names an MTU, a speed and an Rx optical power, all unlike the device's
// own lines (1514, 1 Gbps, -5.23 dBm), so a reading taken from the wrong line
// cannot be mistaken for the right one.
const srosPortDetailDescriptionTrap = `===============================================================================
Ethernet Interface
===============================================================================
Description        : to core-02    MTU : 9000    Oper Speed : 10 Gbps    Rx Optical Power : -1.00 dBm
Interface          : 1/1/1                  Oper Speed       : 1 Gbps
Link-level         : Ethernet               Config Speed     : 1 Gbps
Admin State        : up                     Oper State       : up
Physical Link      : Yes                    MTU              : 1514
IfIndex            : 35684352               Hold time up     : 0 seconds
===============================================================================
Transceiver Digital Diagnostic Monitoring
===============================================================================
Temperature (C)    : 34.5                   Rx Optical Power : -5.23 dBm
Tx Output Power    : -2.10 dBm              Voltage          : 3.29 V
`

// FIXTURE PROVENANCE: SYNTHETIC, authored 2026-09-10. Not a device capture.
// The guard for srosPortDetailDescriptionTrap: the same port with NO description
// line at all. An SR OS port-detail capture carries exactly one port, so the
// no-description record cannot sit beside the trap in one capture the way it
// does in the Cisco, Junos and VRP fixtures.
const srosPortDetailNoDescription = `===============================================================================
Ethernet Interface
===============================================================================
Interface          : 1/1/1                  Oper Speed       : 1 Gbps
Link-level         : Ethernet               Config Speed     : 1 Gbps
Admin State        : up                     Oper State       : up
Physical Link      : Yes                    MTU              : 1514
IfIndex            : 35684352               Hold time up     : 0 seconds
===============================================================================
Transceiver Digital Diagnostic Monitoring
===============================================================================
Temperature (C)    : 34.5                   Rx Optical Power : -5.23 dBm
Tx Output Power    : -2.10 dBm              Voltage          : 3.29 V
`

const srosShowPortDetail = `===============================================================================
Ethernet Interface
===============================================================================
Description        : uplink to core-02
Interface          : 1/1/1                  Oper Speed       : 1 Gbps
Link-level         : Ethernet               Config Speed     : 1 Gbps
Admin State        : up                     Oper State       : up
Physical Link      : Yes                    MTU              : 1514
Single Fiber Mode  : No                     Min Frame Length : 64 Bytes
IfIndex            : 35684352               Hold time up     : 0 seconds
===============================================================================
Transceiver Digital Diagnostic Monitoring
===============================================================================
Temperature (C)    : 34.5                   Rx Optical Power : -5.23 dBm
Tx Output Power    : -2.10 dBm              Voltage          : 3.29 V
`

// ── interfaces: brief tables ────────────────────────────────────────────────

const ciscoIPIntBrief = `Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up
GigabitEthernet0/1     unassigned      YES NVRAM  administratively down down
Loopback0              10.255.0.1      YES NVRAM  up                    up
`

const nxosIPIntBrief = `IP Interface Status for VRF "default"(1)
Interface            IP Address      Interface Status
Vlan10               10.0.0.1        protocol-up/link-up/admin-up
Eth1/1               10.0.1.1        protocol-down/link-down/admin-up
`

const eosIPIntBrief = `                                                                      Address
Interface         IP Address         Status       Protocol           MTU    Owner
----------------- ------------------ ------------ -------------- ---------- -------
Ethernet1         10.0.0.1/30        up           up                 1500
Ethernet2         unassigned         down         down               1500
`

const junosInterfacesTerse = `Interface               Admin Link Proto    Local                 Remote
ge-0/0/0                up    up
ge-0/0/0.0              up    up   inet     10.0.0.1/30
ge-0/0/1                down  down
lo0.0                   up    up   inet     10.255.0.1/32
`

// ── optics ──────────────────────────────────────────────────────────────────

const ciscoTransceiverCombined = `If device is externally calibrated, only calibrated values are printed.
++ : high alarm, +  : high warning, -  : low warning, -- : low alarm.
NA or N/A: not applicable, Tx: transmit, Rx: receive.
mA: milliamperes, dBm: decibels (milliwatts).

                                     Optical   Optical
           Temperature  Voltage  Tx Power  Rx Power  Current
Port       (Celsius)    (Volts)  (dBm)     (dBm)     (mA)
---------  -----------  -------  --------  --------  --------
Gi0/0         34.2       3.29      -2.1      -5.6       6.3
Gi0/1         35.8       3.30      -2.4      -19.8      6.1
`

// ciscoTransceiverDetailSkipFixture is the PER-METRIC "detail" flavour, whose
// header names one measurement but whose rows carry four threshold columns. The
// parser must SKIP it rather than read a low-alarm threshold as an Rx power.
const ciscoTransceiverDetailSkipFixture = `                              High Alarm  High Warn  Low Warn   Low Alarm
           Temperature        Threshold   Threshold  Threshold  Threshold
Port       (Celsius)          (Celsius)   (Celsius)  (Celsius)  (Celsius)
---------  -----------------  ----------  ---------  ---------  ---------
Gi0/0        34.2               75.0        70.0       0.0       -5.0
`

const nxosTransceiverDetails = `Ethernet1/1
    transceiver is present
    type is 10Gbase-SR
    name is CISCO-FINISAR
           SFP Detail Diagnostics Information
----------------------------------------------------------------------------
                        Current       Alarms             Warnings
                        Measurement   High     Low       High    Low
----------------------------------------------------------------------------
  Temperature        34.20 C          75.00 C  -5.00 C   70.00 C  0.00 C
  Voltage             3.29 V           3.63 V   2.97 V    3.46 V  3.13 V
  Current             6.30 mA         11.80 mA  0.50 mA  10.80 mA 1.00 mA
  Tx Power           -2.10 dBm         1.69 dBm -11.30 dBm -1.30 dBm -7.30 dBm
  Rx Power           -5.60 dBm         2.00 dBm -13.90 dBm -1.00 dBm -9.90 dBm
`

const junosOpticsDiagnostics = `Physical interface: ge-0/0/0
    Laser bias current                        :  6.300 mA
    Laser output power                        :  0.6160 mW / -2.10 dBm
    Module temperature                        :  34 degrees C / 93 degrees F
    Module voltage                            :  3.2900 V
    Receiver signal average optical power     :  0.2754 mW / -5.60 dBm
`

const vrpTransceiverVerbose = `GigabitEthernet0/0/1 transceiver information:
  Common information:
    Transceiver Type              :1000_BASE_LX_SFP
    Connector Type                :LC
    Wavelength (nm)               :1310
  Diagnostic information:
    Temperature (C)               :34.00
    Voltage (V)                   :3.29
    Bias Current (mA)             :6.30
    Current Tx Power (dBm)        :-2.10
    Current Rx Power (dBm)        :-5.60
`

// ── IGP ─────────────────────────────────────────────────────────────────────

const ciscoOSPFNeighbor = `Neighbor ID     Pri   State           Dead Time   Address         Interface
10.0.0.2          1   FULL/DR         00:00:35    10.0.0.2        GigabitEthernet0/0
10.0.0.3          1   EXSTART/DROTHER 00:00:33    10.0.0.6        GigabitEthernet0/1
`

const nxosOSPFNeighbor = ` OSPF Process ID 1 VRF default
 Total number of neighbors: 2
 Neighbor ID     Pri State            Up Time  Address         Interface
 10.0.0.2          1 FULL/DR          02:31:11 10.0.0.2        Eth1/1
 10.0.0.3          1 INIT/DROTHER     00:00:04 10.0.0.6        Eth1/2
`

const eosOSPFNeighbor = `Neighbor ID     VRF      Pri State       Dead Time   Address         Interface
10.0.0.2        default  1   FULL/DR     00:00:35    10.0.0.2        Ethernet1
10.0.0.3        default  1   2WAY/DROTHER 00:00:33   10.0.0.6        Ethernet2
`

const junosOSPFNeighbor = `Address          Interface              State     ID               Pri  Dead
10.0.0.2         ge-0/0/0.0             Full      10.0.0.2         128    35
10.0.0.6         ge-0/0/1.0             ExStart   10.0.0.3         128    33
`

const srosOSPFNeighbor = `===============================================================================
Rtr Base OSPFv2 Instance 0 Neighbors
===============================================================================
Interface-Name                   Rtr Id          State      Pri  RetxQ   TTL
-------------------------------------------------------------------------------
to-core-02                       10.0.0.2        Full       1    0       33
to-core-03                       10.0.0.3        ExStart    1    0       31
-------------------------------------------------------------------------------
`

const vrpOSPFPeerBrief = `	 OSPF Process 1 with Router ID 10.0.0.1
		  Peer Statistic Information
 ----------------------------------------------------------------------------
 Area Id          Interface                        Neighbor id      State
 0.0.0.0          GigabitEthernet0/0/1             10.0.0.2         Full
 0.0.0.0          GigabitEthernet0/0/2             10.0.0.3         Init
 ----------------------------------------------------------------------------
`

const ciscoISISNeighbors = `System Id      Type Interface     IP Address      State Holdtime Circuit Id
core-02        L2   Gi0/0         10.0.0.2        UP    27       core-01.01
core-03        L1   Gi0/1         10.0.0.6        INIT  9        core-01.02
`

const iosxrISISAdjacency = `IS-IS 1 Level-2 adjacencies:
System Id      Interface        SNPA           State Hold Changed  NSF  IPv4 IPv6
                                                                        BFD  BFD
core-02        Gi0/0/0/0        *PtoP*         Up    27   00:12:34 Yes  None None
core-03        Gi0/0/0/1        *PtoP*         Init  9    00:00:04 Yes  None None

Total adjacency count: 2
`

const junosISISAdjacency = `Interface             System         L State        Hold (secs) SNPA
ge-0/0/0.0            core-02        2  Up                   24
ge-0/0/1.0            core-03        1  Init                  8
`

const srosISISAdjacency = `===============================================================================
Rtr Base ISIS Instance 0 Adjacency
===============================================================================
System ID                Usage State Hold Interface
-------------------------------------------------------------------------------
core-02                  L2    Up    23   to-core-02
core-03                  L1    Init  8    to-core-03
-------------------------------------------------------------------------------
`

// ── BGP ─────────────────────────────────────────────────────────────────────

const ciscoBGPSummary = `BGP router identifier 10.255.0.1, local AS number 65001
BGP table version is 1234, main routing table version 1234

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4        65002    1234    1235     1234    0    0 02:31:11       12
10.0.0.3        4        65003       0       0        1    0    0 never    Idle
10.0.0.4        4        65004       0       0        1    0    0 00:00:12 Active
10.0.0.5        4        65005       0       0        1    0    0 never    Idle (Admin)
`

// FIXTURE PROVENANCE: SYNTHETIC, authored 2026-09-10 from the documented IOS-XR
// `show bgp summary` layout. Not a device capture. The point of the fixture is
// the SECOND COLUMN: XR heads it "Spk" and prints the BGP speaker id (0 on an
// ordinary router) where IOS prints the BGP version. The preamble lines are kept
// because they are what a row head has to refuse — "Speaker" and "Table ID" are
// not peer addresses.
const iosxrBGPSummary = `BGP router identifier 10.255.0.1, local AS number 65001
BGP generic scan interval 60 secs
Non-stop routing is enabled
BGP table state: Active
Table ID: 0xe0000000   RD version: 1234
BGP main routing table version 1234
BGP scan interval 60 secs

BGP is operating in STANDALONE mode.

Process       RcvTblVer   bRIB/RIB   LabelVer  ImportVer  SendTblVer  StandbyVer
Speaker            1234       1234       1234       1234        1234        1234

Neighbor        Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down  St/PfxRcd
10.0.0.2          0 65002    1234    1235     1234    0    0 02:31:11         12
10.0.0.3          0 65003       0       0        0    0    0 00:00:12      Idle
10.0.0.4          0 65004       0       0        0    0    0 00:00:00      Active
10.0.0.5          0 65005       0       0        0    0    0 00:00:00 Idle (Admin)
`

const eosBGPSummary = `BGP summary information for VRF default
Router identifier 10.255.0.1, local AS number 65001
Neighbor         V  AS           MsgRcvd   MsgSent  InQ OutQ  Up/Down State   PfxRcd PfxAcc
10.0.0.2         4  65002           1234      1235    0    0 02:31:11 Estab   12     12
10.0.0.3         4  65003              0         0    0    0 00:00:00 Idle    0      0
`

const junosBGPSummary = `Groups: 2 Peers: 2 Down peers: 1
Table          Tot Paths  Act Paths Suppressed    History Damp State    Pending
inet.0               120        100          0          0          0          0
Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...
10.0.0.2              65002       1234       1235       0       0     2d3:12:44 100/120/120/0
10.0.0.3              65003          0          0       0       2          1:02 Active
`

const srosBGPSummary = `===============================================================================
 BGP Summary
===============================================================================
Neighbor
                   AS PktRcvd InQ  Up/Down   State|Rcv/Act/Sent (Addr Family)
                      PktSent OutQ
-------------------------------------------------------------------------------
10.0.0.2
                65002    1234    0 02h31m11s 100/100/120
                         1235    0
10.0.0.3
                65003       0    0 00h00m12s Active
                            0    0
-------------------------------------------------------------------------------
`

const vrpBGPPeer = ` BGP local router ID : 10.255.0.1
 Local AS number : 65001
 Total number of peers : 2        Peers in established state : 1

  Peer            V    AS  MsgRcvd  MsgSent  OutQ  Up/Down       State  PrefRcv
  10.0.0.2        4 65002     1234     1235     0 02:31:11 Established       12
  10.0.0.3        4 65003        0        0     0 00:00:12        Idle        0
`

// ── routes ──────────────────────────────────────────────────────────────────

const ciscoRouteDetail = `Routing entry for 192.0.2.0/24
  Known via "ospf 1", distance 110, metric 20, type intra area
  Last update from 10.0.0.2 on GigabitEthernet0/0, 00:12:34 ago
  Routing Descriptor Blocks:
  * 10.0.0.2, from 10.0.0.2, 00:12:34 ago, via GigabitEthernet0/0
      Route metric is 20, traffic share count is 1
`

const ciscoRouteTable = `Codes: L - local, C - connected, S - static, O - OSPF, B - BGP

O        192.0.2.0/24 [110/20] via 10.0.0.2, 00:12:34, GigabitEthernet0/0
B        198.51.100.0/24 [20/0] via 10.0.0.6, 01:02:03, GigabitEthernet0/1
`

const ciscoRouteNotInTable = `% Network not in table
`

const junosRouteDetail = `inet.0: 120 destinations, 130 routes (120 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

192.0.2.0/24       *[OSPF/10] 00:12:34, metric 20
                    > to 10.0.0.2 via ge-0/0/0.0
198.51.100.0/24    *[BGP/170] 01:02:03, localpref 100
                    > to 10.0.0.6 via ge-0/0/1.0
`

// ── L2 ──────────────────────────────────────────────────────────────────────

const ciscoARP = `Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.0.0.1                -   000c.29ab.cdef  ARPA   GigabitEthernet0/0
Internet  10.0.0.2               12   000c.29ab.cdf1  ARPA   GigabitEthernet0/0
`

const nxosARP = `Flags: * - Adjacencies learnt on non-active FHRP router
IP ARP Table for context default
Total number of entries: 2
Address         Age       MAC Address     Interface
10.0.0.2        00:12:34  000c.29ab.cdf1  Ethernet1/1
10.0.0.6        00:00:41  000c.29ab.cdf2  Ethernet1/2
`

const srosARP = `===============================================================================
ARP Table (Router: Base)
===============================================================================
IP Address      MAC Address       Expiry    Type   Interface
-------------------------------------------------------------------------------
10.0.0.2        00:0c:29:ab:cd:f1 00h58m32s Dynamic to-core-02
-------------------------------------------------------------------------------
`

const ciscoMACTable = `          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  10    000c.29ab.cdf1    DYNAMIC     Gi0/1
  20    000c.29ab.cdf2    STATIC      Gi0/2
`

const nxosMACTable = `Legend:
        * - primary entry, G - Gateway MAC, (R) - Routed MAC
   VLAN     MAC Address      Type      age     Secure NTFY Ports
---------+-----------------+--------+---------+------+----+------------------
*   10     000c.29ab.cdf1   dynamic  0          F      F   Eth1/1
`

const vrpMACTable = `-------------------------------------------------------------------------------
MAC Address    VLAN/VSI/BD   Learned-From        Type
-------------------------------------------------------------------------------
000c-29ab-cdf1 10/-/-        GE0/0/1             dynamic
-------------------------------------------------------------------------------
`

// ── platform ────────────────────────────────────────────────────────────────

const ciscoProcessesCPU = `CPU utilization for five seconds: 12%/1%; one minute: 10%; five minutes: 9%
 PID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process
   1        1234        5678        217  0.15%  0.10%  0.09%   0 Chunk Manager
`

const nxosSystemResources = `Load average:   1 minute: 0.30   5 minutes: 0.20  15 minutes: 0.15
Processes   :   500 total, 1 running
CPU states  :   5.0% user,   3.0% kernel,  92.0% idle
Memory usage:   8127096K total,   3225104K used,   4901992K free
`

const junosRoutingEngine = `Routing Engine status:
    Slot 0:
    Current state                  Master
    Temperature                 34 degrees C / 93 degrees F
    CPU temperature             40 degrees C / 104 degrees F
    DRAM                      2048 MB
    Memory utilization          22 percent
    CPU utilization:
      User                       5 percent
      Background                 0 percent
      Kernel                     4 percent
      Interrupt                  0 percent
      Idle                      91 percent
    Uptime                     10 days, 2 hours, 31 minutes, 11 seconds
    Last reboot reason         0x200:normal shutdown
`

const vrpCPUUsage = `CPU Usage Stat. Cycle: 60 (Second)
CPU Usage            : 12% Max: 45%
CPU Usage Stat. Time : 2026-09-02 10:00:00
`

const vrpMemoryUsage = `Memory utilization statistics at 2026-09-02 10:00:00
System Total Memory Is: 2147483648 bytes
Total Memory Used Is: 901943132 bytes
Memory Using Percentage Is: 42%
`

const ciscoShowVersion = `Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M)

core-01 uptime is 10 weeks, 2 days, 3 hours, 12 minutes
Uptime for this control processor is 10 weeks, 2 days, 3 hours, 14 minutes
System returned to ROM by reload
System restarted at 12:00:00 UTC Mon Jun 23 2026
`

const junosSystemUptime = `Current time: 2026-09-02 10:00:00 UTC
System booted: 2026-08-23 07:29:00 UTC (1w2d 02:31 ago)
Protocols started: 2026-08-23 07:30:00 UTC (1w2d 02:30 ago)
Last configured: 2026-09-01 08:00:00 UTC (1d 02:00 ago) by admin
10:00AM  up 10 days,  2:31, 1 user, load averages: 0.10, 0.15, 0.20
`

// ── logs ────────────────────────────────────────────────────────────────────

const ciscoLogging = `Syslog logging: enabled (0 messages dropped, 3 messages rate-limited)
Log Buffer (16384 bytes):

*Sep  2 09:58:12.345: %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on GigabitEthernet0/0 from LOADING to FULL, Loading Done
*Sep  2 09:59:01.001: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
*Sep  2 09:59:01.002: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down
`

const junosLogMessages = `Sep  2 09:58:12  core-01 rpd[1234]: RPD_OSPF_NBRUP: OSPF neighbor 10.0.0.2 (realm ipv4-unicast ge-0/0/0.0 area 0.0.0.0) state changed from Loading to Full
Sep  2 09:59:01  core-01 mib2d[1240]: SNMP_TRAP_LINK_DOWN: ifIndex 526, ifAdminStatus up, ifOperStatus down, ifName ge-0/0/1
`

const vrpLogbuffer = `Sep  2 2026 09:58:12+08:00 core-01 %%01OSPF/5/NBR_CHG_DOWN(l)[123]:Neighbor changes event: neighbor status changed
Sep  2 2026 09:59:01+08:00 core-01 %%01IFNET/3/LINK_STATE(l)[124]:The line protocol IP on the interface GigabitEthernet0/0/2 has entered the DOWN state
`

const srosEventLog = `===============================================================================
Event Log 99
===============================================================================
Description : Default System Log
Memory Log contents  [size=500   next event=124  (not wrapped)]

123 2026/09/02 09:58:12.34 UTC MINOR: OSPF #2005 Base VR 1: Neighbor state change
122 2026/09/02 09:59:01.10 UTC MAJOR: SYSTEM #2013 Base Port 1/1/2 down
`

// ── garbage / truncated / adversarial ───────────────────────────────────────

const garbageOutput = `% Invalid input detected at '^' marker.

The device rejected the command; there is nothing here to parse at all,
only a few lines of English prose and a stray 42 that means nothing.
`

// truncatedCiscoInterfaces is a capture cut off by a dropped session: the header
// line landed, the counter and MTU lines never did.
const truncatedCiscoInterfaces = `GigabitEthernet0/0 is up, line protocol is up
  Hardware is CSR vNIC, address is 000c.29`

// ── review H5: header boundaries and misattributed counters ─────────────────

// eosAdminDownSecondInterface is the Arista capture that reproduced review H5.
// Ethernet2's line-protocol phrase is "down (disabled)", which the old closed
// state-word list did not carry — so the header read as body text and
// Ethernet2's 15 000 CRC errors were reported against Ethernet1.
const eosAdminDownSecondInterface = `Ethernet1 is up, line protocol is up (connected)
  Hardware is Ethernet, address is 001c.7300.0001
  MTU 1500 bytes, BW 1000000 Kbit/sec
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 output errors, 0 collisions
Ethernet2 is administratively down, line protocol is down (disabled)
  Hardware is Ethernet, address is 001c.7300.0002
  MTU 1500 bytes, BW 1000000 Kbit/sec
     15000 input errors, 15000 CRC, 0 frame, 0 overrun, 0 ignored
     0 output errors, 0 collisions
`

// nxosLinkNotConnected is the NX-OS spelling the old list also lacked.
const nxosLinkNotConnected = `Ethernet1/1 is up
  admin state is up, Dedicated Interface
  MTU 1500 bytes, BW 10000000 Kbit/sec
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
Ethernet1/2 is down (Link not connected)
  admin state is up, Dedicated Interface
  MTU 1500 bytes, BW 10000000 Kbit/sec
     4242 input errors, 4242 CRC, 0 frame, 0 overrun, 0 ignored
`

// ciscoUnknownStatePhrase carries a header whose state phrase this parser does
// NOT read ("standby mode", the IOS phrase for a redundant serial interface).
// The counters under it must not reach Serial0/0/0, and the fact that they were
// read and not used must be visible.
const ciscoUnknownStatePhrase = `Serial0/0/0 is up, line protocol is up
  MTU 1500 bytes, BW 1544 Kbit/sec
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 output errors, 0 collisions
Serial0/0/1 is standby mode, line protocol is down
  MTU 1500 bytes, BW 1544 Kbit/sec
     9999 input errors, 9999 CRC, 0 frame, 0 overrun, 0 ignored
     7777 output errors, 0 collisions
`

// vrpTruncatedSecondHeader is the VRP form of the same defect: the second
// header is cut off right after the colon, so the value parser refuses it. The
// "Line protocol current state : DOWN" line and the CRC storm below it must not
// reach GigabitEthernet0/0/1, which is up and clean.
const vrpTruncatedSecondHeader = `GigabitEthernet0/0/1 current state : UP
Line protocol current state : UP
Route Port,The Maximum Transmit Unit is 1500
    Input:
      Unicast: 1234567, Multicast: 1000
    Output:
      Unicast: 2345678, Multicast: 500
GigabitEthernet0/0/2 current state :
Line protocol current state : DOWN
    Input:
      CRC: 9999, Overrun: 0, Fragment: 0
      Total Error: 9999, Drop: 88
`

// vrpTwoInterfaces is the guard: ordinary multi-interface VRP output must still
// parse into one row per interface, with each interface's own counters.
const vrpTwoInterfaces = `GigabitEthernet0/0/1 current state : UP
Line protocol current state : UP
Route Port,The Maximum Transmit Unit is 1500
    Input:
      CRC: 7, Overrun: 0, Fragment: 0
      Total Error: 12, Drop: 3
GigabitEthernet0/0/2 current state : DOWN
Line protocol current state : DOWN
Route Port,The Maximum Transmit Unit is 9000
    Input:
      CRC: 500, Overrun: 0, Fragment: 0
      Total Error: 600, Drop: 4
`

// vrpDescriptionMentionsState guards the header-shape predicate: a description
// that happens to contain the marker words is NOT a record boundary.
const vrpDescriptionMentionsState = `GigabitEthernet0/0/1 current state : UP
Line protocol current state : UP
Description:watch the current state of the core link
Route Port,The Maximum Transmit Unit is 1500
    Input:
      CRC: 7, Overrun: 0, Fragment: 0
      Total Error: 12, Drop: 3
`

// ── tracker 282(e): a value the device did not print ───────────────────────

// vrpEmptyDuplex is tracker 282(e): VRP printed the key and no value, and the
// " x" sentinel turned that into Duplex = "x" — a field the device never gave.
const vrpEmptyDuplex = `GigabitEthernet0/0/1 current state : UP
Line protocol current state : UP
Route Port,The Maximum Transmit Unit is 1500
Speed : ,  Loopback: NONE
Duplex: ,  Negotiation: ENABLE
`

// vrpEmptyLineProtocol is the same fabrication one line up: a truncated
// line-protocol line must leave Oper absent, not set it to the empty string.
const vrpEmptyLineProtocol = `GigabitEthernet0/0/1 current state : UP
Line protocol current state :
Route Port,The Maximum Transmit Unit is 1500
`

// ciscoEmptyVersionToken is the platform-uptime form: a version line that
// carries only punctuation must leave Version absent.
const ciscoEmptyVersionToken = `Cisco IOS Software, IOSv Software, Version ,  RELEASE SOFTWARE
router uptime is 5 days, 4 hours, 3 minutes
System returned to ROM by reload
`

// ciscoRoutingEntryNoPrefix is the route.go sentinel site: "Routing entry for "
// with nothing after it must start no route, not a route named "x".
const ciscoRoutingEntryNoPrefix = `Routing entry for 
  Known via "ospf 1", distance 110, metric 20
`

// ciscoEmptyInternetAddress is the iface.go IPv4 sentinel site: a line that
// ends right after the marker must leave IPv4 absent, not set it to "x".
const ciscoEmptyInternetAddress = `GigabitEthernet0/0 is up, line protocol is up
  Internet address is 
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
`
