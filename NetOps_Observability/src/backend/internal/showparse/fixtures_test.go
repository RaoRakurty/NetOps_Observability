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
10:00AM  up 10 days,  2:31, 1 users, load averages: 0.10, 0.15, 0.20
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
