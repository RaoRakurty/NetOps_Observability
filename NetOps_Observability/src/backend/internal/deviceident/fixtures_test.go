// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package deviceident

// fixtures_test.go — the show output the per-vendor patterns are asserted
// against, and where each fixture's SHAPE comes from.
//
// PROVENANCE IS PART OF THE FIXTURE. A parser test is only worth what its
// fixture is worth, so every constant below says whether its shape is
// REPO-GROUNDED (copied verbatim from output already committed to this
// repository) or DOC_CLAIMED (authored from the vendor's documented output
// shape, never read off a device here). A doc_claimed fixture proves the
// pattern reads the line the profile SAYS it reads; only a device can promote
// it, and the profile notes say so too.

// ── REPO-GROUNDED ───────────────────────────────────────────────────────────
//
// These four are copied verbatim from internal/osprobe/sources_test.go, which
// authored them for the OS-version ladder's CLI rung.

// showVersionEOS — an Arista 7050SX3 running EOS 4.32.0F. Model on the first
// line, chassis serial four lines down.
const showVersionEOS = `Arista DCS-7050SX3-48YC8-F
Hardware version: 11.03
Serial number: JPE19141ABC
Hardware MAC address: 2899.3a11.2233
System MAC address: 2899.3a11.2233

Software image version: 4.32.0F
Architecture: x86_64
Internal build version: 4.32.0F-36993274.4320F
Internal build ID: 6a0b1c2d-3e4f-5061-7283-94a5b6c7d8e9

Uptime: 31 weeks, 4 days, 2 hours and 9 minutes
Total memory: 8127708 kB
Free memory: 5241016 kB`

// showVersionSRLinux — Nokia SR Linux on a 7220 IXR-D3L, the shape the
// reference lab's spines print. The serial really is the string `Sim Serial
// No.`: a containerlab node has no chassis, and the parser reports what the
// device SAID rather than deciding that answer does not look like a serial.
const showVersionSRLinux = `--------------------------------------------------------------------------------
Hostname             : spine1
Chassis Type         : 7220 IXR-D3L
Part Number          : Sim Part No.
Serial Number        : Sim Serial No.
System HW MAC Address: 1A:9E:02:FF:00:00
OS                   : SR Linux
Software Version     : v26.3.2
Build Number         : 426-g2b38957bbca
Architecture         : x86_64
Last Booted          : 2026-09-02T09:14:31.000Z
Total Memory         : 20463034 kB
Free Memory          : 12103391 kB
--------------------------------------------------------------------------------`

// showVersionNXOS — a Nexus 9000 running 10.3(4a). The Hardware block's
// `cisco … Chassis` line is the model.
const showVersionNXOS = `Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Copyright (C) 2002-2024, Cisco and/or its affiliates.

Software
  BIOS: version 05.47
  NXOS: version 10.3(4a)
  BIOS compile time:  09/11/2023
  NXOS image file is: bootflash:///nxos64-cs.10.3.4a.M.bin
  NXOS compile time:  2/9/2024 12:00:00 [02/09/2024 20:33:36]

Hardware
  cisco Nexus9000 C93180YC-FX3 Chassis
  Intel(R) Xeon(R) CPU D-1528 @ 1.90GHz with 24571632 kB of memory.
  Processor Board ID FDO21120U5D

  Device name: n9k-1
  bootflash:  115805708 kB`

// showVersionJunos — an MX204 running a Junos service release. Junos prints the
// model here and the chassis serial NOWHERE in this output, which is the whole
// reason the profile binds a second command.
const showVersionJunos = `Hostname: mx-edge-1
Model: mx204
Junos: 21.4R3-S5.4
JUNOS OS Kernel 64-bit  [20230419.5b1b0eb_builder_stable_12-214ab]
JUNOS OS runtime [20230419.5b1b0eb_builder_stable_12-214ab]
JUNOS Routing Engine 64-bit [20230419.5b1b0eb_builder_stable_12-214ab]
JUNOS py extensions [20230419.5b1b0eb_builder_stable_12-214ab]`

// showVersionIOSXEBase is the repo-grounded IOS-XE banner: a Catalyst 9300,
// two version lines and the `cisco <PID> (<arch>) processor` model line.
const showVersionIOSXEBase = `Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Thu 12-Oct-23 22:02 by mcpre

ROM: IOS-XE ROMMON
BOOTLDR: System Bootstrap, Version 17.9.1r[FC1], RELEASE SOFTWARE (P)

switch uptime is 41 weeks, 2 days, 6 hours, 11 minutes
System returned to ROM by Reload Command
System image file is "flash:cat9k_iosxe.17.09.04a.SPA.bin"

cisco C9300-48P (X86) processor with 1343803K/6147K bytes of memory.`

// ── DOC_CLAIMED ─────────────────────────────────────────────────────────────

// showVersionIOSXE is the repo-grounded banner plus the Catalyst switch-stack
// block that carries the serial. The block's `System Serial Number` /
// `Model Number` labels are doc_claimed.
const showVersionIOSXE = showVersionIOSXEBase + `
Processor board ID FOC2130Z0RD

Base Ethernet MAC Address          : 04:eb:40:9a:b0:80
Motherboard Assembly Number        : 73-18271-04
Motherboard Serial Number          : FOC21301ABC
Model Revision Number              : A0
Model Number                       : C9300-48P
System Serial Number               : FOC2130Z0RD
`

// showInventoryIOSXE — the Cisco inventory grammar: one NAME/DESCR line and one
// PID/VID/SN line per FRU, CHASSIS FIRST. Padded exactly as a real listing pads
// its columns, so the patterns are proven against the spacing too.
const showInventoryIOSXE = `NAME: "Switch1 Chassis", DESCR: "Cisco Catalyst 9300 Series Switch"
PID: C9300-48P         , VID: V03  , SN: FOC2130Z0RD

NAME: "Switch 1 - Power Supply A", DESCR: "Switch 1 - Power Supply A"
PID: PWR-C1-715WAC     , VID: V02  , SN: LIT21094XYZ
`

// showInventoryIOSXR — the same grammar on IOS-XR, where it is the ONLY place a
// chassis serial appears (`show version` has none).
const showInventoryIOSXR = `NAME: "Rack 0", DESCR: "Cisco ASR9006 4 Line Card Slot Chassis with V2 AC PEM"
PID: ASR-9006-AC-V2, VID: V01, SN: FOX1441GPWM

NAME: "0/RSP0/CPU0", DESCR: "ASR9K Route Switch Processor with 440G/slot Fabric"
PID: A9K-RSP440-TR, VID: V02, SN: FOC1808N5XX
`

// showVersionIOS — classic IOS on an ISR 4331: the same two lines IOS-XE
// carries, without the stack block.
const showVersionIOS = `Cisco IOS Software, ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 16.9.4, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2019 by Cisco Systems, Inc.

isr-branch-01 uptime is 12 weeks, 3 days, 1 hour, 4 minutes
System returned to ROM by reload

cisco ISR4331/K9 (1RU) processor with 1795123K/6147K bytes of memory.
Processor board ID FTX1840ALBS
`

// showChassisHardwareJunos — the `Hardware inventory:` table. The chassis row
// leaves the Version and Part number columns EMPTY, so the serial is the first
// column after the literal word `Chassis` and the model follows it.
const showChassisHardwareJunos = `Hardware inventory:
Item             Version  Part number  Serial number     Description
Chassis                                JN123456AB        MX204
Midplane         REV 07   750-072994   ACRE1234
Routing Engine 0                       BUILTIN           RE-S-1600x8
FPC 0            REV 15   750-072995   ACRE5678          MPC
`

// showChassisSROS — Nokia SR OS `show chassis`: a Chassis Information block
// (Type) and a Hardware Data block (Serial number).
const showChassisSROS = `===============================================================================
Chassis Information
===============================================================================
  Name                       : sros-pe-1
  Type                       : 7750 SR-12
  Chassis Topology           : Standalone
  Location                   : (Not Specified)
  Coordinates                : (Not Specified)
  CLLI code                  :
  Number of slots            : 12
  Oper number of slots       : 12
  Critical LED state         : Off
  Base MAC address           : 4c:5f:d3:00:00:00
-------------------------------------------------------------------------------
Hardware Data
  Part number                : 3HE02773AARB01
  CLEI code                  : IPMUV10ERA
  Serial number              : NS1234C5678
  Manufacture date           : 01152013
  Manufacturing string       : (Not Specified)
  Time of last boot          : 2026/09/02 09:14:31
  Current alarm state        : alarm cleared
===============================================================================
`

// showSystemInfoPANOS — PAN-OS `show system info`, a flat `key: value` block.
const showSystemInfoPANOS = `hostname: pa-edge-1
ip-address: 10.10.10.1
netmask: 255.255.255.0
default-gateway: 10.10.10.254
mac-address: 00:1b:17:00:00:00
time: Wed Sep  2 10:00:00 2026
uptime: 41 days, 2:31:04
devicename: pa-edge-1
family: 3200
model: PA-3220
serial: 001801000123
sw-version: 10.2.4
app-version: 8745-8231
threat-version: 8745-8231
`

// getSystemStatusFortiOS — FortiOS `get system status`. The model is the token
// ahead of the firmware on the Version line; the serial has its own label.
const getSystemStatusFortiOS = `Version: FortiGate-100F v7.2.5,build1517,230606 (GA.F)
Security Level: 1
Firmware Signature: certified
Virus-DB: 91.02539(2023-06-06 09:12)
IPS-DB: 22.00468(2023-06-05 22:31)
Serial-Number: FG100FTK20000123
License Status: Valid
Log hard disk: Available
Hostname: fgt-branch-01
Operation Mode: NAT
Current HA mode: standalone
System time: Wed Sep  2 10:00:00 2026
`

// ── adversarial ─────────────────────────────────────────────────────────────

// garbageOutput is what a device says when it did not understand the command.
// There is nothing here to parse and the parser must say so.
const garbageOutput = `% Invalid input detected at '^' marker.

The device rejected the command; there is nothing here to parse at all,
only a few lines of English prose and a stray serial that means nothing.
`

// truncatedIOSXE is a capture cut off by a dropped session: the banner landed,
// the serial block never did.
const truncatedIOSXE = `Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Ver`

// labelsWithNoValues is the shape that most tempts a parser into guessing: every
// label the profiles key on is present, and every one of them is EMPTY.
const labelsWithNoValues = `Serial Number        :
Chassis Type         :
serial:
model:
Serial-Number:
Serial number:
PID: , VID: , SN:
Processor board ID
`
