# SNMP Vendor Profiles — OID & Default-Metric Reference (Backlog #6)

Research-and-document deliverable for the **SNMP "profile manager"** library.
For each device **category** and major **vendor**, this lists the MIBs/OIDs and a
recommended **default metric set** a monitoring profile should poll.

> Status: **research / design only — no application code changed.**
> Every OID is grounded in a real, standard **MIB / RFC** or a published vendor
> enterprise MIB. OIDs the author is **not fully confident about are flagged
> `⚠ VERIFY`** with the reason (usually: leaf index not pinned down from a
> primary MIB source). Do **not** ship a `⚠ VERIFY` OID into a production poll
> set without walking it against a live device or the vendor MIB.

---

## Conventions

- **OID notation** — full numeric, dotted. A trailing `.0` denotes the scalar
  instance; tabular objects are shown as the **column OID** (you append the row
  index from an SNMP *walk*, e.g. ifIndex, entPhysicalIndex).
- **Type** — `counter` (monotonic, 32/64-bit — rate it), `gauge` (point-in-time),
  `string` (inventory/label, poll rarely), `enum` (status code → map to state).
- **Poll interval** — operational guidance:
  - **Inventory / identity** (sysDescr, model, serial): once per discovery, then
    every **24h**.
  - **Counters** (octets, errors, sessions): **30–60s** (the platform already
    ticks collectors on this order; 60s is the safe default for big interface
    walks).
  - **Health gauges** (CPU, memory, temp, fan/PSU): **60s** (CPU spikes), temp/PSU
    can relax to **300s**.
  - **Slow-moving inventory counters** (printer page count, UPS battery): **300s**.
- **64-bit first** — for octet/packet counters prefer the `ifXTable` HC
  (high-capacity) `Counter64` variants on any interface ≥ ~20 Mbps; the 32-bit
  `ifTable` counters wrap too fast to trust.

---

# 1. Universal Standard MIBs (apply to *every* category first)

These are IETF-standard and implemented by essentially all SNMP-capable gear.
A profile should **always** start from this base and then layer the vendor
enterprise OIDs on top.

## 1.1 SNMPv2-MIB — system identity (`1.3.6.1.2.1.1`, RFC 3418)

| Metric | OID | Type | Notes |
|---|---|---|---|
| sysDescr | `1.3.6.1.2.1.1.1.0` | string | Vendor/OS/version banner — primary classifier text |
| sysObjectID | `1.3.6.1.2.1.1.2.0` | oid | **Vendor/model fingerprint** — see §1.8 for prefixes |
| sysUpTime | `1.3.6.1.2.1.1.3.0` | gauge (timeticks) | Reboot detection (value resets) |
| sysContact | `1.3.6.1.2.1.1.4.0` | string | Inventory |
| sysName | `1.3.6.1.2.1.1.5.0` | string | Hostname |
| sysLocation | `1.3.6.1.2.1.1.6.0` | string | Inventory |
| sysServices | `1.3.6.1.2.1.1.7.0` | gauge | Layer bitmap |

## 1.2 IF-MIB — interface counters (`1.3.6.1.2.1.2` / `.31`, RFC 2863)

**ifTable** (`1.3.6.1.2.1.2.2.1.*`) — indexed by **ifIndex**:

| Metric | Column OID | Type | Unit |
|---|---|---|---|
| ifDescr | `1.3.6.1.2.1.2.2.1.2` | string | name |
| ifType | `1.3.6.1.2.1.2.2.1.3` | enum | IANAifType |
| ifMtu | `1.3.6.1.2.1.2.2.1.4` | gauge | bytes |
| ifSpeed | `1.3.6.1.2.1.2.2.1.5` | gauge | bps (caps at 4.29 Gbps → use ifHighSpeed) |
| ifAdminStatus | `1.3.6.1.2.1.2.2.1.7` | enum | up/down/testing |
| ifOperStatus | `1.3.6.1.2.1.2.2.1.8` | enum | up/down/… |
| ifLastChange | `1.3.6.1.2.1.2.2.1.9` | gauge | timeticks |
| ifInOctets | `1.3.6.1.2.1.2.2.1.10` | counter32 | bytes |
| ifInUcastPkts | `1.3.6.1.2.1.2.2.1.11` | counter32 | packets |
| ifInDiscards | `1.3.6.1.2.1.2.2.1.13` | counter32 | packets |
| ifInErrors | `1.3.6.1.2.1.2.2.1.14` | counter32 | packets |
| ifOutOctets | `1.3.6.1.2.1.2.2.1.16` | counter32 | bytes |
| ifOutUcastPkts | `1.3.6.1.2.1.2.2.1.17` | counter32 | packets |
| ifOutDiscards | `1.3.6.1.2.1.2.2.1.19` | counter32 | packets |
| ifOutErrors | `1.3.6.1.2.1.2.2.1.20` | counter32 | packets |

**ifXTable** (`1.3.6.1.2.1.31.1.1.1.*`) — HC + names, **same ifIndex**:

| Metric | Column OID | Type | Unit |
|---|---|---|---|
| ifName | `1.3.6.1.2.1.31.1.1.1.1` | string | short name |
| ifHCInOctets | `1.3.6.1.2.1.31.1.1.1.6` | counter64 | bytes |
| ifHCInUcastPkts | `1.3.6.1.2.1.31.1.1.1.7` | counter64 | packets |
| ifHCInMulticastPkts | `1.3.6.1.2.1.31.1.1.1.8` | counter64 | packets |
| ifHCInBroadcastPkts | `1.3.6.1.2.1.31.1.1.1.9` | counter64 | packets |
| ifHCOutOctets | `1.3.6.1.2.1.31.1.1.1.10` | counter64 | bytes |
| ifHCOutUcastPkts | `1.3.6.1.2.1.31.1.1.1.11` | counter64 | packets |
| ifHCOutMulticastPkts | `1.3.6.1.2.1.31.1.1.1.12` | counter64 | packets |
| ifHCOutBroadcastPkts | `1.3.6.1.2.1.31.1.1.1.13` | counter64 | packets |
| ifHighSpeed | `1.3.6.1.2.1.31.1.1.1.15` | gauge | Mbps |
| ifAlias | `1.3.6.1.2.1.31.1.1.1.18` | string | admin description |

## 1.3 ENTITY-MIB — physical inventory (`1.3.6.1.2.1.47`, RFC 4133)

`entPhysicalTable` (`1.3.6.1.2.1.47.1.1.1.1.*`), indexed by **entPhysicalIndex**:

| Metric | Column OID | Type |
|---|---|---|
| entPhysicalDescr | `1.3.6.1.2.1.47.1.1.1.1.2` | string |
| entPhysicalClass | `1.3.6.1.2.1.47.1.1.1.1.5` | enum (chassis/fan/powerSupply/sensor/module…) |
| entPhysicalName | `1.3.6.1.2.1.47.1.1.1.1.7` | string |
| entPhysicalHardwareRev | `1.3.6.1.2.1.47.1.1.1.1.8` | string |
| entPhysicalFirmwareRev | `1.3.6.1.2.1.47.1.1.1.1.9` | string |
| entPhysicalSerialNum | `1.3.6.1.2.1.47.1.1.1.1.11` | string |
| entPhysicalModelName | `1.3.6.1.2.1.47.1.1.1.1.13` | string |

## 1.4 ENTITY-SENSOR-MIB — generic sensors (`1.3.6.1.2.1.99`, RFC 3433)

The vendor-neutral way to read temp/voltage/fan/current. Indexed by
**entPhysicalIndex** (join to ENTITY-MIB for the sensor's name/location).

| Metric | Column OID | Type | Notes |
|---|---|---|---|
| entPhySensorType | `1.3.6.1.2.1.99.1.1.1.1` | enum | celsius/voltsAC/rpm/… |
| entPhySensorScale | `1.3.6.1.2.1.99.1.1.1.2` | enum | milli/units/kilo… |
| entPhySensorPrecision | `1.3.6.1.2.1.99.1.1.1.3` | gauge | decimal places |
| **entPhySensorValue** | `1.3.6.1.2.1.99.1.1.1.4` | gauge | **the reading** (interpret with type+scale+precision) |
| entPhySensorOperStatus | `1.3.6.1.2.1.99.1.1.1.5` | enum | ok/unavailable/nonoperational |

> Arista, Juniper, and modern Cisco/Nexus expose temp/fan/PSU primarily through
> this table — prefer it when present; it avoids per-vendor leaf hunting.

## 1.5 HOST-RESOURCES-MIB — CPU / storage / processes (`1.3.6.1.2.1.25`, RFC 2790)

Best on servers/hosts (net-snmp, Windows), and many appliances expose it too.

| Metric | OID | Type | Unit |
|---|---|---|---|
| hrSystemUptime | `1.3.6.1.2.1.25.1.1.0` | gauge | timeticks |
| hrSystemNumUsers | `1.3.6.1.2.1.25.1.5.0` | gauge | count |
| hrSystemProcesses | `1.3.6.1.2.1.25.1.6.0` | gauge | count |
| hrMemorySize | `1.3.6.1.2.1.25.2.2.0` | gauge | KBytes (total RAM) |
| **hrProcessorLoad** | `1.3.6.1.2.1.25.3.3.1.2` | gauge | % per-core (walk → average) |
| hrStorageType | `1.3.6.1.2.1.25.2.3.1.2` | oid | RAM/fixed-disk/virtual-mem selector |
| hrStorageDescr | `1.3.6.1.2.1.25.2.3.1.3` | string | mount/volume name |
| hrStorageAllocationUnits | `1.3.6.1.2.1.25.2.3.1.4` | gauge | bytes/unit |
| hrStorageSize | `1.3.6.1.2.1.25.2.3.1.5` | gauge | units (× alloc = total) |
| hrStorageUsed | `1.3.6.1.2.1.25.2.3.1.6` | gauge | units (× alloc = used) |

> **Printers** also implement `hrPrinterStatus` (`1.3.6.1.2.1.25.3.5.1.1`) and
> `hrDeviceStatus` (`1.3.6.1.2.1.25.3.2.1.5`) from this MIB — see §7.

## 1.6 IP-MIB — L3 stats (`1.3.6.1.2.1.4`, RFC 4293)

| Metric | OID | Type |
|---|---|---|
| ipForwarding | `1.3.6.1.2.1.4.1.0` | enum (forwarding/not) |
| ipInReceives | `1.3.6.1.2.1.4.3.0` | counter32 |
| ipInHdrErrors | `1.3.6.1.2.1.4.4.0` | counter32 |
| ipInAddrErrors | `1.3.6.1.2.1.4.5.0` | counter32 |
| ipInDiscards | `1.3.6.1.2.1.4.8.0` | counter32 |
| ipOutDiscards | `1.3.6.1.2.1.4.11.0` | counter32 |
| ipReasmFails | `1.3.6.1.2.1.4.16.0` | counter32 |
| ipFragFails | `1.3.6.1.2.1.4.18.0` | counter32 |

(The newer `ipSystemStatsTable` `1.3.6.1.2.1.4.31.1` carries v4+v6 HC equivalents
where supported.)

## 1.7 Optional-but-common standard MIBs

| MIB | Root | What it gives |
|---|---|---|
| TCP-MIB | `1.3.6.1.2.1.6` | tcpCurrEstab `.9.0`, tcpActiveOpens `.5.0`, tcpRetransSegs `.12.0` |
| UDP-MIB | `1.3.6.1.2.1.7` | udpInDatagrams, udpNoPorts |
| BGP4-MIB | `1.3.6.1.2.1.15` | bgpPeerState `.3.1.2`, bgpPeerAdminStatus — routers |
| LLDP-MIB | `1.0.8802.1.1.2` | lldpRemSysName — topology/neighbor discovery |
| DISMAN-PING-MIB | `1.3.6.1.2.1.80` | active reachability probes |

## 1.8 sysObjectID prefixes for vendor auto-detection

`sysObjectID` (`1.3.6.1.2.1.1.2.0`) returns an OID rooted in the vendor's
enterprise arc `1.3.6.1.4.1.<N>`. Match the **prefix** to identify the vendor;
the full value usually identifies the exact model.

| Vendor | Enterprise N | sysObjectID prefix | Confidence |
|---|---|---|---|
| Cisco | 9 | `1.3.6.1.4.1.9.1.<modelId>` (IOS/IOS-XE products under `.9.1`) | high |
| Cisco Nexus (NX-OS) | 9 | `1.3.6.1.4.1.9.12.3.1.3.<n>` (ciscoProducts under `.9.12.3`) | medium ⚠ exact model leaf varies |
| Juniper | 2636 | `1.3.6.1.4.1.2636.1.1.1.2.<n>` (jnxProductName arc) | high |
| Arista | 30065 | `1.3.6.1.4.1.30065.1.<n>` | high |
| Nokia (SR OS) | 6527 | `1.3.6.1.4.1.6527.1.3.<n>` (tmnxModelChassis arc) | medium ⚠ |
| Huawei | 2011 | `1.3.6.1.4.1.2011.2.<n>` | high |
| MikroTik | 14988 | `1.3.6.1.4.1.14988.1` | high |
| HPE/Aruba (ProCurve/ArubaOS-Switch) | 11 | `1.3.6.1.4.1.11.2.3.7.11.<n>` | high |
| Aruba (controllers/WLC, ex-Aruba Networks) | 14823 | `1.3.6.1.4.1.14823.1.<n>` | high |
| Palo Alto | 25461 | `1.3.6.1.4.1.25461.2.<modelId>` | high |
| Fortinet | 12356 | `1.3.6.1.4.1.12356.101.1.<n>` (FortiGate) | high |
| Check Point | 2620 | `1.3.6.1.4.1.2620.1.<n>` | high |
| Ubiquiti | 41112 | `1.3.6.1.4.1.41112.1.<n>` | high |
| Ruckus (CommScope) | 25053 | `1.3.6.1.4.1.25053.1.<n>` | high |
| Cisco Meraki | 29671 | `1.3.6.1.4.1.29671.1.<n>` | high |
| Polycom/Poly | 13885 | `1.3.6.1.4.1.13885.<n>` | medium ⚠ |
| AudioCodes | 5003 | `1.3.6.1.4.1.5003.<n>` | high |
| Ribbon/Sonus | 2879 | `1.3.6.1.4.1.2879.<n>` | medium ⚠ |
| Avaya | 6889 | `1.3.6.1.4.1.6889.<n>` | medium ⚠ |
| APC (UPS) | 318 | `1.3.6.1.4.1.318.1.3.<n>` | high |
| HP (printers) | 11 | `1.3.6.1.4.1.11.2.3.9.1` (jetdirect) | high |
| Xerox | 253 | `1.3.6.1.4.1.253.<n>` | high |
| Lexmark | 641 | `1.3.6.1.4.1.641.<n>` | high |
| Canon | 1602 | `1.3.6.1.4.1.1602.<n>` | high |

---

# 2. Routers / Switches

**Always poll the universal base (§1):** SNMPv2-MIB identity, IF-MIB ifTable +
ifXTable per interface, ENTITY-MIB inventory, ENTITY-SENSOR-MIB sensors, IP-MIB,
BGP4-MIB peer state. The vendor enterprise OIDs below add **CPU/memory** (which
HOST-RESOURCES often does *not* report meaningfully on network OSes) and
vendor-specific health.

## 2.1 Cisco — IOS / IOS-XE (enterprise `1.3.6.1.4.1.9`)

**CPU/Mem — CISCO-PROCESS-MIB** (`1.3.6.1.4.1.9.9.109`):

| Metric | OID (column, index = cpmCPUTotalIndex) | Type | Unit |
|---|---|---|---|
| cpmCPUTotal5secRev | `1.3.6.1.4.1.9.9.109.1.1.1.1.6` | gauge | % (5 s) |
| cpmCPUTotal1minRev | `1.3.6.1.4.1.9.9.109.1.1.1.1.7` | gauge | % (1 min) |
| **cpmCPUTotal5minRev** | `1.3.6.1.4.1.9.9.109.1.1.1.1.8` | gauge | % (5 min) ✅ verified |
| cpmCPUMemoryUsed | `1.3.6.1.4.1.9.9.109.1.1.1.1.12` | gauge | KB ✅ verified |
| cpmCPUMemoryFree | `1.3.6.1.4.1.9.9.109.1.1.1.1.13` | gauge | KB |

**Mem pools — CISCO-MEMORY-POOL-MIB** (`1.3.6.1.4.1.9.9.48`), idx = pool:

| Metric | OID | Type | Unit |
|---|---|---|---|
| ciscoMemoryPoolUsed | `1.3.6.1.4.1.9.9.48.1.1.1.5` | gauge | bytes |
| ciscoMemoryPoolFree | `1.3.6.1.4.1.9.9.48.1.1.1.6` | gauge | bytes |

**Environment — CISCO-ENVMON-MIB** (`1.3.6.1.4.1.9.9.13`):

| Metric | OID | Type | Notes |
|---|---|---|---|
| ciscoEnvMonTemperatureValue | `1.3.6.1.4.1.9.9.13.1.3.1.3` | gauge | °C |
| ciscoEnvMonTemperatureState | `1.3.6.1.4.1.9.9.13.1.3.1.6` | enum | normal/warning/critical/shutdown |
| ciscoEnvMonFanState | `1.3.6.1.4.1.9.9.13.1.4.1.3` | enum | fan health |
| ciscoEnvMonSupplyState | `1.3.6.1.4.1.9.9.13.1.5.1.3` | enum | PSU health |
| ciscoEnvMonSupplySource | `1.3.6.1.4.1.9.9.13.1.5.1.4` | enum | AC/DC |

## 2.2 Cisco — NX-OS (Nexus)

Nexus reports CPU/mem via **CISCO-SYSTEM-EXT-MIB** (`1.3.6.1.4.1.9.9.305`) and
temps via ENTITY-SENSOR-MIB (§1.4), not the IOS ENVMON MIB.

| Metric | OID | Type | Confidence |
|---|---|---|---|
| cseSysCPUUtilization | `1.3.6.1.4.1.9.9.305.1.1.1.0` | gauge % | medium ⚠ VERIFY leaf on target NX-OS rev |
| cseSysMemoryUtilization | `1.3.6.1.4.1.9.9.305.1.1.2.0` | gauge % | medium ⚠ VERIFY |
| temps/fans/PSU | ENTITY-SENSOR-MIB `1.3.6.1.2.1.99.1.1.1.4` | gauge | high (prefer this) |

> Newer IOS-XE also supports CISCO-PROCESS-MIB; CISCO-PROCESS-MIB remains the
> portable Cisco CPU source across IOS/IOS-XE.

## 2.3 Juniper — JUNOS (enterprise `1.3.6.1.4.1.2636`)

**JUNIPER-MIB jnxOperatingTable** (`1.3.6.1.4.1.2636.3.1.13.1.*`), indexed by the
operating entity (CPU/RE/FPC/PSU/fan):

| Metric | OID | Type | Unit | Confidence |
|---|---|---|---|---|
| jnxOperatingDescr | `1.3.6.1.4.1.2636.3.1.13.1.5` | string | entity name | high |
| jnxOperatingState | `1.3.6.1.4.1.2636.3.1.13.1.6` | enum | running/ok/failed… | high |
| **jnxOperatingTemp** | `1.3.6.1.4.1.2636.3.1.13.1.7` | gauge | °C | ✅ verified |
| **jnxOperatingCPU** | `1.3.6.1.4.1.2636.3.1.13.1.8` | gauge | % | ✅ verified |
| jnxOperatingBuffer | `1.3.6.1.4.1.2636.3.1.13.1.11` | gauge | % memory buffer util | high |
| jnxOperatingMemory | `1.3.6.1.4.1.2636.3.1.13.1.15` | gauge | MB installed (DRAM) | medium ⚠ |
| jnxOperating1MinLoadAvg | `1.3.6.1.4.1.2636.3.1.13.1.20` | gauge | load avg | medium ⚠ |

**JUNIPER-MIB jnxRedundancy / jnxBox**: serials via `jnxBoxSerialNo`
`1.3.6.1.4.1.2636.3.1.3.0`. Over-temp event `jnxOverTemperature`
`1.3.6.1.4.1.2636.4.1.3` (verified arc).

## 2.4 Arista — EOS (enterprise `1.3.6.1.4.1.30065`)

Arista's design intent: **use standard MIBs**. CPU/mem via HOST-RESOURCES-MIB
(§1.5: `hrProcessorLoad` `1.3.6.1.2.1.25.3.3.1.2`, hrStorage for RAM), temps/
fans/PSU via **ENTITY-SENSOR-MIB** (§1.4: `entPhySensorValue`
`1.3.6.1.2.1.99.1.1.1.4`) plus the **ARISTA-ENTITY-SENSOR-MIB**
(`1.3.6.1.4.1.30065.3.12`) which *augments* entPhySensorTable with thresholds.

| Metric | OID | Type | Confidence |
|---|---|---|---|
| CPU (per core, average it) | `1.3.6.1.2.1.25.3.3.1.2` (hrProcessorLoad) | gauge % | high |
| Memory total / used | `1.3.6.1.2.1.25.2.3.1.5` / `.6` (hrStorage, RAM row) | gauge units | high |
| Temp / fan / voltage | `1.3.6.1.2.1.99.1.1.1.4` (entPhySensorValue) | gauge | high |
| Sensor thresholds (low/high) | under `1.3.6.1.4.1.30065.3.12.*` | gauge | medium ⚠ exact leaf VERIFY |

## 2.5 Nokia — SR OS (enterprise `1.3.6.1.4.1.6527`)

CPU/mem in **TIMETRA-SYSTEM-MIB** (`...6527.3.1.2.1`), hardware temp in
**TIMETRA-CHASSIS-MIB** (`...6527.3.1.2.2`).

| Metric | OID | Type | Confidence |
|---|---|---|---|
| sgiCpuUsage (system CPU) | `1.3.6.1.4.1.6527.3.1.2.1.1.1.0` | gauge % | medium ⚠ VERIFY leaf against TIMETRA-SYSTEM-MIB |
| sgiMemoryUsed | `1.3.6.1.4.1.6527.3.1.2.1.1.2.0` | gauge bytes | medium ⚠ VERIFY |
| sgiMemoryAvailable | `1.3.6.1.4.1.6527.3.1.2.1.1.3.0` | gauge bytes | medium ⚠ VERIFY |
| tmnxHwTemperature | under `1.3.6.1.4.1.6527.3.1.2.2.1.x` (tmnxHwTable) | gauge °C | medium ⚠ VERIFY column |
| tmnxHwTempThreshold | tmnxHwTable | gauge °C | medium ⚠ |

> Nokia SR OS leaf indices vary by release; confirm against the exact
> TIMETRA-SYSTEM-MIB / TIMETRA-CHASSIS-MIB revision on the box. Enterprise root
> `6527` and module arcs are correct.

## 2.6 Huawei (enterprise `1.3.6.1.4.1.2011`)

**HUAWEI-ENTITY-EXTENT-MIB** `hwEntityStateTable` (`1.3.6.1.4.1.2011.5.25.31.1.1.1.1.*`),
indexed by entPhysicalIndex (join ENTITY-MIB):

| Metric | OID | Type | Unit | Confidence |
|---|---|---|---|---|
| **hwEntityCpuUsage** | `1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5` | gauge | % | ✅ verified |
| hwEntityMemUsage | `1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7` | gauge | % | high |
| **hwEntityTemperature** | `1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11` | gauge | °C | ✅ verified |
| hwEntityCpuFreq | `1.3.6.1.4.1.2011.5.25.31.1.1.1.1.2` | gauge | MHz | medium ⚠ |
| hwEntityMemSize | `1.3.6.1.4.1.2011.5.25.31.1.1.1.1.6` | gauge | bytes | medium ⚠ |

(Older Huawei/Quidway gear uses HUAWEI-MIB `hwAvgDuty5min` under `...2011.6.*` —
⚠ VERIFY per platform.)

## 2.7 MikroTik (enterprise `1.3.6.1.4.1.14988`)

CPU via standard `hrProcessorLoad`. Health via **MIKROTIK-MIB**
`mtxrHealthTable` (`1.3.6.1.4.1.14988.1.1.3.*`):

| Metric | OID | Type | Unit | Confidence |
|---|---|---|---|---|
| CPU load | `1.3.6.1.2.1.25.3.3.1.2` (hrProcessorLoad) | gauge | % | high |
| mtxrHlCoreVoltage | `1.3.6.1.4.1.14988.1.1.3.1.0` | gauge | V (÷10 or ÷100) | high |
| mtxrHlVoltage | `1.3.6.1.4.1.14988.1.1.3.8.0` | gauge | V (÷10) | medium ⚠ |
| **mtxrHlTemperature** | `1.3.6.1.4.1.14988.1.1.3.10.0` | gauge | °C (÷10) | ✅ verified |
| **mtxrHlProcessorTemperature** | `1.3.6.1.4.1.14988.1.1.3.11.0` | gauge | °C (÷10) | ✅ verified |
| mtxrHlPower | `1.3.6.1.4.1.14988.1.1.3.12.0` | gauge | W | medium ⚠ |
| mtxrHlActiveFan / fan speed | `1.3.6.1.4.1.14988.1.1.3.17.0` | gauge | RPM | medium ⚠ |

## 2.8 HPE / Aruba switching

- **ArubaOS-Switch / ProCurve** (enterprise `11`): CPU/mem are awkward — many
  models only expose **STATISTICS-MIB** `hpSwitchCpuStat` `1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0`
  (gauge %, ⚠ VERIFY per model) and memory via `1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7.1`
  (used) / `...6.1` (free) (⚠ VERIFY). Temp/fan/PSU via **HP-ICF-CHASSIS-MIB**
  `1.3.6.1.4.1.11.2.14.11.1.2.*` (⚠ VERIFY exact leaves).
- **Aruba CX (AOS-CX)**: prefers ENTITY-SENSOR-MIB (§1.4) + hrProcessorLoad.
  Use the standard base; vendor CPU leaf differs across CX revisions (⚠ VERIFY).

### Default profile — Routers / Switches (≈34 metrics)

| # | Metric | OID | Type | Unit | Interval |
|---|---|---|---|---|---|
| 1 | sysObjectID | 1.3.6.1.2.1.1.2.0 | oid | — | 24h |
| 2 | sysDescr | 1.3.6.1.2.1.1.1.0 | string | — | 24h |
| 3 | sysName | 1.3.6.1.2.1.1.5.0 | string | — | 24h |
| 4 | sysUpTime | 1.3.6.1.2.1.1.3.0 | gauge | ticks | 60s |
| 5 | ifOperStatus | 1.3.6.1.2.1.2.2.1.8 | enum | — | 60s |
| 6 | ifAdminStatus | 1.3.6.1.2.1.2.2.1.7 | enum | — | 60s |
| 7 | ifHCInOctets | 1.3.6.1.2.1.31.1.1.1.6 | counter64 | bytes | 60s |
| 8 | ifHCOutOctets | 1.3.6.1.2.1.31.1.1.1.10 | counter64 | bytes | 60s |
| 9 | ifHCInUcastPkts | 1.3.6.1.2.1.31.1.1.1.7 | counter64 | pkts | 60s |
| 10 | ifHCOutUcastPkts | 1.3.6.1.2.1.31.1.1.1.11 | counter64 | pkts | 60s |
| 11 | ifInErrors | 1.3.6.1.2.1.2.2.1.14 | counter32 | pkts | 60s |
| 12 | ifOutErrors | 1.3.6.1.2.1.2.2.1.20 | counter32 | pkts | 60s |
| 13 | ifInDiscards | 1.3.6.1.2.1.2.2.1.13 | counter32 | pkts | 60s |
| 14 | ifOutDiscards | 1.3.6.1.2.1.2.2.1.19 | counter32 | pkts | 60s |
| 15 | ifHighSpeed | 1.3.6.1.2.1.31.1.1.1.15 | gauge | Mbps | 24h |
| 16 | ifAlias | 1.3.6.1.2.1.31.1.1.1.18 | string | — | 24h |
| 17 | CPU 5min (Cisco) | 1.3.6.1.4.1.9.9.109.1.1.1.1.8 | gauge | % | 60s |
| 18 | CPU (Juniper) | 1.3.6.1.4.1.2636.3.1.13.1.8 | gauge | % | 60s |
| 19 | CPU (Arista/MikroTik/host) | 1.3.6.1.2.1.25.3.3.1.2 | gauge | % | 60s |
| 20 | CPU (Huawei) | 1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5 | gauge | % | 60s |
| 21 | Mem used (Cisco) | 1.3.6.1.4.1.9.9.48.1.1.1.5 | gauge | bytes | 60s |
| 22 | Mem free (Cisco) | 1.3.6.1.4.1.9.9.48.1.1.1.6 | gauge | bytes | 60s |
| 23 | Mem buffer% (Juniper) | 1.3.6.1.4.1.2636.3.1.13.1.11 | gauge | % | 60s |
| 24 | Mem total (host) | 1.3.6.1.2.1.25.2.2.0 | gauge | KB | 300s |
| 25 | Sensor value (generic) | 1.3.6.1.2.1.99.1.1.1.4 | gauge | per type | 300s |
| 26 | Temp (Cisco ENVMON) | 1.3.6.1.4.1.9.9.13.1.3.1.3 | gauge | °C | 300s |
| 27 | Temp state (Cisco) | 1.3.6.1.4.1.9.9.13.1.3.1.6 | enum | — | 300s |
| 28 | Fan state (Cisco) | 1.3.6.1.4.1.9.9.13.1.4.1.3 | enum | — | 300s |
| 29 | PSU state (Cisco) | 1.3.6.1.4.1.9.9.13.1.5.1.3 | enum | — | 300s |
| 30 | Temp (Juniper) | 1.3.6.1.4.1.2636.3.1.13.1.7 | gauge | °C | 300s |
| 31 | Temp (Huawei) | 1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11 | gauge | °C | 300s |
| 32 | entPhysicalSerialNum | 1.3.6.1.2.1.47.1.1.1.1.11 | string | — | 24h |
| 33 | bgpPeerState | 1.3.6.1.2.1.15.3.1.2 | enum | — | 60s |
| 34 | lldpRemSysName | 1.0.8802.1.1.2.1.4.1.1.9 | string | — | 300s |

---

# 3. Firewalls

Universal base applies (interfaces, identity, ENTITY). Firewall-specific value
is in **session/connection counts, throughput, HA state, and CPU/mem under DPI
load**.

## 3.1 Palo Alto — PAN-OS (enterprise `1.3.6.1.4.1.25461`)

**PAN-COMMON-MIB** (`...25461.2.1.2`):

| Metric | OID | Type | Unit | Confidence |
|---|---|---|---|---|
| panSysSwVersion | `1.3.6.1.4.1.25461.2.1.2.1.1.0` | string | — | ✅ verified |
| panSysHwVersion | `1.3.6.1.4.1.25461.2.1.2.1.2.0` | string | — | high |
| panSysSerialNumber | `1.3.6.1.4.1.25461.2.1.2.1.3.0` | string | — | high |
| panSysHAState | `1.3.6.1.4.1.25461.2.1.2.1.11.0` | enum | active/passive | medium ⚠ |
| **panSessionUtilization** | `1.3.6.1.4.1.25461.2.1.2.3.1.0` | gauge | % | ✅ verified |
| panSessionMax | `1.3.6.1.4.1.25461.2.1.2.3.2.0` | gauge | sessions | high |
| panSessionActive | `1.3.6.1.4.1.25461.2.1.2.3.3.0` | gauge | sessions | high |
| panSessionActiveTcp | `1.3.6.1.4.1.25461.2.1.2.3.4.0` | gauge | sessions | medium ⚠ |
| panSessionActiveUdp | `1.3.6.1.4.1.25461.2.1.2.3.5.0` | gauge | sessions | medium ⚠ |

> CPU/mem on PA: data-plane/management CPU is exposed via HOST-RESOURCES-MIB
> (`hrProcessorLoad`) and the per-DP counters via PAN's vendor MIB extensions —
> `hrProcessorLoad` is the reliable cross-model source.

## 3.2 Fortinet — FortiGate (enterprise `1.3.6.1.4.1.12356`)

**FORTINET-FORTIGATE-MIB** `fgSystemInfo` (`...12356.101.4.1`):

| Metric | OID | Type | Unit | Confidence |
|---|---|---|---|---|
| **fgSysCpuUsage** | `1.3.6.1.4.1.12356.101.4.1.3.0` | gauge | % | ✅ verified |
| **fgSysMemUsage** | `1.3.6.1.4.1.12356.101.4.1.4.0` | gauge | % | ✅ verified |
| fgSysMemCapacity | `1.3.6.1.4.1.12356.101.4.1.5.0` | gauge | KB | high |
| fgSysLowMemUsage | `1.3.6.1.4.1.12356.101.4.1.9.0` | gauge | % | ✅ verified (was `.6`; corrected) |
| fgSysDiskUsage | `1.3.6.1.4.1.12356.101.4.1.6.0`? | gauge | MB | ⚠ VERIFY leaf (disk leaf moved across FortiOS) |
| **fgSysSesCount** | `1.3.6.1.4.1.12356.101.4.1.8.0` | gauge | sessions | ✅ verified |
| fgSysSesRate1 | `1.3.6.1.4.1.12356.101.4.1.11.0` | gauge | sess/s | ✅ verified (was `.9` = fgSysLowMemUsage; corrected) |
| fgHaSystemMode | `1.3.6.1.4.1.12356.101.13.1.1.0` | enum | standalone/a-p/a-a | medium ⚠ |
| Per-CPU table | `fgProcessorTable` `1.3.6.1.4.1.12356.101.4.4` | gauge | % | medium ⚠ |

VPN tunnels: `fgVpnTunEntStatus` under `fgVpnTunTable`
`1.3.6.1.4.1.12356.101.12.2.2.1` (⚠ VERIFY leaf).

## 3.3 Cisco ASA / Firepower (enterprise `9`)

CPU/mem reuse **CISCO-PROCESS-MIB** / **CISCO-MEMORY-POOL-MIB** (§2.1).
Connections via **CISCO-FIREWALL-MIB** (`1.3.6.1.4.1.9.9.147`):

| Metric | OID | Type | Confidence |
|---|---|---|---|
| cfwConnectionStatValue (in-use / max) | `1.3.6.1.4.1.9.9.147.1.2.2.2.1.5` | gauge | high (index .40.6=in-use, .40.7=high) ⚠ verify index |
| cfwHardwareStatusValue | `1.3.6.1.4.1.9.9.147.1.2.1.1.1.3` | gauge/enum | high |
| cfwHardwareStatusDetail | `1.3.6.1.4.1.9.9.147.1.2.1.1.1.4` | string | medium ⚠ |
| ASA CPU 5min | `1.3.6.1.4.1.9.9.109.1.1.1.1.8` | gauge % | high |
| ASA mem used/free | `1.3.6.1.4.1.9.9.48.1.1.1.5` / `.6` | gauge bytes | high |

## 3.4 Check Point (enterprise `1.3.6.1.4.1.2620`)

**CHECKPOINT-MIB** (svnStat / fw arcs):

| Metric | OID | Type | Confidence |
|---|---|---|---|
| svnStatCPUTotalLoad / fwCPUUsage | `1.3.6.1.4.1.2620.1.6.7.2.4.0` | gauge % | medium ⚠ VERIFY (procUsage scalar) |
| memTotalReal / memActiveReal | `1.3.6.1.4.1.2620.1.6.7.4.x.0` | gauge bytes | medium ⚠ VERIFY |
| fwModuleState | `1.3.6.1.4.1.2620.1.1.1.0` | enum | medium ⚠ |
| fwNumConn (concurrent connections) | `1.3.6.1.4.1.2620.1.1.25.3.0` | gauge | medium ⚠ |
| fwAccepted / fwDropped / fwRejected | `1.3.6.1.4.1.2620.1.1.4/5/6.0` | counter | medium ⚠ |
| haState | `1.3.6.1.4.1.2620.1.5.6.0` | enum | medium ⚠ |

> Check Point splits across svnStat (OS/host) and fw (policy) arcs; exact scalar
> leaves shift between Gaia versions. Walk `1.3.6.1.4.1.2620` and pin per fleet.

## 3.5 Juniper SRX (enterprise `2636`)

Reuses JUNIPER-MIB jnxOperatingTable (§2.3) for CPU/temp. Flow/session stats via
**JUNIPER-SRX / jnxJsSPUMonitoringMIB** (`1.3.6.1.4.1.2636.3.39.1.12.1.1`):

| Metric | OID | Type | Confidence |
|---|---|---|---|
| jnxJsSPUMonitoringCurrentFlowSession | `1.3.6.1.4.1.2636.3.39.1.12.1.1.1.6` | gauge | medium ⚠ VERIFY |
| jnxJsSPUMonitoringMaxFlowSession | `1.3.6.1.4.1.2636.3.39.1.12.1.1.1.7` | gauge | medium ⚠ |
| jnxJsSPUMonitoringCPUUsage | `1.3.6.1.4.1.2636.3.39.1.12.1.1.1.4` | gauge % | medium ⚠ |

### Default profile — Firewalls (≈30 metrics)

| # | Metric | OID | Type | Unit | Interval |
|---|---|---|---|---|---|
| 1 | sysObjectID | 1.3.6.1.2.1.1.2.0 | oid | — | 24h |
| 2 | sysDescr | 1.3.6.1.2.1.1.1.0 | string | — | 24h |
| 3 | sysUpTime | 1.3.6.1.2.1.1.3.0 | gauge | ticks | 60s |
| 4 | ifHCInOctets | 1.3.6.1.2.1.31.1.1.1.6 | counter64 | bytes | 60s |
| 5 | ifHCOutOctets | 1.3.6.1.2.1.31.1.1.1.10 | counter64 | bytes | 60s |
| 6 | ifOperStatus | 1.3.6.1.2.1.2.2.1.8 | enum | — | 60s |
| 7 | ifInErrors | 1.3.6.1.2.1.2.2.1.14 | counter32 | pkts | 60s |
| 8 | ifOutErrors | 1.3.6.1.2.1.2.2.1.20 | counter32 | pkts | 60s |
| 9 | PAN session util | 1.3.6.1.4.1.25461.2.1.2.3.1.0 | gauge | % | 60s |
| 10 | PAN session active | 1.3.6.1.4.1.25461.2.1.2.3.3.0 | gauge | sess | 60s |
| 11 | PAN session max | 1.3.6.1.4.1.25461.2.1.2.3.2.0 | gauge | sess | 300s |
| 12 | PAN HA state | 1.3.6.1.4.1.25461.2.1.2.1.11.0 | enum | — | 60s |
| 13 | Forti CPU | 1.3.6.1.4.1.12356.101.4.1.3.0 | gauge | % | 60s |
| 14 | Forti mem | 1.3.6.1.4.1.12356.101.4.1.4.0 | gauge | % | 60s |
| 15 | Forti sessions | 1.3.6.1.4.1.12356.101.4.1.8.0 | gauge | sess | 60s |
| 16 | Forti session rate | 1.3.6.1.4.1.12356.101.4.1.11.0 | gauge | sess/s | 60s |
| 17 | Forti HA mode | 1.3.6.1.4.1.12356.101.13.1.1.0 | enum | — | 300s |
| 18 | ASA conns in-use | 1.3.6.1.4.1.9.9.147.1.2.2.2.1.5 | gauge | conns | 60s |
| 19 | ASA CPU 5min | 1.3.6.1.4.1.9.9.109.1.1.1.1.8 | gauge | % | 60s |
| 20 | ASA mem used | 1.3.6.1.4.1.9.9.48.1.1.1.5 | gauge | bytes | 60s |
| 21 | ASA mem free | 1.3.6.1.4.1.9.9.48.1.1.1.6 | gauge | bytes | 60s |
| 22 | ASA HW status | 1.3.6.1.4.1.9.9.147.1.2.1.1.1.3 | enum | — | 300s |
| 23 | CKP fw conns | 1.3.6.1.4.1.2620.1.1.25.3.0 | gauge | conns | 60s |
| 24 | CKP CPU | 1.3.6.1.4.1.2620.1.6.7.2.4.0 | gauge | % | 60s |
| 25 | CKP HA state | 1.3.6.1.4.1.2620.1.5.6.0 | enum | — | 60s |
| 26 | SRX cur sessions | 1.3.6.1.4.1.2636.3.39.1.12.1.1.1.6 | gauge | sess | 60s |
| 27 | SRX CPU (jnxOperating) | 1.3.6.1.4.1.2636.3.1.13.1.8 | gauge | % | 60s |
| 28 | Generic CPU (hrProcessorLoad) | 1.3.6.1.2.1.25.3.3.1.2 | gauge | % | 60s |
| 29 | tcpCurrEstab | 1.3.6.1.2.1.6.9.0 | gauge | conns | 60s |
| 30 | entPhysicalSerialNum | 1.3.6.1.2.1.47.1.1.1.1.11 | string | — | 24h |

---

# 4. Wireless — APs / Controllers

For controller-based fleets (Cisco WLC, Aruba), poll the **controller** and walk
per-AP/per-radio tables. For cloud-managed (Meraki) prefer the dashboard API;
SNMP is limited.

## 4.1 Cisco — AireOS WLC (enterprise `1.3.6.1.4.1.14179`)

**AIRESPACE-WIRELESS-MIB**:

| Metric | OID | Type | Confidence |
|---|---|---|---|
| bsnApIfNoOfUsers (clients per radio) | `1.3.6.1.4.1.14179.2.2.2.1.15` | gauge | ✅ verified |
| bsnAPIfLoadNumOfClients | `1.3.6.1.4.1.14179.2.2.13.1.4` | gauge | ✅ verified |
| bsnAPIfLoadChannelUtilization | `1.3.6.1.4.1.14179.2.2.13.1.3` | gauge % | high |
| bsnAPIfLoadRxUtilization | `1.3.6.1.4.1.14179.2.2.13.1.1` | gauge % | high |
| bsnAPIfLoadTxUtilization | `1.3.6.1.4.1.14179.2.2.13.1.2` | gauge % | high |
| bsnAPOperationStatus | `1.3.6.1.4.1.14179.2.2.1.1.6` | enum | medium ⚠ |
| bsnApIfPoorSNRClients | `1.3.6.1.4.1.14179.2.2.2.1.20` | gauge | medium ⚠ |

> Cisco 9800 (IOS-XE) controllers use **CISCO-LWAPP-*** MIBs instead of AireOS
> arcs; AireOS OIDs above do **not** apply to 9800 (⚠ different MIB tree).

## 4.2 Aruba — Mobility Controllers (enterprise `1.3.6.1.4.1.14823`)

**WLSX-SYSTEMEXT-MIB** (`...14823.2.2.1.2.1`) for controller health, **WLSX-WLAN-MIB**
for AP/client stats:

| Metric | OID | Type | Confidence |
|---|---|---|---|
| wlsxSysExtCpuUsedPercent | `1.3.6.1.4.1.14823.2.2.1.2.1.30` | gauge % | medium ⚠ VERIFY leaf (table column, may be `.31`) |
| wlsxSysExtMemoryUsedPercent | `1.3.6.1.4.1.14823.2.2.1.2.1.31` | gauge % | medium ⚠ VERIFY |
| wlsxSysExtPacketLossPercent | `1.3.6.1.4.1.14823.2.2.1.2.1.13` | gauge % | medium ⚠ |
| wlanAPNumClients (per AP) | under WLSX-WLAN-MIB `1.3.6.1.4.1.14823.2.2.1.5.2.1.4` | gauge | medium ⚠ VERIFY |
| total APs up / total clients | WLSX-SWITCH/WLAN totals | gauge | ⚠ VERIFY |

> Aruba's `wlsx*` leaf indices differ between ArubaOS 6.x and 8.x — pin against
> the controller's MIB before trusting the leaf numbers above.

## 4.3 Ubiquiti — UniFi (enterprise `1.3.6.1.4.1.41112`)

UniFi APs expose **UBNT-UniFi-MIB** plus standard MIBs.

| Metric | OID | Type | Confidence |
|---|---|---|---|
| unifiApSystemModel | `1.3.6.1.4.1.41112.1.6.1.2.1.5` | string | medium ⚠ |
| unifiVapNumStations (clients/VAP) | `1.3.6.1.4.1.41112.1.6.1.2.1.8` | gauge | medium ⚠ VERIFY |
| unifiRadioCuTotal (channel util) | `1.3.6.1.4.1.41112.1.6.1.2.1.x` | gauge % | ⚠ VERIFY |
| CPU/mem | hrProcessorLoad / hrStorage (§1.5) | gauge | high |

## 4.4 Ruckus (enterprise `1.3.6.1.4.1.25053`)

Standalone/ZoneDirector use **RUCKUS-ZD-WLAN-MIB**; SmartZone uses the SmartZone
MIB set. Common: per-AP client counts, channel utilization, AP up/down.

| Metric | OID | Type | Confidence |
|---|---|---|---|
| ruckusZDWLANAPNumSta (clients) | under `1.3.6.1.4.1.25053.1.2.2.1.1.15.x` | gauge | ⚠ VERIFY — Ruckus arcs vary widely by product/version |
| AP CPU / mem | vendor table | gauge | ⚠ VERIFY |

## 4.5 Cisco Meraki (enterprise `1.3.6.1.4.1.29671`)

Meraki SNMP is limited (device list + interface counters via cloud SNMP). For
client counts / channel util **use the Meraki Dashboard API**, not SNMP. SNMP
exposes: `devStatus`, `devClientCount`, `devInterfaceSentPkts` under
`1.3.6.1.4.1.29671.1.1.4.1.*` (⚠ VERIFY leaves; cloud-SNMP only).

### Default profile — Wireless (≈30 metrics)

| # | Metric | OID | Type | Unit | Interval |
|---|---|---|---|---|---|
| 1 | sysObjectID | 1.3.6.1.2.1.1.2.0 | oid | — | 24h |
| 2 | sysUpTime | 1.3.6.1.2.1.1.3.0 | gauge | ticks | 60s |
| 3 | ifHCInOctets | 1.3.6.1.2.1.31.1.1.1.6 | counter64 | bytes | 60s |
| 4 | ifHCOutOctets | 1.3.6.1.2.1.31.1.1.1.10 | counter64 | bytes | 60s |
| 5 | ifOperStatus | 1.3.6.1.2.1.2.2.1.8 | enum | — | 60s |
| 6 | Controller CPU (hrProcessorLoad) | 1.3.6.1.2.1.25.3.3.1.2 | gauge | % | 60s |
| 7 | Cisco WLC clients/radio | 1.3.6.1.4.1.14179.2.2.13.1.4 | gauge | clients | 60s |
| 8 | Cisco WLC chan util | 1.3.6.1.4.1.14179.2.2.13.1.3 | gauge | % | 60s |
| 9 | Cisco WLC rx util | 1.3.6.1.4.1.14179.2.2.13.1.1 | gauge | % | 60s |
| 10 | Cisco WLC tx util | 1.3.6.1.4.1.14179.2.2.13.1.2 | gauge | % | 60s |
| 11 | Cisco AP oper status | 1.3.6.1.4.1.14179.2.2.1.1.6 | enum | — | 60s |
| 12 | Cisco AP users/radio | 1.3.6.1.4.1.14179.2.2.2.1.15 | gauge | users | 60s |
| 13 | Aruba ctrl CPU | 1.3.6.1.4.1.14823.2.2.1.2.1.30 | gauge | % | 60s |
| 14 | Aruba ctrl mem | 1.3.6.1.4.1.14823.2.2.1.2.1.31 | gauge | % | 60s |
| 15 | Aruba AP clients | 1.3.6.1.4.1.14823.2.2.1.5.2.1.4 | gauge | clients | 60s |
| 16 | UniFi VAP stations | 1.3.6.1.4.1.41112.1.6.1.2.1.8 | gauge | clients | 60s |
| 17 | UniFi AP CPU | 1.3.6.1.2.1.25.3.3.1.2 | gauge | % | 60s |
| 18 | Ruckus AP clients | 1.3.6.1.4.1.25053.1.2.2.1.1.15 | gauge | clients | 60s |
| 19 | Meraki client count | 1.3.6.1.4.1.29671.1.1.4.1.5 | gauge | clients | 300s |
| 20 | AP temp (entPhySensor) | 1.3.6.1.2.1.99.1.1.1.4 | gauge | °C | 300s |
| 21 | ifInErrors | 1.3.6.1.2.1.2.2.1.14 | counter32 | pkts | 60s |
| 22 | ifOutErrors | 1.3.6.1.2.1.2.2.1.20 | counter32 | pkts | 60s |
| 23 | entPhysicalSerialNum | 1.3.6.1.2.1.47.1.1.1.1.11 | string | — | 24h |
| 24 | sysName | 1.3.6.1.2.1.1.5.0 | string | — | 24h |

> Items 13–19 are `⚠ VERIFY` (vendor leaf indices vary by OS version). Activate
> only the subset matching the discovered vendor (via sysObjectID, §1.8).

---

# 5. VoIP Phones / SBCs

IP phones are thin SNMP citizens (often just system + IF-MIB). SBCs (AudioCodes,
Ribbon) and call agents (CUCM, Avaya CM) carry richer call-quality MIBs.

## 5.1 Cisco VoIP / SBC

- **IP phones**: typically only SNMPv2-MIB + IF-MIB. Registration/quality comes
  from CUCM (CISCO-CCM-MIB `1.3.6.1.4.1.9.9.156`: `ccmRegisteredPhones`
  `...156.1.5.4.0`, `ccmActivePhones` ⚠ VERIFY) — not the phone.
- **Cisco CUBE/SBC**: dial-peer + call-leg counters via CISCO-VOICE-DIAL-CONTROL-MIB
  (`1.3.6.1.4.1.9.9.63`) and DSP via CISCO-DSP-MGMT-MIB (⚠ VERIFY leaves).

## 5.2 Polycom / Poly (enterprise `1.3.6.1.4.1.13885`)

Poly phones/endpoints expose POLYCOM-* MIBs; useful objects are call status and
registration under `...13885.*` (⚠ VERIFY — varies widely VVX vs Trio vs
RealPresence; pin per model). Use IF-MIB + sysUpTime as the reliable base.

## 5.3 Avaya (enterprise `1.3.6.1.4.1.6889`)

Avaya CM / G-series gateways expose G3-AVAYA / CM MIBs (`...6889.*`). DSP
resource and trunk usage are model-specific (⚠ VERIFY). Reliable base = IF-MIB +
ENTITY-MIB + sysUpTime.

## 5.4 Ribbon (Sonus, ent. `2879`) / AudioCodes (ent. `5003`)

- **AudioCodes** SBC/GW: **AcGateway / AcPerf MIBs** under `1.3.6.1.4.1.5003.*`.
  Useful: active calls, call attempt/success counters, DSP utilization, IP-group
  stats (⚠ VERIFY exact leaves against AudioCodes' SNMP reference for the running
  firmware). System health via **acSysStateMIB** (`...5003.9.10.10`) ⚠ VERIFY.
- **Ribbon/Sonus** SBC: SONUS-* MIBs under `1.3.6.1.4.1.2879.*` (call counts,
  channel usage). ⚠ VERIFY leaves per SBC product line.

### Default profile — VoIP / SBC (≈18 metrics; base-heavy, vendor counters flagged)

| # | Metric | OID | Type | Unit | Interval |
|---|---|---|---|---|---|
| 1 | sysObjectID | 1.3.6.1.2.1.1.2.0 | oid | — | 24h |
| 2 | sysDescr | 1.3.6.1.2.1.1.1.0 | string | — | 24h |
| 3 | sysUpTime | 1.3.6.1.2.1.1.3.0 | gauge | ticks | 60s |
| 4 | sysName | 1.3.6.1.2.1.1.5.0 | string | — | 24h |
| 5 | ifOperStatus | 1.3.6.1.2.1.2.2.1.8 | enum | — | 60s |
| 6 | ifHCInOctets | 1.3.6.1.2.1.31.1.1.1.6 | counter64 | bytes | 60s |
| 7 | ifHCOutOctets | 1.3.6.1.2.1.31.1.1.1.10 | counter64 | bytes | 60s |
| 8 | ifInErrors | 1.3.6.1.2.1.2.2.1.14 | counter32 | pkts | 60s |
| 9 | ifOutErrors | 1.3.6.1.2.1.2.2.1.20 | counter32 | pkts | 60s |
| 10 | Generic CPU (hrProcessorLoad) | 1.3.6.1.2.1.25.3.3.1.2 | gauge | % | 60s |
| 11 | Mem total | 1.3.6.1.2.1.25.2.2.0 | gauge | KB | 300s |
| 12 | CUCM registered phones | 1.3.6.1.4.1.9.9.156.1.5.4.0 | gauge | phones | 60s ⚠ |
| 13 | CUBE active calls (voice dial ctrl) | 1.3.6.1.4.1.9.9.63.* | gauge | calls | 60s ⚠ |
| 14 | AudioCodes active calls | 1.3.6.1.4.1.5003.* | gauge | calls | 60s ⚠ |
| 15 | AudioCodes sys state | 1.3.6.1.4.1.5003.9.10.10.* | enum | — | 60s ⚠ |
| 16 | Ribbon active channels | 1.3.6.1.4.1.2879.* | gauge | ch | 60s ⚠ |
| 17 | entPhysicalSerialNum | 1.3.6.1.2.1.47.1.1.1.1.11 | string | — | 24h |
| 18 | Temp (entPhySensorValue) | 1.3.6.1.2.1.99.1.1.1.4 | gauge | °C | 300s |

> Items 12–16 are vendor/firmware-specific `⚠ VERIFY` — confirm exact leaves
> against the vendor MIB for the running release before enabling.

---

# 6. Printers — Printer-MIB (RFC 3805) + vendor

The **Printer-MIB** (`1.3.6.1.2.1.43`) is broadly implemented; most needs are met
by it plus HOST-RESOURCES `hrPrinterStatus`. Vendor MIBs add lifetime page counts
and per-supply detail when the standard supplies table is incomplete.

## 6.1 Standard Printer-MIB (RFC 3805) + HOST-RESOURCES-MIB

| Metric | OID | Type | Notes |
|---|---|---|---|
| hrDeviceStatus | `1.3.6.1.2.1.25.3.2.1.5` | enum | running/warning/down |
| hrPrinterStatus | `1.3.6.1.2.1.25.3.5.1.1` | enum | idle/printing/warmup |
| hrPrinterDetectedErrorState | `1.3.6.1.2.1.25.3.5.1.2` | bits | jam/noPaper/lowToner/doorOpen |
| prtGeneralServiceCount | `1.3.6.1.2.1.43.5.1.1.17` | counter32 | — |
| **prtMarkerLifeCount** | `1.3.6.1.2.1.43.10.2.1.4` | counter32 | total pages (idx 1.1) |
| prtMarkerCounterUnit | `1.3.6.1.2.1.43.10.2.1.3` | enum | impressions/sheets |
| prtInputCurrentLevel (tray) | `1.3.6.1.2.1.43.8.2.1.10` | gauge | sheets remaining |
| prtInputMaxCapacity | `1.3.6.1.2.1.43.8.2.1.9` | gauge | sheets |
| prtMarkerSuppliesDescription | `1.3.6.1.2.1.43.11.1.1.6` | string | "Black Toner" etc |
| **prtMarkerSuppliesLevel** | `1.3.6.1.2.1.43.11.1.1.9` | gauge | current level (−2=unknown, −3=remaining-unknown) |
| prtMarkerSuppliesMaxCapacity | `1.3.6.1.2.1.43.11.1.1.8` | gauge | max (compute %=level/max) |
| prtMarkerSuppliesType | `1.3.6.1.2.1.43.11.1.1.5` | enum | toner/ink/wasteToner/drum |
| prtConsoleDisplayBufferText | `1.3.6.1.2.1.43.16.5.1.2` | string | front-panel message |
| prtAlertDescription | `1.3.6.1.2.1.43.18.1.1.8` | string | active alert text |

> **Supply %** = `prtMarkerSuppliesLevel / prtMarkerSuppliesMaxCapacity × 100`,
> guarding for negative sentinel values (−1 other, −2 unknown, −3 some-remaining).

## 6.2 HP (enterprise `11`, JetDirect)

Standard Printer-MIB covers HP well. HP adds page-count detail under
**HP** `1.3.6.1.4.1.11.2.3.9.4.2.1.*` and total engine page count at
`1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.2.5.0` (⚠ VERIFY per model; prefer
prtMarkerLifeCount).

## 6.3 Xerox (`253`), Lexmark (`641`), Canon (`1602`)

All three implement Printer-MIB; vendor arcs add serial/consumable detail
(Xerox `...253.8.*`, Lexmark `...641.2.*`, Canon `...1602.*`) — ⚠ VERIFY exact
leaves per model. Default to the standard Printer-MIB tables above.

### Default profile — Printers (≈16 metrics)

| # | Metric | OID | Type | Unit | Interval |
|---|---|---|---|---|---|
| 1 | sysObjectID | 1.3.6.1.2.1.1.2.0 | oid | — | 24h |
| 2 | sysDescr | 1.3.6.1.2.1.1.1.0 | string | — | 24h |
| 3 | sysUpTime | 1.3.6.1.2.1.1.3.0 | gauge | ticks | 300s |
| 4 | hrDeviceStatus | 1.3.6.1.2.1.25.3.2.1.5 | enum | — | 300s |
| 5 | hrPrinterStatus | 1.3.6.1.2.1.25.3.5.1.1 | enum | — | 300s |
| 6 | hrPrinterDetectedErrorState | 1.3.6.1.2.1.25.3.5.1.2 | bits | — | 300s |
| 7 | prtMarkerLifeCount | 1.3.6.1.2.1.43.10.2.1.4 | counter32 | pages | 300s |
| 8 | prtMarkerSuppliesLevel | 1.3.6.1.2.1.43.11.1.1.9 | gauge | units | 300s |
| 9 | prtMarkerSuppliesMaxCapacity | 1.3.6.1.2.1.43.11.1.1.8 | gauge | units | 24h |
| 10 | prtMarkerSuppliesDescription | 1.3.6.1.2.1.43.11.1.1.6 | string | — | 24h |
| 11 | prtMarkerSuppliesType | 1.3.6.1.2.1.43.11.1.1.5 | enum | — | 24h |
| 12 | prtInputCurrentLevel | 1.3.6.1.2.1.43.8.2.1.10 | gauge | sheets | 300s |
| 13 | prtInputMaxCapacity | 1.3.6.1.2.1.43.8.2.1.9 | gauge | sheets | 24h |
| 14 | prtConsoleDisplayBufferText | 1.3.6.1.2.1.43.16.5.1.2 | string | — | 300s |
| 15 | prtAlertDescription | 1.3.6.1.2.1.43.18.1.1.8 | string | — | 300s |
| 16 | ifHCInOctets (mgmt NIC) | 1.3.6.1.2.1.31.1.1.1.6 | counter64 | bytes | 300s |

---

# 7. IoT / Environmental / UPS

## 7.1 UPS-MIB (RFC 1628, `1.3.6.1.2.1.33`) — all verified vs the RFC

| Metric | OID | Type | Unit |
|---|---|---|---|
| upsIdentManufacturer | `1.3.6.1.2.1.33.1.1.1.0` | string | — |
| upsIdentModel | `1.3.6.1.2.1.33.1.1.2.0` | string | — |
| **upsBatteryStatus** | `1.3.6.1.2.1.33.1.2.1.0` | enum | unknown/normal/low/depleted |
| upsSecondsOnBattery | `1.3.6.1.2.1.33.1.2.2.0` | gauge | seconds |
| **upsEstimatedMinutesRemaining** | `1.3.6.1.2.1.33.1.2.3.0` | gauge | minutes |
| upsEstimatedChargeRemaining | `1.3.6.1.2.1.33.1.2.4.0` | gauge | % |
| upsBatteryVoltage | `1.3.6.1.2.1.33.1.2.5.0` | gauge | 0.1 V DC |
| upsBatteryTemperature | `1.3.6.1.2.1.33.1.2.7.0` | gauge | °C |
| upsInputFrequency | `1.3.6.1.2.1.33.1.3.1.2` | gauge | 0.1 Hz (per line) |
| upsInputVoltage | `1.3.6.1.2.1.33.1.3.1.3` | gauge | V RMS (per line) |
| upsOutputSource | `1.3.6.1.2.1.33.1.4.1.0` | enum | normal/battery/bypass/booster |
| upsOutputFrequency | `1.3.6.1.2.1.33.1.4.2.0` | gauge | 0.1 Hz |
| upsOutputVoltage | `1.3.6.1.2.1.33.1.4.4.1.2` | gauge | V RMS (per line) |
| upsOutputCurrent | `1.3.6.1.2.1.33.1.4.4.1.3` | gauge | 0.1 A (per line) |
| upsOutputPower | `1.3.6.1.2.1.33.1.4.4.1.4` | gauge | Watts (per line) |
| **upsOutputPercentLoad** | `1.3.6.1.2.1.33.1.4.4.1.5` | gauge | % (per line) |
| upsAlarmsPresent | `1.3.6.1.2.1.33.1.6.1.0` | gauge | active alarm count |

## 7.2 APC (PowerNet-MIB, enterprise `318`)

APC predates/extends RFC 1628 with **PowerNet-MIB** (`1.3.6.1.4.1.318`):

| Metric | OID | Type | Confidence |
|---|---|---|---|
| upsAdvBatteryCapacity | `1.3.6.1.4.1.318.1.1.1.2.2.1.0` | gauge % | high |
| upsAdvBatteryRunTimeRemaining | `1.3.6.1.4.1.318.1.1.1.2.2.3.0` | gauge timeticks | high |
| upsAdvBatteryTemperature | `1.3.6.1.4.1.318.1.1.1.2.2.2.0` | gauge °C | high |
| upsAdvInputLineVoltage | `1.3.6.1.4.1.318.1.1.1.3.2.1.0` | gauge V | high |
| upsAdvOutputLoad | `1.3.6.1.4.1.318.1.1.1.4.2.3.0` | gauge % | high |
| upsAdvOutputVoltage | `1.3.6.1.4.1.318.1.1.1.4.2.1.0` | gauge V | high |
| upsBasicOutputStatus | `1.3.6.1.4.1.318.1.1.1.4.1.1.0` | enum | high |

## 7.3 Environmental sensors

- Generic appliance sensors: **ENTITY-SENSOR-MIB** `entPhySensorValue`
  `1.3.6.1.2.1.99.1.1.1.4` (§1.4) with `entPhySensorType` to know units.
- APC NetBotz / environmental monitor: PowerNet-MIB `...318.1.1.10.*`
  (temp/humidity probes) ⚠ VERIFY per probe model.
- Many IoT sensor gateways expose nothing beyond SNMPv2-MIB + a vendor scalar —
  treat sysObjectID-keyed vendor leaves as `⚠ VERIFY` per device.

### Default profile — UPS / Environmental (≈18 metrics)

| # | Metric | OID | Type | Unit | Interval |
|---|---|---|---|---|---|
| 1 | upsIdentModel | 1.3.6.1.2.1.33.1.1.2.0 | string | — | 24h |
| 2 | upsBatteryStatus | 1.3.6.1.2.1.33.1.2.1.0 | enum | — | 60s |
| 3 | upsSecondsOnBattery | 1.3.6.1.2.1.33.1.2.2.0 | gauge | s | 60s |
| 4 | upsEstMinutesRemaining | 1.3.6.1.2.1.33.1.2.3.0 | gauge | min | 60s |
| 5 | upsEstChargeRemaining | 1.3.6.1.2.1.33.1.2.4.0 | gauge | % | 60s |
| 6 | upsBatteryVoltage | 1.3.6.1.2.1.33.1.2.5.0 | gauge | 0.1V | 60s |
| 7 | upsBatteryTemperature | 1.3.6.1.2.1.33.1.2.7.0 | gauge | °C | 300s |
| 8 | upsInputVoltage | 1.3.6.1.2.1.33.1.3.1.3 | gauge | V | 60s |
| 9 | upsInputFrequency | 1.3.6.1.2.1.33.1.3.1.2 | gauge | 0.1Hz | 60s |
| 10 | upsOutputSource | 1.3.6.1.2.1.33.1.4.1.0 | enum | — | 60s |
| 11 | upsOutputVoltage | 1.3.6.1.2.1.33.1.4.4.1.2 | gauge | V | 60s |
| 12 | upsOutputCurrent | 1.3.6.1.2.1.33.1.4.4.1.3 | gauge | 0.1A | 60s |
| 13 | upsOutputPower | 1.3.6.1.2.1.33.1.4.4.1.4 | gauge | W | 60s |
| 14 | upsOutputPercentLoad | 1.3.6.1.2.1.33.1.4.4.1.5 | gauge | % | 60s |
| 15 | upsAlarmsPresent | 1.3.6.1.2.1.33.1.6.1.0 | gauge | count | 60s |
| 16 | APC battery capacity | 1.3.6.1.4.1.318.1.1.1.2.2.1.0 | gauge | % | 60s |
| 17 | APC output load | 1.3.6.1.4.1.318.1.1.1.4.2.3.0 | gauge | % | 60s |
| 18 | Env sensor value | 1.3.6.1.2.1.99.1.1.1.4 | gauge | per type | 300s |

---

# 8. Servers / Hosts (net-snmp, Windows)

Primary source is **HOST-RESOURCES-MIB** (§1.5) plus **net-snmp UCD-SNMP-MIB**
(`1.3.6.1.4.1.2021`) on Linux/Unix.

## 8.1 HOST-RESOURCES-MIB (RFC 2790) — universal

CPU = average of `hrProcessorLoad` `1.3.6.1.2.1.25.3.3.1.2`; memory + disks from
`hrStorageTable` (filter by `hrStorageType`: RAM `...25.2.1.2`, fixed disk
`...25.2.1.4`, virtual memory `...25.2.1.3`).

## 8.2 net-snmp UCD-SNMP-MIB (enterprise `2021`) — Linux/Unix, verified arcs

| Metric | OID | Type | Unit |
|---|---|---|---|
| ssCpuIdle | `1.3.6.1.4.1.2021.11.11.0` | gauge | % (100−idle = busy) |
| ssCpuRawUser | `1.3.6.1.4.1.2021.11.50.0` | counter | ticks |
| ssCpuRawSystem | `1.3.6.1.4.1.2021.11.52.0` | counter | ticks |
| ssCpuRawIdle | `1.3.6.1.4.1.2021.11.53.0` | counter | ticks |
| laLoad (1/5/15-min) | `1.3.6.1.4.1.2021.10.1.3.1/2/3` | gauge | load avg |
| memTotalReal | `1.3.6.1.4.1.2021.4.5.0` | gauge | KB |
| memAvailReal | `1.3.6.1.4.1.2021.4.6.0` | gauge | KB |
| memTotalSwap | `1.3.6.1.4.1.2021.4.3.0` | gauge | KB |
| memAvailSwap | `1.3.6.1.4.1.2021.4.4.0` | gauge | KB |
| memBuffer | `1.3.6.1.4.1.2021.4.14.0` | gauge | KB |
| memCached | `1.3.6.1.4.1.2021.4.15.0` | gauge | KB |
| dskPercent (per mount) | `1.3.6.1.4.1.2021.9.1.9` | gauge | % |
| dskTotal / dskUsed / dskAvail | `1.3.6.1.4.1.2021.9.1.6/8/7` | gauge | KB |

> Windows hosts: standard SNMP service exposes HOST-RESOURCES-MIB +
> LANMGR-MIB-II; richer CPU/mem typically comes from WMI/Telegraf, not SNMP.

### Default profile — Servers / Hosts (≈22 metrics)

| # | Metric | OID | Type | Unit | Interval |
|---|---|---|---|---|---|
| 1 | sysObjectID | 1.3.6.1.2.1.1.2.0 | oid | — | 24h |
| 2 | sysDescr | 1.3.6.1.2.1.1.1.0 | string | — | 24h |
| 3 | sysUpTime | 1.3.6.1.2.1.1.3.0 | gauge | ticks | 60s |
| 4 | hrProcessorLoad (avg) | 1.3.6.1.2.1.25.3.3.1.2 | gauge | % | 60s |
| 5 | ssCpuIdle | 1.3.6.1.4.1.2021.11.11.0 | gauge | % | 60s |
| 6 | laLoad 1min | 1.3.6.1.4.1.2021.10.1.3.1 | gauge | load | 60s |
| 7 | laLoad 5min | 1.3.6.1.4.1.2021.10.1.3.2 | gauge | load | 60s |
| 8 | memTotalReal | 1.3.6.1.4.1.2021.4.5.0 | gauge | KB | 300s |
| 9 | memAvailReal | 1.3.6.1.4.1.2021.4.6.0 | gauge | KB | 60s |
| 10 | memTotalSwap | 1.3.6.1.4.1.2021.4.3.0 | gauge | KB | 300s |
| 11 | memAvailSwap | 1.3.6.1.4.1.2021.4.4.0 | gauge | KB | 60s |
| 12 | memCached | 1.3.6.1.4.1.2021.4.15.0 | gauge | KB | 60s |
| 13 | hrStorageUsed (per fs) | 1.3.6.1.2.1.25.2.3.1.6 | gauge | units | 300s |
| 14 | hrStorageSize (per fs) | 1.3.6.1.2.1.25.2.3.1.5 | gauge | units | 300s |
| 15 | dskPercent | 1.3.6.1.4.1.2021.9.1.9 | gauge | % | 300s |
| 16 | hrSystemProcesses | 1.3.6.1.2.1.25.1.6.0 | gauge | count | 60s |
| 17 | hrSystemNumUsers | 1.3.6.1.2.1.25.1.5.0 | gauge | count | 300s |
| 18 | ifHCInOctets | 1.3.6.1.2.1.31.1.1.1.6 | counter64 | bytes | 60s |
| 19 | ifHCOutOctets | 1.3.6.1.2.1.31.1.1.1.10 | counter64 | bytes | 60s |
| 20 | tcpCurrEstab | 1.3.6.1.2.1.6.9.0 | gauge | conns | 60s |
| 21 | ipInReceives | 1.3.6.1.2.1.4.3.0 | counter32 | pkts | 60s |
| 22 | hrSystemUptime | 1.3.6.1.2.1.25.1.1.0 | gauge | ticks | 60s |

---

# 9. JSON skeleton for the profile manager

Importable shape: `vendor -> { sysobjectid_prefix, metrics: [{name, oid, type, unit}] }`.
Tabular OIDs are **column** OIDs (the manager appends the walked row index).
`⚠`-flagged OIDs from the sections above are intentionally **omitted** here so the
skeleton is safe to import as-is; add them per-fleet after verification.

```json
{
  "_universal_if_mib": {
    "sysobjectid_prefix": "*",
    "metrics": [
      {"name": "sysObjectID", "oid": "1.3.6.1.2.1.1.2.0", "type": "oid", "unit": ""},
      {"name": "sysDescr", "oid": "1.3.6.1.2.1.1.1.0", "type": "string", "unit": ""},
      {"name": "sysName", "oid": "1.3.6.1.2.1.1.5.0", "type": "string", "unit": ""},
      {"name": "sysUpTime", "oid": "1.3.6.1.2.1.1.3.0", "type": "gauge", "unit": "timeticks"},
      {"name": "ifOperStatus", "oid": "1.3.6.1.2.1.2.2.1.8", "type": "enum", "unit": ""},
      {"name": "ifAdminStatus", "oid": "1.3.6.1.2.1.2.2.1.7", "type": "enum", "unit": ""},
      {"name": "ifHCInOctets", "oid": "1.3.6.1.2.1.31.1.1.1.6", "type": "counter", "unit": "bytes"},
      {"name": "ifHCOutOctets", "oid": "1.3.6.1.2.1.31.1.1.1.10", "type": "counter", "unit": "bytes"},
      {"name": "ifHCInUcastPkts", "oid": "1.3.6.1.2.1.31.1.1.1.7", "type": "counter", "unit": "packets"},
      {"name": "ifHCOutUcastPkts", "oid": "1.3.6.1.2.1.31.1.1.1.11", "type": "counter", "unit": "packets"},
      {"name": "ifInErrors", "oid": "1.3.6.1.2.1.2.2.1.14", "type": "counter", "unit": "packets"},
      {"name": "ifOutErrors", "oid": "1.3.6.1.2.1.2.2.1.20", "type": "counter", "unit": "packets"},
      {"name": "ifInDiscards", "oid": "1.3.6.1.2.1.2.2.1.13", "type": "counter", "unit": "packets"},
      {"name": "ifOutDiscards", "oid": "1.3.6.1.2.1.2.2.1.19", "type": "counter", "unit": "packets"},
      {"name": "ifHighSpeed", "oid": "1.3.6.1.2.1.31.1.1.1.15", "type": "gauge", "unit": "Mbps"},
      {"name": "ifAlias", "oid": "1.3.6.1.2.1.31.1.1.1.18", "type": "string", "unit": ""},
      {"name": "entPhysicalSerialNum", "oid": "1.3.6.1.2.1.47.1.1.1.1.11", "type": "string", "unit": ""},
      {"name": "entPhySensorValue", "oid": "1.3.6.1.2.1.99.1.1.1.4", "type": "gauge", "unit": "per-type"}
    ]
  },

  "cisco": {
    "sysobjectid_prefix": "1.3.6.1.4.1.9",
    "metrics": [
      {"name": "cpmCPUTotal5minRev", "oid": "1.3.6.1.4.1.9.9.109.1.1.1.1.8", "type": "gauge", "unit": "percent"},
      {"name": "cpmCPUTotal1minRev", "oid": "1.3.6.1.4.1.9.9.109.1.1.1.1.7", "type": "gauge", "unit": "percent"},
      {"name": "cpmCPUMemoryUsed", "oid": "1.3.6.1.4.1.9.9.109.1.1.1.1.12", "type": "gauge", "unit": "kbytes"},
      {"name": "ciscoMemoryPoolUsed", "oid": "1.3.6.1.4.1.9.9.48.1.1.1.5", "type": "gauge", "unit": "bytes"},
      {"name": "ciscoMemoryPoolFree", "oid": "1.3.6.1.4.1.9.9.48.1.1.1.6", "type": "gauge", "unit": "bytes"},
      {"name": "ciscoEnvMonTemperatureValue", "oid": "1.3.6.1.4.1.9.9.13.1.3.1.3", "type": "gauge", "unit": "celsius"},
      {"name": "ciscoEnvMonTemperatureState", "oid": "1.3.6.1.4.1.9.9.13.1.3.1.6", "type": "enum", "unit": ""},
      {"name": "ciscoEnvMonFanState", "oid": "1.3.6.1.4.1.9.9.13.1.4.1.3", "type": "enum", "unit": ""},
      {"name": "ciscoEnvMonSupplyState", "oid": "1.3.6.1.4.1.9.9.13.1.5.1.3", "type": "enum", "unit": ""}
    ]
  },

  "juniper": {
    "sysobjectid_prefix": "1.3.6.1.4.1.2636",
    "metrics": [
      {"name": "jnxOperatingCPU", "oid": "1.3.6.1.4.1.2636.3.1.13.1.8", "type": "gauge", "unit": "percent"},
      {"name": "jnxOperatingTemp", "oid": "1.3.6.1.4.1.2636.3.1.13.1.7", "type": "gauge", "unit": "celsius"},
      {"name": "jnxOperatingBuffer", "oid": "1.3.6.1.4.1.2636.3.1.13.1.11", "type": "gauge", "unit": "percent"},
      {"name": "jnxOperatingState", "oid": "1.3.6.1.4.1.2636.3.1.13.1.6", "type": "enum", "unit": ""},
      {"name": "jnxOperatingDescr", "oid": "1.3.6.1.4.1.2636.3.1.13.1.5", "type": "string", "unit": ""}
    ]
  },

  "arista": {
    "sysobjectid_prefix": "1.3.6.1.4.1.30065",
    "metrics": [
      {"name": "hrProcessorLoad", "oid": "1.3.6.1.2.1.25.3.3.1.2", "type": "gauge", "unit": "percent"},
      {"name": "hrStorageSize", "oid": "1.3.6.1.2.1.25.2.3.1.5", "type": "gauge", "unit": "alloc-units"},
      {"name": "hrStorageUsed", "oid": "1.3.6.1.2.1.25.2.3.1.6", "type": "gauge", "unit": "alloc-units"},
      {"name": "entPhySensorValue", "oid": "1.3.6.1.2.1.99.1.1.1.4", "type": "gauge", "unit": "per-type"},
      {"name": "entPhySensorType", "oid": "1.3.6.1.2.1.99.1.1.1.1", "type": "enum", "unit": ""}
    ]
  },

  "fortinet": {
    "sysobjectid_prefix": "1.3.6.1.4.1.12356",
    "metrics": [
      {"name": "fgSysCpuUsage", "oid": "1.3.6.1.4.1.12356.101.4.1.3.0", "type": "gauge", "unit": "percent"},
      {"name": "fgSysMemUsage", "oid": "1.3.6.1.4.1.12356.101.4.1.4.0", "type": "gauge", "unit": "percent"},
      {"name": "fgSysMemCapacity", "oid": "1.3.6.1.4.1.12356.101.4.1.5.0", "type": "gauge", "unit": "kbytes"},
      {"name": "fgSysSesCount", "oid": "1.3.6.1.4.1.12356.101.4.1.8.0", "type": "gauge", "unit": "sessions"}
    ]
  },

  "paloalto": {
    "sysobjectid_prefix": "1.3.6.1.4.1.25461",
    "metrics": [
      {"name": "panSessionUtilization", "oid": "1.3.6.1.4.1.25461.2.1.2.3.1.0", "type": "gauge", "unit": "percent"},
      {"name": "panSessionActive", "oid": "1.3.6.1.4.1.25461.2.1.2.3.3.0", "type": "gauge", "unit": "sessions"},
      {"name": "panSessionMax", "oid": "1.3.6.1.4.1.25461.2.1.2.3.2.0", "type": "gauge", "unit": "sessions"},
      {"name": "panSysSwVersion", "oid": "1.3.6.1.4.1.25461.2.1.2.1.1.0", "type": "string", "unit": ""},
      {"name": "hrProcessorLoad", "oid": "1.3.6.1.2.1.25.3.3.1.2", "type": "gauge", "unit": "percent"}
    ]
  },

  "printer_mib": {
    "sysobjectid_prefix": "*",
    "metrics": [
      {"name": "hrDeviceStatus", "oid": "1.3.6.1.2.1.25.3.2.1.5", "type": "enum", "unit": ""},
      {"name": "hrPrinterStatus", "oid": "1.3.6.1.2.1.25.3.5.1.1", "type": "enum", "unit": ""},
      {"name": "hrPrinterDetectedErrorState", "oid": "1.3.6.1.2.1.25.3.5.1.2", "type": "bits", "unit": ""},
      {"name": "prtMarkerLifeCount", "oid": "1.3.6.1.2.1.43.10.2.1.4", "type": "counter", "unit": "pages"},
      {"name": "prtMarkerSuppliesLevel", "oid": "1.3.6.1.2.1.43.11.1.1.9", "type": "gauge", "unit": "units"},
      {"name": "prtMarkerSuppliesMaxCapacity", "oid": "1.3.6.1.2.1.43.11.1.1.8", "type": "gauge", "unit": "units"},
      {"name": "prtMarkerSuppliesDescription", "oid": "1.3.6.1.2.1.43.11.1.1.6", "type": "string", "unit": ""},
      {"name": "prtInputCurrentLevel", "oid": "1.3.6.1.2.1.43.8.2.1.10", "type": "gauge", "unit": "sheets"},
      {"name": "prtConsoleDisplayBufferText", "oid": "1.3.6.1.2.1.43.16.5.1.2", "type": "string", "unit": ""}
    ]
  },

  "ups_mib": {
    "sysobjectid_prefix": "*",
    "metrics": [
      {"name": "upsBatteryStatus", "oid": "1.3.6.1.2.1.33.1.2.1.0", "type": "enum", "unit": ""},
      {"name": "upsSecondsOnBattery", "oid": "1.3.6.1.2.1.33.1.2.2.0", "type": "gauge", "unit": "seconds"},
      {"name": "upsEstimatedMinutesRemaining", "oid": "1.3.6.1.2.1.33.1.2.3.0", "type": "gauge", "unit": "minutes"},
      {"name": "upsEstimatedChargeRemaining", "oid": "1.3.6.1.2.1.33.1.2.4.0", "type": "gauge", "unit": "percent"},
      {"name": "upsBatteryVoltage", "oid": "1.3.6.1.2.1.33.1.2.5.0", "type": "gauge", "unit": "0.1volt-dc"},
      {"name": "upsBatteryTemperature", "oid": "1.3.6.1.2.1.33.1.2.7.0", "type": "gauge", "unit": "celsius"},
      {"name": "upsInputVoltage", "oid": "1.3.6.1.2.1.33.1.3.1.3", "type": "gauge", "unit": "volts-rms"},
      {"name": "upsOutputSource", "oid": "1.3.6.1.2.1.33.1.4.1.0", "type": "enum", "unit": ""},
      {"name": "upsOutputVoltage", "oid": "1.3.6.1.2.1.33.1.4.4.1.2", "type": "gauge", "unit": "volts-rms"},
      {"name": "upsOutputCurrent", "oid": "1.3.6.1.2.1.33.1.4.4.1.3", "type": "gauge", "unit": "0.1amp"},
      {"name": "upsOutputPower", "oid": "1.3.6.1.2.1.33.1.4.4.1.4", "type": "gauge", "unit": "watts"},
      {"name": "upsOutputPercentLoad", "oid": "1.3.6.1.2.1.33.1.4.4.1.5", "type": "gauge", "unit": "percent"},
      {"name": "upsAlarmsPresent", "oid": "1.3.6.1.2.1.33.1.6.1.0", "type": "gauge", "unit": "count"}
    ]
  }
}
```

---

## Appendix — Verification status & primary sources

**OIDs verified against a primary MIB / RFC source during this research:**
Cisco cpmCPUTotal5minRev/cpmCPUMemoryUsed (CISCO-PROCESS-MIB); Juniper
jnxOperatingTemp/jnxOperatingCPU (JUNIPER-MIB); Fortinet
fgSysCpuUsage/fgSysMemUsage/fgSysSesCount (FORTINET-FORTIGATE-MIB); Palo Alto
panSysSwVersion/panSessionUtilization (PAN-COMMON-MIB); Huawei
hwEntityCpuUsage/hwEntityTemperature (HUAWEI-ENTITY-EXTENT-MIB); MikroTik
mtxrHlTemperature/mtxrHlProcessorTemperature (MIKROTIK-MIB); Cisco AireOS
bsnApIfNoOfUsers/bsnAPIfLoadNumOfClients (AIRESPACE-WIRELESS-MIB); Cisco ASA
cfwHardwareStatusValue (CISCO-FIREWALL-MIB); **all UPS-MIB OIDs (RFC 1628,
fetched from rfc-editor.org)**; standard IF-MIB/SNMPv2-MIB/ENTITY-MIB/
ENTITY-SENSOR-MIB/HOST-RESOURCES-MIB/Printer-MIB roots (RFCs 2863/3418/4133/3433/
2790/3805); enterprise numbers for all vendors (IANA PEN assignments).

**Flagged `⚠ VERIFY` (confirm against the device's MIB before production):**
Nokia SR OS sgi*/tmnxHw* leaf indices; Cisco NX-OS CISCO-SYSTEM-EXT-MIB
util leaves; Check Point svnStat/fw scalar leaves; Aruba controller wlsx* column
indices (6.x vs 8.x); Juniper SRX jnxJsSPU* session leaves; HPE/ProCurve CPU/mem
leaves; UniFi/Ruckus/Meraki vendor leaves; Cisco ASA cfwConnectionStat row index;
all VoIP/SBC vendor call-counter leaves (CUCM/CUBE/AudioCodes/Ribbon/Avaya);
Polycom and Avaya phone arcs; vendor printer page-count extensions (HP/Xerox/
Lexmark/Canon — prefer standard prtMarkerLifeCount).

**Recommended workflow for the profile manager:** discover `sysObjectID` →
match prefix (§1.8) → load the universal base + matched vendor profile → on first
poll, `snmpwalk` each enterprise table to confirm leaf presence and *learn the
row indices* (entPhysicalIndex, cpmCPUTotalIndex, line index) before committing
the metric to the recurring poll schedule.
