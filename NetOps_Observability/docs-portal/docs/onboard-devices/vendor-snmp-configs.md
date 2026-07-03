---
title: Vendor SNMP configs (v2c & v3)
sidebar_label: Vendor SNMP configs
sidebar_position: 9
description: Copy-paste golden SNMP configuration for every supported vendor — SNMPv2c and the more secure SNMPv3 (auth + privacy) — with the matching Correlix credential profile.
---

# Vendor SNMP configs (v2c & v3)

This is the golden, copy-paste SNMP configuration for every vendor Correlix
monitors. Each vendor has two blocks:

- **SNMPv2c** — a read-only community string. Simplest to stand up; the community
  is sent in clear text, so prefer it only on trusted management networks.
- **SNMPv3** — a per-user credential with **authentication + privacy (encryption)**.
  Preferred for anything internet-facing or a security device (firewalls, DMZ).

After configuring the device, create or edit the matching
[SNMP credential profile](/onboard-devices/snmp-profiles) so the values line up.
Correlix's **credential sentinel** then verifies the bound profile every couple
of minutes and, if it can't authenticate, automatically tries your other stored
profiles for that tenant — so a v2c fallback is adopted the moment v3 drifts,
and it reverts to v3 the moment that recovers.

:::tip Match auth/privacy to what Correlix supports
Correlix's SNMPv3 supports auth **MD5 / SHA / SHA-224/256/384/512** and privacy
**AES-128 / DES**. Use **SHA + AES-128** unless a device forces otherwise — it is
the widest interoperable pairing. In a profile, set `priv_protocol` to `AES128`
(not `AES`).
:::

:::caution Cardinality & secrets
Correlix stores community strings and v3 keys **write-only** (encrypted at rest,
never returned by the API). The golden configs below use placeholders —
substitute your own secrets and never commit real keys.
:::

## Cisco IOS / IOS-XE / NX-OS

```text
! SNMPv2c (read-only)
snmp-server community CORRELIX-RO RO

! SNMPv3 (auth SHA + priv AES-128)
snmp-server group CORRELIX v3 priv
snmp-server user correlix CORRELIX v3 auth sha <AUTH_KEY> priv aes 128 <PRIV_KEY>
```

> NX-OS persists `snmp-server user`; classic IOS-XE may not survive reload
> without `write memory` — always save. Profile: `cisco-v2c` / `cisco-v3`.

## Juniper Junos (MX / SRX / EX / QFX)

```text
# SNMPv2c
set snmp community CORRELIX-RO authorization read-only

# SNMPv3 (USM, auth SHA + priv AES-128)
set snmp v3 usm local-engine user correlix authentication-sha authentication-key "<AUTH_KEY>"
set snmp v3 usm local-engine user correlix privacy-aes128 privacy-key "<PRIV_KEY>"
set snmp v3 vacm security-to-group security-model usm security-name correlix group correlix-grp
set snmp v3 vacm access group correlix-grp default-context-prefix security-model usm security-level privacy read-view all
set snmp view all oid .1 include
```

> SRX is the same Junos SNMP stack as MX/EX. Profile: `juniper-v2c` / `juniper-v3`.

## Arista EOS

```text
! SNMPv2c
snmp-server community CORRELIX-RO ro

! SNMPv3 (auth SHA + priv AES-128)
snmp-server group CORRELIX v3 priv
snmp-server user correlix CORRELIX v3 auth sha <AUTH_KEY> priv aes <PRIV_KEY>
```

> Arista exposes CPU/memory (HOST-RESOURCES) and optics (ENTITY-SENSOR) over
> standard MIBs — no vendor profile needed. Profile: `arista-v2c` / `arista-v3`.

## Fortinet FortiGate (FortiOS)

```text
config system snmp sysinfo
    set status enable
end

# SNMPv2c community, open to the management subnet
config system snmp community
    edit 1
        set name "CORRELIX-RO"
        set status enable
        set query-v2c-status enable
        config hosts
            edit 1
                set ip <MGMT_SUBNET> <MASK>
            next
        end
    next
end

# SNMPv3 (auth SHA + priv AES)
config system snmp user
    edit "correlix"
        set status enable
        set queries enable
        set query-port 161
        set security-level auth-priv
        set auth-proto sha
        set auth-pwd <AUTH_KEY>
        set priv-proto aes
        set priv-pwd <PRIV_KEY>
    next
end

# Ensure the management interface permits SNMP
config system interface
    edit "port1"
        append allowaccess snmp
    next
end
```

> FortiGate config can be truncated by an external config push — if SNMP stops
> answering after a change, re-apply this block. The credential sentinel will
> hold monitoring up on a v2c fallback in the meantime. Profile: `fortinet-v2c` /
> `fortinet-v3`.

## Palo Alto (PAN-OS)

```text
# SNMPv2c — Device > Setup > Operations > SNMP, or CLI:
set deviceconfig system snmp-setting access-setting version v2c snmp-community-string CORRELIX-RO

# SNMPv3 (auth SHA + priv AES)
set deviceconfig system snmp-setting access-setting version v3 views correlix-view view all oid 1 option include
set deviceconfig system snmp-setting access-setting version v3 users correlix view correlix-view authpwd <AUTH_KEY> privpwd <PRIV_KEY> authprotocol sha privprotocol aes-128
commit
```

> Profile: `paloalto-v2c` / `paloalto-v3`.

## F5 BIG-IP (TMOS)

```text
# SNMPv2c — allow the poller + set the community
modify sys snmp allowed-addresses add { <POLLER_IP>/32 }
modify sys snmp communities add { correlix-ro { community-name CORRELIX-RO access ro } }

# SNMPv3 (auth SHA + priv AES)
modify sys snmp users add { correlix { username correlix auth-protocol sha \
  auth-password <AUTH_KEY> privacy-protocol aes privacy-password <PRIV_KEY> \
  security-level auth-privacy access ro } }
save sys config
```

> F5 pool/VIP/member health feeds the load-balancer RCA signatures. Profile:
> `f5-v2c` / `f5-v3`.

## Check Point (Gaia)

```text
# SNMPv2c
set snmp mode default
set snmp community CORRELIX-RO read-only
set snmp agent-version v2

# SNMPv3 (auth SHA + priv AES)
set snmp agent-version v3-Only
add snmp usm user correlix security-level authPriv \
  auth-pass-phrase <AUTH_KEY> privacy-pass-phrase <PRIV_KEY> \
  authentication-protocol SHA1 privacy-protocol AES
set snmp enable
save config
```

> Profile: `checkpoint-v2c` / `checkpoint-v3`.

## MikroTik RouterOS

```text
# SNMPv2c
/snmp community add name=CORRELIX-RO read-access=yes addresses=<MGMT_SUBNET>
/snmp set enabled=yes

# SNMPv3 (auth SHA + priv AES)
/snmp community add name=correlix-v3 authentication-protocol=SHA1 \
  authentication-password=<AUTH_KEY> encryption-protocol=AES \
  encryption-password=<PRIV_KEY> security=private read-access=yes
/snmp set enabled=yes contact="correlix" location="<SITE>"
```

> RouterOS CPU/memory come from HOST-RESOURCES; the vendor profile adds
> temperature/voltage. Profile: `mikrotik-v2c` / `mikrotik-v3`.

## Huawei VRP (CE / NE / AR)

```text
# SNMPv2c
snmp-agent
snmp-agent community read cipher CORRELIX-RO
snmp-agent sys-info version v2c

# SNMPv3 (auth SHA + priv AES)
snmp-agent sys-info version v3
snmp-agent group v3 correlix-grp privacy read-view iso-view
snmp-agent mib-view included iso-view iso
snmp-agent usm-user v3 correlix group correlix-grp
snmp-agent usm-user v3 correlix authentication-mode sha2-256 cipher <AUTH_KEY>
snmp-agent usm-user v3 correlix privacy-mode aes128 cipher <PRIV_KEY>
```

> Profile: `huawei-v2c` / `huawei-v3`.

## Extreme EXOS

```text
# SNMPv2c
configure snmp add community readonly CORRELIX-RO
enable snmp access

# SNMPv3 (auth SHA + priv AES)
configure snmpv3 add user correlix authentication sha auth-password <AUTH_KEY> \
  privacy aes priv-password <PRIV_KEY>
configure snmpv3 add group correlix-grp user correlix sec-model usm
configure snmpv3 add access correlix-grp sec-model usm sec-level priv \
  read-view defaultAdminView
enable snmp access snmp-v3
```

> Profile: `extreme-v2c` / `extreme-v3`.

## Sophos SFOS (XG Firewall)

SFOS exposes limited SNMP (mostly standard IF-MIB). Enable it under
**Administration → SNMP** in the SFOS console:

- **SNMPv2c** — create an *Agent* + a *Community* (read-only), allow the poller IP.
- **SNMPv3** — create a *User* with SHA authentication + AES encryption.

> Sophos rides the generic standard-MIB floor; there is no rich vendor profile.
> Profile: `sophos-v2c` / `sophos-v3`.

## Ubiquiti

Ubiquiti device health lives in the **UniFi/EdgeMax controller**, not device
SNMP. For UniFi, use the [UniFi controller connector](/onboard-devices/data-sources)
(`FEATURE_UNIFI` + controller URL/credentials) rather than SNMP. EdgeRouter
(EdgeOS) does answer standard SNMP:

```text
# EdgeOS (EdgeRouter) — SNMPv2c
set service snmp community CORRELIX-RO authorization ro

# EdgeOS — SNMPv3 (auth SHA + priv AES)
set service snmp v3 user correlix auth type sha
set service snmp v3 user correlix auth plaintext-key <AUTH_KEY>
set service snmp v3 user correlix privacy type aes
set service snmp v3 user correlix privacy plaintext-key <PRIV_KEY>
set service snmp v3 user correlix mode ro
commit ; save
```

> Profile: `ubiquiti-v2c` / `ubiquiti-v3` (EdgeOS); UniFi APs/switches → controller connector.

## Any other vendor (the standard-MIB floor)

Correlix monitors **any** SNMP device the moment it's discovered — no vendor
profile required. The generic profile polls the universal RFC MIBs (IF-MIB,
ENTITY-MIB, ENTITY-SENSOR-MIB, HOST-RESOURCES-MIB), which give you interface
state, traffic, errors, hardware inventory, CPU, and optics DOM. A vendor
profile only *adds* device-class-specific health. So the minimal golden config
for an unlisted vendor is simply: **enable SNMP (v2c or v3) with a read-only
credential** using that vendor's syntax, then create the matching Correlix
profile.
```
