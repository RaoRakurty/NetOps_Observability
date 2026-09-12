---
title: SNMP configuration by vendor
sidebar_label: SNMP configuration by vendor
description: The device-side SNMP CLI Correlix generates for each vendor it has a template for, the profile it provisions, and what an untemplated vendor gets.
page_type: reference
sidebar_position: 4
---

# SNMP configuration by vendor

Correlix generates the device configuration and the matching credential profile
in one call. You pick a vendor and a version, Correlix mints the secrets, stores
them write-only in a credential profile, and returns the CLI block to paste on
the device. It never writes to the device.

The blocks below are the templates the generator ships, taken from the
`snmp_configgen` section of each vendor document in
`src/backend/internal/vendorprofile/profiles/`. `<<sec_name>>`,
`<<auth_key>>`, `<<priv_key>>`, `<<community>>`, `<<mgmt_subnet>>` and
`<<mask>>` are the placeholders the generator fills. Eleven vendors have a
template; every other vendor gets a real credential and generic guidance.

## Generate a block

**Administration → Data sources → SNMP Profiles → Generate Config**. Choose
a **Vendor** and a **Version**, then select **Generate**. For Fortinet with
`v2c` the form also asks for **Mgmt subnet** and **Mask**, which fill the host
restriction in that template.

The same call over the API, which requires a platform administrator:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"vendor":"cisco","version":"v3"}' \
  http://localhost:8000/api/onboard/snmp-config
```

The response carries `device_config`, `profile_id`, and the generated secrets.
The secrets are returned once. Send `"skip_profile": true` to get the block
without provisioning a profile.

## The profile that is provisioned

| Field | Value |
|---|---|
| Profile id | `<vendor>-<version>-gen`, for example `cisco-v3-gen` or `fortinet-v2c-gen` |
| Profile name | `<Vendor> <version> (generated)`, for example `Cisco v3 (generated)` |
| Port | 161 |
| v3 security level | `authPriv` |
| v3 authentication | `SHA` |
| v3 privacy | `AES128` |

`SHA` with `AES128` is the pairing the generator uses because those are the
protocols the SNMPv3 engine implements. The full allowed set is in
[Add an SNMP credential](/onboard-devices/snmp-profiles). `AES192`, `AES256` and
`3DES` are refused on save, so a device configured for them will not be
readable.

Bind the generated profile to a device by setting the device's
`credential_ref` to the profile id.

## Secrets

The generated community, authentication key and privacy key are shown once, in
the response and in the console panel, and are then unreachable. The audit
record for the call carries the vendor, the version and the profile id, and
never the secrets. Copy them before leaving the page.

---

## Arista EOS

```text
snmp-server community <<community>> ro
```

```text
snmp-server group CORRELIX v3 priv
snmp-server user <<sec_name>> CORRELIX v3 auth sha <<auth_key>> priv aes <<priv_key>>
```

## Check Point Gaia

```text
set snmp community <<community>> read-only
set snmp agent-version v2
set snmp enable
save config
```

```text
set snmp agent-version v3-Only
add snmp usm user <<sec_name>> security-level authPriv auth-pass-phrase <<auth_key>> privacy-pass-phrase <<priv_key>> authentication-protocol SHA1 privacy-protocol AES
set snmp enable
save config
```

## Cisco IOS, IOS-XE and NX-OS

```text
snmp-server community <<community>> RO
```

```text
snmp-server group CORRELIX v3 priv
snmp-server user <<sec_name>> CORRELIX v3 auth sha <<auth_key>> priv aes 128 <<priv_key>>
```

## Extreme EXOS

```text
configure snmp add community readonly <<community>>
enable snmp access
```

```text
configure snmpv3 add user <<sec_name>> authentication sha auth-password <<auth_key>> privacy aes priv-password <<priv_key>>
configure snmpv3 add group correlix-grp user <<sec_name>> sec-model usm
configure snmpv3 add access correlix-grp sec-model usm sec-level priv read-view defaultAdminView
enable snmp access snmp-v3
```

## F5 BIG-IP

```text
modify sys snmp communities add { correlix-ro { community-name <<community>> access ro } }
save sys config
```

```text
modify sys snmp users add { <<sec_name>> { username <<sec_name>> auth-protocol sha auth-password <<auth_key>> privacy-protocol aes privacy-password <<priv_key>> security-level auth-privacy access ro } }
save sys config
```

The template sets the community and the user. It does not add the Correlix
address to `sys snmp allowed-addresses`, which BIG-IP enforces separately. Add
it on the device.

## Fortinet FortiOS

```text
config system snmp sysinfo
    set status enable
end
config system snmp community
    edit 1
        set name "<<community>>"
        set status enable
        set query-v2c-status enable
        config hosts
            edit 1
                set ip <<mgmt_subnet>> <<mask>>
            next
        end
    next
end
```

```text
config system snmp user
    edit "<<sec_name>>"
        set status enable
        set queries enable
        set query-port 161
        set security-level auth-priv
        set auth-proto sha
        set auth-pwd <<auth_key>>
        set priv-proto aes
        set priv-pwd <<priv_key>>
    next
end
```

`<<mgmt_subnet>>` and `<<mask>>` default to `0.0.0.0` and `0.0.0.0` when the
form leaves them blank, which permits every source. Supply the management
subnet. The template does not add `snmp` to an interface `allowaccess` list;
do that on the device.

## Huawei VRP

```text
snmp-agent
snmp-agent community read cipher <<community>>
snmp-agent sys-info version v2c
```

```text
snmp-agent sys-info version v3
snmp-agent group v3 correlix-grp privacy read-view iso-view
snmp-agent mib-view included iso-view iso
snmp-agent usm-user v3 <<sec_name>> group correlix-grp
snmp-agent usm-user v3 <<sec_name>> authentication-mode SHA cipher <<auth_key>>
snmp-agent usm-user v3 <<sec_name>> privacy-mode aes128 cipher <<priv_key>>
```

The template and the provisioned profile both use `SHA` authentication with
`AES-128` privacy, so no change is needed after generating.

## Juniper Junos

```text
set snmp community <<community>> authorization read-only
```

```text
set snmp v3 usm local-engine user <<sec_name>> authentication-sha authentication-key "<<auth_key>>"
set snmp v3 usm local-engine user <<sec_name>> privacy-aes128 privacy-key "<<priv_key>>"
set snmp v3 vacm security-to-group security-model usm security-name <<sec_name>> group correlix-grp
set snmp v3 vacm access group correlix-grp default-context-prefix security-model usm security-level privacy read-view all
set snmp view all oid .1 include
```

## MikroTik RouterOS

```text
/snmp community add name=<<community>> read-access=yes
/snmp set enabled=yes
```

```text
/snmp community add name=<<sec_name>> authentication-protocol=SHA1 authentication-password=<<auth_key>> encryption-protocol=AES encryption-password=<<priv_key>> security=private read-access=yes
/snmp set enabled=yes
```

## Palo Alto PAN-OS

```text
set deviceconfig system snmp-setting access-setting version v2c snmp-community-string <<community>>
```

```text
set deviceconfig system snmp-setting access-setting version v3 users <<sec_name>> authpwd <<auth_key>> privpwd <<priv_key>> authprotocol sha privprotocol aes-128
commit
```

## Ubiquiti EdgeOS

```text
set service snmp community <<community>> authorization ro
commit ; save
```

```text
set service snmp v3 user <<sec_name>> auth type sha
set service snmp v3 user <<sec_name>> auth plaintext-key <<auth_key>>
set service snmp v3 user <<sec_name>> privacy type aes
set service snmp v3 user <<sec_name>> privacy plaintext-key <<priv_key>>
set service snmp v3 user <<sec_name>> mode ro
commit ; save
```


UniFi access points and switches report their health through the controller
API, not device SNMP. That path is the UniFi connector, controlled by
`FEATURE_UNIFI`, and it is not SNMP configuration.

## Every other vendor

A vendor with no template still receives a real, minted credential and a
provisioned profile. `device_config` then carries guidance instead of CLI:

```text
# Configure an SNMPv3 read-only user on this device:
#   user=correlix  auth=SHA key=<generated>  priv=AES-128 key=<generated>
```

```text
# Configure an SNMPv2c read-only community on this device:
#   community=<generated>
```

Apply the equivalent in that platform's own syntax. Correlix does not invent a
CLI block for a platform it has not validated.

## Verify the device answers

The credential sentinel re-checks each device's active credential every two
minutes, so a correct paste shows up within about that long. Confirm on
**Administration → Data sources → Sensors** that the device's collector
reports it reachable, or on
[the coverage matrix](/onboard-devices/data-sources) that **SNMP metrics**
turned green.

## Related

- [Add an SNMP credential](/onboard-devices/snmp-profiles)
- [Supported devices](/onboard-devices/supported-devices)
- [Verify a device is being monitored](/onboard-devices/verify-monitoring)
