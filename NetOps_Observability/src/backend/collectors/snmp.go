package collectors

import "time"

// SNMP collectors poll devices with a real SNMP GET of sysUpTimeInstance over
// UDP/161 (see snmpProbe) and record reachability + latency.
//
// The single "snmp" collector is split into two so the Collectors view can show
// SNMPv2c and SNMPv3 device populations separately — they have very different
// security postures and operators want to see at a glance how many devices are
// still on community-string v2c vs authenticated/encrypted v3. The per-device
// version comes from its credential profile (credential_ref); v2c covers the
// community-string versions (v1/v2c, SNMPVersion 0 or 2), v3 covers USM.

// NewSNMPv2c polls only devices whose resolved credential is community-based
// (v1/v2c). SNMP_COMMUNITY overrides the default "public" when a device has no
// profile community.
func NewSNMPv2c(targets TargetFunc) Collector {
	return newPoller("snmpv2c", 30*time.Second, 161, snmpProbe, byProtocolVersion(targets, "snmp", false))
}

// NewSNMPv3 polls only devices whose resolved credential is USM v3.
func NewSNMPv3(targets TargetFunc) Collector {
	return newPoller("snmpv3", 30*time.Second, 161, snmpProbe, byProtocolVersion(targets, "snmp", true))
}
