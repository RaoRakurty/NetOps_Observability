package collectors

import "time"

// SNMP is a v2c polling collector. It issues a real SNMP GET for
// sysUpTimeInstance to each target over UDP/161 (see snmpProbe) and records
// reachability + latency. SNMP_COMMUNITY overrides the default "public".
func NewSNMP(targets TargetFunc) Collector {
	return newPoller("snmp", 30*time.Second, 161, snmpProbe, byProtocol(targets, "snmp"))
}
