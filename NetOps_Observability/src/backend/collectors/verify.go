package collectors

// verify.go — read-only one-shot SNMP surface for the Active Verification
// engine (RCA spec item 8). Exposes exactly the values the verify battery
// needs, delegating to the package-private SNMP client (snmpGet / snmpGetV3
// stay internal — the closed surface is the point).

import "context"

// SysUpTimeSeconds performs a credentialed sysUpTime GET (v2c or v3 per the
// target's fields, same resolution as ProbeSNMP) and returns the device's
// uptime in whole seconds. sysUpTime is TimeTicks (centiseconds) on the wire.
// READ-ONLY by construction; bounded by ctx.
func SysUpTimeSeconds(ctx context.Context, t Target) (int64, error) {
	v, err := snmpGet(ctx, withPort(t.Address, 161), t.creds(), sysUpTimeOID)
	if err != nil {
		return 0, err
	}
	return valueInt(v) / 100, nil
}
