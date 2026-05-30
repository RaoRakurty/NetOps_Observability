package collectors

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// vendor.go — authoritative vendor identification via SNMP, the way modern NMS
// tools (LibreNMS, Observium, Datadog NDM) do it: read sysObjectID (the
// vendor's own device identity) and map its enterprise number to a vendor;
// fall back to parsing the sysDescr text. Reuses the GET/decoder in poller.go
// and tunnels.go, so it stays stdlib-only.

var sysObjectIDOID = []int{1, 3, 6, 1, 2, 1, 1, 2, 0} // SNMPv2-MIB::sysObjectID.0
var sysDescrOID = []int{1, 3, 6, 1, 2, 1, 1, 1, 0}    // SNMPv2-MIB::sysDescr.0

// enterpriseVendor maps IANA Private Enterprise Numbers (the 7th arc of a
// sysObjectID under 1.3.6.1.4.1.<ENT>) to a normalized vendor name. Extend as
// new vendors are onboarded.
var enterpriseVendor = map[int]string{
	9:     "cisco",
	2636:  "juniper",
	30065: "arista",
	12356: "fortinet",
	25461: "paloalto",
	6527:  "nokia",
	2011:  "huawei",
	14988: "mikrotik",
	1916:  "extreme",
	3375:  "f5",
	674:   "dell",
	11:    "hp",
	2620:  "checkpoint",
	8072:  "net-snmp",
}

// DetectVendor SNMP-GETs sysObjectID (authoritative) then sysDescr (fallback)
// and returns a normalized vendor name plus the raw sysDescr string. Vendor is
// "" when it can't be determined (unreachable, or an unknown enterprise with an
// unrecognizable sysDescr).
func DetectVendor(ctx context.Context, addr, community string) (vendor, sysDescr string) {
	addr = withPort(addr, 161)
	if v, err := snmpGet(ctx, addr, community, sysObjectIDOID); err == nil && v.tag == 0x06 {
		if ent, ok := enterpriseOf(decodeOID(v.raw)); ok {
			vendor = enterpriseVendor[ent] // "" if enterprise not in the table
		}
	}
	if d, err := snmpGet(ctx, addr, community, sysDescrOID); err == nil {
		sysDescr = d.str()
		if vendor == "" {
			vendor = vendorFromDescr(sysDescr)
		}
	}
	return vendor, sysDescr
}

// enterpriseOf returns the enterprise number from a sysObjectID under
// 1.3.6.1.4.1.<ENT>... and whether the OID had that shape.
func enterpriseOf(arcs []int) (int, bool) {
	prefix := []int{1, 3, 6, 1, 4, 1}
	if len(arcs) < len(prefix)+1 {
		return 0, false
	}
	for i := range prefix {
		if arcs[i] != prefix[i] {
			return 0, false
		}
	}
	return arcs[len(prefix)], true
}

// vendorFromDescr is the sysDescr text backstop when the enterprise number is
// unknown — sysDescr usually names the vendor/OS in plain text.
func vendorFromDescr(d string) string {
	s := strings.ToLower(d)
	switch {
	case strings.Contains(s, "cisco"):
		return "cisco"
	case strings.Contains(s, "junos"), strings.Contains(s, "juniper"):
		return "juniper"
	case strings.Contains(s, "arista"):
		return "arista"
	case strings.Contains(s, "fortinet"), strings.Contains(s, "fortigate"):
		return "fortinet"
	case strings.Contains(s, "palo alto"), strings.Contains(s, "pan-os"):
		return "paloalto"
	case strings.Contains(s, "nokia"), strings.Contains(s, "timos"), strings.Contains(s, "sr os"):
		return "nokia"
	case strings.Contains(s, "huawei"), strings.Contains(s, "vrp"):
		return "huawei"
	case strings.Contains(s, "mikrotik"), strings.Contains(s, "routeros"):
		return "mikrotik"
	case strings.Contains(s, "linux"):
		return "linux"
	}
	return ""
}

// snmpGet issues a single SNMP v2c GET and returns the first varbind's value.
// Errors on transport failure or an SNMP exception value (noSuchObject etc.).
func snmpGet(ctx context.Context, addr, community string, oid []int) (berVal, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return berVal{}, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(buildSNMPGet(community, oid, 1)); err != nil {
		return berVal{}, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return berVal{}, err
	}
	_, valTag, val, err := firstVarbind(buf[:n])
	if err != nil {
		return berVal{}, err
	}
	if valTag == tagNoSuchObject || valTag == tagNoSuchInstance || valTag == tagEndOfMibView {
		return berVal{}, fmt.Errorf("snmp: no such object")
	}
	return berVal{tag: valTag, raw: append([]byte(nil), val...)}, nil
}
