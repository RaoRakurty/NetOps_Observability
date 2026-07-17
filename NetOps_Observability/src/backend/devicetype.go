package main

import (
	"strings"

	"netops/backend/models"
)

// inferDeviceType classifies a device into a functional NOC type from its
// SNMP-derived signals (vendor + model + sysDescr/OS + name) — the same text an
// operator reads. Returns one of: router, switch, firewall, load-balancer, ap,
// wlc, cloud-gw, generic. An operator override in labels["device_type"] always
// wins (the "manual" half of the SNMP-infer + manual policy). Order matters:
// specific roles (firewall/LB/WLC/AP/cloud-gw) are tested before the generic
// switch-vs-router split so a firewall is never mislabelled a router.
func inferDeviceType(d models.Device) string {
	if d.Labels != nil {
		if t := strings.TrimSpace(d.Labels["device_type"]); t != "" {
			return t // operator override
		}
	}
	h := strings.ToLower(d.Vendor + " " + d.Model + " " + d.OS + " " + d.Name)
	switch {
	case hasAny(h, "fortigate", "fortios", "firewall", "asa", "palo alto", "pan-os", "panos", "checkpoint", "check point", "srx", "ngfw", "firepower", "fpr-", "ftd"):
		return "firewall"
	case hasAny(h, "big-ip", "bigip", "f5 ", "load-balanc", "loadbalanc", "netscaler", "citrix adc", "avi vantage"):
		return "load-balancer"
	case hasAny(h, "wlc", "wireless lan controller", "wism", "9800", "mobility express", "wireless controller"):
		return "wlc"
	// "wireless ap" catches Ruckus standalone AP banners ("… Wireless AP");
	// "uap-" catches Ubiquiti UniFi AP model strings (UAP-AC-Pro, UAP-nanoHD).
	case hasAny(h, "aironet", "access point", "accesspoint", "air-ap", "air-cap", "meraki mr", "wifi", "wireless ap", "uap-"):
		return "ap"
	case hasAny(h, "vgw", "tgw", "transit gateway", "vpn gateway", "cloud gateway", "cloudgw", "cloud-gw", "csr1000v", "c8000v cloud", "vmx cloud"):
		return "cloud-gw"
	case hasAny(h, "catalyst", "nexus", "qfx", " ex2", " ex3", " ex4", "arista", " eos", "dcs-", "icx", "powerconnect", "ws-c", "switch"):
		return "switch"
	case hasAny(h, "router", "asr", "isr", "ncs", " mx", "ptx", "crs", "gsr", "7750", "7250", "csr", "c8000v", "vmx", "vsr"):
		return "router"
	}
	return "generic"
}

// withDeviceType fills the Type on each device (infer-on-read) without touching
// the discovery store — so re-discovery never clobbers it and there's no migration.
func withDeviceType(ds []models.Device) []models.Device {
	for i := range ds {
		if ds[i].Type == "" {
			ds[i].Type = inferDeviceType(ds[i])
		}
	}
	return ds
}

func hasAny(hay string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}
