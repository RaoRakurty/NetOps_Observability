package main

import (
	"testing"

	"netops/backend/models"
)

func TestInferDeviceType(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    models.Device
		want string
	}{
		{"cisco asr → router", models.Device{Vendor: "cisco", Model: "ASR1000"}, "router"},
		{"cisco catalyst → switch", models.Device{Vendor: "cisco", Model: "Catalyst 9300"}, "switch"},
		{"arista eos → switch", models.Device{Vendor: "arista", Model: "DCS-7050"}, "switch"},
		{"fortigate → firewall", models.Device{Vendor: "fortinet", Model: "FortiGate 1000D"}, "firewall"},
		{"palo → firewall", models.Device{Vendor: "paloalto", OS: "PAN-OS 10.2"}, "firewall"},
		{"f5 bigip → load-balancer", models.Device{Vendor: "f5", Model: "BIG-IP i4800"}, "load-balancer"},
		{"catalyst 9800 → wlc", models.Device{Vendor: "cisco", Model: "Catalyst 9800-CL"}, "wlc"},
		{"aironet → ap", models.Device{Vendor: "cisco", Model: "AIR-AP2802"}, "ap"},
		{"ruckus wireless ap → ap", models.Device{Vendor: "ruckus", OS: "Ruckus R610 Multimedia Hotzone Wireless AP"}, "ap"},
		{"unifi uap → ap", models.Device{Vendor: "ubiquiti", Model: "UAP-AC-Pro"}, "ap"},
		{"tgw → cloud-gw", models.Device{Name: "aws-transit gateway"}, "cloud-gw"},
		{"juniper mx → router", models.Device{Vendor: "juniper", Model: "MX240"}, "router"},
		{"unknown → generic", models.Device{Vendor: "acme", Model: "widget"}, "generic"},
		{"operator override wins", models.Device{Vendor: "cisco", Model: "ASR1000", Labels: map[string]string{"device_type": "load-balancer"}}, "load-balancer"},
	} {
		if got := inferDeviceType(tc.d); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
