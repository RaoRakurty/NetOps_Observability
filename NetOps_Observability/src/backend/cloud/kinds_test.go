package cloud

import "testing"

func TestComponentFamily_MapsEveryEmittedType(t *testing.T) {
	// One representative per family per provider — pins the discovery↔backend
	// contract (a type the pollers emit must never fall through to "other").
	cases := map[string]string{
		// instances
		"ec2:instance":           FamilyInstance,
		"compute:virtualMachine": FamilyInstance, // case-insensitive
		"compute:instance":       FamilyInstance,
		// lb
		"elbv2:loadbalancer":         FamilyLB,
		"network:loadBalancer":       FamilyLB,
		"network:applicationGateway": FamilyLB,
		"cdn:frontdoorProfile":       FamilyLB,
		"compute:forwardingRule":     FamilyLB,
		"compute:backendService":     FamilyLB,
		// waf
		"wafv2:webacl":           FamilyWAF,
		"compute:securityPolicy": FamilyWAF,
		// firewall
		"ec2:securitygroup":            FamilyFirewall,
		"network:networkSecurityGroup": FamilyFirewall,
		"compute:firewallRuleSet":      FamilyFirewall,
		// dns
		"route53:hostedzone": FamilyDNS,
		"network:dnszone":    FamilyDNS,
		"dns:managedZone":    FamilyDNS,
		// gateway
		"ec2:natgateway":      FamilyGateway,
		"ec2:internetgateway": FamilyGateway,
		"network:natGateway":  FamilyGateway,
		"compute:cloudNat":    FamilyGateway,
		"compute:router":      FamilyGateway,
		// seam endpoints (§4a)
		"ec2:vpngateway":                FamilySeam,
		"ec2:vpnconnection":             FamilySeam,
		"directconnect:connection":      FamilySeam,
		"ec2:transitgateway":            FamilySeam,
		"ec2:tgw-attachment":            FamilySeam,
		"network:virtualNetworkGateway": FamilySeam,
		"network:vnetPeering":           FamilySeam,
		"network:expressRouteCircuit":   FamilySeam,
		"compute:vpnGateway":            FamilySeam,
		"compute:vpnTunnel":             FamilySeam,
		"compute:vpcPeering":            FamilySeam,
	}
	for typ, want := range cases {
		if got := ComponentFamily(typ); got != want {
			t.Errorf("ComponentFamily(%q) = %q, want %q", typ, got, want)
		}
	}
	if got := ComponentFamily("acme:quantum-router"); got != FamilyOther {
		t.Errorf("unknown type must be %q, got %q", FamilyOther, got)
	}
}

func TestNormalizeComponentStatus_DefaultClosed(t *testing.T) {
	cases := map[string]string{
		"healthy":      StatusHealthy,
		" Degraded ":   StatusDegraded,
		"DOWN":         StatusDown,
		"not_measured": StatusNotMeasured,
		"":             StatusNotMeasured, // absent is not measured
		"green":        StatusNotMeasured, // invented vocab never reads as a state
		"ok":           StatusNotMeasured,
	}
	for in, want := range cases {
		if got := NormalizeComponentStatus(in); got != want {
			t.Errorf("NormalizeComponentStatus(%q) = %q, want %q", in, got, want)
		}
	}
}
