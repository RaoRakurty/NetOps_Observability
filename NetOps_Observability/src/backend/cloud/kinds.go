package cloud

// kinds.go — the component vocabulary of the Cloud Network Overview (P0).
//
// Discovery (deployment/docker/cloud-ingest/{aws,azure,gcp}_components.py)
// emits provider-specific resource_type strings; the overview's roll-up and
// render layers reason in a small provider-neutral family vocabulary
// (design §4: LB · WAF · Firewall · DNS · Gateway · Seam · Instance). This
// file is the ONE mapping between the two, plus the honest component-status
// vocabulary those rows carry.

import "strings"

// Component status vocabulary (mirrors components_common.py). A component's
// status comes from a REAL provider signal only; anything else is
// StatusNotMeasured — unknown ≠ green is a binding platform rule.
const (
	StatusHealthy     = "healthy"
	StatusDegraded    = "degraded"
	StatusDown        = "down"
	StatusNotMeasured = "not_measured"
)

// NormalizeComponentStatus maps an inventory row's status onto the vocabulary,
// default-closed: empty or unrecognised reads not_measured, never a state we
// did not measure (and never healthy).
func NormalizeComponentStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case StatusHealthy:
		return StatusHealthy
	case StatusDegraded:
		return StatusDegraded
	case StatusDown:
		return StatusDown
	default:
		return StatusNotMeasured
	}
}

// Component families (design §2/§4 — the component axis inside a VPC).
const (
	FamilyInstance = "instance"
	FamilyLB       = "lb"
	FamilyWAF      = "waf"
	FamilyFirewall = "firewall"
	FamilyDNS      = "dns"
	FamilyGateway  = "gateway"
	FamilySeam     = "seam" // lateral link endpoints (§4a): VPN/DX/ER/TGW/peering
	FamilyOther    = "other"
)

// componentFamilies maps every resource_type the discovery lanes emit to its
// family. Additions here MUST match a type an inventory writer actually emits.
var componentFamilies = map[string]string{
	// compute instances (the pre-P0 inventory)
	"ec2:instance":           FamilyInstance,
	"compute:virtualmachine": FamilyInstance,
	"compute:instance":       FamilyInstance,

	// load balancing / entry points
	"elbv2:loadbalancer":         FamilyLB,
	"network:loadbalancer":       FamilyLB,
	"network:applicationgateway": FamilyLB,
	"cdn:frontdoorprofile":       FamilyLB,
	"compute:forwardingrule":     FamilyLB,
	"compute:backendservice":     FamilyLB,

	// WAF / edge policy
	"wafv2:webacl":           FamilyWAF,
	"compute:securitypolicy": FamilyWAF, // Cloud Armor

	// firewalling
	"ec2:securitygroup":            FamilyFirewall,
	"network:networksecuritygroup": FamilyFirewall,
	"compute:firewallruleset":      FamilyFirewall,

	// DNS
	"route53:hostedzone": FamilyDNS,
	"network:dnszone":    FamilyDNS,
	"dns:managedzone":    FamilyDNS,

	// in-VPC egress gateways
	"ec2:natgateway":      FamilyGateway,
	"ec2:internetgateway": FamilyGateway,
	"network:natgateway":  FamilyGateway,
	"compute:cloudnat":    FamilyGateway,
	"compute:router":      FamilyGateway,

	// seam endpoints (§4a) — VPN/DX/ER gateways, TGW/peering attachments
	"ec2:vpngateway":                FamilySeam,
	"ec2:vpnconnection":             FamilySeam,
	"directconnect:connection":      FamilySeam,
	"ec2:transitgateway":            FamilySeam,
	"ec2:tgw-attachment":            FamilySeam,
	"network:virtualnetworkgateway": FamilySeam,
	"network:vnetpeering":           FamilySeam,
	"network:expressroutecircuit":   FamilySeam,
	"compute:vpngateway":            FamilySeam,
	"compute:vpntunnel":             FamilySeam,
	"compute:vpcpeering":            FamilySeam,
}

// ComponentFamily buckets a provider-specific resource_type into the overview
// vocabulary. Unrecognised types are FamilyOther — rendered as such, never
// silently dropped and never guessed into a family.
func ComponentFamily(resourceType string) string {
	if f, ok := componentFamilies[strings.ToLower(strings.TrimSpace(resourceType))]; ok {
		return f
	}
	return FamilyOther
}
