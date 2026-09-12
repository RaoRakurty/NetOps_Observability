// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloud

// kinds.go — the component vocabulary of the Cloud Network Overview (P0).
//
// Discovery (deployment/docker/cloud-ingest/{aws,azure,gcp}_components.py)
// emits provider-specific resource_type strings; the overview's roll-up and
// render layers reason in a small provider-neutral family vocabulary
// (design §4: LB · WAF · Firewall · DNS · Gateway · Seam · Instance). This
// file is the ONE mapping between the two, plus the honest component-status
// vocabulary those rows carry.

import (
	"sort"
	"strings"
)

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
	// Workload breadth (Wave 5 #15): the K8s layer and the serverless/PaaS
	// layer — inventory was VM-only before these classes.
	FamilyK8s        = "k8s"        // managed clusters + their node pools
	FamilyServerless = "serverless" // functions / sites / plans / Cloud Run
	FamilyDatabase   = "db"         // managed database instances
	FamilyOther      = "other"
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

	// K8s layer (Wave 5 #15) — clusters + node pools
	"eks:cluster":                     FamilyK8s,
	"eks:nodegroup":                   FamilyK8s,
	"containerservice:managedcluster": FamilyK8s, // AKS
	"containerservice:agentpool":      FamilyK8s,
	"container:cluster":               FamilyK8s, // GKE
	"container:nodepool":              FamilyK8s,

	// serverless / PaaS (Wave 5 #15)
	"lambda:function": FamilyServerless,
	"web:site":        FamilyServerless, // App Service web apps + Function apps
	"web:serverfarm":  FamilyServerless, // App Service plans
	"run:service":     FamilyServerless, // Cloud Run

	// managed databases (Wave 5 #15)
	"rds:instance":      FamilyDatabase,
	"sql:server":        FamilyDatabase, // Azure SQL logical server
	"sql:database":      FamilyDatabase,
	"sqladmin:instance": FamilyDatabase, // Cloud SQL
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

// validFamilies is the closed set a family FILTER may name (§3 boundary
// validation for /api/cloud/resources?family=…).
var validFamilies = map[string]bool{
	FamilyInstance: true, FamilyLB: true, FamilyWAF: true, FamilyFirewall: true,
	FamilyDNS: true, FamilyGateway: true, FamilySeam: true,
	FamilyK8s: true, FamilyServerless: true, FamilyDatabase: true,
	FamilyOther: true,
}

// ValidComponentFamily reports whether s names a known component family —
// used to reject a bad ?family= filter with a clean 400 at the boundary.
func ValidComponentFamily(s string) bool {
	return validFamilies[strings.ToLower(strings.TrimSpace(s))]
}

// FamilyTypes returns the lowercase resource_type strings that map to the
// given family (sorted copy). Empty for FamilyOther — "other" is the
// complement of every known type, not a list (see KnownComponentTypes).
func FamilyTypes(family string) []string {
	var out []string
	for typ, fam := range componentFamilies {
		if fam == family {
			out = append(out, typ)
		}
	}
	sort.Strings(out)
	return out
}

// KnownComponentTypes returns every mapped lowercase resource_type (sorted) —
// the complement set a FamilyOther filter excludes.
func KnownComponentTypes() []string {
	out := make([]string, 0, len(componentFamilies))
	for typ := range componentFamilies {
		out = append(out, typ)
	}
	sort.Strings(out)
	return out
}
