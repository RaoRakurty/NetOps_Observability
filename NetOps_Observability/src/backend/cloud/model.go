// Package cloud is the canonical model + pure resolution logic for Cloud App
// Observability (#81 P3) — the app-to-underlay RCA story: Identity → Health →
// Change → Cloud Network → Underlay → RCA, every step evidence-grounded with an
// explicit confidence and an attribution reason. This file is the P3A identity
// substrate; health/change/flow/RCA build on it in later phases.
//
// Design principles enforced here (per the spec):
//   - Never guess identity. Confidence is explicit: confirmed > strong > suspected
//     > weak > unknown, and UNKNOWN is first-class (a real, visible answer).
//   - Cloud-internal identity comes from cloud inventory/graph/tags/labels/resource
//     ids/ENIs/target-groups — NOT IP ranges (IP catalog is the weakest source,
//     for public SaaS/cloud egress only).
//   - Pure + stdlib-only: no cloud SDK here. Real connectors implement
//     CloudInventoryProvider later; the first pass is fixture-driven.
package cloud

import "time"

// Provider is a supported cloud.
type Provider string

const (
	AWS   Provider = "aws"
	Azure Provider = "azure"
	GCP   Provider = "gcp"
)

func ValidProvider(p Provider) bool { return p == AWS || p == Azure || p == GCP }

// Confidence is the evidence-strength ladder. Higher rank wins precedence.
type Confidence string

const (
	Confirmed Confidence = "confirmed" // authoritative (operator tag, native service field)
	Strong    Confidence = "strong"    // resource-graph name, firewall app-id
	Suspected Confidence = "suspected" // a single medium signal (domain)
	Weak      Confidence = "weak"      // coarse (IP catalog / region / account only)
	Unknown   Confidence = "unknown"   // first-class: evidence does not support attribution
)

func (c Confidence) rank() int {
	switch c {
	case Confirmed:
		return 4
	case Strong:
		return 3
	case Suspected:
		return 2
	case Weak:
		return 1
	default:
		return 0
	}
}

// Source is where an identity attribution came from. Ordered by trust.
type Source string

const (
	SrcCloudTag        Source = "cloud_tag"        // operator tag on the resource — authoritative
	SrcCloudGraph      Source = "cloud_graph"      // resource-graph name (ASG/ECS/Lambda/etc) — strong
	SrcOperatorCatalog Source = "operator_catalog" // operator-declared override — authoritative
	SrcFirewallAppID   Source = "firewall_appid"   // firewall on-box DPI — strong
	SrcDomain          Source = "domain"           // DNS/SNI domain match — suspected
	SrcIPCatalog       Source = "ip_catalog"       // vendor IP-range — weak (public egress only)
	SrcUnknown         Source = "unknown"
)

// DefaultConfidence is the confidence a source carries unless a record overrides it.
func (s Source) DefaultConfidence() Confidence {
	switch s {
	case SrcCloudTag, SrcOperatorCatalog:
		return Confirmed
	case SrcCloudGraph, SrcFirewallAppID:
		return Strong
	case SrcDomain:
		return Suspected
	case SrcIPCatalog:
		return Weak
	default:
		return Unknown
	}
}

// MatchKeyType is the kind of key a flow/log record is enriched by — the cloud
// joins on resource identity, not just IP.
type MatchKeyType string

const (
	MatchPrivateIP   MatchKeyType = "private_ip"
	MatchENI         MatchKeyType = "eni"
	MatchNIC         MatchKeyType = "nic"
	MatchResourceID  MatchKeyType = "resource_id"
	MatchARN         MatchKeyType = "arn"
	MatchLogGroup    MatchKeyType = "log_group"
	MatchTargetGroup MatchKeyType = "target_group"
	MatchDNSName     MatchKeyType = "dns_name"
	MatchK8sService  MatchKeyType = "k8s_service"
	MatchPodIP       MatchKeyType = "pod_ip"
)

// EdgeType is the relationship between an app and a resource.
type EdgeType string

const (
	EdgeOwns        EdgeType = "owns"
	EdgeRunsOn      EdgeType = "runs_on"
	EdgeFronts      EdgeType = "fronts"
	EdgeDependsOn   EdgeType = "depends_on"
	EdgeEgressesVia EdgeType = "egresses_via"
	EdgeBackedBy    EdgeType = "backed_by"
)

// CloudResource is a discovered cloud resource with its tags/labels and the app it
// was attributed to (with confidence). Tenant-stamped; provider-neutral.
type CloudResource struct {
	TenantID            string            `json:"tenant_id"`
	Provider            Provider          `json:"cloud_provider"`
	AccountID           string            `json:"account_id"` // account_id | subscription_id | project_id
	Region              string            `json:"region"`
	Zone                string            `json:"zone,omitempty"`
	ResourceID          string            `json:"resource_id"`
	ResourceURI         string            `json:"resource_arn_or_uri,omitempty"`
	ResourceType        string            `json:"resource_type"`
	ResourceName        string            `json:"resource_name,omitempty"`
	PrivateIPs          []string          `json:"private_ips,omitempty"`
	PublicIPs           []string          `json:"public_ips,omitempty"`
	NetworkInterfaceIDs []string          `json:"network_interface_ids,omitempty"`
	Tags                map[string]string `json:"tags,omitempty"`
	Owner               string            `json:"owner,omitempty"`
	Env                 string            `json:"env,omitempty"`
	AppID               string            `json:"app_id,omitempty"`
	AppName             string            `json:"app_name,omitempty"`
	DiscoveredAt        time.Time         `json:"discovered_at"`
	LastSeenAt          time.Time         `json:"last_seen_at"`
	Source              Source            `json:"source"`
	Confidence          Confidence        `json:"confidence"`
}

// AppResourceEdge is an app→resource relationship (the dependency/seam graph).
type AppResourceEdge struct {
	TenantID    string     `json:"tenant_id"`
	AppID       string     `json:"app_id"`
	ResourceID  string     `json:"resource_id"`
	EdgeType    EdgeType   `json:"edge_type"`
	Source      Source     `json:"source"`
	Confidence  Confidence `json:"confidence"`
	EvidenceRef string     `json:"evidence_ref,omitempty"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
}

// CloudIdentityMapping is one (match_key → app) attribution — the lookup the flow/
// log enrichment joins on. Carries source, confidence, and a human attribution
// reason so every verdict is explainable.
type CloudIdentityMapping struct {
	TenantID          string       `json:"tenant_id"`
	MatchKeyType      MatchKeyType `json:"match_key_type"`
	MatchKey          string       `json:"match_key"`
	AppID             string       `json:"app_id"`
	AppName           string       `json:"app_name"`
	Owner             string       `json:"owner,omitempty"`
	Env               string       `json:"env,omitempty"`
	ResourceID        string       `json:"resource_id,omitempty"`
	Source            Source       `json:"source"`
	Confidence        Confidence   `json:"confidence"`
	AttributionReason string       `json:"attribution_reason"`
	UpdatedAt         time.Time    `json:"updated_at"`
}
