package cloudconn

import "sort"

// CapabilityPack is a versioned, immutable-after-release bundle of what a
// connector is allowed to do. Permissions are declared here explicitly and can
// never be silently broadened: broadening = a NEW pack version. Each pack is
// least-privilege and read-only for the observer packs.
//
// A pack is the single source of truth the UI shows ("what will Correlix be able
// to read?"), the setup templates render (the exact IAM/role permissions), and
// the permission validator checks against.
type CapabilityPack struct {
	ID           string       `json:"id"`      // stable family id, e.g. "aws-observer"
	Version      string       `json:"version"` // immutable version, e.g. "v1"
	Provider     Provider     `json:"provider"`
	Title        string       `json:"title"`
	Summary      string       `json:"summary"`
	ReadOnly     bool         `json:"read_only"`
	Capabilities []Capability `json:"capabilities"`
}

// FullID is the immutable "<id>-<version>" token, e.g. "aws-observer-v1".
func (p CapabilityPack) FullID() string { return p.ID + "-" + p.Version }

// Capability is one observable lane inside a pack: which provider APIs it calls,
// the exact permissions it needs, what data it collects, and why it matters for RCA.
type Capability struct {
	Key           string   `json:"key"` // stable, e.g. "inventory", "metrics", "flow_logs"
	Title         string   `json:"title"`
	APIs          []string `json:"apis"`        // provider API surfaces touched
	Permissions   []string `json:"permissions"` // exact provider permission strings (least-privilege)
	ReadOnly      bool     `json:"read_only"`
	DataCollected string   `json:"data_collected"`
	RCAValue      string   `json:"rca_value"`
}

// AllPermissions returns the union of every capability's permissions, sorted and
// de-duplicated — the exact set the setup templates and validator use.
func (p CapabilityPack) AllPermissions() []string {
	seen := map[string]bool{}
	for _, c := range p.Capabilities {
		for _, perm := range c.Permissions {
			seen[perm] = true
		}
	}
	out := make([]string, 0, len(seen))
	for perm := range seen {
		out = append(out, perm)
	}
	sort.Strings(out)
	return out
}

// registry holds the built-in packs, keyed by FullID. It is populated once at
// init and never mutated → packs are immutable after release.
var registry = map[string]CapabilityPack{}

func register(p CapabilityPack) {
	registry[p.FullID()] = p
}

// Pack looks up a pack by its full id ("aws-observer-v1"). ok=false if unknown.
func Pack(fullID string) (CapabilityPack, bool) {
	p, ok := registry[fullID]
	return p, ok
}

// PacksForProvider returns the packs available for a provider, deterministically
// ordered by full id.
func PacksForProvider(p Provider) []CapabilityPack {
	out := make([]CapabilityPack, 0)
	for _, pk := range registry {
		if pk.Provider == p {
			out = append(out, pk)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullID() < out[j].FullID() })
	return out
}

func init() {
	// ── aws-observer-v1 ─ least-privilege, read-only. Mirrors the shipped
	// deployment/docker/cloud-ingest/iam-policy-aws.json permission surface.
	register(CapabilityPack{
		ID: "aws-observer", Version: "v1", Provider: ProviderAWS, ReadOnly: true,
		Title:   "AWS Observer (read-only)",
		Summary: "Read-only inventory, metrics, change-audit and flow-log telemetry for RCA. No mutating actions.",
		Capabilities: []Capability{
			{
				Key: "inventory", Title: "Inventory & topology", ReadOnly: true,
				APIs:          []string{"ec2", "directconnect"},
				Permissions:   []string{"ec2:Describe*", "directconnect:Describe*"},
				DataCollected: "EC2 instances, ENIs, VPCs, subnets, route tables, TGWs, Direct Connect virtual interfaces.",
				RCAValue:      "Builds the cloud-side topology and seam inventory RCA correlates faults against.",
			},
			{
				Key: "metrics", Title: "CloudWatch metrics", ReadOnly: true,
				APIs:          []string{"cloudwatch"},
				Permissions:   []string{"cloudwatch:GetMetricData", "cloudwatch:ListMetrics"},
				DataCollected: "CloudWatch metric series for the discovered resources.",
				RCAValue:      "Golden-signal series (util, errors, latency) feed anomaly detection + z-score baselining.",
			},
			{
				Key: "change_audit", Title: "Change audit", ReadOnly: true,
				APIs:          []string{"cloudtrail"},
				Permissions:   []string{"cloudtrail:LookupEvents"},
				DataCollected: "CloudTrail management-event lookups (config/route/security-group changes).",
				RCAValue:      "Correlates a fault onset to the change that caused it (change-as-cause evidence).",
			},
			{
				Key: "flow_logs", Title: "VPC flow logs", ReadOnly: true,
				APIs:          []string{"logs", "s3"},
				Permissions:   []string{"logs:GetLogEvents", "logs:DescribeLogStreams", "s3:GetObject", "s3:ListBucket"},
				DataCollected: "VPC flow-log records (CloudWatch Logs or S3 delivery).",
				RCAValue:      "Path/reachability evidence: which flows dropped, where the blackhole is.",
			},
		},
	})

	// ── azure-observer-v1 ─ least-privilege, read-only (Reader + Monitoring Reader).
	register(CapabilityPack{
		ID: "azure-observer", Version: "v1", Provider: ProviderAzure, ReadOnly: true,
		Title:   "Azure Observer (read-only)",
		Summary: "Read-only resource inventory, monitor metrics and activity-log change-audit for RCA.",
		Capabilities: []Capability{
			{
				Key: "inventory", Title: "Resource inventory & topology", ReadOnly: true,
				APIs:          []string{"Microsoft.Resources", "Microsoft.Network"},
				Permissions:   []string{"*/read"}, // granted via the built-in Reader role
				DataCollected: "Resource groups, VNets, subnets, NICs, VMs, gateways, ExpressRoute circuits.",
				RCAValue:      "Cloud-side topology + hybrid seam inventory for RCA correlation.",
			},
			{
				Key: "metrics", Title: "Azure Monitor metrics", ReadOnly: true,
				APIs:          []string{"Microsoft.Insights"},
				Permissions:   []string{"Microsoft.Insights/metrics/read", "Microsoft.Insights/metricDefinitions/read"},
				DataCollected: "Azure Monitor metric series for discovered resources.",
				RCAValue:      "Golden-signal series feed anomaly detection.",
			},
			{
				Key: "change_audit", Title: "Activity-log change audit", ReadOnly: true,
				APIs:          []string{"Microsoft.Insights"},
				Permissions:   []string{"Microsoft.Insights/eventtypes/values/read"},
				DataCollected: "Activity-log administrative events (change-audit).",
				RCAValue:      "Change-as-cause correlation on the Azure side.",
			},
		},
	})

	// ── gcp-observer-v1 ─ least-privilege, read-only (viewer roles).
	register(CapabilityPack{
		ID: "gcp-observer", Version: "v1", Provider: ProviderGCP, ReadOnly: true,
		Title:   "GCP Observer (read-only)",
		Summary: "Read-only compute inventory, monitoring metrics and logging for RCA.",
		Capabilities: []Capability{
			{
				Key: "inventory", Title: "Compute inventory & topology", ReadOnly: true,
				APIs:          []string{"compute.googleapis.com"},
				Permissions:   []string{"compute.instances.list", "compute.networks.list", "compute.subnetworks.list", "compute.routers.list"},
				DataCollected: "Instances, VPC networks, subnets, Cloud Routers, interconnect attachments.",
				RCAValue:      "Cloud-side topology + hybrid seam inventory.",
			},
			{
				Key: "metrics", Title: "Cloud Monitoring metrics", ReadOnly: true,
				APIs:          []string{"monitoring.googleapis.com"},
				Permissions:   []string{"monitoring.timeSeries.list", "monitoring.metricDescriptors.list"},
				DataCollected: "Cloud Monitoring time series for discovered resources.",
				RCAValue:      "Golden-signal series feed anomaly detection.",
			},
			{
				Key: "flow_logs", Title: "VPC flow logs", ReadOnly: true,
				APIs:          []string{"logging.googleapis.com"},
				Permissions:   []string{"logging.logEntries.list", "logging.logs.list"},
				DataCollected: "VPC flow-log entries from Cloud Logging.",
				RCAValue:      "Path/reachability evidence on the GCP side.",
			},
		},
	})
}
