package main

import (
	"strings"
	"testing"

	"netops/backend/cloud"
)

func TestAWSConsoleResourceURL(t *testing.T) {
	cases := []struct {
		name, region, id, want string
	}{
		{"instance", "us-west-2", "i-0448c046139420a7f",
			"https://us-west-2.console.aws.amazon.com/ec2/home?region=us-west-2#InstanceDetails:instanceId=i-0448c046139420a7f"},
		{"eni", "us-west-2", "eni-0abc123",
			"https://us-west-2.console.aws.amazon.com/ec2/home?region=us-west-2#NetworkInterface:networkInterfaceId=eni-0abc123"},
		{"unknown id family", "us-west-2", "vol-0abc123", ""},
		{"empty region", "", "i-0abc", ""},
		{"hostile region", "us-west-2.evil.com", "i-0abc", ""},
		{"hostile id charset", "us-west-2", "i-0abc\"><script>", ""},
		{"hostile id scheme", "us-west-2", "javascript:alert(1)", ""}, // no i-/eni- prefix either
	}
	for _, c := range cases {
		if got := awsConsoleResourceURL(c.region, c.id); got != c.want {
			t.Errorf("%s: awsConsoleResourceURL(%q,%q) = %q, want %q", c.name, c.region, c.id, got, c.want)
		}
	}
}

func TestAWSTrailEventURL(t *testing.T) {
	got := awsTrailEventURL("us-west-2", "3a2b1c-event")
	want := "https://us-west-2.console.aws.amazon.com/cloudtrailv2/home?region=us-west-2#/events/3a2b1c-event"
	if got != want {
		t.Errorf("awsTrailEventURL = %q, want %q", got, want)
	}
	if awsTrailEventURL("us-west-2", "") != "" {
		t.Error("empty event id must yield no URL")
	}
	if awsTrailEventURL("", "ev-1") != "" {
		t.Error("missing region must yield no URL")
	}
}

func TestAzurePortalURLs(t *testing.T) {
	arm := "/subscriptions/8d0f8a4e-c36e-4265-821f-d6df48123c24/resourceGroups/correlix-faultlab/providers/Microsoft.Compute/virtualMachines/correlix-app-host-01"
	if got := azurePortalResourceURL(arm); got != "https://portal.azure.com/#resource"+arm {
		t.Errorf("azurePortalResourceURL = %q", got)
	}
	if got := azurePortalEventlogsURL(arm); !strings.HasSuffix(got, "/eventlogs") {
		t.Errorf("azurePortalEventlogsURL = %q, want /eventlogs suffix", got)
	}
	// A bare VM name is not an ARM id — no URL is guessed.
	if azurePortalResourceURL("correlix-app-host-01") != "" {
		t.Error("non-ARM id must yield no URL")
	}
	if azurePortalResourceURL("/subscriptions/x?y=<script>") != "" {
		t.Error("hostile ARM id must be refused")
	}
}

func TestConsoleRefLinks(t *testing.T) {
	idx := map[string]cloud.CloudResource{
		"i-0448c046139420a7f": {
			Provider: "aws", Region: "us-west-2", ResourceID: "i-0448c046139420a7f",
			ResourceName: "correlix-app-host-01",
		},
		// alias keys the index builds for the same resource
		"eni-0aa11bb22": {Provider: "aws", Region: "us-west-2", ResourceID: "i-0448c046139420a7f"},
		"10.60.10.10":   {Provider: "aws", Region: "us-west-2", ResourceID: "i-0448c046139420a7f"},
		"correlix-vpn-nat-01": {
			Provider: "azure", Region: "westus2", ResourceID: "correlix-vpn-nat-01",
			ResourceURI: "/subscriptions/8d0f8a4e/resourceGroups/correlix-faultlab/providers/Microsoft.Compute/virtualMachines/correlix-vpn-nat-01",
		},
	}

	t.Run("aws instance with region on the signal", func(t *testing.T) {
		c, l := consoleRefLinks(cloudEvidenceRef{Provider: "aws", ResourceID: "i-0448c046139420a7f", Region: "us-west-2", LogRef: "ev-123"}, idx)
		if !strings.Contains(c, "#InstanceDetails:instanceId=i-0448c046139420a7f") {
			t.Errorf("console = %q", c)
		}
		if !strings.Contains(l, "cloudtrailv2") || !strings.Contains(l, "ev-123") {
			t.Errorf("log = %q", l)
		}
	})

	t.Run("aws signal that only knew an IP resolves to the owning instance", func(t *testing.T) {
		c, _ := consoleRefLinks(cloudEvidenceRef{Provider: "aws", ResourceID: "10.60.10.10"}, idx)
		if !strings.Contains(c, "instanceId=i-0448c046139420a7f") {
			t.Errorf("console = %q — inventory should supply the instance id and region", c)
		}
	})

	t.Run("azure signal carrying only the VM name picks up the ARM id", func(t *testing.T) {
		c, l := consoleRefLinks(cloudEvidenceRef{Provider: "azure", ResourceID: "correlix-vpn-nat-01", LogRef: "corr-1"}, idx)
		if !strings.HasPrefix(c, "https://portal.azure.com/#resource/subscriptions/") {
			t.Errorf("console = %q", c)
		}
		if !strings.HasSuffix(l, "/eventlogs") {
			t.Errorf("log = %q", l)
		}
	})

	t.Run("unknown resource yields no links", func(t *testing.T) {
		c, l := consoleRefLinks(cloudEvidenceRef{Provider: "aws", ResourceID: "i-deadbeef"}, idx)
		if c != "" || l != "" {
			t.Errorf("expected no links without a region, got %q / %q", c, l)
		}
		c, l = consoleRefLinks(cloudEvidenceRef{Provider: "azure", ResourceID: "mystery-vm"}, idx)
		if c != "" || l != "" {
			t.Errorf("expected no links for an undeclared azure name, got %q / %q", c, l)
		}
	})

	t.Run("azure ARM id with uppercased resource group still resolves", func(t *testing.T) {
		// lookupCloudResource case-folds: Activity Log stamps the RG segment in
		// inconsistent case. The index stores the lowercased URI as an alias.
		armIdx := map[string]cloud.CloudResource{
			strings.ToLower("/subscriptions/8d0f/resourceGroups/correlix-faultlab/providers/Microsoft.Compute/virtualMachines/vm-1"): {
				Provider: "azure", ResourceID: "vm-1", ResourceName: "vm-1",
				ResourceURI: "/subscriptions/8d0f/resourceGroups/correlix-faultlab/providers/Microsoft.Compute/virtualMachines/vm-1",
			},
		}
		c, ok := lookupCloudResource(armIdx, "/subscriptions/8d0f/resourceGroups/CORRELIX-FAULTLAB/providers/Microsoft.Compute/virtualMachines/vm-1")
		if !ok || c.ResourceID != "vm-1" {
			t.Fatalf("case-folded ARM lookup failed: ok=%v c=%+v", ok, c)
		}
	})

	t.Run("no provider yields nothing", func(t *testing.T) {
		c, l := consoleRefLinks(cloudEvidenceRef{ResourceID: "i-0448c046139420a7f", Region: "us-west-2"}, idx)
		if c != "" || l != "" {
			t.Errorf("providerless ref must not link, got %q / %q", c, l)
		}
	})
}

func TestEnrichCloudRef(t *testing.T) {
	idx := map[string]cloud.CloudResource{
		"i-0e8a": {Provider: "aws", Region: "us-west-2", AccountID: "945714973156",
			ResourceID: "i-0e8a", ResourceName: "correlix-vpn-nat-01"},
	}
	// A flow-log signal: instance id but NO provider/region/account attrs.
	ref := enrichCloudRef(cloudEvidenceRef{ResourceID: "i-0e8a"}, idx)
	if ref.Provider != "aws" || ref.Region != "us-west-2" || ref.Account != "945714973156" {
		t.Fatalf("inventory backfill failed: %+v", ref)
	}
	if !strings.Contains(ref.ConsoleURL, "instanceId=i-0e8a") {
		t.Errorf("console url not built after backfill: %q", ref.ConsoleURL)
	}
	// An id nobody declared stays untouched and unlinked.
	ref = enrichCloudRef(cloudEvidenceRef{ResourceID: "sm-90375596da2d"}, idx)
	if ref.Provider != "" || ref.ConsoleURL != "" {
		t.Errorf("undeclared id must not be enriched: %+v", ref)
	}
}

func TestResourceConsoleURL(t *testing.T) {
	aws := cloud.CloudResource{Provider: "aws", Region: "us-west-2", ResourceID: "i-0448c046139420a7f"}
	if u := resourceConsoleURL(aws); !strings.Contains(u, "InstanceDetails") {
		t.Errorf("aws resource url = %q", u)
	}
	az := cloud.CloudResource{Provider: "azure", ResourceID: "correlix-app-host-01",
		ResourceURI: "/subscriptions/8d0f8a4e/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/correlix-app-host-01"}
	if u := resourceConsoleURL(az); !strings.HasPrefix(u, "https://portal.azure.com/#resource/subscriptions/") {
		t.Errorf("azure resource url = %q", u)
	}
	if u := resourceConsoleURL(cloud.CloudResource{Provider: "gcp", ResourceID: "vm-1"}); u != "" {
		t.Errorf("unsupported provider must not link, got %q", u)
	}
}
