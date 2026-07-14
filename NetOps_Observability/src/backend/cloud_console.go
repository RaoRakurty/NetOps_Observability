package main

// Console deep-links — the pivot from a Correlix row to the provider's own
// console (AWS console / Azure portal). Built SERVER-side so the URL formats
// live in one audited place, resolve through the tenant's DECLARED inventory
// (Azure signals often carry a VM name; the portal needs the ARM id), and can
// later be reused by the RCA report. An id we cannot resolve, or that fails the
// charset gate, yields "" — we never guess or emit a hostile URL.

import (
	"net/http"
	"regexp"
	"strings"

	"netops/backend/cloud"
)

// cloudIDPattern bounds every identifier embedded in a console URL. Provider
// handles (i-…, eni-…, ARM paths, CloudTrail event ids) are alphanumerics plus
// . _ / : - ; anything else is refused outright.
var cloudIDPattern = regexp.MustCompile(`^[A-Za-z0-9._/:-]+$`)

// awsRegionPattern — AWS region names (us-west-2, eu-central-1, …).
var awsRegionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d$`)

// awsConsoleResourceURL deep-links an EC2-scoped resource. Only id families the
// console actually routes are linked; an unknown family returns "".
func awsConsoleResourceURL(region, id string) string {
	if !awsRegionPattern.MatchString(region) || !cloudIDPattern.MatchString(id) {
		return ""
	}
	base := "https://" + region + ".console.aws.amazon.com/ec2/home?region=" + region
	switch {
	case strings.HasPrefix(id, "i-"):
		return base + "#InstanceDetails:instanceId=" + id
	case strings.HasPrefix(id, "eni-"):
		return base + "#NetworkInterface:networkInterfaceId=" + id
	}
	return ""
}

// awsTrailEventURL deep-links one CloudTrail event record.
func awsTrailEventURL(region, eventID string) string {
	if !awsRegionPattern.MatchString(region) || eventID == "" || !cloudIDPattern.MatchString(eventID) {
		return ""
	}
	return "https://" + region + ".console.aws.amazon.com/cloudtrailv2/home?region=" + region + "#/events/" + eventID
}

// azurePortalResourceURL deep-links an ARM resource id into the portal.
func azurePortalResourceURL(armID string) string {
	if !strings.HasPrefix(armID, "/subscriptions/") || !cloudIDPattern.MatchString(armID) {
		return ""
	}
	return "https://portal.azure.com/#resource" + armID
}

// azurePortalEventlogsURL opens the resource's Activity Log blade — the portal
// has no stable per-event deep-link, so the blade is the honest landing.
func azurePortalEventlogsURL(armID string) string {
	u := azurePortalResourceURL(armID)
	if u == "" {
		return ""
	}
	return u + "/eventlogs"
}

// cloudResourceIndex — the tenant's declared cloud inventory keyed by every
// handle a signal can carry: the resource id, the ARN/ARM URI (Activity Log
// stamps the ARM path, not the VM name), its ENIs, its private/public IPs.
// ARM paths are case-insensitive on the resource-group segment, so URIs are
// additionally keyed lowercased; look up via lookupCloudResource.
func (s *server) cloudResourceIndex(r *http.Request) map[string]cloud.CloudResource {
	res, _, _, err := s.cloudResources(r)
	if err != nil || len(res) == 0 {
		return nil
	}
	idx := make(map[string]cloud.CloudResource, len(res))
	put := func(key string, rs cloud.CloudResource) {
		if key == "" {
			return
		}
		if _, ok := idx[key]; !ok {
			idx[key] = rs
		}
	}
	for _, rs := range res {
		idx[rs.ResourceID] = rs
		put(rs.ResourceURI, rs)
		put(strings.ToLower(rs.ResourceURI), rs)
		for _, eni := range rs.NetworkInterfaceIDs {
			put(eni, rs)
		}
		for _, ip := range append(append([]string{}, rs.PrivateIPs...), rs.PublicIPs...) {
			put(ip, rs)
		}
	}
	return idx
}

// lookupCloudResource resolves a signal handle against the index: exact first,
// then case-folded (Azure ARM ids arrive with inconsistent resource-group case).
func lookupCloudResource(idx map[string]cloud.CloudResource, id string) (cloud.CloudResource, bool) {
	id = strings.TrimSpace(id)
	if c, ok := idx[id]; ok {
		return c, true
	}
	c, ok := idx[strings.ToLower(id)]
	return c, ok
}

// namerFromIndex — id → operator name resolver over the inventory index.
// Returns "" for anything the inventory does not claim: we never invent a name.
func namerFromIndex(idx map[string]cloud.CloudResource) func(string) string {
	if len(idx) == 0 {
		return nil
	}
	return func(id string) string {
		c, ok := lookupCloudResource(idx, id)
		if !ok {
			return ""
		}
		if c.ResourceName != "" {
			return c.ResourceName
		}
		return c.AppName
	}
}

// enrichCloudRef fills identity gaps from the DECLARED inventory (provider,
// region, account — e.g. flow-log signals carry an instance id but no provider
// attr) and builds the console links. Only fields the signal did not carry are
// filled, and only from what the tenant itself declared — never a guess.
func enrichCloudRef(ref cloudEvidenceRef, idx map[string]cloud.CloudResource) cloudEvidenceRef {
	if c, ok := lookupCloudResource(idx, ref.ResourceID); ok {
		if ref.Provider == "" {
			ref.Provider = string(c.Provider)
		}
		if ref.Region == "" {
			ref.Region = c.Region
		}
		if ref.Account == "" {
			ref.Account = c.AccountID
		}
	}
	ref.ConsoleURL, ref.LogURL = consoleRefLinks(ref, idx)
	return ref
}

// consoleRefLinks resolves a cloud_ref to (console URL, provider-log URL).
// The inventory fills what the signal did not carry: an AWS signal that only
// knew an IP/ENI links to the owning resource; an Azure signal that only knew
// the VM name picks up the ARM id. Unresolvable ⇒ "".
func consoleRefLinks(ref cloudEvidenceRef, idx map[string]cloud.CloudResource) (consoleURL, logURL string) {
	id := strings.TrimSpace(ref.ResourceID)
	region := ref.Region
	owner, inInv := lookupCloudResource(idx, id)
	if region == "" && inInv {
		region = owner.Region
	}
	switch strings.ToLower(ref.Provider) {
	case "aws":
		consoleURL = awsConsoleResourceURL(region, id)
		if consoleURL == "" && inInv {
			consoleURL = awsConsoleResourceURL(region, owner.ResourceID)
		}
		if ref.LogRef != "" {
			logURL = awsTrailEventURL(region, ref.LogRef)
		}
	case "azure":
		arm := id
		if !strings.HasPrefix(arm, "/subscriptions/") && inInv {
			arm = owner.ResourceURI
		}
		consoleURL = azurePortalResourceURL(arm)
		if ref.LogRef != "" {
			logURL = azurePortalEventlogsURL(arm)
		}
	}
	return consoleURL, logURL
}

// resourceConsoleURL — the console pivot for a declared inventory resource
// (the Resources tab / drawer).
func resourceConsoleURL(rs cloud.CloudResource) string {
	switch strings.ToLower(string(rs.Provider)) {
	case "aws":
		return awsConsoleResourceURL(rs.Region, rs.ResourceID)
	case "azure":
		arm := rs.ResourceURI
		if arm == "" && strings.HasPrefix(rs.ResourceID, "/subscriptions/") {
			arm = rs.ResourceID
		}
		return azurePortalResourceURL(arm)
	}
	return ""
}
