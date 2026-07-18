package cloud

import "strings"

// tags.go — required-tag governance (Wave 4 #11 slice 1).
//
// The coverage/missing-tags surfaces used to hard-code the app/owner/env
// requirement (the resolve.go TODO: "make this list operator-configurable").
// This file is the pure half of that editor: given a tenant's required-tag
// list, report which required tags a resource is missing and how compliant an
// inventory is. The per-tenant list itself lives in the API layer's
// tenant-governance store; this package stays tenant-agnostic (the caller has
// already scoped the resources it passes in).

// DefaultRequiredTags is the requirement an unconfigured tenant gets — exactly
// the hard-coded behavior that existed before the editor (app/owner/env).
func DefaultRequiredTags() []string { return []string{"app", "owner", "env"} }

// tagAliases expands a required-tag name to the accepted key spellings. The
// three canonical categories reuse the attribution key conventions above
// (resolve.go), so "app" is satisfied by any key AttributeResource would read
// — a required tag must never be reported missing on a resource attribution
// just accepted. Any other name matches only itself (case-insensitive).
func tagAliases(name string) []string {
	switch name {
	case "app":
		return appTagKeys
	case "owner":
		return ownerTagKeys
	case "env":
		return envTagKeys
	}
	return []string{name}
}

// MissingTags reports which of the required tag names have NO non-empty value
// on the resource's tags (case-insensitive keys, alias-aware). Order follows
// the required list. nil/empty required → nothing is missing.
func MissingTags(tags map[string]string, required []string) []string {
	lower := make(map[string]string, len(tags))
	for k, v := range tags {
		if strings.TrimSpace(v) != "" {
			lower[strings.ToLower(strings.TrimSpace(k))] = v
		}
	}
	var out []string
	for _, req := range required {
		found := false
		for _, k := range tagAliases(strings.ToLower(strings.TrimSpace(req))) {
			if lower[k] != "" {
				found = true
				break
			}
		}
		if !found {
			out = append(out, req)
		}
	}
	return out
}

// TagComplianceReport summarizes required-tag compliance over an inventory —
// the per-tenant "how tagged are we" companion to CoverageReport.
type TagComplianceReport struct {
	RequiredTags []string       `json:"required_tags"`
	Total        int            `json:"total"`
	FullyTagged  int            `json:"fully_tagged"`
	MissingByTag map[string]int `json:"missing_by_tag"`
}

// TagCompliance tallies MissingTags over the (already tenant-scoped) resources.
func TagCompliance(resources []CloudResource, required []string) TagComplianceReport {
	rep := TagComplianceReport{RequiredTags: required, MissingByTag: map[string]int{}}
	for _, r := range resources {
		rep.Total++
		miss := MissingTags(r.Tags, required)
		if len(miss) == 0 {
			rep.FullyTagged++
			continue
		}
		for _, m := range miss {
			rep.MissingByTag[m]++
		}
	}
	return rep
}
