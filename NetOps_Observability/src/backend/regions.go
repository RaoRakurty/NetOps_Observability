package backend

// regions.go — the canonical set of data-plane regions. A region is *where* a
// tenant's telemetry physically lives (data residency). Today regions are an
// attribute recorded on an Org/Tenant for governance and display; region-based
// routing of ingestion and storage to a per-region data plane is a later phase
// (see docs/design — SaaS orgs/regions). Keeping the list here means the Org
// layer can validate `home_region` now without coupling to deployment topology.

import (
	"errors"
	"sort"
	"strings"
)

// Region is a stable identifier for a data-residency zone. Values are slugs so
// they survive in URLs, index names and labels unchanged.
type Region = string

// RegionDefault is assigned when no region is specified. It must always be a
// member of the known set.
const RegionDefault Region = "us-east"

// knownRegions maps a region id to its human label. This is intentionally a
// small curated set — adding a region is a deliberate platform decision (it
// implies a data plane exists or will exist there), not free-form input.
var knownRegions = map[Region]string{
	"us-east":      "US East",
	"us-west":      "US West",
	"eu-central":   "EU Central",
	"eu-west":      "EU West",
	"ap-southeast": "Asia Pacific (Southeast)",
}

// RegionList returns the known regions sorted by id, each as {id,label}, for
// populating selectors. Stable order so the UI is deterministic.
func RegionList() []struct {
	ID    Region `json:"id"`
	Label string `json:"label"`
} {
	ids := make([]Region, 0, len(knownRegions))
	for id := range knownRegions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]struct {
		ID    Region `json:"id"`
		Label string `json:"label"`
	}, 0, len(ids))
	for _, id := range ids {
		out = append(out, struct {
			ID    Region `json:"id"`
			Label string `json:"label"`
		}{ID: id, Label: knownRegions[id]})
	}
	return out
}

// normalizeRegion defaults blank → RegionDefault and rejects unknown values.
// Zero-trust on input: a region the platform doesn't run is not accepted.
func normalizeRegion(r string) (Region, error) {
	r = strings.ToLower(strings.TrimSpace(r))
	if r == "" {
		return RegionDefault, nil
	}
	if _, ok := knownRegions[r]; ok {
		return r, nil
	}
	return "", errors.New("unknown region (us-east|us-west|eu-central|eu-west|ap-southeast)")
}
