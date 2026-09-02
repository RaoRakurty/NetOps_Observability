package threatlane

import (
	"errors"
	"fmt"

	"netops/backend/internal/vendorprofile"
)

// profile.go — the VENDOR PROFILE adapter (T9). The device-log detections in
// this package are TEXT matches and run on any log line they see; what varies
// per vendor is whether the rule's phrasing has been ASSESSED against that
// platform's log grammar. That claim is DECLARATIVE — the `threat.log_rule_ids`
// field of each vendor profile — so this package holds no vendor table.
//
// HONESTY. An empty declared set means UNASSESSED coverage for the platform, not
// "this platform has no threats", and a platform no profile claims is an error
// rather than a silent "all rules apply".

// ErrNoCoverage — the platform declares no assessed device-log coverage (or no
// profile claims it). The caller reports coverage as unassessed.
var ErrNoCoverage = errors.New("threatlane: no assessed device-log coverage for this vendor/platform")

// AssessedLogRules returns the catalog rules the vendor profile declares as
// ASSESSED for (vendor, platform), in catalog order. A declared id the catalog
// does not contain is a DRIFT error — the profile and the catalog must not
// disagree about which rules exist.
func AssessedLogRules(reg *vendorprofile.Registry, cat *Catalog, vendor, platform string) ([]LogRule, error) {
	if reg == nil || cat == nil {
		return nil, fmt.Errorf("%w: nil registry or catalog", ErrNoCoverage)
	}
	b, err := reg.ThreatFor(vendor, platform)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoCoverage, err)
	}
	if len(b.LogRuleIDs) == 0 {
		return nil, fmt.Errorf("%w: %s/%s declares no assessed log rules", ErrNoCoverage, vendor, platform)
	}
	want := make(map[string]struct{}, len(b.LogRuleIDs))
	for _, id := range b.LogRuleIDs {
		want[id] = struct{}{}
	}
	out := make([]LogRule, 0, len(want))
	for _, r := range cat.LogRules() {
		if _, ok := want[r.ID]; ok {
			out = append(out, r)
			delete(want, r.ID)
		}
	}
	if len(want) > 0 {
		for id := range want {
			return nil, fmt.Errorf("threatlane: vendor profile %s/%s declares unknown log rule %q (catalog drift)", vendor, platform, id)
		}
	}
	return out, nil
}

// MnemonicPrefixesFor returns the vendor log mnemonic prefixes the profile
// declares for (vendor, platform) — the tags a log-source classifier keys on.
func MnemonicPrefixesFor(reg *vendorprofile.Registry, vendor, platform string) ([]string, error) {
	if reg == nil {
		return nil, fmt.Errorf("%w: nil registry", ErrNoCoverage)
	}
	b, err := reg.ThreatFor(vendor, platform)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoCoverage, err)
	}
	return append([]string(nil), b.MnemonicPrefixes...), nil
}
