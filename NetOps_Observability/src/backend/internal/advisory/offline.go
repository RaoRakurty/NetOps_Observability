package advisory

import (
	"context"
	"strings"

	"netops/backend/internal/vuln"
)

// OfflineProvider adapts the existing internal/vuln CSV feed to the
// VendorAdvisoryProvider seam. It is the FIRST provider on purpose (owner
// direction): it works with ZERO credentials, keeps the air-gapped
// operator-provisioned bundle the canonical path (§5g), and reuses the feed's
// already-tested version-constraint matcher (vuln.Feed.Match) rather than
// re-deriving matching. The existing /api/vulns behavior is untouched — this is
// an ADDITIVE adapter around the same *vuln.Feed.
type OfflineProvider struct {
	feed *vuln.Feed
}

// NewOfflineProvider wraps a loaded (or lazy-loading) *vuln.Feed. The feed's own
// lazy-load / mtime hot-reload semantics are preserved — AdvisoriesFor calls
// feed.Ensure() so a freshly re-prepared CSV lights up on the next lookup.
func NewOfflineProvider(feed *vuln.Feed) *OfflineProvider {
	return &OfflineProvider{feed: feed}
}

// Name identifies the offline feed provider.
func (p *OfflineProvider) Name() string { return SourceOfflineFeed }

// AdvisoriesFor returns the offline-feed advisories applying to the query. A
// feed that is not provisioned yet returns ErrNotProvisioned (the device is
// UNASSESSED, never a false clear, §5g); a provisioned feed with no matches
// returns (nil, nil) — genuinely assessed, none apply.
func (p *OfflineProvider) AdvisoriesFor(ctx context.Context, q Query) ([]Advisory, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.feed == nil || !p.feed.Ensure() {
		return nil, ErrNotProvisioned
	}
	// The feed stores vendor lowercased and normalizes product itself; lowercase
	// the vendor here to key consistently. Match applies the version constraint.
	entries := p.feed.Match(strings.ToLower(strings.TrimSpace(q.Vendor)), q.Platform, q.Version)
	if len(entries) == 0 {
		return nil, nil
	}
	out := make([]Advisory, 0, len(entries))
	for _, e := range entries {
		out = append(out, advisoryFromEntry(e))
	}
	return out, nil
}

// advisoryFromEntry maps one vuln.Entry into the owned Advisory shape. EPSS and
// EoLRelevant stay nil: the current CSV carries neither (they are enrichment a
// vendor provider supplies), so the offline path leaves them absent rather than
// inventing a value.
func advisoryFromEntry(e vuln.Entry) Advisory {
	return Advisory{
		CVE:       e.CVE,
		Severity:  normalizeSeverity(e.Severity),
		CVSS:      e.CVSS,
		KEV:       e.KEV,
		Summary:   e.Summary,
		Source:    SourceOfflineFeed,
		Published: e.Published,
		AffectedVersion: VersionConstraint{
			Exact:     e.Exact,
			StartIncl: e.StartIncl,
			StartExcl: e.StartExcl,
			EndIncl:   e.EndIncl,
			EndExcl:   e.EndExcl,
		},
	}
}
