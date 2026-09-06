// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package audit

// platformtrail.go — the LONG-LIVED half of the file audit backend (tracker 235).
//
// THE INCIDENT. `data/api/audit.json` is a 5,000-event ring shared by every
// authenticated request. On 2026-09-03 it spanned 07:57Z → 12:02Z: FOUR HOURS.
// When the question was "who disabled the snapshot schedule in the GUI, and
// when?", the answer was unrecoverable — the event had aged out behind a wall
// of ordinary reads, and the reconstruction had to come from the SM policy's
// enabled_time and the ABSENCE of an 01:30 snapshot. Backup posture, auth
// providers, LLM keys, token policy and notification channels are exactly the
// changes that get questioned days later, and they were the cheapest thing in
// the ring to lose: one per week, evicted by thousands of GETs per hour.
//
// THE FIX. A platform-global CONFIG CHANGE is written to a SECOND, separately
// bounded trail as well as to the request ring, and reads merge the two. The
// separation is what makes the horizon affordable: the file backend rewrites
// its whole blob on every append, so a 90-day request ring would rewrite
// megabytes per request — while the retained trail is appended only when
// platform plumbing actually CHANGES, which is a handful of events a week.
//
// WHAT IT DOES NOT DO. It is not a compliance archive and does not pretend to
// be: it is bounded in both age and count, it says what it dropped and when
// (never a silent eviction, §10), and the Postgres backend remains the durable
// path for a deployment that needs one. What it guarantees is the property the
// incident wanted: a platform-global change stays attributable long after the
// request ring has rolled.

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/applog"
)

// Trail defaults. Conservative on purpose: 90 days is the horizon a "who
// changed this?" question is actually asked over, and 20,000 events is roughly
// 8 MB of JSON — a ceiling this file states rather than discovers.
const (
	DefaultTrailDays      = 90
	DefaultTrailMaxEvents = 20000
	// TrailMaxEventsCeiling is the hard upper bound an operator may configure.
	// The whole trail is marshalled on every retained append, so an unbounded
	// (or merely enormous) setting would turn a config change into a
	// multi-megabyte synchronous write. 200,000 events ~ 80 MB, which is the
	// most this SHAPE of store can honestly carry.
	TrailMaxEventsCeiling = 200000
)

// Env var names, in one place so main's read and this package's parse cannot
// drift.
const (
	EnvTrailDays      = "AUDIT_PLATFORM_TRAIL_DAYS"
	EnvTrailMaxEvents = "AUDIT_PLATFORM_TRAIL_MAX_EVENTS"
)

// TrailPolicy bounds the retained platform trail in BOTH dimensions, because
// either one alone fails: an age bound alone cannot stop a burst from filling
// the disk, and a count bound alone lets a quiet deployment keep events from
// years ago while a busy one keeps a week.
type TrailPolicy struct {
	// Days is the age horizon. <= 0 means "no age bound" — the trail is then
	// bounded only by MaxEvents, which is never unbounded.
	Days int
	// MaxEvents is the hard ceiling on retained events. Always positive.
	MaxEvents int
}

// DefaultTrailPolicy is what an operator who configures nothing gets.
func DefaultTrailPolicy() TrailPolicy {
	return TrailPolicy{Days: DefaultTrailDays, MaxEvents: DefaultTrailMaxEvents}
}

// ParseTrailPolicy reads the policy from the two raw env values. It is the
// ParseRetentionDays precedent with the OPPOSITE default, and deliberately so:
// retention there DELETES evidence, so an operator typo must leave it off;
// here a typo must leave the trail RETAINING, so an unparseable value falls
// back to the default horizon rather than to "keep nothing".
//
// "0" for days is a real choice ("no age bound"), not a typo, and is honoured.
// A count over TrailMaxEventsCeiling is clamped, not refused: refusing would
// leave the trail unconfigured at boot, and clamping is the safe direction.
// Every deviation from what was asked for is logged.
func ParseTrailPolicy(daysRaw, maxRaw string) TrailPolicy {
	p := DefaultTrailPolicy()
	if s := strings.TrimSpace(daysRaw); s != "" {
		n, err := strconv.Atoi(s)
		switch {
		case err != nil:
			applog.Error("audit", "invalid "+EnvTrailDays+" — keeping the default horizon",
				map[string]any{"value": daysRaw, "retention_days": p.Days})
		case n < 0:
			applog.Error("audit", "negative "+EnvTrailDays+" — keeping the default horizon",
				map[string]any{"value": daysRaw, "retention_days": p.Days})
		default:
			p.Days = n // 0 = no age bound, an explicit and honoured choice
		}
	}
	if s := strings.TrimSpace(maxRaw); s != "" {
		n, err := strconv.Atoi(s)
		switch {
		case err != nil || n <= 0:
			applog.Error("audit", "invalid "+EnvTrailMaxEvents+" — keeping the default ceiling",
				map[string]any{"value": maxRaw, "max_events": p.MaxEvents})
		case n > TrailMaxEventsCeiling:
			applog.Error("audit", EnvTrailMaxEvents+" above the ceiling this store can carry — clamped",
				map[string]any{"value": maxRaw, "ceiling": TrailMaxEventsCeiling})
			p.MaxEvents = TrailMaxEventsCeiling
		default:
			p.MaxEvents = n
		}
	}
	return p
}

// platformPathPrefixes is the closed list of PLATFORM-GLOBAL route prefixes —
// the stack's own plumbing, which belongs to no tenant and which CLAUDE.md §3a
// rule 3 gates behind requirePlatformAdmin/requireCrossTenant.
//
// It is a prefix list rather than a per-route table because these routes carry
// ids and sub-paths (/api/auth/providers/{id}, /api/system/backup/schedule),
// and it is PROVEN COMPLETE rather than trusted: the root package's
// TestEveryPlatformRouteIsRetainedInTheAuditTrail walks every route the
// isolation ledger classifies "platform" and fails if a mutation on it would
// not be retained here. A new platform route therefore cannot quietly land
// outside the trail.
//
// Ordinary tenant-scoped writes are deliberately NOT here. They are business
// data with their own histories; this trail exists for the changes whose only
// record IS the audit trail.
var platformPathPrefixes = []string{
	"/api/admin/",  // platform administration surfaces
	"/api/auth/",   // identity providers, LDAP/TACACS/OIDC/SSO config, token policy
	"/api/system/", // stack config: backup posture, network, TLS, licence
	"/api/notify/", // notification channels + their test sends
	"/api/debug/",  // the pipeline debugger's platform-admin surfaces
	"/api/cloud/ingest/",
	"/api/automation/", // NetBox integration + sync
	"/api/integrations/",
	"/api/credentials", // integration credential posture
	"/api/copilot/",    // LLM provider configuration
	"/api/ai/tenants",  // per-tenant AI enablement, set platform-side
	"/api/discovery/config",
	"/api/discovery/refresh",
	"/api/security/transport-posture/",
	"/api/reports/channels",
	"/api/exports/policy",
	"/api/breakglass",
	"/api/onboard",
	"/api/quarantine",
	// The tenancy tree and platform identity. Not "platform" in the route
	// ledger's sense (they are adminScoped/scoped) but they are exactly the
	// kind of change questioned days later — who created that tenant, who
	// minted that API key — and they are low-volume.
	"/api/orgs",
	"/api/tenants",
	"/api/users",
	"/api/roles",
	"/api/apikeys",
}

// platformPathExclusions are checked FIRST: paths that sit under a retained
// prefix but are not platform CONFIG at all.
//
// Two reasons, and both matter. Volume: /api/auth/login and /api/auth/refresh
// are the highest-frequency POSTs on the platform, and retaining them would
// evict real config changes out of a trail sized for a handful a week —
// re-creating the very defect this file exists to fix, one level down.
// Meaning: /api/auth/me, the MFA self-service routes and an inbound webhook are
// a user acting on themselves or a third party calling in, not an operator
// changing the stack.
//
// The root package's TestEveryPlatformRouteIsRetainedInTheAuditTrail enforces
// BOTH directions against the route ledger: every "platform" route must be
// retained, and no "public", "selfScoped" or "token" route may be.
var platformPathExclusions = []string{
	"/api/auth/login",
	"/api/auth/logout",
	"/api/auth/refresh",
	"/api/auth/methods",
	"/api/auth/console-gate",
	"/api/auth/osd-gate",
	"/api/auth/password-policy",
	"/api/auth/me",
	"/api/auth/permissions",
	"/api/auth/change-password",
	"/api/auth/mfa/",
	"/api/auth/sso/login",
	"/api/auth/sso/callback",
	"/api/auth/ldap/login",
	"/api/auth/tacacs/login",
	"/api/copilot/chat",
	"/api/integrations/webhook/",
	"/api/notify/contact-points",
	"/api/notify/itsm",
	"/api/system/licence/usage",
}

// IsPlatformChange reports whether an event is a platform-global CONFIG CHANGE
// — the class the request ring must not be allowed to evict.
//
// A change is a MUTATING method on a platform-global path. Both allowed and
// DENIED attempts are retained: "who tried to rotate the LLM key and was
// refused" is exactly as much a part of the record as who succeeded, and a
// trail that kept only successes would answer the wrong question during an
// investigation.
func IsPlatformChange(e Event) bool {
	switch e.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}
	return IsPlatformPath(e.Path)
}

// IsPlatformPath reports whether a request path names platform-global plumbing.
// Exported so the completeness guard can walk the route ledger against it.
func IsPlatformPath(path string) bool {
	p := strings.TrimSpace(path)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if matchesPrefix(p, platformPathExclusions) {
		return false
	}
	return matchesPrefix(p, platformPathPrefixes)
}

// matchesPrefix reports whether p is one of the listed prefixes or sits under
// one. A trailing "/" in a prefix still matches the bare route ("/api/notify/"
// matches "/api/notify"), which is how the route table spells a subtree.
func matchesPrefix(p string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if p == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// TrailStats is what the retained trail is currently holding, and what it has
// had to let go. Dropped is CUMULATIVE for the process: an eviction is a real
// loss of attribution and must be countable, not merely loggable.
type TrailStats struct {
	Policy  TrailPolicy
	Kept    int
	Dropped int64
	Oldest  time.Time // zero when the trail is empty
}

// pruneTrail applies the policy to a time-ordered slice and reports how many it
// removed. Age first, then count: dropping a 91-day-old event because it is old
// is the policy working; dropping a two-day-old one because the ceiling was hit
// is the policy being NARROWER than the operator asked for, and the caller logs
// that case distinctly.
func pruneTrail(events []Event, p TrailPolicy, now time.Time) (kept []Event, byAge, byCount int) {
	if p.Days > 0 {
		cutoff := now.AddDate(0, 0, -p.Days)
		out := events[:0:0]
		for _, e := range events {
			if e.Time.Before(cutoff) {
				byAge++
				continue
			}
			out = append(out, e)
		}
		events = out
	}
	max := p.MaxEvents
	if max <= 0 {
		max = DefaultTrailMaxEvents
	}
	if len(events) > max {
		byCount = len(events) - max
		events = events[len(events)-max:]
	}
	return events, byAge, byCount
}
