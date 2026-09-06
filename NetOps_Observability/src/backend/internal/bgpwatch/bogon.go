// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpwatch

// bogon.go — tracker row #1.
//
// A BOGON is an address block that must never appear in the global routing
// table: RFC-reserved / special-purpose space, and space IANA has not delegated
// to any RIR. Seeing one in a feed is either a misconfiguration inside the
// operator's own network or someone announcing space they do not hold.
//
// ── The embedded set: SOURCE AND DATE (stated, not implied) ─────────────────
//
// The static half of this file is transcribed from, and current as of
// 2026-09-02:
//
//   - IANA IPv4 Special-Purpose Address Registry (RFC 6890 §2.2.2), the rows
//     whose "Globally Reachable" column is False.
//   - IANA IPv6 Special-Purpose Address Registry (RFC 6890 §2.2.3), same rule.
//   - RFC 1112 §4 (240.0.0.0/4), RFC 1122 §3.2.1.3 (0/8, 127/8),
//     RFC 1918 (private v4), RFC 2544 §C.2.2 (198.18.0.0/15),
//     RFC 3849 (2001:db8::/32), RFC 3927 (169.254.0.0/16),
//     RFC 4193 (fc00::/7), RFC 4291 (fe80::/10, ff00::/8),
//     RFC 5737 (TEST-NET-1/2/3), RFC 5771 (224.0.0.0/4),
//     RFC 6598 (100.64.0.0/10), RFC 6666 (100::/64),
//     RFC 7450 (192.52.193.0/24), RFC 7526 (192.88.99.0/24, 2002::/16),
//     RFC 7534/7535 (AS112), RFC 8215 (64:ff9b:1::/48),
//     RFC 9602 (5f00::/16), RFC 9637 (3fff::/20).
//
// UNALLOCATED SPACE, honestly:
//
//   - IPv4 has had NO unallocated unicast /8 since the IANA free pool was
//     exhausted on 2011-02-03. Every IPv4 block that is not in the
//     special-purpose registry above is delegated to an RIR. So the IPv4
//     "unallocated" half of a bogon list is EMPTY, and this file says so
//     instead of shipping a stale /8 table that would start false-positiving
//     the day it aged.
//   - IPv6 global unicast is 2000::/3 (RFC 4291 §2.4). Anything OUTSIDE it that
//     is not already a listed special-purpose block is undelegated space and is
//     reported as such (ReasonUnallocated). That rule is derived from the
//     address architecture, not from a snapshot, so it cannot go stale.
//
// The FULL-bogon list (unallocated-by-RIR /24s and more-specifics) genuinely
// does change daily and cannot be embedded honestly. That is what the OPTIONAL
// Team Cymru feed below is for: https-only, bounded, cached, retried with
// jitter, flag-gated and DEFAULT OFF.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Bogon reasons — a small closed vocabulary the UI can switch on.
const (
	ReasonSpecialPurpose = "special_purpose" // RFC/IANA reserved block
	ReasonUnallocated    = "unallocated"     // outside delegated global unicast
	ReasonFullBogonFeed  = "full_bogon_feed" // Team Cymru full-bogons row
)

// BogonEntry is one matched bogon block.
type BogonEntry struct {
	// Block is the reserved block that matched (e.g. "10.0.0.0/8"), NOT the
	// prefix that was tested — an operator needs to know which rule fired.
	Block  string `json:"block"`
	Reason string `json:"reason"`
	RFC    string `json:"rfc,omitempty"`
	Why    string `json:"why"`
}

// staticBogon is one row of the embedded table.
type staticBogon struct {
	cidr string
	rfc  string
	why  string
}

// staticBogonsV4 — IANA IPv4 Special-Purpose Address Registry, "Globally
// Reachable = False" rows, as of 2026-09-02.
var staticBogonsV4 = []staticBogon{
	{"0.0.0.0/8", "RFC 1122", `"This network" — only valid as a source during bootstrap`},
	{"10.0.0.0/8", "RFC 1918", "Private-use address space"},
	{"100.64.0.0/10", "RFC 6598", "Shared address space (carrier-grade NAT)"},
	{"127.0.0.0/8", "RFC 1122", "Loopback"},
	{"169.254.0.0/16", "RFC 3927", "Link-local (IPv4 autoconfiguration)"},
	{"172.16.0.0/12", "RFC 1918", "Private-use address space"},
	{"192.0.0.0/24", "RFC 6890", "IETF protocol assignments"},
	{"192.0.2.0/24", "RFC 5737", "Documentation (TEST-NET-1)"},
	{"192.31.196.0/24", "RFC 7535", "AS112-v4 redirection"},
	{"192.52.193.0/24", "RFC 7450", "Automatic multicast tunneling (AMT)"},
	{"192.88.99.0/24", "RFC 7526", "Deprecated 6to4 relay anycast"},
	{"192.168.0.0/16", "RFC 1918", "Private-use address space"},
	{"192.175.48.0/24", "RFC 7534", "Direct delegation AS112 service"},
	{"198.18.0.0/15", "RFC 2544", "Benchmarking / device testing"},
	{"198.51.100.0/24", "RFC 5737", "Documentation (TEST-NET-2)"},
	{"203.0.113.0/24", "RFC 5737", "Documentation (TEST-NET-3)"},
	{"224.0.0.0/4", "RFC 5771", "Multicast — never a unicast announcement"},
	{"240.0.0.0/4", "RFC 1112", "Reserved for future use (incl. 255.255.255.255)"},
}

// staticBogonsV6 — IANA IPv6 Special-Purpose Address Registry, same rule, as of
// 2026-09-02. (2000::/3 delegated global unicast is handled by the architecture
// rule in Lookup, not by a table row.)
var staticBogonsV6 = []staticBogon{
	{"::/128", "RFC 4291", "Unspecified address"},
	{"::1/128", "RFC 4291", "Loopback"},
	{"::ffff:0:0/96", "RFC 4291", "IPv4-mapped IPv6 address"},
	{"64:ff9b:1::/48", "RFC 8215", "Local-use IPv4/IPv6 translation"},
	{"100::/64", "RFC 6666", "Discard-only address block"},
	{"2001::/23", "RFC 2928", "IETF protocol assignments"},
	{"2001:db8::/32", "RFC 3849", "Documentation"},
	{"2002::/16", "RFC 7526", "Deprecated 6to4"},
	{"3fff::/20", "RFC 9637", "Documentation"},
	{"5f00::/16", "RFC 9602", "Segment Routing (SRv6) SIDs"},
	{"fc00::/7", "RFC 4193", "Unique-local addresses"},
	{"fe80::/10", "RFC 4291", "Link-local unicast"},
	{"ff00::/8", "RFC 4291", "Multicast — never a unicast announcement"},
}

// StaticSetDate is the transcription date of the embedded tables. It is served
// on the API so an operator can see how old the offline half of the answer is.
const StaticSetDate = "2026-09-02"

// StaticSetSource names where the embedded tables came from.
const StaticSetSource = "IANA IPv4/IPv6 Special-Purpose Address Registries (RFC 6890) + the RFCs listed in bogon.go"

// v6GlobalUnicast is RFC 4291 §2.4's delegated global unicast range. Anything
// outside it that is not already a listed special-purpose block is undelegated.
var v6GlobalUnicast = netip.MustParsePrefix("2000::/3")

// bogonRule is one compiled block.
type bogonRule struct {
	p      netip.Prefix
	reason string
	rfc    string
	why    string
}

// BogonSet is the compiled bogon table: the embedded static half plus, when the
// operator enabled it, the fetched full-bogons half. Safe for concurrent use.
type BogonSet struct {
	mu     sync.RWMutex
	static []bogonRule
	// feed rules are kept SEPARATE so a feed failure can never corrupt or
	// silently shrink the embedded half — the static answer always stands.
	feed      []bogonRule
	feedAt    time.Time
	feedURL   string
	feedErr   string
	feedCount int
}

// NewBogonSet compiles the embedded tables. It never fails at runtime: the
// literals are validated by TestStaticBogonTableParses, and a row that somehow
// failed to parse is DROPPED with the count reported rather than panicking a
// running server.
func NewBogonSet() *BogonSet {
	s := &BogonSet{}
	add := func(rows []staticBogon) {
		for _, r := range rows {
			p, err := netip.ParsePrefix(r.cidr)
			if err != nil {
				continue
			}
			s.static = append(s.static, bogonRule{p: p.Masked(), reason: ReasonSpecialPurpose, rfc: r.rfc, why: r.why})
		}
	}
	add(staticBogonsV4)
	add(staticBogonsV6)
	return s
}

// StaticCount is how many embedded blocks compiled.
func (s *BogonSet) StaticCount() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.static)
}

// Lookup reports whether p is a bogon and which rule matched.
//
// A prefix is a bogon when it is EQUAL TO or CONTAINED IN a reserved block —
// containment, not equality, because 10.1.2.0/24 is every bit as bogus as
// 10.0.0.0/8. A prefix that merely COVERS a reserved block (0.0.0.0/0 covers
// 10/8) is NOT reported: a default route is not a bogon announcement.
func (s *BogonSet) Lookup(p netip.Prefix) (BogonEntry, bool) {
	if s == nil || !p.IsValid() {
		return BogonEntry{}, false
	}
	p = p.Masked()
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Feed rules first: they are the more specific, more current answer.
	for _, set := range [][]bogonRule{s.feed, s.static} {
		for _, r := range set {
			if r.p.Addr().Is4() != p.Addr().Is4() {
				continue
			}
			if r.p.Bits() <= p.Bits() && r.p.Contains(p.Addr()) {
				return BogonEntry{Block: r.p.String(), Reason: r.reason, RFC: r.rfc, Why: r.why}, true
			}
		}
	}
	// The architecture rule: IPv6 outside 2000::/3 is not delegated global
	// unicast. Derived, so it cannot go stale like a snapshot table would.
	if p.Addr().Is6() && !p.Addr().Is4In6() && !v6GlobalUnicast.Contains(p.Addr()) {
		return BogonEntry{
			Block:  p.String(),
			Reason: ReasonUnallocated,
			RFC:    "RFC 4291",
			Why:    "Outside 2000::/3, the only IPv6 range delegated for global unicast",
		}, true
	}
	return BogonEntry{}, false
}

// FeedStatus is the honest state of the OPTIONAL full-bogons half.
type FeedStatus struct {
	Enabled   bool      `json:"enabled"`
	URL       string    `json:"url,omitempty"`
	Entries   int       `json:"entries"`
	FetchedAt time.Time `json:"fetched_at,omitempty"`
	Error     string    `json:"error,omitempty"`
	// Note is set when the feed is off, so an empty full-bogon half reads as
	// "not enabled" and never as "nothing is bogus".
	Note string `json:"note,omitempty"`
}

// FeedStatus returns the current state of the fetched half.
func (s *BogonSet) FeedStatus(enabled bool) FeedStatus {
	st := FeedStatus{Enabled: enabled}
	if s == nil {
		return st
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	st.URL, st.Entries, st.FetchedAt, st.Error = s.feedURL, s.feedCount, s.feedAt, s.feedErr
	if !enabled {
		st.Note = "Only the embedded RFC/IANA special-purpose set is in force. Set " +
			EnvBogonFeed + "=true to also fetch the Team Cymru full-bogons list (unallocated-by-RIR space, which changes daily)."
	}
	return st
}

// Bogon feed bounds (§9 — nothing here is unbounded).
const (
	// DefaultFeedURL is Team Cymru's public full-bogons text list. It is a
	// plain-text file of one CIDR per line, free to fetch, no credential.
	DefaultFeedURL = "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt"
	// FeedMaxBytes caps the fetched body. The v4 list is ~100 KB.
	FeedMaxBytes = 4 << 20
	// FeedMaxEntries caps how many rows are compiled from one fetch.
	FeedMaxEntries = 20000
	// FeedTTL is how long a successful fetch stands before a refetch.
	FeedTTL = 6 * time.Hour
	// feedAttempts bounds the retry loop.
	feedAttempts = 3
)

// FeedGetter is the injected bounded HTTPS fetch. internal/bgpdepth's Fetcher
// satisfies it (SafeOutboundURL + a dialer that refuses non-public addresses +
// a hard byte cap), which is exactly the gate a third-party URL needs.
type FeedGetter interface {
	Get(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error)
}

// RefreshFeed fetches and compiles the full-bogons list. It is a NO-OP when the
// cached copy is younger than FeedTTL, retries with exponential backoff + full
// jitter, and on failure LEAVES THE PREVIOUS ROWS IN PLACE while recording the
// error — a feed outage must not silently un-bogon anything.
func (s *BogonSet) RefreshFeed(ctx context.Context, g FeedGetter, rawURL string, now func() time.Time,
	sleep func(context.Context, time.Duration) error, jitter func() float64) error {
	if s == nil {
		return errors.New("bgpwatch: nil bogon set")
	}
	if g == nil {
		return errors.New("bgpwatch: no fetcher for the full-bogons feed")
	}
	if strings.TrimSpace(rawURL) == "" {
		rawURL = DefaultFeedURL
	}
	s.mu.RLock()
	fresh := !s.feedAt.IsZero() && now().Sub(s.feedAt) < FeedTTL
	s.mu.RUnlock()
	if fresh {
		return nil
	}

	var lastErr error
	backoff := 2 * time.Second
	for attempt := 0; attempt < feedAttempts; attempt++ {
		if attempt > 0 {
			wait := time.Duration(jitter() * float64(backoff))
			if err := sleep(ctx, wait); err != nil {
				return err
			}
			backoff *= 2
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		body, err := g.Get(ctx, rawURL, FeedMaxBytes)
		if err != nil {
			lastErr = err
			continue
		}
		rules, kept, dropped := parseFullBogons(string(body))
		if kept == 0 {
			lastErr = fmt.Errorf("full-bogons feed held no parsable CIDR rows (%d unparsable)", dropped)
			continue
		}
		s.mu.Lock()
		s.feed, s.feedCount, s.feedAt, s.feedURL, s.feedErr = rules, kept, now(), rawURL, ""
		s.mu.Unlock()
		return nil
	}
	s.mu.Lock()
	s.feedURL = rawURL
	if lastErr != nil {
		s.feedErr = lastErr.Error()
	}
	s.mu.Unlock()
	return fmt.Errorf("full-bogons feed unreachable after %d attempts: %w", feedAttempts, lastErr)
}

// parseFullBogons compiles the text list. It is deliberately CONSERVATIVE: a
// row it cannot read is dropped and counted, never guessed at — a mis-parsed
// bogon row would blackhole a real customer prefix on someone's screen.
func parseFullBogons(body string) (rules []bogonRule, kept, dropped int) {
	for _, line := range strings.Split(body, "\n") {
		if kept >= FeedMaxEntries {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			dropped++
			continue
		}
		rules = append(rules, bogonRule{
			p:      p.Masked(),
			reason: ReasonFullBogonFeed,
			why:    "Listed in the Team Cymru full-bogons feed (space not delegated to any RIR, or reserved)",
		})
		kept++
	}
	return rules, kept, dropped
}

// ── sightings ───────────────────────────────────────────────────────────────

// SightingMaxPerTenant bounds the per-tenant sighting register (§9).
const SightingMaxPerTenant = 200

// Sighting is one observation of a bogon prefix, with the vantage point that
// saw it and the window it has been seen over.
type Sighting struct {
	Prefix    string     `json:"prefix"`
	Entry     BogonEntry `json:"entry"`
	Source    string     `json:"source"` // "watchlist" | "feed" | "bmp"
	Peer      string     `json:"peer,omitempty"`
	Origin    uint32     `json:"origin,omitempty"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	Count     int        `json:"count"`
}

// sightingKey identifies one (prefix, source, peer) sighting.
type sightingKey struct{ prefix, source, peer string }

// sightingRegister is the bounded per-tenant register. Isolation lives IN the
// store (§3a rule 4): every method takes a concrete tenant and there is no
// method that returns more than one tenant's rows.
type sightingRegister struct {
	mu   sync.Mutex
	rows map[string]map[sightingKey]*Sighting
}

func newSightingRegister() *sightingRegister {
	return &sightingRegister{rows: map[string]map[sightingKey]*Sighting{}}
}

// note records one sighting for ONE tenant, returning true when it is NEW
// (first time this (prefix, source, peer) has been seen) so the caller can
// alert on the transition rather than on every evaluation.
func (r *sightingRegister) note(tenant string, s Sighting) bool {
	tenant = normTenant(tenant)
	if tenant == "" || tenant == "*" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	per := r.rows[tenant]
	if per == nil {
		per = map[sightingKey]*Sighting{}
		r.rows[tenant] = per
	}
	k := sightingKey{prefix: s.Prefix, source: s.Source, peer: s.Peer}
	if ex, ok := per[k]; ok {
		ex.LastSeen = s.LastSeen
		ex.Count++
		ex.Entry = s.Entry
		return false
	}
	if len(per) >= SightingMaxPerTenant {
		// Bounded: evict the stalest row rather than growing without limit.
		var oldest sightingKey
		var oldestAt time.Time
		first := true
		for kk, vv := range per {
			if first || vv.LastSeen.Before(oldestAt) {
				oldest, oldestAt, first = kk, vv.LastSeen, false
			}
		}
		delete(per, oldest)
	}
	cp := s
	cp.Count = 1
	per[k] = &cp
	return true
}

// list returns ONE tenant's sightings, newest-last-seen first. A caller with no
// concrete tenant gets an empty list — never the fleet's.
func (r *sightingRegister) list(tenant string, limit int) []Sighting {
	tenant = normTenant(tenant)
	out := []Sighting{}
	if tenant == "" || tenant == "*" {
		return out
	}
	r.mu.Lock()
	for _, v := range r.rows[tenant] {
		out = append(out, *v)
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Prefix < out[j].Prefix
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
