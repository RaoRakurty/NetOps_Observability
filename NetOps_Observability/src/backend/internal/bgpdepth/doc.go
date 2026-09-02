// Package bgpdepth is the "BGP depth" half of the BGP Operations page (frontend
// wave item 10): RPKI origin validation, ASPA, RFC 8805 geofeeds, an AS-path
// graph, and a near-live BGP update feed with a per-tenant bounded ring buffer.
//
// # Why a package and not more root code
//
// CLAUDE.md §2: the root package is the HTTP/composition boundary only. Every
// decision here (parsing untrusted registry text, building a capped graph,
// buffering updates) is domain logic with no HTTP in it, so it lives behind a
// compiler-enforced boundary and is unit-testable without a server. The root
// keeps a thin adapter (bgp_ops.go) that implements Fetcher and maps results to
// JSON.
//
// # Zero trust (§3)
//
// EVERY input to this package is untrusted: RIPEstat JSON, RDAP/whois records,
// and — worst of all — a geofeed URL that a third party published in a whois
// remark. Nothing here reaches the network without SafeOutboundURL + a dialer
// that re-checks the ACTUAL dialed IP (DNS-rebinding safe), every body is read
// through a byte cap, every parse is conservative (a malformed row is dropped,
// never guessed), and every collection is bounded before it is returned.
//
// # Honesty (no fabrication)
//
// Where a real public data source does not exist, this package says so instead
// of inventing one. Verified 2026-09-02 against the live services:
//
//   - RPKI    — RIPEstat "rpki-validation" (resource=<origin ASN>&prefix=<p>).
//     REAL, verified: returns {status, validating_roas[]} from Routinator.
//   - geofeed — discovery from the RIPEstat "whois" data call (an RFC 9092
//     "geofeed:" attribute, or the "Geofeed: <url>" remark/comment form), then
//     the RFC 8805 CSV itself. REAL, verified end to end on 104.28.0.0/16 →
//     https://api.cloudflare.com/local-ip-ranges.csv (5.4 MB, parsed).
//   - AS-path — RIPEstat "bgp-state" (path is a []int per collector peer) with
//     "looking-glass" (as_path strings) as the fallback. REAL, verified.
//   - updates — RIPEstat "bgp-updates". REAL, verified.
//   - ASPA    — NO PUBLIC PER-ASN SOURCE EXISTS. RIPEstat has no aspa data call
//     (stat.ripe.net/data/aspa and /data/rpki-aspa both 404, verified
//     2026-09-02); rpki-client's public console publishes ASPA only inside a
//     single ~104 MB global rpki.json with no per-ASN query, which blows any
//     bounded fetch budget; ASPA is still an IETF draft in deployment terms.
//     So ASPA ships as an HONEST "no ASPA source configured" card behind a
//     PLUGGABLE provider (see aspa.go): point BGP_ASPA_PROVIDER_URL at your own
//     validator (Routinator/rpki-client style per-ASN JSON) and the same panel
//     renders real data. We never fabricate an ASPA verdict.
//
// # Why a poller and not RIS Live
//
// RIPE's RIS Live is a WebSocket-only stream. A WebSocket client is not in the
// Go standard library and CLAUDE.md §6 permits no such dependency (the
// allowlist is pgx / x/crypto ssh / x/net ipv4+icmp — nothing else). Rather
// than hand-roll RFC 6455 framing (exactly the error-prone wire code §6 exists
// to prevent) or add a module, the feed is a BOUNDED, JITTERED POLLER over the
// plain-HTTP "bgp-updates" data call: near-live (one poll interval behind)
// instead of live, with a constant-size per-tenant ring buffer in front of it.
// If a vetted WebSocket capability ever lands, only feed.go's producer changes
// — the ring, the API shape and the UI stay exactly as they are.
package bgpdepth

// Env knobs (all optional; the feature is OFF unless the flag is "true").
const (
	// EnvFeatureFlag turns the near-live update feed on. Anything but "true"
	// leaves the poller dormant and /api/bgp/feed answering "not enabled".
	EnvFeatureFlag = "FEATURE_BGP_LIVE_FEED"

	// EnvASPAProviderURL points at an operator-run ASPA source. The URL is
	// called as <url>?asn=<n> and must answer the JSON shape documented in
	// aspa.go. Unset (the default) = the honest "not configured" card.
	EnvASPAProviderURL = "BGP_ASPA_PROVIDER_URL"
)
