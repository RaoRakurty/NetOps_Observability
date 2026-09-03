// Package bgpwatch is the BGP watchlist EVALUATOR: the half of the BGP
// Operations page that watches, classifies and ALERTS, rather than answering a
// question an operator typed.
//
// It closes four rows of docs/design/BGP_OPS_CAPABILITY_TRACKER_2026-09-02.md:
//
//	#10 alerting              — a per-tenant, bounded, jittered evaluator that
//	                            emits notifications + correlation evidence.
//	#5  leak/hijack classes   — one classifier (Classify) producing an incident
//	                            class per watched prefix, with evidence and
//	                            first/last seen. The SAME classifier drives #10;
//	                            there is exactly one implementation.
//	#4  peers                 — PeerObservation feeds the "peer down" alert; the
//	                            table itself is the frontend's Peers tab.
//	#1  bogons                — an embedded IANA/RFC special-purpose set plus an
//	                            OPTIONAL Team Cymru full-bogons feed, checked
//	                            against the watchlist and the observed feeds.
//
// # Why a package and not more root code
//
// CLAUDE.md §2: the root package is the HTTP/composition boundary only. Nothing
// here opens a socket, reads an environment variable or holds ambient
// authority — every collaborator arrives through Deps (§5 interfaces for
// external dependencies), which is what makes the whole evaluator unit-testable
// with no network, no bus, no Postgres and no clock (§11: CI is offline).
//
// # Zero trust (§3) and tenancy (§3a)
//
// Every input is untrusted: RIPEstat JSON reaches this package already decoded
// by internal/bgpdepth, a bogon feed is third-party TEXT, and a BMP peer state
// came off the wire from a customer router. Every collection is bounded before
// it is stored or returned, every copied string is clipped, and every read and
// write in this package takes a CONCRETE tenant — there is no unscoped "list
// all" anywhere, not even an internal one, and the alert ring, the sighting
// ring, the incident map and the policy store are all keyed by tenant.
//
// # Honesty (§10, no silent failure)
//
//   - A class is only ever asserted from MEASURED evidence. A single collector
//     peer holding a stale path is NOT an origin change: every path-derived
//     class needs corroboration from at least MinVantages distinct vantage
//     points (PolicyConfig.MinVantages, default 2), and the vantage points that
//     supported the verdict are named in the evidence.
//   - A failed upstream lookup is an ERROR on the observation, never a verdict.
//     "We could not measure this prefix" and "this prefix is fine" are different
//     answers and this package never conflates them.
//   - Full valley-free leak detection needs AS provider/customer relationships
//     that no free source publishes per-ASN. What IS derivable from the tenant's
//     own DECLARED upstream set is derived (see classify.go), and the rest is
//     declared missing rather than guessed.
//
// # The correlation seam (evidence events)
//
// The evaluator publishes a GENERIC evidence event — byte-for-byte the envelope
// shape internal/secbus emits and src/correlation/signals.py's
// evidence_signal_from_event consumes (schema_version, tenant_id, ts, kind,
// entity_id, entity_type, entity_tokens, severity, native_id, attrs) — onto its
// own topic, DefaultEvidenceTopic. See evidence.go's "GROUNDING SEAM" note for
// the one engine-side data row that turns these into correlation signals; this
// package deliberately contains no engine code and the engine contains no
// bgpwatch code.
package bgpwatch

// Env knobs. This package READS none of them — the integrator (the root
// package) does, and hands the values in through Deps. They are declared here
// so the contract lives with the code it configures.
const (
	// EnvFeatureFlag gates the whole evaluator. Default FALSE: with the flag
	// off nothing is constructed, no goroutine starts, no outbound call is made
	// and the routes answer an honest "not enabled".
	EnvFeatureFlag = "FEATURE_BGP_ALERTS"
	// EnvInterval is the bounded evaluation cadence (a Go duration).
	EnvInterval = "BGP_ALERT_INTERVAL"
	// EnvCooldown is the per-(prefix,class) re-notification cool-down.
	EnvCooldown = "BGP_ALERT_COOLDOWN"
	// EnvConfigFile is the FileStore fallback path for the per-tenant policy
	// (expected origins / upstreams / thresholds) on a non-Postgres build.
	EnvConfigFile = "BGP_ALERT_CONFIG_FILE"
	// EnvWatchlistFile is the WatchFileStore path for the per-tenant WATCHLIST
	// (which prefixes/ASNs a tenant asked us to watch) on a non-Postgres build.
	// Postgres deployments never read it — migration 0035's FORCE-RLS table is
	// the store there.
	EnvWatchlistFile = "BGP_WATCHLIST_FILE"
	// EnvBogonFeed turns the OPTIONAL Team Cymru full-bogons fetch on. Default
	// FALSE — the embedded RFC/IANA set works with no network at all.
	EnvBogonFeed = "FEATURE_BGP_BOGON_FEED"
	// EnvBogonFeedURL overrides the full-bogons URL (https only; the fetch is
	// bounded, cached and retried with jitter).
	EnvBogonFeedURL = "BGP_BOGON_FEED_URL"
	// EnvEvidenceTopic overrides the bus topic the evidence events go to.
	EnvEvidenceTopic = "BGP_EVIDENCE_TOPIC"
)
