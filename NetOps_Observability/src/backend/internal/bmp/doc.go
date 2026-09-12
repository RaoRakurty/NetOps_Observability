// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package bmp is a RECEIVER for the BGP Monitoring Protocol (RFC 7854).
//
// A router with `bmp server` configured opens a TCP session TO this platform
// and pushes a copy of what its BGP RIB-In sees. This package terminates that
// session, parses the frames, and serves a bounded, per-tenant read API over
// what arrived. It is the "live BGP feed" that needs no external service: no
// RIS/RouteViews subscription, no looking glass, no vendor API — the operator's
// own routers are the source.
//
// # The honesty contract
//
// This package REPORTS ONLY WHAT A ROUTER SENT IT. It never infers, never
// backfills, and never presents an empty feed as a healthy one:
//
//   - Nothing is collected until a router is configured to export BMP to us.
//     With no session up, /sessions is an empty list and /updates is an empty
//     list — NOT a zero-route "converged" verdict. The platform performs NO
//     device configuration; pointing a router here is a human act (see
//     docs/INGESTION.md).
//   - The feed is a SAMPLE OF WHAT THE ROUTER CHOSE TO SEND, bounded further
//     by our own ring. `dropped_updates` on a session is the honest count of
//     what we discarded under backpressure; a non-zero value means the view is
//     incomplete and says so, rather than looking like a quiet network.
//   - It is a MONITORING feed, not a RIB. We hold the last N updates per
//     session (a ring), not a converged routing table. "prefix X is not in the
//     list" means "we have not seen an update for it recently", never "it is
//     not routed".
//   - Everything we could not parse is COUNTED, not hidden: unknown message
//     types, unknown AFI/SAFI, unknown path attributes and malformed frames
//     each increment a counter and are skipped. A silently-dropped frame would
//     make the feed quietly lie about completeness (§10, no silent failures).
//   - Adjacent-RIB-Out / Local-RIB (RFC 8671, RFC 9069) and ADD-PATH-encoded
//     NLRI are NOT decoded. Their frames parse at the BMP layer and are counted
//     as unsupported at the UPDATE layer rather than being misread as
//     ordinary prefixes.
//
// # Zero trust on the wire (CLAUDE.md §3)
//
// Every byte a router sends is hostile input. The parser is hand-written over
// a bounded cursor that CANNOT read past its slice: there is no reflection, no
// allocation driven by an attacker-supplied length, and no path that panics —
// a truncated, oversized or garbage frame is an error value. Fuzz targets
// (FuzzParseMessage, FuzzParseUpdate, FuzzConnStream) hold that property.
//
// Resource bounds (§9): MaxMessageSize caps one frame, MaxConnections caps
// concurrent sessions, MaxUpdatesPerSession caps memory per session
// (drop-oldest with a counter — never unbounded growth), and both an idle and
// an in-message read deadline disconnect a stalled peer.
//
// # Tenant attribution (CLAUDE.md §3a)
//
// A BMP session carries NO tenant of its own — the router does not know about
// our tenancy model, and trusting anything it said would be a cross-tenant
// leak waiting to happen. The session's REMOTE ADDRESS is resolved against the
// platform inventory through the injected ResolveDevice, and the tenant is
// stamped from the resolved device row. An address that resolves to nothing is
// REJECTED: the connection is closed and counted. An unknown source is NEVER
// admitted as tenant "" — that would pool foreign routing data into the global
// bucket every tenant-less read can see.
//
// Every stored record is keyed by that tenant, and every read filters by the
// caller's principal. A cross-tenant read returns the caller's own rows only;
// it never 200s with another tenant's feed and never reveals that another
// tenant's session exists.
//
// The principal also carries the OPERATOR-VISIBILITY restriction, and this
// package obeys it exactly as it obeys the tenant. A BMP feed is the customer's
// routing table — peers, AS paths, prefixes — so a tenant that has switched the
// compliance restriction on is invisible to the platform operator here, the
// same way it is invisible on logs, flows, metrics and igpmon. The restriction
// is RESOLVED by the composition root (it owns the tenant store) and applied in
// scopeAdmits, the one place the read rule lives.
package bmp

import "time"

// Environment switches. Both are read by the composition root (never here —
// this package holds no ambient authority, §5).
const (
	// EnvFeatureFlag is the opt-in switch. Anything but "true" leaves the
	// module entirely dormant: no listener binds, no route is registered, no
	// goroutine starts and no metric series exists.
	EnvFeatureFlag = "FEATURE_BMP"

	// EnvListen overrides the TCP bind address for the receiver.
	EnvListen = "BMP_LISTEN"

	// DefaultListen is the bind address used when EnvListen is unset. Port
	// 11019 is the IANA-registered `bmp` port; the receiver binds it directly
	// (it is unprivileged, so no host-port indirection is needed).
	DefaultListen = ":11019"
)

// Wire and resource bounds (§9: every IO has a ceiling and a timeout).
const (
	// MaxMessageSize caps ONE BMP message. RFC 7854 gives no ceiling of its
	// own, so we impose one: the largest legitimate frame is a Peer Up
	// carrying two BGP OPEN messages plus TLVs, or a Route Monitoring carrying
	// one UPDATE (<=4096 octets classically, <=65535 with RFC 8654 extended
	// messages). 1 MiB is generous by three orders of magnitude and still
	// bounds a hostile length field to something a single session can afford.
	MaxMessageSize = 1 << 20

	// MaxConnections caps concurrent BMP sessions. A router opens exactly one;
	// this is the blast radius of a source that reconnects in a loop.
	MaxConnections = 64

	// MaxSessionRecords caps how many session records (live + recently closed)
	// the store holds. Closed records are kept so an operator can see that a
	// session flapped; the oldest CLOSED record is evicted first, and a new
	// connection is refused rather than evicting a LIVE one.
	MaxSessionRecords = 256

	// MaxUpdatesPerSession is the per-session ring depth. On overflow the
	// OLDEST update is dropped and DroppedUpdates is incremented — backpressure
	// that is counted, never unbounded memory (§9).
	MaxUpdatesPerSession = 4096

	// IdleTimeout disconnects a peer that has sent nothing at all for this
	// long. BMP is a push protocol with no keepalive of its own, so this is
	// deliberately long: a stable full table can be quiet for a while.
	IdleTimeout = 15 * time.Minute

	// MessageTimeout is the deadline for the REST of a message once its common
	// header has been read. A peer that announces a 900 KiB frame and then
	// dribbles it is a slowloris; this is the bound that ends it.
	MessageTimeout = 30 * time.Second

	// AcceptBackoff is the FIRST pause after a transient accept() failure, so a
	// wedged listener cannot spin the CPU. It doubles, jittered, up to
	// MaxAcceptBackoff.
	AcceptBackoff = 250 * time.Millisecond

	// MaxAcceptBackoff caps that growth. Long enough that an fd exhaustion has
	// a chance to clear, short enough that a receiver which recovers starts
	// accepting again within a scrape interval.
	MaxAcceptBackoff = 30 * time.Second

	// MaxAcceptRetries bounds how many CONSECUTIVE transient accept failures the
	// receiver rides out before it declares itself down. Retrying forever would
	// leave a receiver that has been broken for hours still reporting itself as
	// enabled; giving up on the first error would kill it on a single EMFILE
	// spike. A success resets the count.
	MaxAcceptRetries = 20
)
