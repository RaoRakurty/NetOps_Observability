// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ingest_auth.go — F-08: the single place that authenticates this process to
// the Vector ingest tier.
//
// THE DEFECT THIS CLOSES: the four Vector `http_server` ingest sources (traps
// :8688, probes :8689, metrics :8690, bus bridge :8692) accepted writes from
// anything that could reach the compose network. The bus bridge enforced only
// that the requested topic starts with `netops.` — a topic-prefix check, not
// an identity check — so a foothold anywhere on that network could inject
// events onto any netops.* topic carrying a FORGED tenant_id, which
// vector-router then routes into that tenant's OpenSearch index. That is
// cross-tenant data injection and a direct violation of CLAUDE.md §3.
//
// ONE function, used by every forwarder, on purpose. There are four ingest
// call sites in three files; a credential applied at three of them is a
// credential that does not work, and the failure would look exactly like
// "that lane is quiet today".

// ingestCredential is the ingest identity for ONE lane. Read once: it is
// process configuration, and re-reading per request would let a mid-flight
// env change split the fleet's behaviour without anything logging it.
type ingestCredential struct {
	user  string
	token string
}

// Lane names — the four vector-aggregator http_server sources. SEC-013.1
// scopes the credential per lane so a compromised collector credential
// cannot write to another lane (the bus bridge above all). NARROWED
// (enforce wave step 4): each lane reads ONLY its own INGEST_TOKEN_<LANE>;
// the shared INGEST_TOKEN is no longer accepted as a lane credential in
// any direction — install.py has seeded per-lane tokens since the epic
// landed, and its migration path seeds them into pre-epic .envs. The
// shared token's one remaining role is the stack-internal edge-keys gate
// (internalStackCaller / sealingEdgeCaller in pipeline_processors.go),
// which is a different trust decision on a different surface.
const (
	LaneTraps   = "traps"
	LaneProbes  = "probes"
	LaneMetrics = "metrics"
	LaneBus     = "bus"
)

func laneTokenEnv(lane string) string {
	switch lane {
	case LaneTraps:
		return "INGEST_TOKEN_TRAPS"
	case LaneProbes:
		return "INGEST_TOKEN_PROBES"
	case LaneMetrics:
		return "INGEST_TOKEN_METRICS"
	case LaneBus:
		return "INGEST_TOKEN_BUS"
	}
	return ""
}

func readIngestCredentials() map[string]ingestCredential {
	user := os.Getenv("INGEST_USER")
	if user == "" {
		user = "netops-ingest"
	}
	out := make(map[string]ingestCredential, 4)
	for _, lane := range []string{LaneTraps, LaneProbes, LaneMetrics, LaneBus} {
		// Per-lane token ONLY. A missing lane token means this lane sends no
		// header (see SetIngestAuth) and every POST 401s — observable in
		// collector_ingest_rejected and the throttled log line, never silent.
		// Falling back to the shared token here is the accept-set the
		// narrowing closed: it made INGEST_TOKEN a skeleton key for whichever
		// lanes lacked their own credential.
		out[lane] = ingestCredential{user: user, token: os.Getenv(laneTokenEnv(lane))}
	}
	return out
}

var loadIngestCredential = sync.OnceValue(readIngestCredentials)

// resetIngestCredentialForTest re-reads the environment. Only tests call it:
// the once-only read is deliberate in production (a mid-flight env change must
// not split the fleet's behaviour silently), but a test that cannot vary the
// credential cannot exercise the rejection path — and the rejection path is
// the half of F-08 that keeps a bad token from silently killing three lanes.
func resetIngestCredentialForTest() {
	loadIngestCredential = sync.OnceValue(readIngestCredentials)
}

// ResetIngestCredentialForTest is the exported form of the reset below, for
// tests in OTHER packages (the bus producer lives in package main). Test-only:
// production must never re-read the credential mid-flight.
func ResetIngestCredentialForTest() { resetIngestCredentialForTest() }

// SetIngestAuth stamps the lane's ingest credential on an outbound request.
// The lane is one of the Lane* constants — every call site knows which lane
// it feeds, and the credential must match that lane's accept config
// (SEC-013.1: per-lane tokens; a metrics credential opens nothing else).
//
// An EMPTY token deliberately sends no header rather than sending an empty
// password: that is the documented upgrade window in which Vector has not
// yet been reconfigured, and an empty-password Basic header would fail
// against an authenticated Vector in a way that is harder to read in a packet
// capture than no header at all. Vector is the fail-closed half of this pair —
// it refuses to start without a lane token — so an unauthenticated client can
// never reach an unauthenticated collector by accident.
func SetIngestAuth(req *http.Request, lane string) {
	c, ok := loadIngestCredential()[lane]
	if !ok || c.token == "" {
		return
	}
	req.SetBasicAuth(c.user, c.token)
}

// IngestAuthConfigured reports whether this process has an ingest credential
// for at least one lane. Exported so the API's health surface can say
// "ingest is unauthenticated" out loud instead of leaving it to be
// discovered during an incident.
func IngestAuthConfigured() bool {
	for _, c := range loadIngestCredential() {
		if c.token != "" {
			return true
		}
	}
	return false
}

// ingestRejections counts non-2xx responses from the Vector ingest tier, per
// lane. Introducing authentication introduces a NEW way for three telemetry
// lanes to go completely silent (a wrong token = 401 on every POST), and the
// forwarders were already best-effort: two of the three discarded the status
// code entirely. Adding the credential without adding this counter would have
// been a textbook instance of the class this audit is about — a fix whose own
// failure mode is invisible.
var ingestRejections sync.Map // lane string -> *int64

// ingestLogThrottle keeps a 401 storm from becoming a log flood: the message
// is identical every time, so once a minute per lane carries all the
// information and none of the noise.
var ingestLogThrottle sync.Map // lane string -> *int64 (unix seconds)

func logIngestRejection(lane, sink string, status int) {
	v, _ := ingestRejections.LoadOrStore(lane, new(int64))
	n := atomic.AddInt64(v.(*int64), 1)

	now := time.Now().Unix()
	lv, _ := ingestLogThrottle.LoadOrStore(lane, new(int64))
	last := atomic.LoadInt64(lv.(*int64))
	if now-last >= 60 && atomic.CompareAndSwapInt64(lv.(*int64), last, now) {
		hint := ""
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			hint = fmt.Sprintf(" — check %s matches vector-aggregator's (F-08/SEC-013; the shared INGEST_TOKEN no longer opens lanes)", laneTokenEnv(lane))
		}
		// sink is logged without credentials: SetIngestAuth uses a header, not
		// a userinfo URL, so there is nothing to redact here (§8 no PII/secret
		// leakage in logs) — keep it that way if the URL ever becomes
		// operator-supplied.
		log.Printf("ingest: %s lane REJECTED by %s: status %d (%d total)%s", lane, sink, status, n, hint)
	}

	// Same lane label the Vector side uses, so the two halves of the path line
	// up in one query. Emitted as an absolute counter gauge like the rest of
	// the collector_* family (see snmpmetrics.go).
	emitMetrics(context.Background(), fmt.Sprintf(
		`collector_ingest_rejected{lane=%q} %d %d`, lane, n, time.Now().UnixMilli()))
}

// IngestRejections returns the per-lane rejection count. Exported for the
// API's collector health surface and for tests.
func IngestRejections(lane string) int64 {
	if v, ok := ingestRejections.Load(lane); ok {
		return atomic.LoadInt64(v.(*int64))
	}
	return 0
}
