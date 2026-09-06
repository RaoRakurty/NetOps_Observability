// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// build_provenance.go — lets the RUNNING process state which commit it is.
//
// WHY THIS EXISTS (2026-07-22). F-08 shipped correct code and correct config,
// both committed, and was never deployed: the api image was never rebuilt. It
// sat built-but-undeployed for weeks while looking complete, because nothing in
// the system could answer "which commit is actually running?". The failure
// surfaced only when the config half — vector.yaml, a BIND MOUNT, so it takes
// effect on restart — went live against a binary that was 8 hours older and
// could not comply. `prober` was running a 38-hour-old binary and had been
// "restarted" repeatedly without ever gaining the fix.
//
// The trap is general: `docker compose up -d` recreates a container from
// whatever image already exists. It does not rebuild. So the ordinary reflex —
// restart the service — silently redeploys old code, and nothing objects.
//
// This is the same class as the audit's own diagnosis. A config-level check
// ("is INGEST_TOKEN in the container env?") proves what compose passed IN, never
// what the binary DOES with it — exactly like grepping for the word StatusCode
// instead of firing a real error. Provenance makes the difference observable.
//
// Values are injected at build time by Dockerfile.backend:
//
//	-ldflags "-X main.buildSHA=<sha> -X main.buildTime=<rfc3339>"

import (
	"time"
)

// buildSHA and buildTime are set via -ldflags at image build time. They are
// deliberately NOT constants.
//
// "unknown" is the honest default and must stay that way: a binary that was not
// told its revision must not invent one. Drift detection treats unknown as a
// FAILURE rather than a pass, because an unidentifiable artifact is exactly the
// situation this file exists to end.
var (
	buildSHA  = "unknown"
	buildTime = "unknown"
)

// buildInfo is the wire shape of /api/version.
type buildInfo struct {
	Version   string `json:"version"`
	SHA       string `json:"sha"`
	BuiltAt   string `json:"built_at"`
	StartedAt string `json:"started_at"`
	Uptime    string `json:"uptime"`
	// Identified is false when this binary cannot name its own revision. A
	// drift checker keys off this rather than string-matching "unknown".
	Identified bool `json:"identified"`
}

func (s *server) currentBuildInfo() buildInfo {
	return buildInfo{
		Version:    version,
		SHA:        buildSHA,
		BuiltAt:    buildTime,
		StartedAt:  s.startedAt.UTC().Format(time.RFC3339),
		Uptime:     time.Since(s.startedAt).Truncate(time.Second).String(),
		Identified: buildSHA != "" && buildSHA != "unknown",
	}
}

// The handler lives on the EXISTING /admin/version route (main.go), which was
// already in publicPaths. Extending it rather than adding a second endpoint
// keeps one answer to "what is running", and inherits the unauthenticated
// access a drift checker needs.
//
// Unauthenticated is right here, and worth justifying since everything else is
// gated: an external checker — the watchdog, a deploy script, a human with curl
// — must be able to ask "what is actually running?" without holding a
// credential. A check that needs auth is a check that gets skipped, and a
// skipped drift check is precisely how F-08 stayed invisible. The disclosure is
// a git SHA and a timestamp: it names nothing about tenants, topology or
// configuration, and the handler touches no store, so it cannot leak data even
// under a bug.
