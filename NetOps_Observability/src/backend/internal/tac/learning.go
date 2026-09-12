// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// learning.go — what a TAC collection produced that Correlix could NOT read.
//
// THE POINT OF THIS FILE. A collection is the one moment Correlix holds real
// output from a real device for a real incident. Everything the parsers
// recognise becomes evidence; everything they do not recognise has, until now,
// been written into the bundle and forgotten. That silence is the gap the
// design calls out (TAC_ESCALATION_2026-09-05 §3 "Learning", §6 W3): "a
// collected output no parser recognises becomes a parser/binding work item".
// A backlog that is never recorded cannot be worked, and — worse — the Iris →
// Knowledge page had to say "not yet tracked" because showing a 0 would have
// read as "there are none".
//
// WHAT IS AND IS NOT A GAP. Three distinct things, kept distinct, because
// collapsing them would send an engineer at the wrong work:
//
//   · no_parser — the intent has no parser bound on ANY dialect. The work item
//     is "author a parser for this concept".
//   · no_dialect — a parser exists for the concept but not for THIS dialect,
//     or the device's platform did not resolve to a dialect the library knows.
//     The work item is "extend the parser to this dialect".
//   · unparsed — a parser ran on this dialect and could not recognise the
//     output, and says why. The work item is "the authored format is wrong or
//     incomplete", and the excerpt is the evidence for it.
//
// A command that ERRORED is not a gap. Nothing was read, so nothing failed to
// be recognised; recording it would inflate the backlog with connectivity.
//
// EVERYTHING STORED IS ALREADY REDACTED, AND IS RE-REDACTED ANYWAY. The
// collector redacts at capture (collect.go), so cc.Output arrives clean. The
// excerpt still passes through protocoldiag.RedactOutput a second time: this
// record OUTLIVES the collection, is read by a different surface, and is
// exported to a file a human sends to a vendor. One redaction upstream is a
// dependency; two is the property.
//
// BOUNDED, LIKE EVERYTHING ELSE THAT COMES OFF A DEVICE (§9). At most
// MaxGapsPerRecord gaps, each with at most maxExcerptBytes of at most
// maxExcerptLines lines. A record that hit a ceiling says so in Truncated
// rather than quietly holding less than it claims.

import (
	"sort"
	"strings"
	"time"

	"netops/backend/internal/protocoldiag"
	"netops/backend/internal/showparse"
)

// GapKind is why one collected output was not recognised.
type GapKind string

const (
	// GapNoParser — no parser is authored for this concept at all.
	GapNoParser GapKind = "no_parser"
	// GapNoDialect — a parser exists for the concept, but not for this dialect.
	GapNoDialect GapKind = "no_dialect"
	// GapUnparsed — a parser ran and could not recognise the output.
	GapUnparsed GapKind = "unparsed"
)

// GapKinds is every kind, in a stable order (listings, tests, UI).
func GapKinds() []GapKind { return []GapKind{GapNoParser, GapNoDialect, GapUnparsed} }

const (
	// MaxGapsPerRecord bounds one collection's contribution to the backlog.
	// A 200-command plan cannot bury the page.
	MaxGapsPerRecord = 40
	// maxExcerptBytes bounds ONE gap's evidence.
	maxExcerptBytes = 2 << 10
	// maxExcerptLines bounds it again by lines, because a wide table can be
	// 2 KiB of one line and unreadable.
	maxExcerptLines = 12
)

// Gap is one command whose output Correlix could not read.
type Gap struct {
	Kind    GapKind `json:"kind"`
	Intent  string  `json:"intent"`
	Title   string  `json:"title,omitempty"`
	Command string  `json:"command"`
	Dialect string  `json:"dialect"`
	// Reason is the parser's own words, or this file's, in operator language.
	Reason string `json:"reason"`
	// Excerpt is the redacted head of the output the parser could not read. It
	// is the ONLY thing that makes the work item actionable, and the only thing
	// here that came off a device.
	Excerpt string `json:"excerpt,omitempty"`
	// Bytes is the FULL output's size, so a 12-line excerpt of a 400 KB answer
	// does not read as a 400-byte one.
	Bytes int `json:"bytes"`
}

// LearningRecord is one collection's unrecognised output, tenant-scoped.
//
// TenantID is `json:"-"` for the same reason Capture's is: the tenant is the
// bucket a record lives in, not a field a client may read back or send.
type LearningRecord struct {
	ID         string `json:"id"`
	TenantID   string `json:"-"`
	IncidentID string `json:"incident_id"`
	DeviceID   string `json:"device_id"`
	Hostname   string `json:"hostname"`
	Platform   string `json:"platform"`
	Dialect    string `json:"dialect"`

	ClassID    string `json:"class_id"`
	ClassTitle string `json:"class_title"`
	// ClassFromSignature records whether a SIGNATURE chose this class, as
	// opposed to an alert name or a hypothesis. A class chosen without one is
	// itself the seed of a signature candidate, which is why it is a field and
	// not a derivation somebody has to remember to make.
	ClassFromSignature bool `json:"class_from_signature"`

	EngineVersion string    `json:"engine_version"`
	CollectedAt   time.Time `json:"collected_at"`

	// Commands is how many commands ran; Recognised how many a parser read.
	Commands   int `json:"commands"`
	Recognised int `json:"recognised"`

	Gaps []Gap `json:"gaps"`
	// Truncated is set when MaxGapsPerRecord cut the list, so a partial record
	// never reads as a complete one.
	Truncated bool `json:"truncated,omitempty"`
}

// GapCounts is the per-kind tally, in GapKinds() order.
func (r LearningRecord) GapCounts() map[GapKind]int {
	out := map[GapKind]int{}
	for _, k := range GapKinds() {
		out[k] = 0
	}
	for _, g := range r.Gaps {
		out[g.Kind]++
	}
	return out
}

// ── the intent → parser binding ─────────────────────────────────────────────
//
// A CLOSED, HAND-AUTHORED TABLE, and deliberately not a guess. `internal/tac`
// speaks intents ("ospf.neighbors") and `internal/showparse` speaks command
// CONCEPTS ("ospf-neighbor"); the two vocabularies overlap but are not the same
// set, and inferring one from the other by string surgery would silently bind
// `ospf.database` to nothing while claiming it was covered. An intent absent
// from this table is honestly GapNoParser — which is the backlog item.
var intentParsers = map[string]string{
	"interface.brief":         showparse.CmdInterfaceBrief,
	"interface.status":        showparse.CmdInterfaceBrief,
	"interface.detail":        showparse.CmdInterfaceDetail,
	"interface.counters":      showparse.CmdInterfaceDetail,
	"interface.errors":        showparse.CmdInterfaceDetail,
	"optics.detail":           showparse.CmdInterfaceOptics,
	"ospf.neighbors":          showparse.CmdOSPFNeighbor,
	"ospf.neighbors.detail":   showparse.CmdOSPFNeighbor,
	"isis.adjacency":          showparse.CmdISISNeighbor,
	"isis.adjacency.detail":   showparse.CmdISISNeighbor,
	"bgp.summary":             showparse.CmdBGPSummary,
	"route.prefix":            showparse.CmdRoutePrefix,
	"fib.prefix":              showparse.CmdRoutePrefix,
	"arp.table":               showparse.CmdARP,
	"l2.mac":                  showparse.CmdMAC,
	"system.processes.cpu":    showparse.CmdPlatformCPU,
	"system.processes.memory": showparse.CmdPlatformMemory,
	"hardware.environment":    showparse.CmdPlatformEnv,
	"system.version":          showparse.CmdPlatformUptime,
	"system.uptime":           showparse.CmdPlatformUptime,
	"logging.recent":          showparse.CmdLogs,
}

// ParserForIntent reports the parser concept bound to an intent, if any.
func ParserForIntent(intent string) (string, bool) {
	id, ok := intentParsers[strings.TrimSpace(intent)]
	return id, ok
}

// ── observing a capture ─────────────────────────────────────────────────────

// ObserveCapture reads a finished capture and returns the learning record for
// it. It runs the parsers over output that is ALREADY redacted and already on
// this host — it touches no device, opens no connection, and cannot fail.
//
// A nil capture yields the zero record: there is nothing to learn from a
// collection that did not happen, and inventing an empty backlog entry for it
// would be the "0 reads as none" mistake in a different place.
func ObserveCapture(capt *Capture, id string, now time.Time) LearningRecord {
	if capt == nil {
		return LearningRecord{}
	}
	rec := LearningRecord{
		ID:            id,
		TenantID:      capt.TenantID,
		IncidentID:    capt.IncidentID,
		DeviceID:      capt.DeviceID,
		Hostname:      capt.Hostname,
		Platform:      capt.Platform,
		Dialect:       capt.Dialect,
		ClassID:       capt.ClassID,
		ClassTitle:    capt.ClassTitle,
		EngineVersion: Version,
		CollectedAt:   now.UTC(),
		Commands:      len(capt.Commands),
		Gaps:          []Gap{},
	}
	dialect, dialectKnown := showparse.DialectFromPlatform(capt.Platform)

	for _, cc := range capt.Commands {
		if !cc.OK() || strings.TrimSpace(cc.Output) == "" {
			// Nothing was read here. A command that failed is a collection
			// problem, not a recognition problem.
			continue
		}
		cmdID, bound := ParserForIntent(cc.Intent)
		if !bound {
			rec.addGap(Gap{
				Kind: GapNoParser, Intent: cc.Intent, Title: cc.Title, Command: cc.Command,
				Dialect: capt.Dialect,
				Reason:  "no parser is authored for this concept, on any platform",
				Excerpt: excerpt(cc.Output), Bytes: cc.Bytes,
			})
			continue
		}
		if !dialectKnown {
			rec.addGap(Gap{
				Kind: GapNoDialect, Intent: cc.Intent, Title: cc.Title, Command: cc.Command,
				Dialect: capt.Dialect,
				Reason:  "this platform is not one the parsers are authored for",
				Excerpt: excerpt(cc.Output), Bytes: cc.Bytes,
			})
			continue
		}
		res, err := showparse.Parse(cmdID, dialect, cc.Output)
		switch {
		case err != nil:
			rec.addGap(Gap{
				Kind: GapNoDialect, Intent: cc.Intent, Title: cc.Title, Command: cc.Command,
				Dialect: capt.Dialect, Reason: err.Error(),
				Excerpt: excerpt(cc.Output), Bytes: cc.Bytes,
			})
		case res.Skipped:
			reason := strings.TrimSpace(res.Reason)
			if reason == "" {
				reason = "the parser did not recognise this output and gave no reason"
			}
			rec.addGap(Gap{
				Kind: GapUnparsed, Intent: cc.Intent, Title: cc.Title, Command: cc.Command,
				Dialect: capt.Dialect, Reason: reason,
				Excerpt: excerpt(cc.Output), Bytes: cc.Bytes,
			})
		default:
			rec.Recognised++
		}
	}
	sortGaps(rec.Gaps)
	return rec
}

// addGap appends within the ceiling, recording that the ceiling was reached.
func (r *LearningRecord) addGap(g Gap) {
	if len(r.Gaps) >= MaxGapsPerRecord {
		r.Truncated = true
		return
	}
	r.Gaps = append(r.Gaps, g)
}

// sortGaps orders a record deterministically: kind, then intent, then command.
// Determinism is what lets a test assert a record and a reader diff two.
func sortGaps(g []Gap) {
	rank := map[GapKind]int{GapUnparsed: 0, GapNoDialect: 1, GapNoParser: 2}
	sort.SliceStable(g, func(i, j int) bool {
		if rank[g[i].Kind] != rank[g[j].Kind] {
			return rank[g[i].Kind] < rank[g[j].Kind]
		}
		if g[i].Intent != g[j].Intent {
			return g[i].Intent < g[j].Intent
		}
		return g[i].Command < g[j].Command
	})
}

// excerpt is the redacted, bounded head of an output.
//
// Redaction runs FIRST and on the WHOLE text, not on the clipped head: a
// secret split across the boundary must not survive because the clip landed
// mid-token.
func excerpt(raw string) string {
	clean := protocoldiag.RedactOutput(raw)
	lines := strings.Split(clean, "\n")
	if len(lines) > maxExcerptLines {
		lines = lines[:maxExcerptLines]
	}
	out := strings.Join(lines, "\n")
	if len(out) > maxExcerptBytes {
		out = out[:maxExcerptBytes]
	}
	return strings.TrimRight(out, " \t\r\n")
}
