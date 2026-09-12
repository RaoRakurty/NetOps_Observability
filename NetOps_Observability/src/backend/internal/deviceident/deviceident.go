// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package deviceident reads a device's HARDWARE IDENTITY — chassis serial
// number and model/PID — out of the show output the device itself printed.
//
// WHY IT EXISTS. A serial number is the one identifier that survives a
// re-address, a rename and a re-cable: it is what a support case is opened
// against, what an RMA is issued for, what an asset register reconciles on and
// what internal/discovery's identity resolution already treats as stronger than
// an IP (deviceIdentities, sot_import's IRE precedence: serial → IP →
// hostname). Until now the platform could only receive one from an importer or
// a NetBox sync; a device that Correlix logs into every hour to read a
// `show version` was never asked the question it can answer itself.
//
// THE ONE INVARIANT, inherited from internal/showparse: A PARSER NEVER
// FABRICATES A FIELD. Output this package does not recognize yields an EMPTY
// Identity — never a partial guess, never a token lifted off a line that
// happened to look right. A device record that says "serial unknown" is
// auditable; one that says "FOC1234ABCD" because a regexp got lucky is not, and
// it is worse than the blank it replaced because a person will act on it.
//
// WHERE THE VENDOR KNOWLEDGE LIVES. Not here. WHICH command prints a serial on
// a platform, and WHICH line of its output carries it, are DECLARATIVE DATA in
// internal/vendorprofile (`identity_probe`), resolved through the registry — the
// ONE VOCABULARY rule (§13, vendorprofile/vocabulary_guard_test.go). This
// package holds the matching, the bounds and the merge order, and nothing that
// names a vendor.
//
// TWO CALLERS, ONE PARSER.
//
//	(a) internal/osprobe's SSH rung, which runs the authored commands at a live
//	    device on the visit it was already making for the OS version;
//	(b) a finished COLLECTION whose captures happen to contain the same output —
//	    a TAC bundle, a runbook capture — walked through FromCapture, which
//	    parses text that is already in hand and reaches no device at all.
//
// BOUNDS (§9). One output is scanned only up to MaxOutputBytes, at most
// MaxCommands captures are considered in one call, and each extracted field is
// capped (MaxSerialBytes / MaxModelBytes). Every authored pattern is RE2 with no
// nested quantifier, so adversarial output cannot make matching super-linear.
// Nothing here starts a goroutine, opens a socket, reads a file or mutates its
// input.
package deviceident

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"netops/backend/internal/vendorprofile"
)

const (
	// MaxSerialBytes bounds one extracted serial. Serials are ~10–20
	// characters; a device that answers with more is answering with something
	// that is not a serial, and the value is refused rather than stored.
	MaxSerialBytes = 64
	// MaxModelBytes bounds one extracted model/PID.
	MaxModelBytes = 64
	// MaxOutputBytes is the ceiling on ONE command's output. It is the same
	// number internal/showparse.MaxInputBytes and protocoldiag.MaxOutputBytes
	// use: a bigger blob means something upstream skipped its cap, and the
	// output is left unscanned rather than trusted.
	MaxOutputBytes = 512 << 10
	// MaxCommands bounds how many captures FromCapture will consider in one
	// call. A TAC collection is dozens of commands; this is headroom.
	MaxCommands = 512
)

// Identity is what a device printed about its own hardware, plus WHERE each
// half was read from. Both fields are independently optional: a platform may
// print a model and no serial (Junos `show version`) or a serial and no model,
// and the absence of one must never suppress the other.
type Identity struct {
	// Serial is the chassis serial number exactly as the device printed it.
	Serial string
	// Model is the chassis model / product id exactly as the device printed it.
	Model string
	// SerialCommand / ModelCommand name the command whose output each field was
	// read out of. They are the audit trail: a serial with no statement of
	// which command produced it is a string nobody can re-derive.
	SerialCommand string
	ModelCommand  string
	// ProfileID is the vendorprofile profile whose patterns matched
	// ("cisco/ios_xe"). Empty when nothing matched.
	ProfileID string
}

// Empty reports whether nothing at all was read.
func (i Identity) Empty() bool { return i.Serial == "" && i.Model == "" }

// Complete reports whether both fields were read, which is what lets a probe
// stop early instead of running the next command at a live device.
func (i Identity) Complete() bool { return i.Serial != "" && i.Model != "" }

// merge fills this identity's EMPTY fields from other and returns the result.
// First reading wins per field: the profile lists its commands in preference
// order, so an earlier command's answer is the authored preference and a later
// one is the backstop.
func (i Identity) merge(other Identity) Identity {
	out := i
	if out.Serial == "" && other.Serial != "" {
		out.Serial, out.SerialCommand = other.Serial, other.SerialCommand
	}
	if out.Model == "" && other.Model != "" {
		out.Model, out.ModelCommand = other.Model, other.ModelCommand
	}
	if out.ProfileID == "" {
		out.ProfileID = other.ProfileID
	}
	return out
}

// CapturedCommand is ONE already-collected (command, output) pair together with
// the platform the collection was run against.
//
// It is a PLAIN STRUCT on purpose: the callers that hold finished collections
// (internal/tac's Capture/CollectedCommand today, a runbook importer tomorrow)
// each have their own richer record, and this package must not depend on any of
// them — nor they on it beyond this one shape. Converting is a three-field copy
// at the call site, which is exactly the seam width this is meant to be.
type CapturedCommand struct {
	// Command is the command as it was issued at the device.
	Command string
	// Output is that command's raw output.
	Output string
	// Platform is the platform the collection ran against, in any spelling the
	// registry recognizes: a canonical profile id ("cisco/ios_xe"), a plan id
	// ("cisco-iosxe"), or a free-form label ("Cisco IOS-XE 17.9").
	Platform string
}

// Profiles is the vendor-knowledge seam. *vendorprofile.Registry satisfies it;
// injecting it is what lets every parse be tested against authored data without
// reaching for the embedded profile set, and what keeps this package from
// holding a second copy of any vendor's knowledge.
type Profiles interface {
	// IdentityProbeForDevice resolves a LIVE DEVICE's (vendor, OS label) onto
	// the profile that owns it and that profile's identity data. The resolution
	// is vendor-bounded: the commands it returns will be RUN at that device.
	IdentityProbeForDevice(vendor, osText string) (vendorprofile.Profile, vendorprofile.IdentityProbe, bool)
	// IdentityProbeForPlatformID resolves an ALREADY-COLLECTED capture's
	// platform identifier. No device is reached, so the resolution is by
	// identifier rather than vendor-bounded.
	IdentityProbeForPlatformID(platform string) (vendorprofile.Profile, vendorprofile.IdentityProbe, bool)
}

// Extractor matches authored patterns against show output. It is immutable
// except for its compiled-pattern cache, and safe for concurrent use.
type Extractor struct {
	profiles Profiles

	mu    sync.Mutex
	cache map[string]*regexp.Regexp
}

// NewExtractor builds an extractor over an injected vendor-knowledge seam. A
// nil seam yields an extractor that resolves nothing — the honest state of a
// deployment that wired no registry, never a silent fallback to a global one.
func NewExtractor(profiles Profiles) *Extractor {
	return &Extractor{profiles: profiles, cache: map[string]*regexp.Regexp{}}
}

// defaultExtractor is the package-level extractor over the shipped registry,
// built once on first use. It is a sync.OnceValue rather than a mutable
// package variable (§5, and the same shape internal/showparse's package-level
// Parse helper uses).
var defaultExtractor = sync.OnceValue(func() *Extractor {
	return NewExtractor(vendorprofile.Default())
})

// FromCapture parses the hardware identity out of an ALREADY-COLLECTED set of
// captures, using the shipped profile registry. It reaches no device.
//
// This is the seam a finished collection is walked through: hand it every
// (command, output, platform) triple the collection produced and it returns
// what the device said about itself, or an empty Identity when none of the
// output was recognized.
func FromCapture(cmds []CapturedCommand) Identity {
	return defaultExtractor().FromCapture(cmds)
}

// FromCapture parses the hardware identity out of an already-collected set of
// captures.
//
// Order is the caller's order, and the FIRST recognized value for each field
// wins — a collection lists its commands in the order they were run, and an
// earlier capture is no less true than a later one. A capture whose platform
// resolves to no profile, whose command no profile binds, or whose output is
// over the size cap contributes NOTHING; it never degrades into a guess.
func (e *Extractor) FromCapture(cmds []CapturedCommand) Identity {
	var out Identity
	if e == nil || e.profiles == nil {
		return out
	}
	if len(cmds) > MaxCommands {
		cmds = cmds[:MaxCommands]
	}
	// Resolve each distinct platform ONCE: a collection is dozens of commands
	// against one device, and the ranked platform tables are not free.
	type resolved struct {
		profile vendorprofile.Profile
		probe   vendorprofile.IdentityProbe
		ok      bool
	}
	seen := map[string]resolved{}
	for _, c := range cmds {
		if out.Complete() {
			return out
		}
		key := strings.ToLower(strings.TrimSpace(c.Platform))
		r, known := seen[key]
		if !known {
			p, probe, ok := e.profiles.IdentityProbeForPlatformID(c.Platform)
			r = resolved{profile: p, probe: probe, ok: ok}
			seen[key] = r
		}
		if !r.ok {
			continue
		}
		bound, ok := bindCommand(r.probe, c.Command)
		if !ok {
			continue
		}
		out = out.merge(e.extract(r.profile.ID, bound, c.Command, c.Output))
	}
	return out
}

// ForDevice resolves the identity probe for a LIVE device row. It is the
// vendor-bounded resolution: the commands it returns are about to be run at
// that device. ok=false is the honest "no established identity source here".
func (e *Extractor) ForDevice(vendor, osText string) (vendorprofile.Profile, vendorprofile.IdentityProbe, bool) {
	if e == nil || e.profiles == nil {
		return vendorprofile.Profile{}, vendorprofile.IdentityProbe{}, false
	}
	return e.profiles.IdentityProbeForDevice(vendor, osText)
}

// FromOutput reads ONE authored command's output. profileID is carried through
// onto the Identity as provenance; issuedCommand is the command as it was
// actually issued (which may be a longer form of the authored one), and is what
// the Identity records, because that is what a person would have to re-run.
//
// An error is returned only when an authored PATTERN cannot be compiled — a
// data/validator drift, which is a defect worth seeing rather than a branch
// worth swallowing (§10). Output that simply does not match is not an error: it
// is an empty Identity.
func (e *Extractor) FromOutput(profileID string, bound vendorprofile.IdentityCommand, issuedCommand, output string) (Identity, error) {
	if e == nil {
		return Identity{}, nil
	}
	if len(output) > MaxOutputBytes {
		return Identity{}, fmt.Errorf("deviceident: output for %q is %d bytes, over the %d-byte cap", issuedCommand, len(output), MaxOutputBytes)
	}
	out := Identity{}
	serial, err := e.first(bound.SerialPatterns, output, MaxSerialBytes)
	if err != nil {
		return Identity{}, err
	}
	model, err := e.first(bound.ModelPatterns, output, MaxModelBytes)
	if err != nil {
		return Identity{}, err
	}
	if serial != "" {
		out.Serial, out.SerialCommand = serial, strings.TrimSpace(issuedCommand)
	}
	if model != "" {
		out.Model, out.ModelCommand = model, strings.TrimSpace(issuedCommand)
	}
	if !out.Empty() {
		out.ProfileID = profileID
	}
	return out, nil
}

// extract is FromOutput with the drift error routed to "nothing was read".
// FromCapture uses it because a walk over a whole collection must not stop on
// one platform's bad pattern; the live probe path uses FromOutput and surfaces
// the error, so a drift is still SEEN somewhere rather than nowhere.
func (e *Extractor) extract(profileID string, bound vendorprofile.IdentityCommand, issuedCommand, output string) Identity {
	id, err := e.FromOutput(profileID, bound, issuedCommand, output)
	if err != nil {
		return Identity{}
	}
	return id
}

// first returns the first non-empty capture group 1 across the patterns, in
// order, bounded to max bytes. A value that is over the bound is REFUSED, not
// truncated: half a serial is not a serial.
func (e *Extractor) first(patterns []string, output string, max int) (string, error) {
	for _, expr := range patterns {
		re, err := e.compile(expr)
		if err != nil {
			return "", err
		}
		m := re.FindStringSubmatch(output)
		if m == nil {
			continue
		}
		v := strings.TrimSpace(m[1])
		if v == "" || len(v) > max {
			continue
		}
		return v, nil
	}
	return "", nil
}

// compile compiles an authored pattern once per extractor. The patterns come
// from validated profile data, so a compile failure is a data/validator drift.
func (e *Extractor) compile(expr string) (*regexp.Regexp, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, fmt.Errorf("deviceident: empty identity pattern")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cache == nil {
		e.cache = map[string]*regexp.Regexp{}
	}
	if re, ok := e.cache[expr]; ok {
		return re, nil
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("deviceident: identity pattern %q: %w", expr, err)
	}
	e.cache[expr] = re
	return re, nil
}

// BindCommand selects the authored binding that reads the output of an issued
// command, if the profile has one.
//
// The match is on the NORMALIZED command text (lower-cased, runs of whitespace
// collapsed), and an authored command matches an issued one that EXTENDS it at
// a word boundary — `show chassis hardware` binds a capture taken with
// `show chassis hardware detail`, and `show inventory` binds
// `show inventory location 0/RSP0/CPU0`. It deliberately does NOT match the
// other way round: a profile that authored the longer form is stating that the
// shorter one prints something else.
//
// Exported so a caller holding a finished collection can ask "is this capture
// one the identity probe knows how to read?" without re-implementing the rule.
func BindCommand(probe vendorprofile.IdentityProbe, issued string) (vendorprofile.IdentityCommand, bool) {
	return bindCommand(probe, issued)
}

func bindCommand(probe vendorprofile.IdentityProbe, issued string) (vendorprofile.IdentityCommand, bool) {
	got := normalizeCommand(issued)
	if got == "" {
		return vendorprofile.IdentityCommand{}, false
	}
	for _, c := range probe.Commands {
		want := normalizeCommand(c.Command)
		if want == "" {
			continue
		}
		if got == want || strings.HasPrefix(got, want+" ") {
			return c, true
		}
	}
	return vendorprofile.IdentityCommand{}, false
}

// normalizeCommand lower-cases a command and collapses whitespace runs, so the
// spacing a capture happened to be recorded with cannot decide whether its
// output is parsed.
func normalizeCommand(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}
