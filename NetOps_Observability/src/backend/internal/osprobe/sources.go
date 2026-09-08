// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package osprobe

// sources.go — the three rungs.
//
// Each one is a thin adapter over an INJECTED transport plus the platform's own
// profile data. Nothing here names a vendor: the gNMI paths, the CLI command and
// the two extraction patterns all arrive from internal/vendorprofile through the
// Profiles seam (§13, the ONE VENDOR VOCABULARY rule).

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"netops/backend/internal/deviceident"
	"netops/backend/internal/vendorprofile"
)

// Profiles is the vendor-knowledge seam. *vendorprofile.Registry satisfies it;
// injecting it is what lets every rung be tested against authored data without
// reaching for the embedded profile set, and what keeps this package from
// holding a second copy of any vendor's knowledge.
type Profiles interface {
	// OSVersionProbeForDevice resolves a device's (vendor, OS label) onto the
	// profile that owns it and that profile's probe data. ok=false is the honest
	// "no established non-SNMP version source for this device".
	OSVersionProbeForDevice(vendor, osText string) (vendorprofile.Profile, vendorprofile.OSVersionProbe, bool)
	// IdentityProbeForDevice resolves the same device onto that platform's
	// HARDWARE IDENTITY commands and patterns. It is a SEPARATE resolution
	// because the two are separately authored: a platform may declare one, the
	// other, both or neither, and the SSH rung asks each question only of a
	// platform that answered it.
	IdentityProbeForDevice(vendor, osText string) (vendorprofile.Profile, vendorprofile.IdentityProbe, bool)
	// IdentityProbeForPlatformID is deviceident.Profiles' other half; the SSH
	// rung never calls it, but the seam is ONE interface so a deployment wires
	// ONE registry rather than two views of it.
	IdentityProbeForPlatformID(platform string) (vendorprofile.Profile, vendorprofile.IdentityProbe, bool)
}

// ─── (a) SNMP sysDescr ───────────────────────────────────────────────────────

// SysDescrFunc is the injected SNMP identity read. It matches
// collectors.DetectVendor's shape: it returns what the device SAID, and an
// unreachable device answers with empty strings rather than an error, because
// an SNMP timeout is indistinguishable from "no agent here" at this layer.
type SysDescrFunc func(ctx context.Context, addr string) (vendor, sysDescr string)

// SNMPSource is the top rung: the device's own description line.
//
// It needs NO profile data — every vendor packs its version into sysDescr in a
// shape the vendor's os_version_pattern already parses — which is exactly why it
// leads the ladder: it is the one rung that works for a platform nobody has
// authored a probe block for.
type SNMPSource struct {
	// Describe is the injected sysDescr read. Nil = the rung is not configured.
	Describe SysDescrFunc
}

// NewSNMPSource builds the sysDescr rung.
func NewSNMPSource(describe SysDescrFunc) *SNMPSource { return &SNMPSource{Describe: describe} }

// Method implements Source.
func (s *SNMPSource) Method() Method { return MethodSNMP }

// Probe implements Source. The sysDescr is returned VERBATIM (bounded by the
// ladder): it is already the canonical text the vendor pattern reads, so there
// is nothing here to render and nothing to guess.
func (s *SNMPSource) Probe(ctx context.Context, t Target) (string, error) {
	if s == nil || s.Describe == nil {
		return "", ErrNotConfigured
	}
	if strings.TrimSpace(t.Address) == "" {
		return "", fmt.Errorf("%w: no address", ErrNotConfigured)
	}
	_, descr := s.Describe(ctx, t.Address)
	return strings.TrimSpace(descr), nil
}

// ─── (b) gNMI software-version leaf ──────────────────────────────────────────

// GNMIGetter is the injected read-only gNMI Get seam: ONE path, ONE value, no
// subscription and no write. The value may be a bare scalar, a JSON scalar, or
// the single-leaf JSON object a gNMI Get notification carries — ExtractLeaf
// handles all three, so an implementation may hand back whatever its client
// decoded without pre-processing it.
//
// It is an interface rather than a func so a deployment can wire a client that
// holds its own connection pool and credential custody, exactly as the SSH
// gateway does.
type GNMIGetter interface {
	Get(ctx context.Context, t Target, path string) (string, error)
}

// GNMISource is the middle rung: the platform's software-version leaf, at the
// paths its profile declares.
type GNMISource struct {
	// Get is the injected transport. Nil = the rung is not configured, which is
	// the state a deployment without a gNMI client is honestly in; the ladder
	// then falls through to SSH instead of claiming a capability.
	Get GNMIGetter
	// Profiles resolves the paths and the extraction pattern.
	Profiles Profiles

	mu    sync.Mutex
	cache map[string]*regexp.Regexp
}

// NewGNMISource builds the gNMI rung.
func NewGNMISource(get GNMIGetter, profiles Profiles) *GNMISource {
	return &GNMISource{Get: get, Profiles: profiles, cache: map[string]*regexp.Regexp{}}
}

// Method implements Source.
func (s *GNMISource) Method() Method { return MethodGNMI }

// Probe implements Source. Paths are tried in the order the profile declares
// them and the FIRST that yields a version wins; a path that errors is not the
// end of the probe, because a chassis that does not publish one path may well
// publish the next.
func (s *GNMISource) Probe(ctx context.Context, t Target) (string, error) {
	if s == nil || s.Get == nil || s.Profiles == nil {
		return "", ErrNotConfigured
	}
	_, probe, ok := s.Profiles.OSVersionProbeForDevice(t.Vendor, t.OSText)
	if !ok || !probe.HasGNMI() {
		return "", fmt.Errorf("%w: no gnmi version path for this platform", ErrNotConfigured)
	}
	re, err := s.pattern(probe.GNMIVersionPattern)
	if err != nil {
		return "", err
	}
	var firstErr error
	for _, path := range probe.GNMIPaths {
		raw, gerr := s.Get.Get(ctx, t, path)
		if gerr != nil {
			// Keep the FIRST failure so a probe that never finds a path still
			// reports why, rather than degrading into a silent "no version".
			if firstErr == nil {
				firstErr = fmt.Errorf("gnmi get %s: %w", path, gerr)
			}
			continue
		}
		value := ExtractLeaf(raw, LeafOf(path))
		if value == "" {
			continue
		}
		if m := re.FindStringSubmatch(value); m != nil {
			if v := probe.Render(strings.TrimSpace(m[1])); v != "" {
				return v, nil
			}
		}
	}
	if firstErr != nil {
		return "", firstErr
	}
	return "", nil
}

func (s *GNMISource) pattern(expr string) (*regexp.Regexp, error) {
	return compileCached(&s.mu, &s.cache, expr)
}

// ─── (c) read-only SSH `show version` ────────────────────────────────────────

// CommandRunner runs ONE already-chosen read-only command on one device over
// the platform's SSH gateway and returns its output. It is the SAME seam
// internal/configstore and internal/protocoldiag use: injecting it is what keeps
// this package free of ambient authority to reach devices, and what keeps CI
// offline (no test here opens a socket).
type CommandRunner interface {
	Run(ctx context.Context, t Target, command string) (string, error)
}

// SSHSource is the bottom rung: the profile's OWN capture.show_version_cmd,
// parsed by the profile's own per-platform pattern.
//
// It is a CLOSED command source by construction. The only string it can put on
// a wire is the one the registry returned for this device's platform — there is
// no caller input anywhere on this path — and it is shape-checked again here
// before it is run, so a profile edit can never turn this rung into a way to
// execute an arbitrary command at a device (§8 least privilege).
type SSHSource struct {
	// Run is the injected gateway. Nil = the rung is not configured.
	Run CommandRunner
	// Profiles resolves the command and the extraction pattern.
	Profiles Profiles
	// Logf is the structured-log sink for a NON-FATAL failure — an identity
	// command that could not be run at a device whose version was read fine.
	// Nil falls back to the stdlib logger, never to silence (§10).
	Logf func(msg string, fields map[string]any)

	mu    sync.Mutex
	cache map[string]*regexp.Regexp

	identOnce sync.Once
	ident     *deviceident.Extractor
}

// NewSSHSource builds the read-only CLI rung.
func NewSSHSource(run CommandRunner, profiles Profiles) *SSHSource {
	return &SSHSource{Run: run, Profiles: profiles, cache: map[string]*regexp.Regexp{}}
}

// extractor is the identity parser, built once over the SAME injected profile
// seam. It is lazy so a caller that never asks for an identity never builds one,
// and so NewSSHSource keeps the signature every existing wiring passes.
func (s *SSHSource) extractor() *deviceident.Extractor {
	s.identOnce.Do(func() { s.ident = deviceident.NewExtractor(s.Profiles) })
	return s.ident
}

// Method implements Source.
func (s *SSHSource) Method() Method { return MethodSSH }

// commandForbiddenBytes are the bytes an authored show-version command may never
// contain: shell/CLI CHAINING metacharacters, redirection and control
// characters. The pipe is deliberately NOT here — on Junos the only way to read
// some output is a device-CLI display filter (`| no-more`), which is a display
// directive, not a second command — the same carve-out and the same reasoning
// internal/vendorprofile's config-capture validator records.
var commandForbiddenBytes = []string{";", "&", "`", "$", "\\", "\n", "\r", ">", "<"}

// Probe implements Source: the VERSION half only, for a caller that did not ask
// for the hardware identity.
func (s *SSHSource) Probe(ctx context.Context, t Target) (string, error) {
	version, _, err := s.probe(ctx, t, false)
	return version, err
}

// ProbeWithIdentity implements IdentitySource: the version AND the hardware
// identity, read on ONE visit to the device.
func (s *SSHSource) ProbeWithIdentity(ctx context.Context, t Target) (string, deviceident.Identity, error) {
	return s.probe(ctx, t, true)
}

// probe is the rung's body.
//
// ONE VISIT, TWO QUESTIONS. The version and the identity are authored
// separately (a platform may declare either, both or neither) but they are read
// on the same SSH session's worth of work, and — for every platform whose
// identity commands include its own show-version command — out of the SAME
// captured output, which is re-used rather than re-fetched. A platform that
// needs a second command (Cisco `show inventory`, Junos `show chassis
// hardware`) pays for exactly that one extra read-only command.
//
// FAILURE IS NOT SHARED. A failure of the VERSION command is the rung's error,
// as it always was. A failure of an IDENTITY command is logged and leaves the
// identity empty: discarding a version that was read successfully because a
// second command timed out would make the rung less reliable than it was before
// the identity existed.
func (s *SSHSource) probe(ctx context.Context, t Target, wantIdentity bool) (string, deviceident.Identity, error) {
	var id deviceident.Identity
	if s == nil || s.Run == nil || s.Profiles == nil {
		return "", id, ErrNotConfigured
	}
	profile, probe, versionOK := s.Profiles.OSVersionProbeForDevice(t.Vendor, t.OSText)
	identProfile, identProbe, identOK := vendorprofile.Profile{}, vendorprofile.IdentityProbe{}, false
	if wantIdentity {
		identProfile, identProbe, identOK = s.Profiles.IdentityProbeForDevice(t.Vendor, t.OSText)
	}
	if versionOK && !probe.HasCLI() {
		versionOK = false
	}
	if !versionOK && !identOK {
		return "", id, fmt.Errorf("%w: no cli version pattern or identity probe for this platform", ErrNotConfigured)
	}

	// outputs caches what this visit has already read, keyed by the command, so
	// a platform whose identity is in its own show-version output costs ONE
	// command at the device rather than two.
	outputs := map[string]string{}
	run := func(command string) (string, error) {
		if out, ok := outputs[command]; ok {
			return out, nil
		}
		if err := s.checkCommand(command); err != nil {
			return "", err
		}
		out, err := s.Run.Run(ctx, t, command)
		if err != nil {
			return "", fmt.Errorf("ssh %q: %w", command, err)
		}
		outputs[command] = out
		return out, nil
	}

	var version string
	if versionOK {
		command := strings.TrimSpace(profile.Capture.ShowVersionCmd)
		if command == "" {
			// The loader forbids this pairing, so reaching it means the data and
			// the validator have drifted. Refuse rather than improvise a command.
			return "", id, fmt.Errorf("%w: platform %q declares a cli version pattern but no show-version command", ErrNotConfigured, profile.ID)
		}
		re, err := s.pattern(probe.CLIVersionPattern)
		if err != nil {
			return "", id, err
		}
		out, err := run(command)
		if err != nil {
			return "", id, err
		}
		if m := re.FindStringSubmatch(out); m != nil {
			version = probe.Render(strings.TrimSpace(m[1]))
		}
		// m == nil is not an error: the device answered, and nothing in the
		// answer was a version.
	}

	if identOK {
		id = s.readIdentity(t, identProfile, identProbe, run)
	}
	return version, id, nil
}

// readIdentity runs the platform's authored identity commands in order and stops
// as soon as both fields are known. Each command's failure is reported and
// skipped — the next command may still answer, and the version already read is
// never put at risk by one that does not.
func (s *SSHSource) readIdentity(t Target, profile vendorprofile.Profile, probe vendorprofile.IdentityProbe, run func(string) (string, error)) deviceident.Identity {
	var id deviceident.Identity
	ex := s.extractor()
	for _, bound := range probe.Commands {
		if id.Complete() {
			return id
		}
		command := strings.TrimSpace(bound.Command)
		out, err := run(command)
		if err != nil {
			s.log("identity probe command failed", map[string]any{
				"device_id": t.DeviceID, "tenant": t.TenantID, "vendor": t.Vendor,
				"platform": profile.ID, "command": command, "error": err.Error(),
			})
			continue
		}
		got, err := ex.FromOutput(profile.ID, bound, command, out)
		if err != nil {
			// An authored pattern that will not compile is a data/validator
			// drift, not a device problem. It is SEEN, never swallowed (§10).
			s.log("identity probe pattern unusable", map[string]any{
				"device_id": t.DeviceID, "platform": profile.ID,
				"command": command, "error": err.Error(),
			})
			continue
		}
		if id.Serial == "" && got.Serial != "" {
			id.Serial, id.SerialCommand, id.ProfileID = got.Serial, got.SerialCommand, profile.ID
		}
		if id.Model == "" && got.Model != "" {
			id.Model, id.ModelCommand, id.ProfileID = got.Model, got.ModelCommand, profile.ID
		}
	}
	return id
}

// checkCommand re-checks an authored command's shape immediately before it is
// put on a wire. The loader already validated it; this is the second gate that
// makes the rung a CLOSED command source by construction — there is no caller
// input anywhere on this path, and a profile edit can never turn it into a way
// to execute something else at a device (§8 least privilege).
func (s *SSHSource) checkCommand(command string) error {
	if strings.TrimSpace(command) == "" {
		return errors.New("osprobe: refusing an empty command")
	}
	for _, bad := range commandForbiddenBytes {
		if strings.Contains(command, bad) {
			return fmt.Errorf("osprobe: refusing command %q: contains %q", command, bad)
		}
	}
	return nil
}

// log is the rung's structured-log sink, with the same never-silent fallback
// the ladder's own logger has.
func (s *SSHSource) log(msg string, fields map[string]any) {
	logFields(s.Logf, "osprobe: ", msg, fields)
}

func (s *SSHSource) pattern(expr string) (*regexp.Regexp, error) {
	return compileCached(&s.mu, &s.cache, expr)
}

// compileCached compiles an authored pattern once per source. The patterns come
// from validated profile data, so a compile failure here is a data/validator
// drift — returned as an error the ladder counts and logs, never swallowed.
func compileCached(mu *sync.Mutex, cache *map[string]*regexp.Regexp, expr string) (*regexp.Regexp, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, errors.New("osprobe: empty version pattern")
	}
	mu.Lock()
	defer mu.Unlock()
	if *cache == nil {
		*cache = map[string]*regexp.Regexp{}
	}
	if re, ok := (*cache)[expr]; ok {
		return re, nil
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("osprobe: version pattern %q: %w", expr, err)
	}
	(*cache)[expr] = re
	return re, nil
}
