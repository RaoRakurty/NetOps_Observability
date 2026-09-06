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

	mu    sync.Mutex
	cache map[string]*regexp.Regexp
}

// NewSSHSource builds the read-only CLI rung.
func NewSSHSource(run CommandRunner, profiles Profiles) *SSHSource {
	return &SSHSource{Run: run, Profiles: profiles, cache: map[string]*regexp.Regexp{}}
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

// Probe implements Source.
func (s *SSHSource) Probe(ctx context.Context, t Target) (string, error) {
	if s == nil || s.Run == nil || s.Profiles == nil {
		return "", ErrNotConfigured
	}
	profile, probe, ok := s.Profiles.OSVersionProbeForDevice(t.Vendor, t.OSText)
	if !ok || !probe.HasCLI() {
		return "", fmt.Errorf("%w: no cli version pattern for this platform", ErrNotConfigured)
	}
	command := strings.TrimSpace(profile.Capture.ShowVersionCmd)
	if command == "" {
		// The loader forbids this pairing, so reaching it means the data and the
		// validator have drifted. Refuse rather than improvise a command.
		return "", fmt.Errorf("%w: platform %q declares a cli version pattern but no show-version command", ErrNotConfigured, profile.ID)
	}
	for _, bad := range commandForbiddenBytes {
		if strings.Contains(command, bad) {
			return "", fmt.Errorf("osprobe: refusing show-version command for %q: contains %q", profile.ID, bad)
		}
	}
	re, err := s.pattern(probe.CLIVersionPattern)
	if err != nil {
		return "", err
	}
	out, err := s.Run.Run(ctx, t, command)
	if err != nil {
		return "", fmt.Errorf("ssh %q: %w", command, err)
	}
	m := re.FindStringSubmatch(out)
	if m == nil {
		return "", nil // the device answered; nothing in it was a version
	}
	return probe.Render(strings.TrimSpace(m[1])), nil
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
