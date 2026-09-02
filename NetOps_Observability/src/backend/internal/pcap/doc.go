// Package pcap is the per-interface, BOUNDED, on-device packet-capture module
// (docs/design/PACKET_CAPTURE_DESIGN_2026-08-25.md).
//
// A PCAP is the most sensitive artifact this platform produces: unlike a
// configuration, it contains the DATA PLANE — real payload, real credentials,
// real PII. Every decision in this package is therefore made in the direction of
// "capture less, prove more":
//
//   - OPT-IN AND DORMANT. Nothing is constructed, started or routed unless
//     FEATURE_PACKET_CAPTURE=true. A flag-off deployment answers 404, so the
//     feature is not even enumerable.
//   - HARD BOUNDS, ENFORCED HERE. Duration <= MaxDurationSeconds, packets <=
//     MaxPackets, bytes <= MaxBytes, and ONE capture per device at a time.
//     Whichever bound hits first stops the capture and tears the capture point
//     down. There is no "capture forever" and the API cannot express one — an
//     unbounded capture can take a production router off the network (design,
//     "Risks").
//   - NO SHELL, EVER. The device only ever sees a command rendered by the
//     CommandTable from a CLOSED per-vendor template. Caller-supplied values
//     (interface, BPF filter) are validated against strict grammars BEFORE
//     rendering, and the grammars admit no character that means anything to a
//     shell or a device CLI parser. This is the §4/§8 "least-privilege command
//     allowlist, never a general shell" rule made structural.
//   - SEALED AT REST. The capture bytes are sealed under the owning tenant's DEK
//     and written 0600 under a 0700 tree; Postgres (migration 0039,
//     pcap_captures, tenant_iso FORCE-RLS) holds METADATA ONLY. A dumped
//     database yields an inventory of captures, never a packet.
//   - AUDITED. Start, fetch and download are each audited with a `sensitive`
//     tag: a PCAP reveal is a privileged act and must never be anonymous.
//   - TENANT-SCOPED. The device is resolved through the caller's own inventory
//     first; a foreign or absent id answers 404 alike (§3a rule 1), and the
//     store itself filters by tenant (§3a rule 4).
//
// This package holds NO ambient authority: the gateway, the store, the sealer,
// the clock, the authz gate and the audit sink are all injected (§5).
package pcap

import "time"

// Environment knobs (the integrator reads these; this package only names them).
const (
	// EnvFeatureFlag is the opt-in switch. Anything but "true" leaves the module
	// dormant.
	EnvFeatureFlag = "FEATURE_PACKET_CAPTURE"
	// EnvDir is the sealed capture blob directory.
	EnvDir = "PCAP_DIR"
	// EnvKeep is per-device retention (how many captures to keep).
	EnvKeep = "PCAP_KEEP"
	// EnvMetaFile is the file-backend metadata register.
	EnvMetaFile = "PCAP_METADATA_FILE"
	// EnvSSHUser / EnvSSHPassword / EnvSSHKey are the least-privilege capture
	// identity, sealed at rest like every other reversible secret.
	EnvSSHUser     = "PCAP_SSH_USER"
	EnvSSHPassword = "PCAP_SSH_PASSWORD" // #nosec G101 -- env var NAME, not a credential
	EnvSSHKey      = "PCAP_SSH_KEY"
	// EnvSSHPort is the default SSH port when a device carries none.
	EnvSSHPort = "PCAP_SSH_PORT"
)

// Defaults and HARD CAPS. The caps are not configurable: an operator knob that
// can raise "max capture duration" to an hour is the same unbounded capture the
// design forbids, wearing a config file.
const (
	// MaxDurationSeconds is the hard ceiling on one capture's wall time.
	MaxDurationSeconds = 60
	// DefaultDurationSeconds is the small default the design asks for.
	DefaultDurationSeconds = 30
	// MaxPackets is the hard ceiling on captured frames.
	MaxPackets = 10000
	// DefaultPackets is the default frame budget.
	DefaultPackets = 2000
	// MaxBytes is the hard ceiling on the fetched capture file (25 MiB).
	MaxBytes int64 = 25 << 20
	// MaxFilterLen bounds the BPF expression before it is even tokenized (§9).
	MaxFilterLen = 256
	// MaxInterfaceLen bounds an interface name.
	MaxInterfaceLen = 64
	// DefaultKeep is per-device retention.
	DefaultKeep = 20
	// MinKeep / MaxKeep clamp the retention knob: "keep 0" would delete the
	// artifact the module exists to produce.
	MinKeep = 1
	MaxKeep = 200
	// MaxControlOutputBytes bounds what a control-plane command may print back.
	MaxControlOutputBytes int64 = 256 << 10
	// DefaultDialTimeout bounds dial + handshake.
	DefaultDialTimeout = 10 * time.Second
	// StopGrace is how long past the requested duration the runtime waits before
	// forcing the stop/cleanup commands.
	StopGrace = 15 * time.Second
	// MaxListLimit bounds a capture listing (§9 all queues bounded).
	MaxListLimit = 200
	// DefaultListLimit is the unrequested page size.
	DefaultListLimit = 50
)

// ClampKeep bounds the retention knob.
func ClampKeep(keep int) int {
	switch {
	case keep < MinKeep:
		return DefaultKeep
	case keep > MaxKeep:
		return MaxKeep
	default:
		return keep
	}
}
