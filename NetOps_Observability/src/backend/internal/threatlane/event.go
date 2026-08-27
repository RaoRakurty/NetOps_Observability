package threatlane

import (
	"net"
	"strings"
	"time"
)

// LogEvent is the NORMALIZED device-log record the device-log detections match
// over. It is deliberately vendor-neutral and pre-parsed: the upstream syslog
// normalizer (a later deploy step) is responsible for populating these fields
// from the raw wire message, so a rule reasons about a clean event and never
// re-parses vendor framing. Treat every field as UNTRUSTED input (§3/§15) — the
// match logic only reads, never executes, the text.
type LogEvent struct {
	// TenantID is the owning tenant, carried from the principal-scoped syslog row
	// upstream. It is stamped onto the emitted finding (§3a); it is NEVER taken
	// from a request body (this package has no request surface).
	TenantID string
	// DeviceID / Hostname / Platform identify the subject device. DeviceID is the
	// stable inventory id; Hostname/Platform enrich the finding's Resource.
	DeviceID string
	Hostname string
	Platform string
	// Time is the event time (when the device emitted the log), UTC preferred.
	Time time.Time
	// Facility is the syslog facility (e.g. "SEC", "SYS", "LINK"). Optional.
	Facility string
	// Severity is the device's own syslog severity token (e.g. "notifications",
	// "warnings"); it is informational context, not the finding severity.
	Severity string
	// Mnemonic is the vendor mnemonic tag (e.g. "SYS-5-CONFIG_I",
	// "PARSER-5-CFGLOG_LOGGEDCMD"). Low-FP rules key on this where possible.
	Mnemonic string
	// Message is the normalized human-readable event text. For config-delta
	// events the normalizer MAY include the salient changed config line here so a
	// rule can match on it without a separate config fetch.
	Message string
	// User is the actor associated with the event, when the log carries one
	// (e.g. the CLI user who made a change). Optional.
	User string
}

// normalized returns the lowercased mnemonic + message joined for case-
// insensitive matching. It never mutates the event.
func (e LogEvent) normalized() string {
	return strings.ToLower(e.Mnemonic + " " + e.Message)
}

// FlowRecord is a NORMALIZED flow (one IPFIX/NetFlow record) the flow-behavioral
// detections reason over. It is the minimal slice of the netops.flows schema the
// behavioral rules need; the upstream flow normalizer populates it. Fields are
// UNTRUSTED input.
type FlowRecord struct {
	// TenantID owns the flow (from the principal-scoped flows row). Stamped onto
	// the finding (§3a).
	TenantID string
	// DeviceID / Hostname identify the EXPORTER (the device that observed the
	// flow) — the subject the finding grounds on.
	DeviceID string
	Hostname string
	// SrcAddr / DstAddr are the flow endpoints; DstPort / Proto the transport.
	SrcAddr string
	DstAddr string
	DstPort int
	Proto   int
	// Bytes / Packets are the flow's already-scaled counters (sampling applied
	// upstream). Behavioral rules sum these.
	Bytes   uint64
	Packets uint64
	// Start is the flow start time — the ordering key for inter-arrival (beacon)
	// analysis.
	Start time.Time
}

// isInternalIP reports whether addr is an RFC1918 / loopback / link-local /
// unique-local address — i.e. NOT a routable external peer. It is the honest,
// self-contained classifier the exfil rule uses to tell "internal source →
// external destination" without any external geo/reputation feed. A malformed
// address returns false (treated as non-internal, but the exfil rule also
// requires a valid internal source, so a garbage pair cannot trip it).
func isInternalIP(addr string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	// RFC1918 + RFC4193 unique-local (fc00::/7).
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127: // CGNAT 100.64/10
			return true
		default:
			return false
		}
	}
	return len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc
}

// isExternalIP is the parsed-and-routable complement of isInternalIP: true only
// for a well-formed address that is NOT internal. A malformed address is neither
// internal nor external (so it cannot, on its own, satisfy an exfil verdict).
func isExternalIP(addr string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return false
	}
	return !isInternalIP(addr)
}
