package wireless

// identity.go — deterministic identity for every wireless entity (report §7.2)
// and the entity_id string forms correlation signals carry (report §7.3).
//
// TWO RULES, both load-bearing:
//
//  1. Identity is DERIVED, never assigned, and never from a display name. An
//     AP rename must not fork its history; the same controller record fetched
//     twice must produce byte-identical ids (replay + dedupe depend on it).
//
//  2. The entity_id string forms are STRUCTURED for the engine's grounding
//     derivation: engine.py device_part() splits on the first ':', so
//     "ap:<id>:radio0" grounds at rank 1 (resource identity) to "ap:<id>"
//     with no new engine code. Getting these strings wrong silently loses
//     all wireless correlation — change them only with the design doc.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// hashID is the shared derivation: sha256 over the identity fields, joined by
// '|', truncated to 16 bytes hex (32 chars — collision-safe at inventory
// scale, short enough for entity ids and UI).
func hashID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:16])
}

// normMAC canonicalizes a MAC address for identity use: lower-case,
// colon-separated, separators normalized ("AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff"
// and "AA:BB:CC:DD:EE:FF" all converge). A malformed value passes through
// lower-cased — identity must be deterministic, not validating.
func normMAC(mac string) string {
	s := strings.ToLower(strings.TrimSpace(mac))
	s = strings.NewReplacer("-", "", ":", "", ".", "").Replace(s)
	if len(s) != 12 {
		return strings.ToLower(strings.TrimSpace(mac))
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(s[i : i+2])
	}
	return b.String()
}

// IsRandomizedMAC reports whether a MAC is locally administered (U/L bit set)
// — the randomized-MAC signal for the identity ladder (report §9.3). A
// malformed MAC returns true: fail-closed, the identity ladder must
// under-claim continuity, never over-claim it.
func IsRandomizedMAC(mac string) bool {
	m := normMAC(mac)
	if len(m) < 2 {
		return true
	}
	var first byte
	if _, err := fmt.Sscanf(m[:2], "%02x", &first); err != nil {
		return true
	}
	return first&0x02 != 0
}

// ControllerID derives the logical-controller identity from what cannot be
// renamed: tenant + vendor + the management address (the thing APs join). A
// cloud-managed "controller" (dashboard org) uses its org/tenant identifier
// as the address.
func ControllerID(tenant, vendor, managementAddress string) string {
	return hashID(tenant, strings.ToLower(vendor), strings.ToLower(strings.TrimSpace(managementAddress)))
}

// MemberID derives a physical member's identity from its serial (fallback:
// name — a physical box's configured name is stable in a way an AP's is not,
// and some vendors expose no member serial).
func MemberID(tenant, controllerID, serial, name string) string {
	key := strings.TrimSpace(serial)
	if key == "" {
		key = strings.TrimSpace(name)
	}
	return hashID(tenant, controllerID, strings.ToLower(key))
}

// APID derives an AP's identity: serial when present, else base MAC. NEVER the
// name (rename-stability is unit-tested).
func APID(tenant, vendor, serial, macBase string) string {
	if s := strings.TrimSpace(serial); s != "" {
		return hashID(tenant, strings.ToLower(vendor), strings.ToLower(s))
	}
	return hashID(tenant, strings.ToLower(vendor), normMAC(macBase))
}

// RadioID is ap_id|slot. Slot, not band: dual-5GHz and tri-band make band
// ambiguous as an identity axis.
func RadioID(apID string, slot int) string {
	return fmt.Sprintf("%s|%d", apID, slot)
}

// WLANID is controller-scoped: the same profile name on two controllers is
// two WLANs.
func WLANID(tenant, controllerRef, profileName string) string {
	return hashID(tenant, controllerRef, profileName)
}

// SSIDID is deliberately NOT controller-scoped (report §9): the SSID is a
// broadcast string; whether two controllers broadcasting "corp" form one
// roaming domain is answered by mobility_domain_ref, never by SSID identity.
func SSIDID(tenant, ssidName string) string {
	return hashID(tenant, ssidName)
}

// SessionID is the always-reliable per-association identity (report §9.3):
// deterministic over (tenant, bssid, client MAC, association start ms) —
// replayable, never ambiguous, sufficient for every single-session RCA.
func SessionID(tenant, bssid, clientMAC string, assocStartMs int64) string {
	return hashID(tenant, normMAC(bssid), normMAC(clientMAC), fmt.Sprintf("%d", assocStartMs))
}

// ── entity_id string forms (report §7.3, corrected) ─────────────────────────
//
// The engine's device_part() takes everything LEFT OF THE FIRST ':'
// (engine.py:242 — verified, not assumed). So the domain prefix is joined to
// the hash with a HYPHEN, never a colon: "ap-<hash>:radio0" grounds to device
// "ap-<hash>" ✓, whereas "ap:<hash>:radio0" would ground to the literal
// estate-wide token "ap" — every AP in the tenant welded through one shared
// token, the exact #99 bug class. This is unit-tested below and must never
// regress.
//
// The AP uplink deliberately has no helper here: it is an ordinary interface
// entity ("<switch_id>:<ifname>") owned by the LAN domain — that reuse IS the
// rank-1 wireless↔LAN join.

// APEntityID → "ap-<ap_id>".
func APEntityID(apID string) string { return "ap-" + apID }

// RadioEntityID → "ap-<ap_id>:radio<slot>" (device part = "ap-<ap_id>").
func RadioEntityID(apID string, slot int) string {
	return fmt.Sprintf("ap-%s:radio%d", apID, slot)
}

// BSSIDEntityID → "ap-<ap_id>:bssid-<mac-no-colons>" (device part =
// "ap-<ap_id>"). The MAC is compacted — a colon inside the tail would not
// break device_part (only the FIRST ':' splits) but would break the
// "one ':' = device:component" reading humans and dashboards rely on.
func BSSIDEntityID(apID, bssid string) string {
	return "ap-" + apID + ":bssid-" + strings.ReplaceAll(normMAC(bssid), ":", "")
}

// ControllerEntityID → "wlc-<controller_id>".
func ControllerEntityID(controllerID string) string { return "wlc-" + controllerID }

// MemberEntityID → "wlc-<controller_id>:<member_id>" (device part = the
// logical controller, so member health and cluster capability ground rank-1).
func MemberEntityID(controllerID, memberID string) string {
	return "wlc-" + controllerID + ":" + memberID
}

// ClientEntityID → "wcl-<client_id>".
func ClientEntityID(clientID string) string { return "wcl-" + clientID }

// SessionEntityID → "wcl-<client_id>:<session_id>" (device part = the client).
func SessionEntityID(clientID, sessionID string) string {
	return "wcl-" + clientID + ":" + sessionID
}

// WLANEntityID → "wlan-<wlan_id>". NEVER an entity_token: a WLAN (like an
// SSID) spans the estate, and an estate-wide grounding token welds unrelated
// incidents into one object — the #99 bug class. signals.py forbids the
// ssid:/wlan: token prefixes at the model layer.
func WLANEntityID(wlanID string) string { return "wlan-" + wlanID }
