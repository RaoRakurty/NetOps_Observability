package processors

// quarantine.go — F-11 seal-or-quarantine (tracker #151 step 3, owner
// decision 2026-08-12): the generated router config's quarantine stage.
//
// THE INVARIANT: attribution failure must never become a confidentiality
// downgrade. An event whose identity the device→tenant registry does not
// know (a registry MISS, stamped `.tenant_registry = "miss"` at the lookup
// site in the Vector configs) must not be durably stored as plaintext in the
// shared `-untagged-` bucket. It is replaced wholesale by a metadata
// envelope whose payload — the entire original event, JSON-encoded — is
// sealed under the dedicated `quarantine` key scope, then routed by the
// base router config to the operator-only `netops-quarantine-*` index.
//
// WHAT DOES NOT QUARANTINE (Case 1, and the platform bucket):
//   - a registry HIT that maps a KNOWN platform/global device to the empty
//     tenant — that is the platform's own telemetry, the load-bearing
//     untagged bucket every self-monitoring surface reads. The guard below
//     keys on the MISS stamp, never on `tenant_id == ""` alone.
//   - lanes whose tenant arrives from an AUTHENTICATED producer stamp
//     (cloudlogs, the bus bridge) or is platform-only by construction
//     (applogs). Only the device-attribution lanes carry the stage.
//
// FAIL-CLOSED (INV-F11-06): the stage is its own remap with
// drop_on_abort/drop_on_error and NO reroute_dropped. A runtime seal
// failure aborts ⇒ the event is DROPPED and counted by Vector's component
// error metrics (alerted on) — it can neither continue plaintext to the
// normal sinks nor land in the plaintext deadletter index. A MISSING key is
// caught earlier still: the stage embeds SECRET[cxseal.quarantine] /
// SECRET[cxmac.quarantine] references, and Vector refuses to start (exit
// 78) when the secret backend cannot resolve them — the same SEC-018
// semantics every tenant seal key has.

import (
	"fmt"
	"strings"
)

// QuarantineScope is the sealing key scope for unattributable events. It is
// deliberately NOT a tenant: real tenant ids are minted `t_<hex>`, so no
// collision is possible; it passes validSecretKey and the secret-backend
// name parser; the unseal endpoint's owner check makes tokens naming it
// unreachable by every tenant principal (cross/platform only). Lowercase on
// purpose — normTenant and the tenant-guard VRL both downcase.
const QuarantineScope = "quarantine"

// QuarantineProcessorID is the pseudo processor id bound into the token
// context (and shown in audit trails). One id, stable across lanes: the MAC
// context already binds the field and scope, and a per-lane id would make
// re-attribution needlessly lane-aware.
const QuarantineProcessorID = "cx-quarantine"

// QuarantinePayloadField carries the sealed original event.
const QuarantinePayloadField = "cx_quarantine_payload"

// quarantineLanes are the device-attribution lanes (tenant derived from the
// registry lookup, identity supplied by an unauthenticated device protocol).
var quarantineLanes = map[string]bool{"syslog": true, "snmptrap": true, "flows": true}

// quarantineName is the generated transform's name for a lane.
func quarantineName(lane string) string { return lane + "_quarantine" }

// quarantineIdentityVRL extracts, per lane, the same identity value the
// registry lookup used — hashed into the envelope so re-attribution can
// match it against inventory identities without keeping the sender-supplied
// string in plaintext.
func quarantineIdentityVRL(lane string) string {
	switch lane {
	case "flows":
		return `to_string(.sampler_address) ?? ""`
	case "snmptrap":
		// Mirrors the aggregator's lookup: device, falling back to source IP.
		return `if (to_string(.device) ?? "") != "" { to_string!(.device) } else { to_string(.host) ?? "" }`
	default: // syslog
		return `to_string(.hostname) ?? ""`
	}
}

// quarantineSourceIPVRL keeps the transport-derived address where one exists
// (trap source, flow exporter). Syslog's source_ip is the relay, not the
// device — still recorded, honestly, as the ingress hop address.
func quarantineSourceIPVRL(lane string) string {
	switch lane {
	case "flows":
		return `to_string(.sampler_address) ?? ""`
	case "snmptrap":
		return `to_string(.host) ?? ""`
	default:
		return `to_string(.source_ip) ?? ""`
	}
}

// quarantineStageVRL renders the stage body for one lane, or ("", false)
// when the engine cannot seal the quarantine scope — the caller must then
// omit the stage entirely (a half-built stage would pass plaintext through
// a broken guard; absent means the baseline untagged path, which is exactly
// the pre-F-11 state and is at least honest).
func quarantineStageVRL(lane string, e SealEngine) (string, bool) {
	snippet, err := e.EdgeSnippet(QuarantineScope, QuarantineProcessorID,
		QuarantinePayloadField, "quarantine", "."+QuarantinePayloadField)
	if err != nil {
		return "", false
	}
	var b strings.Builder
	// Guard: registry MISS and still-untenanted. Both conditions on purpose —
	// a future lane that stamps tenant from an authenticated source without
	// touching tenant_registry must not quarantine its events.
	b.WriteString(`if ((to_string(.tenant_registry) ?? "") == "miss") && ((downcase(to_string(.tenant_id) ?? "")) == "") {` + "\n")
	fmt.Fprintf(&b, "  _cx_q_identity = %s\n", quarantineIdentityVRL(lane))
	fmt.Fprintf(&b, "  _cx_q_sip = %s\n", quarantineSourceIPVRL(lane))
	b.WriteString("  _cx_q_payload = encode_json(.)\n")
	b.WriteString("  . = {\n")
	b.WriteString(`    "cx_quarantine": true,` + "\n")
	b.WriteString(`    "cx_event_id": uuid_v4(),` + "\n")
	b.WriteString(`    "received_at": format_timestamp!(now(), format: "%+"),` + "\n")
	fmt.Fprintf(&b, "    \"lane\": %q,\n", lane)
	b.WriteString(`    "identity_sha": sha2(_cx_q_identity, variant: "SHA-256"),` + "\n")
	b.WriteString(`    "source_ip": _cx_q_sip,` + "\n")
	b.WriteString(`    "reason": "TENANT_UNATTRIBUTABLE",` + "\n")
	fmt.Fprintf(&b, "    %q: _cx_q_payload\n", QuarantinePayloadField)
	b.WriteString("  }\n")
	// The engine's own snippet: seals .cx_quarantine_payload in place with
	// SECRET[cxseal.quarantine]/SECRET[cxmac.quarantine] — identical VRL to a
	// tenant seal rule, so the parity tests cover this cipher path too.
	b.WriteString("  " + strings.ReplaceAll(strings.TrimRight(snippet, "\n"), "\n", "\n  ") + "\n")
	// Belt (INV-F11-06): if the payload is not a token now — engine snippet
	// regression, empty-plaintext edge — abort, which drops the event.
	b.WriteString(`  if !starts_with(to_string(.` + QuarantinePayloadField + `) ?? "", "<enc:v1:") { abort }` + "\n")
	b.WriteString("}")
	return b.String(), true
}