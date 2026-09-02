package secfindings

// platform.go — the subject's PLATFORM IDENTITY, resolved through the one vendor
// vocabulary (T9 residual, tracker 216).
//
// Every provider fills Resource.Platform with whatever free-form label its own
// upstream carries: "Cisco IOS-XE 17.9" from an inventory row, "cisco ios_xe
// ISR4331" from a vendor+os+model join, a syslog event's platform hint. That
// string is EVIDENCE — it is what the device (or the operator) actually said, and
// it stays on the finding untouched.
//
// What it must NOT be is a thing every consumer re-parses with its own vendor
// substring table. That is exactly the drift the vendor-profile registry exists
// to kill: a consumer that wants to know "is this a Junos box?" should read one
// canonical id, not re-implement detection. ResolvePlatform stamps that id —
// Resource.ProfileID, an internal/vendorprofile profile id like "cisco/ios_xe" —
// from the registry's ranked platform_contains table.
//
// HONESTY. A label the registry does not recognize leaves ProfileID EMPTY. There
// is no default profile and no guess: an empty ProfileID means "we could not
// identify this platform", which a consumer must treat as unassessed, never as
// "some other vendor".

import (
	"strings"

	"netops/backend/internal/vendorprofile"
)

// ResolvePlatform returns a copy of the resource with ProfileID stamped from the
// free-form Platform label through the vendor-profile registry.
//
// It is IDEMPOTENT and never destructive: Platform is left exactly as the
// provider set it, a ProfileID the caller already stamped is kept, and a label
// the registry cannot resolve leaves ProfileID empty (the honest "unidentified
// platform" — never a fallback profile).
func (r Resource) ResolvePlatform() Resource {
	if r.ProfileID != "" || strings.TrimSpace(r.Platform) == "" {
		return r
	}
	if prof, ok := vendorprofile.Default().ProfileForPlatformText(r.Platform); ok {
		r.ProfileID = prof.ID
	}
	return r
}

// ResolvePlatform stamps Resource.ProfileID on the finding in place. It is the
// one-line call a provider makes after filling the resource, so the normalized
// identity is attached at the point the free-form label is known rather than
// re-derived by every downstream reader.
func (f *Finding) ResolvePlatform() {
	f.Resource = f.Resource.ResolvePlatform()
}
