package configstore

import (
	"errors"
	"strings"
	"time"
)

// Capture statuses stored on a version row. A FAILED capture is stored too —
// "we tried and could not reach the device" is information an operator needs,
// and silently keeping only successes would render an unreachable device as
// merely stale (§10 no silent failures).
const (
	StatusOK     = "ok"
	StatusFailed = "failed"
)

// Drift states. This vocabulary is SHARED with internal/configdrift and is the
// exact set the API and the inventory badge render:
//
//	in_sync — the capture matched the previous version and (if one is set) the
//	          golden baseline.
//	changed — the capture differs from the previous version.
//	drifted — the capture differs from the GOLDEN baseline (outranks changed:
//	          a device that walked away from its known-good is the louder fact).
//	unknown — never captured, or the last capture failed. NEVER rendered green:
//	          an unassessed device must not look like a clean one.
const (
	DriftInSync  = "in_sync"
	DriftChanged = "changed"
	DriftDrifted = "drifted"
	DriftUnknown = "unknown"
)

// Device is the minimal device projection this module captures from. It is this
// package's OWN type (the seclane/hardening precedent) so the module never
// depends on the core inventory model — deleting it touches nothing else.
type Device struct {
	ID       string
	Name     string
	Address  string
	Vendor   string
	OS       string
	Model    string
	TenantID string // the owning tenant, from the inventory row (§3a)
	Port     int    // 0 = the integrator's default
}

// Platform renders the free-form platform token the vendor normalizer reads.
func (d Device) Platform() string {
	return strings.TrimSpace(strings.Join(strings.Fields(d.Vendor+" "+d.OS+" "+d.Model), " "))
}

// Version is ONE stored configuration version — METADATA ONLY. The config text
// itself lives sealed under BlobRef and is never carried on this struct, so a
// version row can be logged, listed and joined without any risk of spilling a
// device's secrets (§8).
//
// It is a STORE ROW, not a response body: the JSON tags below are the file
// backend's on-disk format, and NO handler ever marshals this type. Every
// response is projected explicitly in http.go (versionItem and friends), which
// is what keeps TenantID and BlobRef — the owner stamp and a filesystem path —
// off the wire while still round-tripping through the state file.
type Version struct {
	// TenantID is the owning tenant, stamped from the DEVICE row (never a
	// request body, §3a rule 2).
	TenantID   string    `json:"tenant_id"`
	DeviceID   string    `json:"device_id"`
	SHA        string    `json:"sha"` // sha256 of the NORMALIZED config, hex
	CapturedAt time.Time `json:"captured_at"`
	SizeBytes  int64     `json:"size_bytes"` // normalized plaintext size
	// BlobRef is the sealed blob's key inside the blob store.
	BlobRef string `json:"blob_ref,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
	Status  string `json:"status"`          // ok | failed
	Error   string `json:"error,omitempty"` // scrubbed capture error (failed only)
	Golden  bool   `json:"golden,omitempty"`
	// Drift/Added/Removed are the drift verdict this capture produced, filled in
	// by internal/configdrift through RecordDrift. They ride the version row so
	// the versions list can render the timeline without a second store.
	Drift   string `json:"drift,omitempty"`
	Added   int    `json:"added,omitempty"`
	Removed int    `json:"removed,omitempty"`
}

// Errors the HTTP layer maps onto status codes. They are values, not strings
// compared at the boundary, so a rename cannot silently change a status code.
var (
	// ErrNotFound is the 404 condition — including EVERY cross-tenant id, which
	// must never be distinguishable from a non-existent one (§3a rule 1).
	ErrNotFound = errors.New("not found")
	// ErrInFlight is the 429 condition: a capture for this device is already
	// queued or running.
	ErrInFlight = errors.New("a configuration backup is already running for this device")
	// ErrNoVendor is the honest refusal for a device whose platform this module
	// has no capture command for. Guessing a command at a device CLI is exactly
	// the "invent an API" failure mode CLAUDE.md §7 forbids.
	ErrNoVendor = errors.New("no configuration-capture command is bound for this device's platform")
	// ErrNoAddress is a device with nothing to dial.
	ErrNoAddress = errors.New("device has no address")
	// ErrTooLarge is the MaxCaptureBytes refusal.
	ErrTooLarge = errors.New("configuration exceeded the capture size cap")
	// ErrDisabled is returned by a nil/dormant manager.
	ErrDisabled = errors.New("config backup is not enabled")
)

// NormTenant is the canonical tenant-id spelling used by the store keys, the
// RLS GUC and the metric segments. One spelling, one place.
func NormTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// Seg renders a tenant id as a bounded, label-safe metric/path segment. Same
// intent as seclane.TenantSeg, kept local so this package stays a leaf.
func Seg(tenant string) string {
	t := NormTenant(tenant)
	if t == "" {
		return "global"
	}
	var b strings.Builder
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
		if b.Len() >= 64 {
			break
		}
	}
	out := b.String()
	if out == "" {
		return "global"
	}
	return out
}

// visible reports whether a caller scoped to `tenant` (or cross-tenant) may see
// rows owned by `owner`. The ONE place the file backend answers that question.
func visible(tenant string, cross bool, owner string) bool {
	return cross || owner == NormTenant(tenant)
}
