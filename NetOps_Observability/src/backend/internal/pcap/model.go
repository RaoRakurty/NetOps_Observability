// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pcap

import (
	"errors"
	"strings"
	"time"
)

// model.go — the module's own types. Nothing here imports the core inventory
// model, so deleting internal/pcap touches nothing else (the seclane/configstore
// removal-rule precedent).

// Capture lifecycle states. A capture is NEVER silently dropped: a run that
// could not be taken ends `failed` with a scrubbed reason, because "we tried and
// could not" is information the operator needs (§10 no silent failures).
const (
	// StatusRunning — the capture point is up on the device.
	StatusRunning = "running"
	// StatusStored — the capture ended, was fetched and is sealed at rest.
	StatusStored = "stored"
	// StatusFailed — the capture could not be taken, fetched or stored.
	StatusFailed = "failed"
)

// Device is the minimal device projection this module captures from — this
// package's OWN type, so it never depends on the core inventory model.
type Device struct {
	ID       string
	Name     string
	Address  string
	Vendor   string
	OS       string
	Model    string
	TenantID string // the owning tenant, from the inventory row (§3a rule 2)
	Port     int    // 0 = the integrator's default
}

// Platform renders the free-form platform token the command table resolves on.
func (d Device) Platform() string {
	return strings.TrimSpace(strings.Join(strings.Fields(d.Vendor+" "+d.OS+" "+d.Model), " "))
}

// Capture is ONE capture record — METADATA ONLY. The packet bytes live sealed
// under BlobRef and are never carried on this struct, so a record can be logged,
// listed and joined without any risk of spilling a payload byte (§8).
//
// It is a STORE ROW, not a response body: the JSON tags are the file backend's
// on-disk format and no handler marshals this type — every response is projected
// explicitly in http.go, which is what keeps TenantID and BlobRef off the wire.
type Capture struct {
	// TenantID is the owning tenant, stamped from the DEVICE row (never a
	// request body, §3a rule 2).
	TenantID  string `json:"tenant_id"`
	DeviceID  string `json:"device_id"`
	ID        string `json:"capture_id"`
	Interface string `json:"interface"`
	Filter    string `json:"filter,omitempty"`

	DurationSec int `json:"duration_s"`
	MaxPackets  int `json:"max_packets"`

	StartedAt time.Time  `json:"started_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`

	Status  string `json:"status"`
	Packets int    `json:"packets"`
	Bytes   int64  `json:"bytes"`
	// Error is the SCRUBBED reason a capture failed. Present only when
	// Status == StatusFailed.
	Error string `json:"error,omitempty"`
	// BlobRef is the sealed blob's key inside the blob store. Empty until the
	// capture is stored.
	BlobRef string `json:"blob_ref,omitempty"`
	// Actor is the subject that started the capture. A capture is never
	// anonymous (design: "No capture is anonymous").
	Actor string `json:"actor,omitempty"`
	// RemotePath is the on-device file the runtime created, kept ONLY so a
	// cleanup retry knows what to delete. It is never rendered to a client.
	RemotePath string `json:"remote_path,omitempty"`
	// Platform is the resolved command-table key (audit/debug provenance).
	Platform string `json:"platform,omitempty"`
}

// Errors the HTTP layer maps onto status codes. They are values, not strings
// compared at a boundary, so a rename cannot silently change a status code.
var (
	// ErrNotFound is the 404 condition — including EVERY cross-tenant id, which
	// must never be distinguishable from a non-existent one (§3a rule 1).
	ErrNotFound = errors.New("not found")
	// ErrInFlight is the 409 condition: this device already has a capture
	// running. Two capture points on one interface is exactly the device impact
	// the design's top risk is about.
	ErrInFlight = errors.New("a packet capture is already running for this device")
	// ErrNoPlatform is the honest refusal for a device whose platform has no
	// capture command bound. Guessing a capture command at a live router is the
	// "invent an API" failure mode §7 forbids.
	ErrNoPlatform = errors.New("no packet-capture command set is bound for this device's platform")
	// ErrFilterUnsupported is returned when a filter was requested but the
	// device's platform cannot express one. The capture is REFUSED rather than
	// run unfiltered: silently widening a capture the operator deliberately
	// narrowed would capture traffic they did not ask for.
	ErrFilterUnsupported = errors.New("this device's platform cannot apply a capture filter; re-run without one")
	// ErrNoAddress is a device with nothing to dial.
	ErrNoAddress = errors.New("device has no address")
	// ErrTooLarge is the MaxBytes refusal.
	ErrTooLarge = errors.New("packet capture exceeded the maximum capture size")
	// ErrNotReady is a download of a capture that is not stored yet.
	ErrNotReady = errors.New("this capture has no stored bytes")
	// ErrDisabled is returned by a nil/dormant manager.
	ErrDisabled = errors.New("packet capture is not enabled")
)

// NormTenant is the canonical tenant-id spelling used by the store keys, the RLS
// GUC and the blob path segments. One spelling, one place.
func NormTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// Seg renders a filesystem-safe path segment from an untrusted id.
func Seg(s string) string {
	t := NormTenant(s)
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
	if b.Len() == 0 {
		return "global"
	}
	return b.String()
}

// visible reports whether a caller scoped to `tenant` (or cross-tenant) may see
// rows owned by `owner`. It is the ONE place the answer is computed, so there is
// no second, subtly different copy of the isolation rule.
func visible(tenant string, cross bool, owner string) bool {
	if cross {
		return true
	}
	return NormTenant(tenant) == NormTenant(owner)
}

// Active reports whether a capture is still occupying its device.
func (c Capture) Active() bool { return c.Status == StatusRunning }
