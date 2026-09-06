// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package configstore is Correlix's device CONFIG BACKUP module (P3-CFG, design
// docs/design/CONFIG_BACKUP_AND_DRIFT_DESIGN_2026-08-25.md): capture a device's
// running-configuration over the platform's audited SSH gateway, normalize it,
// content-address it, and store it SEALED at rest with per-device retention.
//
// ── WHAT THIS PACKAGE IS ────────────────────────────────────────────────────
// It is a FOUNDATIONAL (NMS-grade) producer, NOT a security package. Security,
// compliance and RCA are CONSUMERS of what it produces (internal/configdrift is
// the first of them). Per the design's module boundary this package therefore
// imports NOTHING security-specific — no secfindings, no secbus, no hardening —
// only the standard library, the allowlisted vendored ssh client (CLAUDE.md §6)
// and internal/platformdb for the relational seam. Deleting internal/configdrift
// leaves this package green; deleting BOTH removes the feature.
//
// ── THE HARD CONSTRAINTS (why the code looks like this) ─────────────────────
//   - §8 A running-config IS a secret (SNMP communities, key material, password
//     hashes). Nothing is ever written to disk in plaintext: the capture is
//     sealed with the platform's own sealing mechanism (vault.Encrypt, per-tenant
//     DEK) before it touches the filesystem, the blob directory is 0700 and the
//     blobs 0600, and Postgres holds METADATA ONLY (device, tenant, version sha,
//     captured_at, size, blob ref, status/error) — never the config text.
//   - §8 Every API response and every diff is REDACTED by a documented,
//     per-vendor secret-line rule list (redact.go). The sealed copy keeps the
//     original; the operator sees "enable secret ****".
//   - §9 Bounded everywhere: a per-capture context timeout, a hard
//     MaxCaptureBytes read cap, ONE capture in flight per device (429 on
//     overlap), a jittered scheduler with TryLock so passes never overlap, a
//     bounded diff, and per-device retention that prunes oldest-first.
//   - §3a Every read/list/write is scoped by the caller's principal. The store
//     ITSELF filters (Postgres by the tenant_iso FORCE-RLS policy through
//     WithTenant, file by a tenant-keyed map) — there is no unscoped "list all".
//     A cross-tenant version or device id answers 404, never 403.
//   - §5 Every external dependency is INJECTED through Deps. This package opens
//     no socket it was not handed a dialer for, reads no environment variable
//     and holds no ambient authority; it is unit-testable end to end with no
//     device, no Postgres and no vault present.
//
// ── SSH CAPTURE ─────────────────────────────────────────────────────────────
// Capture runs over the SAME SSH client the operator gateway (device_ssh.go)
// uses, under the SAME host-key TOFU custody: sshgw.go builds an
// ssh.ClientConfig whose HostKeyCallback delegates to an INJECTED check func
// which production binds to the gateway's own pinned-fingerprint store. There is
// no second host-key policy, no InsecureIgnoreHostKey, and no path that accepts
// a changed key. The session is a single non-interactive `exec` of ONE command
// taken from the closed per-vendor table in dialect.go — never a shell, never a
// caller-supplied string.
package configstore

import "time"

// Environment contract. This package does NOT read the environment; the
// integrator does (the seclane precedent) and hands the resolved values in
// through Deps. The names live here so there is exactly one spelling of each.
const (
	// EnvFeatureFlag gates the whole module. Default FALSE: with the flag off
	// NOTHING is constructed, scheduled or routed, and the routes 404.
	EnvFeatureFlag = "FEATURE_CONFIG_BACKUP"
	// EnvInterval is the scheduled capture cadence (a Go duration).
	EnvInterval = "CONFIG_BACKUP_INTERVAL"
	// EnvKeepVersions is the per-device retention depth.
	EnvKeepVersions = "CONFIG_BACKUP_KEEP_VERSIONS"
	// EnvDir is the sealed-blob directory (created 0700).
	EnvDir = "CONFIG_BACKUP_DIR"
	// EnvSSHUser / EnvSSHPassword / EnvSSHKey configure the least-privilege,
	// read-only capture account. The password/key are sealed at rest by the
	// integrator exactly like every other reversible secret; they never appear
	// in a log, a response or an audit detail.
	EnvSSHUser     = "CONFIG_BACKUP_SSH_USER"
	EnvSSHPassword = "CONFIG_BACKUP_SSH_PASSWORD" // #nosec G101 -- env var NAME, not a credential
	EnvSSHKey      = "CONFIG_BACKUP_SSH_KEY"
	// EnvSSHPort overrides the device SSH port (default 22).
	EnvSSHPort = "CONFIG_BACKUP_SSH_PORT"
)

// Shipped defaults for the environment contract above.
const (
	// DefaultInterval is the shipped scheduled cadence (daily, jittered).
	DefaultInterval = 24 * time.Hour
	// DefaultKeepVersions is the shipped per-device retention depth.
	DefaultKeepVersions = 30
	// DefaultDir is the shipped sealed-blob directory.
	DefaultDir = "/data/config-backups"

	// MaxCaptureBytes is the hard cap on ONE captured configuration (§9). A
	// device that streams more than this fails the capture loudly rather than
	// filling the volume — 4 MiB is ~10x the largest real running-config.
	MaxCaptureBytes = 4 << 20
	// DefaultCaptureTimeout bounds one device's capture end to end.
	DefaultCaptureTimeout = 60 * time.Second
	// DefaultDialTimeout bounds the TCP dial + SSH handshake.
	DefaultDialTimeout = 10 * time.Second

	// scheduleJitterFrac is the ±fraction of full jitter on every scheduled
	// interval, so replicas never capture in lockstep (§9).
	scheduleJitterFrac = 0.10
	// maxDevicesPerPass bounds ONE scheduled pass's fan-out.
	maxDevicesPerPass = 5000
	// minKeepVersions / maxKeepVersions bound the retention knob.
	minKeepVersions = 2
	maxKeepVersions = 500
)
