// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configdrift

import (
	"context"

	"netops/backend/internal/configstore"
	"netops/backend/internal/hardening"
)

// configsource.go — the hardening rule engine's ConfigSource, backed by the
// sealed config store.
//
// This is the wire the hardening lane has been waiting for. Until now
// internal/seclane passed a nil ConfigSource, so every §5e hardening rule
// reported "running-config unavailable — control not assessed (fail-closed)":
// honest, but an entirely unassessed security page. With config backup enabled,
// the SAME rules now evaluate against the device's latest captured
// running-config and produce real verdicts.
//
// Three properties matter and each is deliberate:
//
//   - It returns the UNREDACTED plaintext. The hardening rules detect exactly
//     the things redaction masks (`snmp-server community public`,
//     `enable password`), so a redacted config would make every credential-
//     hygiene rule silently pass. The text never leaves the process: the engine
//     emits verdicts and by-reference evidence pointers, never config lines.
//   - ok=false (never a fabricated empty config) when nothing is captured, so
//     the engine's fail-closed StatusUnknown path is the one that runs.
//   - It is TENANT-SCOPED at construction. The hardening engine's interface
//     takes only a device id, so a source that could see every tenant's configs
//     would be a cross-tenant read waiting to happen. NewConfigSource binds ONE
//     tenant and passes cross=false into the store, which is the same scope the
//     lane's own per-tenant pass runs under (§3a).

// ConfigSource adapts the sealed version store to hardening.ConfigSource for ONE
// tenant.
type ConfigSource struct {
	tenant string
	store  configstore.Store
	open   func(v configstore.Version) (string, error)
}

// NewConfigSource binds a tenant-scoped hardening config source.
func NewConfigSource(tenant string, store configstore.Store, open func(configstore.Version) (string, error)) *ConfigSource {
	return &ConfigSource{tenant: NormTenant(tenant), store: store, open: open}
}

// ConfigSourceFor is the per-tenant factory the lane wiring binds: it hands the
// integrator a fresh, tenant-bound source for each pass without exposing the
// store.
func (e *Evaluator) ConfigSourceFor(tenant string) hardening.ConfigSource {
	return NewConfigSource(tenant, e.deps.Versions, e.deps.Open)
}

// RunningConfig implements hardening.ConfigSource.
func (c *ConfigSource) RunningConfig(ctx context.Context, deviceID string) (string, bool, error) {
	if c == nil || c.store == nil || c.open == nil {
		return "", false, nil
	}
	v, ok, err := c.store.Latest(ctx, c.tenant, false, deviceID)
	if err != nil {
		// A store failure is a TRANSPORT error, distinct from "absent": the
		// engine must not read a Postgres outage as "this device has no config".
		return "", false, err
	}
	if !ok || v.Status != configstore.StatusOK || v.BlobRef == "" {
		return "", false, nil
	}
	text, err := c.open(v)
	if err != nil {
		return "", false, err
	}
	if text == "" {
		return "", false, nil
	}
	return text, true, nil
}

var _ hardening.ConfigSource = (*ConfigSource)(nil)

// inventoryConfigSource is the FLEET-WIDE adapter the security lane's Deps takes.
//
// hardening.ConfigSource is keyed by device id alone, while the sealed store is
// tenant-scoped — so something has to answer "which tenant owns this device".
// The answer comes from the INVENTORY ROW (§3a rule 2: the owner is the device
// record, never a caller's scope and never a request), which is exactly the same
// authority the capture path stamps versions with. A device therefore resolves
// to its own tenant and to no other, and a device the resolver does not know
// yields ok=false — the engine's fail-closed path — rather than a search across
// tenants.
type inventoryConfigSource struct {
	eval  *Evaluator
	owner func(deviceID string) (string, bool)
}

// HardeningSource returns a hardening.ConfigSource covering every device the
// injected owner resolver knows, each read under its OWN tenant's scope. This is
// the value internal/seclane's Deps.ConfigSource takes: with it, the §5e
// hardening rules stop reporting "running-config unavailable — control not
// assessed" for every device that has a backup.
func (e *Evaluator) HardeningSource(owner func(deviceID string) (string, bool)) hardening.ConfigSource {
	return &inventoryConfigSource{eval: e, owner: owner}
}

// RunningConfig implements hardening.ConfigSource.
func (s *inventoryConfigSource) RunningConfig(ctx context.Context, deviceID string) (string, bool, error) {
	if s == nil || s.eval == nil || s.owner == nil {
		return "", false, nil
	}
	tenant, ok := s.owner(deviceID)
	if !ok {
		// Unknown device: fail closed, never a fleet-wide search.
		return "", false, nil
	}
	return s.eval.ConfigSourceFor(tenant).RunningConfig(ctx, deviceID)
}

var _ hardening.ConfigSource = (*inventoryConfigSource)(nil)
