// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

// env.go — the ENVIRONMENT CONTRACT for the LIVE command source.
//
// This package does NOT read the environment: the integrator does (the
// seclane / configstore / pcap precedent) and hands the resolved values in
// through the injected SSHGateway fields, so nothing here holds ambient
// authority and every test injects instead of exporting. The NAMES live here so
// there is exactly one spelling of each, and so the deployment guard in
// tests/test_compose_new_modules.py can read them straight out of the package
// rather than re-typing them.
const (
	// EnvFeatureCollect gates the LIVE collect transport. Default FALSE —
	// dormant like FEATURE_DEVICE_SSH: with the flag off no gateway and no
	// runner are constructed, the server's collector stays nil, and
	// POST /api/troubleshoot/protocol-diagnostics/collect answers the same
	// honest 503 it answered before the transport existed. The catalog and
	// Analyze surfaces are unaffected — neither ever touches a device.
	EnvFeatureCollect = "FEATURE_PROTOCOL_DIAG_COLLECT"

	// EnvSSHUser / EnvSSHPassword / EnvSSHKey configure the DEDICATED
	// least-privilege, READ-ONLY diagnostics identity. It is deliberately its
	// own account rather than a shared one: this feature runs `show` commands
	// only (collect.go's read-only guard + the closed per-vendor table), so the
	// identity it authenticates with should not be able to do anything else on
	// the device either.
	//
	// The password/key are sealed at rest by the integrator exactly like every
	// other reversible secret (§8); neither ever reaches a log, a response or an
	// audit detail. Empty = inert: a collect without a credential fails loudly,
	// it is never guessed.
	//
	// FALLBACK: when NONE of the three is set the integrator falls back to the
	// config-backup capture identity (CONFIG_BACKUP_SSH_*), which is already a
	// least-privilege read-only account on the same devices — so an operator who
	// has one working read-only account does not have to provision a second. A
	// PARTIALLY configured dedicated identity (user set, secret missing) is a
	// hard error, never a silent fallback onto a different account.
	EnvSSHUser     = "PROTOCOL_DIAG_SSH_USER"
	EnvSSHPassword = "PROTOCOL_DIAG_SSH_PASSWORD" // #nosec G101 -- env var NAME, not a credential
	EnvSSHKey      = "PROTOCOL_DIAG_SSH_KEY"

	// EnvSSHPort overrides the device SSH port (default 22). It exists because
	// the inventory row carries no port: without it a lab or a jump-hosted fleet
	// on a non-standard port could not use the feature at all.
	EnvSSHPort = "PROTOCOL_DIAG_SSH_PORT"
)
