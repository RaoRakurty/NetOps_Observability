// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// protocol_diag_gateway.go — the DEPLOY-TIME wiring that turns the
// protocol-diagnostics collect endpoint from an honest 503 into a live,
// read-only capture.
//
// internal/protocoldiag is a pure library: it renders a curated `show` bundle
// and asks an injected CommandRunner to run each command. This file is the
// integrator that supplies that runner, and it is deliberately the ONLY place
// in the tree where the diagnostics feature acquires the authority to reach a
// device. It mirrors configGateway()/pcapGateway() exactly:
//
//   - the SAME vendored ssh client (CLAUDE.md §6 allowlist), never a second one;
//   - the SAME host-key TOFU custody — HostKeyCheck IS device_ssh.go's pinned
//     fingerprint store, so a device whose key changed is refused identically on
//     the operator terminal, config capture, packet capture and here;
//   - the SAME sealed-at-rest credential handling (vault.Decrypt, §8): the
//     secret is resolved per session, never cached on a struct, never logged,
//     never returned by a handler and never put in an audit detail;
//   - the SAME bounded dial (sshDialTimeout()).
//
// DORMANT BY DEFAULT (FEATURE_PROTOCOL_DIAG_COLLECT, like FEATURE_DEVICE_SSH):
// with the flag off nothing here is constructed, srv.protocolCollector stays nil
// and the endpoint keeps answering 503 — the transport cannot be reached by
// accident, only by an operator who turned it on and provisioned a read-only
// account.

import (
	"context"
	"errors"
	"fmt"
	"os"

	"netops/backend/internal/configstore"
	"netops/backend/internal/protocoldiag"
	"netops/backend/models"
)

// pdVaultFieldPassword / pdVaultFieldKey are the vault AAD field ids the
// diagnostics credential is sealed under. They are distinct from the
// config-backup ids on purpose: a ciphertext sealed for one field cannot be
// opened as the other, so a copied .env value fails loudly instead of silently
// re-using another module's secret.
const (
	pdVaultFieldPassword = "protocoldiag.collect.password" // #nosec G101 -- a vault FIELD ID, not a credential
	pdVaultFieldKey      = "protocoldiag.collect.key"
)

// protocolDiagCollectEnabled reports whether the LIVE collect transport is
// turned on. Default false — the feature is dormant unless an operator opts in.
func protocolDiagCollectEnabled() bool { return envBool(protocoldiag.EnvFeatureCollect) }

// pdDeviceFromDiscovery projects a principal-scoped inventory row onto the
// library's Device. It is the ONE place the projection lives so the live SSH
// path can never be handed a device whose address, port or tenant came from
// somewhere other than the resolved inventory row (§3a: owner stamped from the
// device, never from a request body).
//
// Address/Port are what the SSH gateway dials; a row with no address yields an
// empty Address, which the runner refuses (ErrNoAddress) rather than guessing.
func pdDeviceFromDiscovery(d models.Device) protocoldiag.Device {
	return protocoldiag.Device{
		ID:       d.ID,
		Hostname: d.Name,
		Platform: pdPlatformString(d),
		Address:  d.Address,
		Port:     envInt(protocoldiag.EnvSSHPort, 22),
		TenantID: deviceTenant(d), // §3a: owner stamped from the resolved device
	}
}

// protocolDiagCredential resolves the least-privilege, read-only diagnostics
// identity for one session.
//
// Precedence:
//  1. the DEDICATED identity (PROTOCOL_DIAG_SSH_USER + _PASSWORD or _KEY);
//  2. failing that — and only when NONE of the three is set — the config-backup
//     capture identity (CONFIG_BACKUP_SSH_*), which is already a least-privilege
//     read-only account on the same devices.
//
// A PARTIALLY configured dedicated identity (a user with no secret, or a secret
// with no user) is a hard error. Falling back there would silently authenticate
// as a DIFFERENT account than the operator named, which is exactly the kind of
// implicit trust §3 forbids.
//
// The returned secret is held for the life of one session by the caller and is
// never logged, audited or returned (§8).
func (s *server) protocolDiagCredential() (protocoldiag.Credential, error) {
	user := os.Getenv(protocoldiag.EnvSSHUser)
	pw, err := s.vault.Decrypt("", pdVaultFieldPassword, os.Getenv(protocoldiag.EnvSSHPassword))
	if err != nil {
		return protocoldiag.Credential{}, err
	}
	key, err := s.vault.Decrypt("", pdVaultFieldKey, os.Getenv(protocoldiag.EnvSSHKey))
	if err != nil {
		return protocoldiag.Credential{}, err
	}
	switch {
	case user != "" && (pw != "" || key != ""):
		return protocoldiag.Credential{Username: user, Password: pw, PrivateKey: key}, nil
	case user != "" || pw != "" || key != "":
		return protocoldiag.Credential{}, fmt.Errorf(
			"%s is only partially configured — set the user AND a password or key (refusing to fall back to the config-backup account)",
			protocoldiag.EnvSSHUser)
	}

	// Fallback: the config-backup read-only capture identity.
	fbUser := os.Getenv(configstore.EnvSSHUser)
	fbPw, err := s.vault.Decrypt("", "configstore.capture.password", os.Getenv(configstore.EnvSSHPassword))
	if err != nil {
		return protocoldiag.Credential{}, err
	}
	fbKey, err := s.vault.Decrypt("", "configstore.capture.key", os.Getenv(configstore.EnvSSHKey))
	if err != nil {
		return protocoldiag.Credential{}, err
	}
	if fbUser == "" || (fbPw == "" && fbKey == "") {
		return protocoldiag.Credential{}, fmt.Errorf(
			"no protocol-diagnostics credential configured (set %s and %s or %s)",
			protocoldiag.EnvSSHUser, protocoldiag.EnvSSHPassword, protocoldiag.EnvSSHKey)
	}
	return protocoldiag.Credential{Username: fbUser, Password: fbPw, PrivateKey: fbKey}, nil
}

// protocolDiagGateway builds the live SSH command source. HostKeyCheck is the
// server's pinned fingerprint store — a nil store would be a fail-CLOSED error
// inside the gateway (it refuses to connect without a host-key policy), never a
// bypass, so this never hands out an unverified connection.
func (s *server) protocolDiagGateway() *protocoldiag.SSHGateway {
	return &protocoldiag.SSHGateway{
		Credentials: func(context.Context, protocoldiag.Device) (protocoldiag.Credential, error) {
			return s.protocolDiagCredential()
		},
		HostKeyCheck: s.sshHosts.check,
		DialTimeout:  sshDialTimeout(),
		Port:         envInt(protocoldiag.EnvSSHPort, 22),
		OnHostKey: func(dev protocoldiag.Device, fp string, first bool) {
			if first {
				logInfo("protocol-diag", "device host key pinned on first diagnostics collect", map[string]any{
					"device": dev.ID, "fingerprint": fp})
			}
		},
	}
}

// buildProtocolDiagCollector CONSTRUCTS the live collector: the closed
// per-vendor command table + one-in-flight-per-device runner over the SSH
// gateway, wrapped by the catalog-driven collector. It starts NO goroutine and
// registers NO route (the routes already exist and 503 while the collector is
// nil), so there is nothing here for the shutdown drain to own.
//
// It is a no-op unless the feature flag is on, and it returns an error rather
// than half-wiring: a construction failure leaves the collector nil, which the
// handler already reports honestly as 503.
func (s *server) buildProtocolDiagCollector() error {
	if !protocolDiagCollectEnabled() {
		return nil
	}
	if s.sshHosts == nil {
		return errors.New("protocol-diagnostics collect: no SSH host-key store — refusing to wire a transport with no host-key custody")
	}
	runner, err := protocoldiag.NewSSHCommandRunner(s.pdCatalog(), s.protocolDiagGateway())
	if err != nil {
		return fmt.Errorf("protocol-diagnostics collect runner: %w", err)
	}
	col, err := protocoldiag.NewCollector(s.pdCatalog(), runner)
	if err != nil {
		return fmt.Errorf("protocol-diagnostics collector: %w", err)
	}
	s.protocolCollector = col
	logInfo("protocol-diag", "live collect transport wired (read-only SSH)", map[string]any{
		"flag":            protocoldiag.EnvFeatureCollect,
		"ruleset":         protocoldiag.RulesetVersion,
		"port":            envInt(protocoldiag.EnvSSHPort, 22),
		"command_timeout": protocoldiag.DefaultCommandTimeout.String(),
		"max_output":      protocoldiag.MaxOutputBytes,
		"dedicated_creds": os.Getenv(protocoldiag.EnvSSHUser) != "",
	})
	return nil
}
