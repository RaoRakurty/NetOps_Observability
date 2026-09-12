// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// protocol_diag_gateway_test.go — proves the DEPLOY-TIME wiring of the live
// protocol-diagnostics command source, with no network and no device:
//
//   - the feature flag is the ONLY thing that turns the transport on (off ⇒ the
//     collector stays nil ⇒ the endpoint keeps answering 503);
//   - a missing credential is refused BEFORE anything is dialled;
//   - the dedicated diagnostics identity wins over the config-backup fallback,
//     the fallback is used only when the dedicated one is entirely unset, and a
//     PARTIAL dedicated identity is an error rather than a silent fallback onto
//     a different account;
//   - HostKeyCheck is the server's own pinned TOFU store — the same custody the
//     operator terminal and config capture use.

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"netops/backend/internal/configstore"
	"netops/backend/internal/protocoldiag"
	"netops/backend/models"
)

// pdTestServer is a bare server with the one dependency the gateway needs: the
// pinned host-key store. The vault is deliberately nil — a dormant vault is
// plaintext-passthrough, which is exactly the shape a fresh install has.
func pdTestServer(t *testing.T) *server {
	t.Helper()
	return &server{sshHosts: newSSHHostStore(filepath.Join(t.TempDir(), "known_hosts.json"))}
}

// pdClearEnv blanks every variable the credential resolver reads, so a test
// declares its whole environment rather than inheriting the developer's.
func pdClearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		protocoldiag.EnvFeatureCollect,
		protocoldiag.EnvSSHUser, protocoldiag.EnvSSHPassword, protocoldiag.EnvSSHKey,
		protocoldiag.EnvSSHPort,
		configstore.EnvSSHUser, configstore.EnvSSHPassword, configstore.EnvSSHKey,
	} {
		t.Setenv(k, "")
	}
}

func TestProtocolDiagCredential_MissingIsRefused(t *testing.T) {
	pdClearEnv(t)
	s := pdTestServer(t)
	if _, err := s.protocolDiagCredential(); err == nil {
		t.Fatal("expected an error with no credential configured; got nil " +
			"(a guessed or empty credential must never reach a device)")
	}
}

func TestProtocolDiagCredential_DedicatedWinsOverFallback(t *testing.T) {
	pdClearEnv(t)
	t.Setenv(protocoldiag.EnvSSHUser, "diag-ro")
	t.Setenv(protocoldiag.EnvSSHPassword, "diag-secret")
	t.Setenv(configstore.EnvSSHUser, "backup-ro")
	t.Setenv(configstore.EnvSSHPassword, "backup-secret")

	s := pdTestServer(t)
	cred, err := s.protocolDiagCredential()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cred.Username != "diag-ro" || cred.Password != "diag-secret" {
		t.Fatalf("dedicated identity must win over the config-backup fallback; got user=%q", cred.Username)
	}
}

func TestProtocolDiagCredential_FallsBackWhenDedicatedUnset(t *testing.T) {
	pdClearEnv(t)
	t.Setenv(configstore.EnvSSHUser, "backup-ro")
	t.Setenv(configstore.EnvSSHKey, "backup-key-pem")

	s := pdTestServer(t)
	cred, err := s.protocolDiagCredential()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cred.Username != "backup-ro" || cred.PrivateKey != "backup-key-pem" {
		t.Fatalf("expected the config-backup fallback identity; got %+v", cred.Username)
	}
}

func TestProtocolDiagCredential_PartialDedicatedDoesNotFallBack(t *testing.T) {
	pdClearEnv(t)
	// A user with NO secret: authenticating as the config-backup account here
	// would silently use a different identity than the operator named.
	t.Setenv(protocoldiag.EnvSSHUser, "diag-ro")
	t.Setenv(configstore.EnvSSHUser, "backup-ro")
	t.Setenv(configstore.EnvSSHPassword, "backup-secret")

	s := pdTestServer(t)
	cred, err := s.protocolDiagCredential()
	if err == nil {
		t.Fatalf("a partially configured dedicated identity must be an error, got %q", cred.Username)
	}
}

// TestProtocolDiagGateway_RefusesWithoutCredentialAndNeverDials proves the
// refusal happens BEFORE the socket: with no credential configured, Run must
// return an error without the injected Dial ever being called.
func TestProtocolDiagGateway_RefusesWithoutCredentialAndNeverDials(t *testing.T) {
	pdClearEnv(t)
	s := pdTestServer(t)
	gw := s.protocolDiagGateway()
	if gw.HostKeyCheck == nil {
		t.Fatal("HostKeyCheck must be the server's pinned store — a nil policy would be no custody at all")
	}
	dialed := false
	gw.Dial = func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("this test must never reach a socket")
	}
	out, err := gw.Run(context.Background(), protocoldiag.Device{
		ID: "dev-1", Address: "198.51.100.9", Platform: "Cisco IOS-XE",
	}, "show ip ospf neighbor", 0)
	if err == nil {
		t.Fatal("expected a refusal with no credential configured")
	}
	if dialed {
		t.Fatal("the gateway dialled a device before resolving a credential — the refusal must be pre-connect")
	}
	if out != "" {
		t.Fatalf("a refused command must return no output, got %q", out)
	}
}

// TestProtocolDiagGateway_HostKeyCheckIsTheServerStore proves the injected check
// IS the server's TOFU store: the first fingerprint for an address pins, and a
// DIFFERENT fingerprint for that address is refused afterwards — the same
// evidence the operator terminal produces.
func TestProtocolDiagGateway_HostKeyCheckIsTheServerStore(t *testing.T) {
	pdClearEnv(t)
	s := pdTestServer(t)
	gw := s.protocolDiagGateway()
	if gw.HostKeyCheck == nil {
		t.Fatal("HostKeyCheck must be non-nil (the gateway fails closed without one, but the wiring must supply it)")
	}
	first, ok := gw.HostKeyCheck("198.51.100.7", "SHA256:aaa")
	if !first || !ok {
		t.Fatalf("first sighting must pin and pass; got first=%v ok=%v", first, ok)
	}
	// The SERVER's store must now hold it — proving the check is not a private copy.
	if _, ok := s.sshHosts.check("198.51.100.7", "SHA256:bbb"); ok {
		t.Fatal("a changed host key must be refused by the server's own store")
	}
}

func TestProtocolDiagGateway_PortAndTimeoutAreBounded(t *testing.T) {
	pdClearEnv(t)
	t.Setenv(protocoldiag.EnvSSHPort, "2222")
	s := pdTestServer(t)
	gw := s.protocolDiagGateway()
	if gw.Port != 2222 {
		t.Fatalf("port = %d, want 2222 from %s", gw.Port, protocoldiag.EnvSSHPort)
	}
	if gw.DialTimeout <= 0 {
		t.Fatal("dial timeout must be bounded (§9)")
	}
}

func TestBuildProtocolDiagCollector_FlagOffLeavesCollectorNil(t *testing.T) {
	pdClearEnv(t)
	s := pdTestServer(t)
	if err := s.buildProtocolDiagCollector(); err != nil {
		t.Fatalf("flag-off wiring must be a no-op, got %v", err)
	}
	if s.protocolCollector != nil {
		t.Fatal("collector must stay nil with the feature flag off — the collect endpoint 503s")
	}
}

func TestBuildProtocolDiagCollector_FlagOnWiresCollector(t *testing.T) {
	pdClearEnv(t)
	t.Setenv(protocoldiag.EnvFeatureCollect, "true")
	t.Setenv(protocoldiag.EnvSSHUser, "diag-ro")
	t.Setenv(protocoldiag.EnvSSHPassword, "diag-secret")
	s := pdTestServer(t)
	if err := s.buildProtocolDiagCollector(); err != nil {
		t.Fatalf("wiring: %v", err)
	}
	if s.protocolCollector == nil {
		t.Fatal("collector must be wired with the feature flag on")
	}
}

func TestBuildProtocolDiagCollector_RefusesWithoutHostKeyCustody(t *testing.T) {
	pdClearEnv(t)
	t.Setenv(protocoldiag.EnvFeatureCollect, "true")
	s := &server{} // no sshHosts
	if err := s.buildProtocolDiagCollector(); err == nil {
		t.Fatal("wiring a transport with no host-key store must be refused")
	}
	if s.protocolCollector != nil {
		t.Fatal("a refused wiring must leave the collector nil")
	}
}

func TestPdDeviceFromDiscovery_CarriesAddressPortAndTenant(t *testing.T) {
	pdClearEnv(t)
	t.Setenv(protocoldiag.EnvSSHPort, "2222")
	dev := models.Device{
		ID: "dev-1", Name: "edge1", Address: "198.51.100.9",
		Vendor: "Cisco", OS: "IOS-XE", Model: "C8000",
		TenantID: "ACME",
	}
	pd := pdDeviceFromDiscovery(dev)
	if pd.Address != "198.51.100.9" {
		t.Fatalf("address = %q, want the inventory row's address", pd.Address)
	}
	if pd.Port != 2222 {
		t.Fatalf("port = %d, want the configured 2222", pd.Port)
	}
	if pd.TenantID != "acme" {
		t.Fatalf("tenant = %q, want the normalized owner from the resolved device (§3a)", pd.TenantID)
	}
	if pd.Vendor() != protocoldiag.VendorCiscoIOSXE {
		t.Fatalf("vendor = %q, want the dialect derived from the platform string", pd.Vendor())
	}
}
