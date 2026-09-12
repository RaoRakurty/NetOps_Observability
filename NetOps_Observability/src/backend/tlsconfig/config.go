// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tlsconfig

import (
	"crypto/tls"
	"errors"
)

// ServerOptions configures a TLS server (the API ingress, or any internal
// service accepting mTLS). Reloader is required; the rest enable mTLS.
type ServerOptions struct {
	// Reloader supplies the server's own key pair (hot-reloadable). Required.
	Reloader *CertReloader
	// RequireClientCert turns on mTLS: clients MUST present a cert that verifies
	// against ClientCAs. Off → ordinary one-way TLS (still strong).
	RequireClientCert bool
	// ClientCAs is the explicit trust root for client certs (required when
	// RequireClientCert is set). Never the system pool.
	ClientCAs *TrustBundle
	// Peer optionally constrains which client identities are accepted (least
	// privilege on top of chain verification).
	Peer PeerPolicy
}

// ServerConfig builds a hardened *tls.Config for a server. Fail-closed: mTLS
// without a client-CA bundle is a configuration error, not a silent fallback to
// no client auth.
func ServerConfig(o ServerOptions) (*tls.Config, error) {
	if o.Reloader == nil {
		return nil, errors.New("tlsconfig: ServerConfig requires a CertReloader")
	}
	c := baseConfig()
	c.GetCertificate = o.Reloader.GetCertificate
	if o.RequireClientCert {
		if o.ClientCAs == nil {
			return nil, errors.New("tlsconfig: mTLS requires a ClientCAs trust bundle")
		}
		c.ClientAuth = tls.RequireAndVerifyClientCert
		c.ClientCAs = o.ClientCAs.Pool()
		peer := o.Peer
		c.VerifyConnection = peer.verify // least-privilege identity allowlist
	}
	return c, nil
}

// ClientOptions configures a TLS client (the API dialing OpenSearch/ClickHouse/
// VictoriaMetrics/correlation, or any service-to-service call).
type ClientOptions struct {
	// RootCAs is the explicit trust root for the server's cert. Required — we do
	// NOT fall back to the system pool for internal services.
	RootCAs *TrustBundle
	// ServerName is verified against the server cert's SANs (SNI + hostname
	// check). Required — an empty ServerName would disable hostname verification.
	ServerName string
	// Reloader optionally supplies a client cert for mTLS (the client proving its
	// identity to the server).
	Reloader *CertReloader
	// Peer optionally constrains the accepted SERVER identity (URI/DNS SAN
	// allowlist), e.g. pinning that we only talk to the real clickhouse SVID.
	Peer PeerPolicy
	// SystemRoots verifies the server against the host's system CA pool instead
	// of an explicit RootCAs bundle. Use ONLY for EXTERNAL services presenting
	// publicly/corporate-trusted certs (e.g. an LDAP/AD server) — never for
	// internal SVIDs, where an explicit root is mandatory. Mutually exclusive
	// with RootCAs; ServerName is still required, so hostname verification is
	// never disabled.
	SystemRoots bool
}

// ClientConfig builds a hardened *tls.Config for a client. It NEVER sets
// InsecureSkipVerify and requires both an explicit root bundle and a ServerName,
// so hostname verification can't be accidentally disabled.
func ClientConfig(o ClientOptions) (*tls.Config, error) {
	if o.RootCAs == nil && !o.SystemRoots {
		return nil, errors.New("tlsconfig: ClientConfig requires an explicit RootCAs bundle (or SystemRoots:true for external services)")
	}
	if o.RootCAs != nil && o.SystemRoots {
		return nil, errors.New("tlsconfig: ClientConfig RootCAs and SystemRoots are mutually exclusive")
	}
	if o.ServerName == "" {
		return nil, errors.New("tlsconfig: ClientConfig requires a ServerName (hostname verification)")
	}
	c := baseConfig()
	// RootCAs nil → Go verifies against the host's system pool (SystemRoots).
	if o.RootCAs != nil {
		c.RootCAs = o.RootCAs.Pool()
	}
	c.ServerName = o.ServerName
	if o.Reloader != nil {
		c.GetClientCertificate = o.Reloader.GetClientCertificate
	}
	// Install verify when an allowlist OR a federation registry is set — a
	// federated policy may have empty allowlists yet still enforce the domain
	// binding.
	if !o.Peer.empty() || o.Peer.Federation != nil {
		peer := o.Peer
		c.VerifyConnection = peer.verify
	}
	return c, nil
}
