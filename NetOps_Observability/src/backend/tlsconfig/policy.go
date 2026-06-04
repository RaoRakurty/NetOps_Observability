// Package tlsconfig is the single source of transport-security policy for the
// platform (#18). Every TLS server and client — the API ingress, internal
// service-to-service mTLS, and the API's clients to OpenSearch/ClickHouse/
// VictoriaMetrics/correlation — builds its *tls.Config here, so secure defaults
// and trust handling live in exactly one auditable place instead of being
// re-derived (and weakened) per call site.
//
// Design tenets (see docs/design/tls-architecture.md):
//   - TLS 1.3-first; 1.2 permitted with an AEAD+ECDHE-only cipher list; 1.0/1.1
//     never. The floor is enforced here, not per caller.
//   - Explicit trust roots only — never the OS pool for internal mTLS, never
//     InsecureSkipVerify. Hostname/SAN verification is always on.
//   - Fail closed: a missing/*un*loadable cert or trust bundle is a construction
//     error the caller must surface (refuse to start), never a silent downgrade.
//   - Stdlib only (crypto/tls, crypto/x509) — no new dependency.
package tlsconfig

import "crypto/tls"

// MinVersion is the hard protocol floor. TLS 1.3 is negotiated automatically when
// both peers support it; 1.2 is the lowest we will ever speak. 1.0/1.1 are never
// permitted (they are not even reachable below this floor).
const MinVersion uint16 = tls.VersionTLS12

// secureCipherSuites is the curated TLS 1.2 cipher list: ECDHE key exchange
// (perfect forward secrecy) with AEAD ciphers only. No CBC (Lucky13/padding
// oracles), no static-RSA key exchange (no PFS), no RC4/3DES. TLS 1.3 cipher
// suites are not configurable in Go's stdlib and are all strong, so this list
// only affects a 1.2 handshake.
func secureCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}

// secureCurves prefers X25519 (fast, constant-time) then the NIST P-curves.
func secureCurves() []tls.CurveID {
	return []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
}

// baseConfig returns a *tls.Config carrying the shared hardened policy. Server
// and client builders layer trust + identity on top.
func baseConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       MinVersion,
		CipherSuites:     secureCipherSuites(),
		CurvePreferences: secureCurves(),
		// TLS 1.2 renegotiation is a footgun (CVE-2009-3555 class); never allow it.
		Renegotiation: tls.RenegotiateNever,
	}
}
