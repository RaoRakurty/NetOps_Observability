package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
)

// federation.go — SPIFFE multi-region trust (#18 phase 5). It closes a gap that
// only appears once we trust MORE THAN ONE trust domain's CA root (federation /
// multi-region): chain verification proves a peer's cert was signed by *some*
// trusted root, and PeerPolicy proves the URI SAN is on the allowlist — but
// nothing binds the trust domain NAMED in that SPIFFE URI to the root that
// actually signed the chain. So a peer whose chain anchors to region B's root
// could present a SVID claiming spiffe://A/... (a *local* identity) and slip
// through. SPIFFE federation requires the inverse to hold:
//
//	the trust domain in a peer's SPIFFE ID MUST equal the trust domain whose
//	root anchored its verified chain.
//
// This is verifier-side only (issuance is unchanged) and DORMANT by default — a
// nil/unconfigured FederationTrust makes the binding a no-op, so the existing
// single-domain path is untouched. Stdlib only (crypto/x509, net/url).

// spiffeID is a parsed SPIFFE identity. The host IS the trust domain; the path is
// the workload selector (e.g. /ns/default/sa/api). Structured parsing replaces
// fragile whole-string SAN matching so the trust domain can be compared on its
// own.
type spiffeID struct {
	trustDomain string // url.Host, lower-cased; never empty for a valid ID
	path        string // url.Path (may be empty)
}

// parseSpiffeID validates and decomposes a SPIFFE URI. Fail-closed: a non-spiffe
// scheme, an empty host, or any userinfo/port/query/fragment (none legal in a
// SPIFFE ID — and userinfo in particular enables spiffe://A@B/... confusion where
// the real host is B) is an error, not a best-effort parse.
func parseSpiffeID(raw string) (spiffeID, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return spiffeID{}, fmt.Errorf("tlsconfig: invalid SPIFFE ID %q: %w", raw, err)
	}
	if !strings.EqualFold(u.Scheme, "spiffe") {
		return spiffeID{}, fmt.Errorf("tlsconfig: %q is not a spiffe:// URI", raw)
	}
	if u.Host == "" {
		return spiffeID{}, fmt.Errorf("tlsconfig: SPIFFE ID %q has no trust domain", raw)
	}
	if u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		return spiffeID{}, fmt.Errorf("tlsconfig: SPIFFE ID %q carries illegal userinfo/port/query/fragment", raw)
	}
	return spiffeID{trustDomain: strings.ToLower(u.Host), path: u.Path}, nil
}

// FederationEntry maps one trust domain to the PEM bundle of the CA root(s) that
// are authoritative for it. It is the public, env-derived option that feeds
// LoadFederationTrust.
type FederationEntry struct {
	Domain string
	Path   string
}

// FederationTrust is the reverse index "anchoring root → trust domain" used by the
// post-handshake binding check. It is SEPARATE from TrustBundle (which is the
// single combined pool the stdlib uses to BUILD chains): this index answers, for
// the root the stdlib actually selected, which trust domain owns it.
//
// Roots are keyed on the whole-cert DER (x509.Certificate.Raw) — unforgeable and
// collision-free. Subject and SubjectKeyId are attacker-choosable on a self-signed
// root, so they are NOT used as the key.
//
// Dormant by default: an unconfigured (or nil) FederationTrust makes the binding a
// no-op, preserving single-domain behavior.
type FederationTrust struct {
	mu      sync.RWMutex
	byRoot  map[string]string // string(root.Raw) → trust domain
	entries []FederationEntry // source mappings (retained for Reload)
}

// LoadFederationTrust builds the registry from domain→PEM-path entries. Fail-
// closed: an unreadable/empty/unparseable PEM, a duplicate domain, or the SAME
// root appearing under two different domains is an error (any of these would make
// the binding ambiguous). Domains are lower-cased to match parseSpiffeID.
func LoadFederationTrust(entries []FederationEntry) (*FederationTrust, error) {
	if len(entries) == 0 {
		return nil, errors.New("tlsconfig: no federation entries provided")
	}
	f := &FederationTrust{entries: append([]FederationEntry(nil), entries...)}
	if err := f.Reload(); err != nil {
		return nil, err
	}
	return f, nil
}

// Reload re-reads every domain's PEM and atomically swaps the reverse index, so a
// remote region rotating its root is zero-downtime (same pattern as TrustBundle).
func (f *FederationTrust) Reload() error {
	byRoot := make(map[string]string)
	seenDomains := make(map[string]bool)
	for _, e := range f.entries {
		domain := strings.ToLower(strings.TrimSpace(e.Domain))
		if domain == "" {
			return errors.New("tlsconfig: federation entry has an empty trust domain")
		}
		if seenDomains[domain] {
			return fmt.Errorf("tlsconfig: trust domain %q listed more than once", domain)
		}
		seenDomains[domain] = true
		pemBytes, err := os.ReadFile(e.Path)
		if err != nil {
			return fmt.Errorf("tlsconfig: read federation bundle %q: %w", e.Path, err)
		}
		added := 0
		rest := pemBytes
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("tlsconfig: parse federation root in %q: %w", e.Path, err)
			}
			key := string(cert.Raw)
			if other, ok := byRoot[key]; ok && other != domain {
				return fmt.Errorf("tlsconfig: root in %q is claimed by both %q and %q", e.Path, other, domain)
			}
			byRoot[key] = domain
			added++
		}
		if added == 0 {
			return fmt.Errorf("tlsconfig: no certificates in federation bundle %q", e.Path)
		}
	}
	f.mu.Lock()
	f.byRoot = byRoot
	f.mu.Unlock()
	return nil
}

// configured reports whether any federation mapping is loaded.
func (f *FederationTrust) configured() bool {
	if f == nil {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.byRoot) > 0
}

// domainForRoot returns the trust domain the anchoring root belongs to.
func (f *FederationTrust) domainForRoot(root *x509.Certificate) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	d, ok := f.byRoot[string(root.Raw)]
	return d, ok
}

// bindChainToDomain enforces the federation invariant: the trust domain in the
// peer leaf's SPIFFE URI SAN must equal the trust domain whose root anchored the
// verified chain. It returns the matched domain on success; a non-nil error is a
// HARD rejection. When the registry is unconfigured it returns ("", nil) — a
// no-op preserving the single-domain default.
//
// Pre: cs.VerifiedChains is non-empty (the stdlib verified the chain; we never set
// InsecureSkipVerify), and the chain is leaf-first / root-last.
func (f *FederationTrust) bindChainToDomain(cs tls.ConnectionState) (string, error) {
	if !f.configured() {
		return "", nil
	}
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return "", errors.New("tlsconfig: federation: no verified chain")
	}
	chain := cs.VerifiedChains[0]
	root := chain[len(chain)-1]
	domain, ok := f.domainForRoot(root)
	if !ok {
		return "", fmt.Errorf("tlsconfig: federation: anchoring root %q not mapped to a trust domain", root.Subject.CommonName)
	}
	leaf := chain[0]
	var id *spiffeID
	for _, u := range leaf.URIs {
		if u == nil || !strings.EqualFold(u.Scheme, "spiffe") {
			continue
		}
		parsed, err := parseSpiffeID(u.String())
		if err != nil {
			return "", err
		}
		if id != nil && id.trustDomain != parsed.trustDomain {
			return "", fmt.Errorf("tlsconfig: federation: peer presents SPIFFE IDs in multiple trust domains (%q, %q)", id.trustDomain, parsed.trustDomain)
		}
		copyID := parsed
		id = &copyID
	}
	if id == nil {
		return "", errors.New("tlsconfig: federation: peer has no SPIFFE ID")
	}
	if id.trustDomain != domain {
		return "", fmt.Errorf("tlsconfig: federation: peer SPIFFE domain %q does not match chain anchor domain %q", id.trustDomain, domain)
	}
	return domain, nil
}
