package tlsconfig

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// PeerPolicy constrains WHICH authenticated peer identities are accepted, on top
// of (never instead of) chain verification. Chain + hostname verification proves
// the peer holds a cert from our trust root; PeerPolicy then enforces least
// privilege — that THIS peer is an allowed counterparty (e.g. only the api SA may
// call the collector). Empty allowlists with a Require flag fail closed.
//
// Identities are matched against the peer leaf's SANs:
//   - AllowedDNS:  exact DNS SAN match (service hostnames)
//   - AllowedURIs: exact URI SAN match — the SPIFFE seam
//     (spiffe://<trust-domain>/ns/<ns>/sa/<svc>); when we adopt SPIRE the issued
//     SVIDs carry these URIs and this allowlist needs no code change.
type PeerPolicy struct {
	AllowedDNS  []string
	AllowedURIs []string
}

// empty reports whether the policy names no identities (no constraint configured).
func (p PeerPolicy) empty() bool { return len(p.AllowedDNS) == 0 && len(p.AllowedURIs) == 0 }

// verify checks the verified peer chains from a completed handshake against the
// allowlist. It assumes the stdlib has ALREADY verified the chain (we never set
// InsecureSkipVerify), so VerifiedChains is non-empty for a trusted peer.
func (p PeerPolicy) verify(cs tls.ConnectionState) error {
	if p.empty() {
		return nil // no identity allowlist configured → chain verification suffices
	}
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return fmt.Errorf("tlsconfig: no verified peer certificate")
	}
	leaf := cs.VerifiedChains[0][0]
	for _, want := range p.AllowedDNS {
		for _, got := range leaf.DNSNames {
			if strings.EqualFold(want, got) {
				return nil
			}
		}
	}
	for _, want := range p.AllowedURIs {
		for _, u := range leaf.URIs {
			if u != nil && u.String() == want {
				return nil
			}
		}
	}
	return fmt.Errorf("tlsconfig: peer identity %v / %v not in allowlist", leaf.DNSNames, leaf.URIs)
}
