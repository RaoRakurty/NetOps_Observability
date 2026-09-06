// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

// domain.go — the domain/SNI tier (#81 P2). A hostname→app matcher: exact and
// suffix rules, most-specific wins. The domain itself is a STRONG signal (SrcDNS/
// SrcSNI) when it arrives from DNS-flow correlation, TLS-SNI, or a firewall
// hostname field; operator-declared domains are AUTHORITATIVE (SrcOperator).
//
// This is the matcher contract. A live non-firewall domain source (passive DNS /
// SNI export) is collection-gated — FortiGate-crossing traffic already carries the
// firewall's app-id directly (P-NGFW), so the domain tier adds value for traffic
// that has a domain but no on-box app-id.

import (
	"encoding/json"
	"strings"
)

type domainRule struct {
	app    string
	source Source
	conf   float64
}

// DomainIndex matches a hostname to an app. Rules: "outlook.office.com" (exact) or
// "*.outlook.com" / ".outlook.com" (suffix). Immutable after build; swap atomically.
type DomainIndex struct {
	exact  map[string]domainRule
	suffix map[string]domainRule // key is the suffix without a leading dot
}

func NewDomainIndex() *DomainIndex {
	return &DomainIndex{exact: map[string]domainRule{}, suffix: map[string]domainRule{}}
}

func normHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// Add registers a pattern → app rule. source picks the trust bucket (SrcDNS/SrcSNI
// for catalog domains, SrcOperator for operator overrides). conf<=0 uses the
// source's base confidence.
func (d *DomainIndex) Add(pattern, app string, source Source, conf float64) {
	p := normHost(pattern)
	if p == "" || app == "" {
		return
	}
	r := domainRule{app: app, source: source, conf: conf}
	switch {
	case strings.HasPrefix(p, "*."):
		d.suffix[p[2:]] = r
	case strings.HasPrefix(p, "."):
		d.suffix[p[1:]] = r
	default:
		d.exact[p] = r
	}
}

// SignalsFor returns the most-specific domain match for host as a Signal (exact
// beats suffix; a longer suffix beats a shorter one). Empty if no rule matches.
func (d *DomainIndex) SignalsFor(host string) []Signal {
	if d == nil {
		return nil
	}
	h := normHost(host)
	if h == "" {
		return nil
	}
	if r, ok := d.exact[h]; ok {
		return []Signal{sigFromRule(h, r)}
	}
	parts := strings.Split(h, ".")
	for i := 0; i < len(parts)-1; i++ { // longest parent suffix first
		if r, ok := d.suffix[strings.Join(parts[i:], ".")]; ok {
			return []Signal{sigFromRule(strings.Join(parts[i:], "."), r)}
		}
	}
	return nil
}

func sigFromRule(matched string, r domainRule) Signal {
	c := r.conf
	if c <= 0 {
		c = r.source.baseConfidence()
	}
	return Signal{Source: r.source, App: r.app, Confidence: c, Detail: "domain:" + matched}
}

// Size reports the number of rules indexed.
func (d *DomainIndex) Size() int {
	if d == nil {
		return 0
	}
	return len(d.exact) + len(d.suffix)
}

// DomainEntry is a parsed (pattern → app) pair from a feed.
type DomainEntry struct {
	Pattern string `json:"pattern"`
	App     string `json:"app"`
}

// M365Domains extracts the published URL patterns from the Microsoft 365 endpoints
// feed (the urls[] per serviceArea — the domain half of the same feed ParseM365
// reads for IPs). Patterns like "*.outlook.com" / "outlook.office.com".
func M365Domains(raw []byte) ([]DomainEntry, error) {
	var doc []struct {
		ServiceArea string   `json:"serviceArea"`
		URLs        []string `json:"urls"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []DomainEntry
	for _, a := range doc {
		app := "Microsoft 365"
		if a.ServiceArea != "" {
			app = "Microsoft 365 " + a.ServiceArea
		}
		for _, u := range a.URLs {
			u = strings.TrimSpace(u)
			if u != "" {
				out = append(out, DomainEntry{Pattern: u, App: app})
			}
		}
	}
	return out, nil
}
