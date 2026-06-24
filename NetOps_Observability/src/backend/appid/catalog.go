package appid

// catalog.go — the IP→app catalog (#81 P1): feed parsers for the free, vendor-
// published IP-range files (AWS, Azure, GCP, Microsoft 365) and a Catalog that
// resolves a destination IP to an app Verdict via the LPM trie + Fuse.
//
// All feed-derived entries are SrcIPCatalog (medium trust): an IP-range match alone
// is "suspected", which is honest — shared CDN/cloud IPs are coarse. Stronger
// signals (NGFW/IPFIX app-id, DNS, SNI, operator/SoT) are layered by the caller via
// Resolve's extra signals and promote the verdict through Fuse.
//
// Parsing is pure + fixture-tested; fetching the feeds is an out-of-band, opt-in
// job (scripts/fetch-appid-feeds.sh) so the build stays offline.

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
)

// CatalogEntry is one (prefix → app) row. Source is the trust bucket (SrcIPCatalog
// for feed rows); Feed names the originating vendor file for the evidence detail.
type CatalogEntry struct {
	Prefix     string  `json:"prefix"`
	App        string  `json:"app"`
	Source     Source  `json:"source"`
	Feed       string  `json:"feed"`
	Confidence float64 `json:"confidence"`
}

const catalogConfidence = 0.55 // medium — matches SrcIPCatalog.baseConfidence

func ipCatalogEntry(prefix, app, feed string) CatalogEntry {
	return CatalogEntry{Prefix: prefix, App: app, Source: SrcIPCatalog, Feed: feed, Confidence: catalogConfidence}
}

// ── feed parsers (pure: raw bytes → entries) ─────────────────────────────────────

// ParseAWS reads the AWS ip-ranges.json feed.
func ParseAWS(raw []byte) ([]CatalogEntry, error) {
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []CatalogEntry
	for _, p := range doc.Prefixes {
		out = appendValidPrefix(out, p.IPPrefix, awsApp(p.Service), "aws")
	}
	for _, p := range doc.IPv6Prefixes {
		out = appendValidPrefix(out, p.IPv6Prefix, awsApp(p.Service), "aws")
	}
	return out, nil
}

// awsApp names an AWS service. "AMAZON" is the catch-all aggregate covering all of
// AWS — render it as plain "AWS" rather than the awkward "AWS AMAZON"; specific
// service tags (S3, EC2, CLOUDFRONT…) keep their name.
func awsApp(service string) string {
	if service == "" || service == "AMAZON" {
		return "AWS"
	}
	return "AWS " + service
}

// ParseAzure reads the Azure ServiceTags JSON feed.
func ParseAzure(raw []byte) ([]CatalogEntry, error) {
	var doc struct {
		Values []struct {
			Name       string `json:"name"`
			Properties struct {
				SystemService   string   `json:"systemService"`
				AddressPrefixes []string `json:"addressPrefixes"`
			} `json:"properties"`
		} `json:"values"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []CatalogEntry
	for _, v := range doc.Values {
		svc := v.Properties.SystemService
		if svc == "" {
			svc = v.Name
		}
		for _, pfx := range v.Properties.AddressPrefixes {
			out = appendValidPrefix(out, pfx, "Azure "+svc, "azure")
		}
	}
	return out, nil
}

// ParseGCP reads the Google Cloud cloud.json feed.
func ParseGCP(raw []byte) ([]CatalogEntry, error) {
	var doc struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
			Service    string `json:"service"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []CatalogEntry
	for _, p := range doc.Prefixes {
		app := p.Service
		if app == "" {
			app = "Google Cloud"
		}
		if p.IPv4Prefix != "" {
			out = appendValidPrefix(out, p.IPv4Prefix, app, "gcp")
		}
		if p.IPv6Prefix != "" {
			out = appendValidPrefix(out, p.IPv6Prefix, app, "gcp")
		}
	}
	return out, nil
}

// ParseM365 reads the Microsoft 365 endpoints API JSON feed (array of areas). Only
// the ips[] are taken here; the urls[] (domains) feed the P2 DNS/SNI tier.
func ParseM365(raw []byte) ([]CatalogEntry, error) {
	var doc []struct {
		ServiceArea string   `json:"serviceArea"`
		IPs         []string `json:"ips"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []CatalogEntry
	for _, a := range doc {
		app := "Microsoft 365"
		if a.ServiceArea != "" {
			app = "Microsoft 365 " + a.ServiceArea
		}
		for _, pfx := range a.IPs {
			out = appendValidPrefix(out, pfx, app, "m365")
		}
	}
	return out, nil
}

// appendValidPrefix accepts a CIDR or a bare IP (treated as a host route).
func appendValidPrefix(out []CatalogEntry, raw, app, feed string) []CatalogEntry {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out
	}
	if !strings.Contains(raw, "/") {
		if a, err := netip.ParseAddr(raw); err == nil {
			raw = raw + "/" + strconv.Itoa(a.BitLen())
		}
	}
	if _, err := netip.ParsePrefix(raw); err != nil {
		return out
	}
	return append(out, ipCatalogEntry(raw, app, feed))
}

// ── catalog ──────────────────────────────────────────────────────────────────

// Catalog is an immutable, resolved IP→app index. Build once, swap atomically on
// reload (the EntityResolver hot-reload pattern).
type Catalog struct {
	trie    *prefixTrie
	entries int
}

// NewCatalog builds a Catalog from entries (invalid prefixes are skipped).
func NewCatalog(entries []CatalogEntry) *Catalog {
	t := newPrefixTrie()
	for _, e := range entries {
		if p, err := netip.ParsePrefix(e.Prefix); err == nil {
			t.insert(p, e)
		}
	}
	return &Catalog{trie: t, entries: t.n}
}

// Size reports how many prefixes are indexed.
func (c *Catalog) Size() int {
	if c == nil {
		return 0
	}
	return c.entries
}

// Resolve identifies the app for a destination IP. extra carries any stronger
// signals the caller already has for this flow (NGFW/IPFIX app-id, DNS, SNI,
// operator/SoT); they are fused with the IP-catalog hit. An empty catalog + no
// extra signals yields the honest first-class "unknown".
func (c *Catalog) Resolve(ip netip.Addr, extra ...Signal) Verdict {
	var signals []Signal
	if c != nil && ip.IsValid() {
		for _, e := range c.trie.lookup(ip) {
			signals = append(signals, Signal{
				Source: e.Source, App: e.App, Confidence: e.Confidence,
				Detail: e.Feed + ":" + e.Prefix,
			})
		}
	}
	signals = append(signals, extra...)
	return Fuse(signals)
}

// ResolveStr is a convenience wrapper that parses a string IP.
func (c *Catalog) ResolveStr(ip string, extra ...Signal) Verdict {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return Fuse(extra)
	}
	return c.Resolve(a, extra...)
}
