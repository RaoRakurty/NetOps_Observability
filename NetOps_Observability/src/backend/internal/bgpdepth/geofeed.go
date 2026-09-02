package bgpdepth

// geofeed.go — RFC 8805 self-published IP geolocation feeds, discovered per
// RFC 9092 ("geofeed:" attribute, or the historical "Geofeed <url>" remark).
//
// Verified live 2026-09-02: the RIPEstat "whois" data call returns the registry
// object as records of {key,value}. For 104.28.0.0/16 one record is
//
//	{"key":"Comment","value":"Geofeed: https://api.cloudflare.com/local-ip-ranges.csv"}
//
// and that CSV (5.4 MB) parses cleanly as
//
//	103.22.200.0/24,SG,,Singapore,
//	104.22.1.0/24,US,US-GA,Atlanta,
//
// ── Trust posture ───────────────────────────────────────────────────────────
//
// A geofeed URL is a string a THIRD PARTY wrote into a whois object: it is the
// single most attacker-influenced input on this page. Therefore:
//   - the URL goes through SafeOutboundURL AND the dialer-level CheckDialAddress
//     (an https URL whose host resolves to 169.254.169.254 is refused);
//   - the body is read through a byte cap and a line cap;
//   - parsing is CONSERVATIVE — a row that is not a valid prefix + ISO-3166-1
//     alpha-2 country is DROPPED, never repaired;
//   - only rows inside the queried resource are kept, so a feed cannot inject
//     claims about somebody else's address space into this answer;
//   - the returned row count is capped and the truncation is DECLARED.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// GeofeedRespCap bounds a geofeed body. Cloudflare's real feed is 5.4 MB;
	// 12 MiB leaves headroom for the largest published feeds and still refuses
	// to be used as a memory pump.
	GeofeedRespCap = 12 << 20
	// GeofeedMaxLines bounds parsing work independently of the byte cap.
	GeofeedMaxLines = 250_000
	// GeofeedMaxRows bounds what we hand back to a browser.
	GeofeedMaxRows = 500
	// GeofeedCacheTTL — a published feed changes on the scale of days.
	GeofeedCacheTTL = 6 * time.Hour
	// geofeedMaxASNPrefixes bounds the whois discovery fan-out for an ASN.
	geofeedMaxASNPrefixes = 6
)

// GeofeedEntry is one RFC 8805 row, already validated.
type GeofeedEntry struct {
	Prefix  string `json:"prefix"`
	Country string `json:"country,omitempty"` // ISO 3166-1 alpha-2
	Region  string `json:"region,omitempty"`  // ISO 3166-2
	City    string `json:"city,omitempty"`
	Postal  string `json:"postal,omitempty"`
}

// GeofeedResult is the panel's payload. Published=false with no Error means the
// registry simply carries no geofeed — a fact, not a failure.
type GeofeedResult struct {
	Resource    string         `json:"resource"`
	Published   bool           `json:"published"`
	SourceURL   string         `json:"source_url,omitempty"`
	Entries     []GeofeedEntry `json:"entries"`
	RowsScanned int            `json:"rows_scanned"`
	RowsKept    int            `json:"rows_kept"`
	RowsDropped int            `json:"rows_dropped"`
	Truncated   bool           `json:"truncated"`
	FetchedAt   time.Time      `json:"fetched_at"`
	Error       string         `json:"error,omitempty"`
	Note        string         `json:"note,omitempty"`
}

// geofeedURLRe matches both RFC 9092 forms inside a whois value:
// a bare "geofeed: <url>" attribute and the "Geofeed <url>" remark/comment.
var geofeedURLRe = regexp.MustCompile(`(?i)geofeed[:\s]\s*(https://[^\s,;"'<>]+)`)

// whoisRecord is one {key,value} pair of the RIPEstat whois data call.
type whoisRecord struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// DiscoverGeofeedURL scans a RIPEstat "whois" data payload for a geofeed URL.
// It accepts the dedicated attribute (key == "geofeed") and the remark form,
// and returns only a URL that already passes the SSRF gate.
func DiscoverGeofeedURL(data json.RawMessage) (string, bool) {
	var body struct {
		Records    [][]whoisRecord `json:"records"`
		IRRRecords [][]whoisRecord `json:"irr_records"`
	}
	if json.Unmarshal(data, &body) != nil {
		return "", false
	}
	groups := append(append([][]whoisRecord{}, body.Records...), body.IRRRecords...)
	for _, g := range groups {
		for _, rec := range g {
			if strings.EqualFold(strings.TrimSpace(rec.Key), "geofeed") {
				if u, err := SafeOutboundURL(rec.Value); err == nil {
					return u.String(), true
				}
				continue
			}
			if m := geofeedURLRe.FindStringSubmatch(rec.Value); m != nil {
				if u, err := SafeOutboundURL(strings.TrimRight(m[1], ".")); err == nil {
					return u.String(), true
				}
			}
		}
	}
	return "", false
}

// isoCountryRe is deliberately strict: exactly two ASCII letters. A row whose
// country is anything else is dropped rather than guessed.
var isoCountryRe = regexp.MustCompile(`^[A-Za-z]{2}$`)

// isoRegionRe accepts ISO 3166-2 ("US-GA"); anything else is cleared, keeping
// the row (the prefix+country is still useful) but never inventing a region.
var isoRegionRe = regexp.MustCompile(`^[A-Za-z]{2}-[A-Za-z0-9]{1,3}$`)

// ParseGeofeedCSV parses an RFC 8805 feed, keeping only rows whose prefix is
// contained in one of `within` (empty = keep everything). It never allocates
// past GeofeedMaxRows kept rows and never reads past GeofeedMaxLines lines.
func ParseGeofeedCSV(r io.Reader, within []netip.Prefix, maxRows int) (entries []GeofeedEntry, scanned, dropped int, truncated bool) {
	if maxRows <= 0 || maxRows > GeofeedMaxRows {
		maxRows = GeofeedMaxRows
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 8192) // a geofeed line is short; a longer one is not a geofeed line
	for sc.Scan() {
		if scanned >= GeofeedMaxLines {
			truncated = true
			break
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		scanned++
		e, ok := parseGeofeedLine(line)
		if !ok {
			dropped++
			continue
		}
		p, err := netip.ParsePrefix(e.Prefix)
		if err != nil {
			dropped++
			continue
		}
		if !prefixWithinAny(p, within) {
			continue // out of scope — not a drop, just not ours
		}
		if len(entries) >= maxRows {
			truncated = true
			continue
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		truncated = true // an unreadable tail is a truncation, and it is DECLARED
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Prefix < entries[j].Prefix })
	return entries, scanned, dropped, truncated
}

// parseGeofeedLine parses one RFC 8805 record:
// prefix,country,region,city,postal — trailing fields optional/empty.
func parseGeofeedLine(line string) (GeofeedEntry, bool) {
	f := strings.Split(line, ",")
	if len(f) < 1 {
		return GeofeedEntry{}, false
	}
	raw := strings.TrimSpace(f[0])
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		return GeofeedEntry{}, false
	}
	if p.Addr() != p.Masked().Addr() {
		p = p.Masked() // canonicalize; a host-bit-set row is sloppy, not hostile
	}
	e := GeofeedEntry{Prefix: p.String()}
	at := func(i int) string {
		if i < len(f) {
			return clip(strings.TrimSpace(f[i]), 64)
		}
		return ""
	}
	if c := at(1); isoCountryRe.MatchString(c) {
		e.Country = strings.ToUpper(c)
	} else if c != "" {
		return GeofeedEntry{}, false // a country field that is not a country = malformed row
	}
	if reg := at(2); isoRegionRe.MatchString(reg) {
		e.Region = strings.ToUpper(reg)
	}
	e.City = sanitizeGeoText(at(3))
	e.Postal = sanitizeGeoText(at(4))
	return e, true
}

// sanitizeGeoText strips control characters from free-text geofeed fields. The
// value is rendered as escaped React text, but a control character has no
// business reaching a log line or a CSV export either.
func sanitizeGeoText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func prefixWithinAny(p netip.Prefix, within []netip.Prefix) bool {
	if len(within) == 0 {
		return true
	}
	for _, w := range within {
		if w.Overlaps(p) {
			return true
		}
	}
	return false
}

// Geofeed resolves the geofeed for a prefix or an ASN.
//
// For a PREFIX: whois → discover → fetch → parse, keeping rows inside it.
// For an ASN: announced-prefixes (capped) → whois on each until a geofeed URL
// is found → fetch ONE feed → keep rows inside any announced prefix. The
// fan-out cap is why the ASN answer names how many prefixes it looked at.
func Geofeed(ctx context.Context, f Fetcher, now func() time.Time, resource, kind string) GeofeedResult {
	out := GeofeedResult{Resource: resource, Entries: []GeofeedEntry{}, FetchedAt: now()}
	if f == nil {
		out.Error = "no fetcher"
		return out
	}
	var scope []netip.Prefix
	var url string
	switch kind {
	case "prefix":
		p, err := netip.ParsePrefix(resource)
		if err != nil {
			out.Error = "not a prefix"
			return out
		}
		scope = []netip.Prefix{p.Masked()}
		url, out.Error = discoverForPrefix(ctx, f, resource)
	case "asn":
		var looked int
		scope, url, looked, out.Error = discoverForASN(ctx, f, resource)
		out.Note = fmt.Sprintf("checked the first %d announced prefixes of %s", looked, resource)
	default:
		out.Error = "unknown resource kind"
		return out
	}
	if out.Error != "" || url == "" {
		return out
	}
	out.SourceURL = url
	body, err := f.Get(ctx, url, GeofeedRespCap)
	if err != nil {
		out.Error = fmt.Sprintf("geofeed fetch failed: %v", err)
		return out
	}
	out.Published = true
	entries, scanned, dropped, truncated := ParseGeofeedCSV(bytes.NewReader(body), scope, GeofeedMaxRows)
	out.Entries, out.RowsScanned, out.RowsDropped, out.Truncated = entries, scanned, dropped, truncated
	out.RowsKept = len(entries)
	if out.Entries == nil {
		out.Entries = []GeofeedEntry{}
	}
	return out
}

func discoverForPrefix(ctx context.Context, f Fetcher, prefix string) (string, string) {
	data, err := f.RIPEstat(ctx, "whois", prefix, "", GeofeedCacheTTL)
	if err != nil {
		return "", fmt.Sprintf("registry lookup failed: %v", err)
	}
	if u, ok := DiscoverGeofeedURL(data); ok {
		return u, ""
	}
	return "", ""
}

func discoverForASN(ctx context.Context, f Fetcher, asn string) ([]netip.Prefix, string, int, string) {
	data, err := f.RIPEstat(ctx, "announced-prefixes", asn, "", GeofeedCacheTTL)
	if err != nil {
		return nil, "", 0, fmt.Sprintf("announced-prefixes lookup failed: %v", err)
	}
	var body struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	}
	if json.Unmarshal(data, &body) != nil {
		return nil, "", 0, "unparsable announced-prefixes payload"
	}
	var scope []netip.Prefix
	for _, p := range body.Prefixes {
		if len(scope) >= geofeedMaxASNPrefixes {
			break
		}
		if pp, err := netip.ParsePrefix(strings.TrimSpace(p.Prefix)); err == nil {
			scope = append(scope, pp.Masked())
		}
	}
	if len(scope) == 0 {
		return nil, "", 0, "no announced prefixes for this ASN"
	}
	for _, p := range scope {
		u, errStr := discoverForPrefix(ctx, f, p.String())
		if errStr != "" {
			continue // one registry hiccup must not blank the whole panel
		}
		if u != "" {
			return scope, u, len(scope), ""
		}
	}
	return scope, "", len(scope), ""
}
