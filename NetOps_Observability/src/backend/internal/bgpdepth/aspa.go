// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpdepth

// aspa.go — ASPA (Autonomous System Provider Authorization, RFC 9234 objects /
// draft ASPA-based AS_PATH verification).
//
// ── THE HONESTY DECISION (read before "fixing" this file) ───────────────────
//
// There is NO public, per-ASN, bounded, plain-HTTP ASPA lookup we could verify
// on 2026-09-02:
//
//   - RIPEstat has no ASPA data call. https://stat.ripe.net/data/aspa/... and
//     .../rpki-aspa/... both answer 404 (probed live).
//   - rpki-client's public console publishes ASPA objects only inside one
//     global https://console.rpki-client.org/rpki.json — 104 MB, no query
//     parameters. Fetching that per page load is not a bounded call (§9) and is
//     not something a stdlib client should be streaming on an API request.
//   - Every other real ASPA source is a validator you run yourself (Routinator,
//     rpki-client, StayRTR) exposing its own JSON.
//
// Fabricating a verdict here would be the worst possible outcome: an operator
// would read "ASPA valid" off a screen and trust an unverified AS_PATH. So the
// default provider is NoASPAProvider, which returns ErrNoASPASource, and the UI
// renders an explicit "no ASPA data source configured" card.
//
// ── THE PLUGGABLE PATH ──────────────────────────────────────────────────────
//
// Set BGP_ASPA_PROVIDER_URL to an operator-run endpoint and HTTPProvider calls
// <url>?asn=<n>, expecting:
//
//	{"customer_asn": 64500,
//	 "providers": [{"asn": 3333, "afi": "any"}],
//	 "source": "routinator-0.14", "fetched_at": "2026-09-02T00:00:00Z"}
//
// Unknown fields are ignored, every field is bounded, and a provider that
// answers anything else is an ERROR — never an empty "no providers" verdict,
// which would read as "this AS authorizes nobody" and is a very different claim.
//
// The provider is an interface so a future vetted source (a RIPEstat data call,
// a local validator sidecar) drops in with no change above this line.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrNoASPASource is the honest default: nothing is configured, so nothing is
// claimed. Callers render it as a "not configured" card, never as "no ASPA".
var ErrNoASPASource = errors.New("bgpdepth: no ASPA data source configured")

const (
	// aspaMaxProviders bounds a provider list (§9). Real ASPAs are small; a
	// hostile or broken source does not get to allocate without limit.
	aspaMaxProviders = 256
	// ASPARespCap bounds an ASPA provider response body.
	ASPARespCap = 256 << 10
	// ASPACacheTTL — ASPA objects change on the scale of days.
	ASPACacheTTL = 30 * time.Minute
)

// ASPAProvider is the pluggable ASPA source. asn is bare digits ("64500").
type ASPAProvider interface {
	// Name identifies the source in the UI ("not configured", "routinator", …).
	Name() string
	// ASPA returns the customer AS's authorized providers, or an error. It MUST
	// return ErrNoASPASource when it holds no data source at all.
	ASPA(ctx context.Context, asn string) (ASPAResult, error)
}

// ASPAProviderEntry is one authorized provider AS.
type ASPAProviderEntry struct {
	ASN uint32 `json:"asn"`
	AFI string `json:"afi,omitempty"` // "ipv4" | "ipv6" | "any"
}

// ASPAResult is one customer AS's ASPA record.
type ASPAResult struct {
	CustomerASN uint32              `json:"customer_asn"`
	Providers   []ASPAProviderEntry `json:"providers"`
	// Found distinguishes "the source answered and there is no ASPA for this
	// AS" from "we have no source" (which is an error, not a Found=false).
	Found     bool      `json:"found"`
	Source    string    `json:"source"`
	FetchedAt time.Time `json:"fetched_at"`
	Truncated bool      `json:"truncated,omitempty"`
	// ProvidersUnreadable counts provider rows the SOURCE wrote in a form we
	// could not read. Those rows are dropped, never guessed — but the count
	// travels with the verdict (§10): a source quietly emitting garbage must
	// not look like a shorter, healthy authorization list.
	ProvidersUnreadable int `json:"providers_unreadable,omitempty"`
}

// NoASPAProvider is the default. It never guesses.
type NoASPAProvider struct{}

func (NoASPAProvider) Name() string { return "none" }
func (NoASPAProvider) ASPA(context.Context, string) (ASPAResult, error) {
	return ASPAResult{}, ErrNoASPASource
}

// HTTPProvider calls an operator-configured per-ASN JSON endpoint through the
// same SSRF-gated Fetcher every other outbound call in this package uses.
type HTTPProvider struct {
	Base string
	F    Fetcher
	Now  func() time.Time
}

func (p HTTPProvider) Name() string { return "configured" }

// NewASPAProvider builds the provider from the environment. An unset or unsafe
// BGP_ASPA_PROVIDER_URL yields NoASPAProvider — configuring garbage must not
// silently become a fabricated verdict, and it must not break the page either.
func NewASPAProvider(raw string, f Fetcher, now func() time.Time) ASPAProvider {
	raw = strings.TrimSpace(raw)
	if raw == "" || f == nil {
		return NoASPAProvider{}
	}
	if _, err := SafeOutboundURL(raw); err != nil {
		return NoASPAProvider{}
	}
	if now == nil {
		now = time.Now
	}
	return HTTPProvider{Base: raw, F: f, Now: now}
}

func (p HTTPProvider) ASPA(ctx context.Context, asn string) (ASPAResult, error) {
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(asn), "AS"), 10, 32)
	if err != nil {
		// UNREADABLE input — the caller handed us something that is not an ASN
		// at all. Distinct from the well-formed-but-reserved case below so the
		// operator reading the status card can tell a typo from AS0.
		return ASPAResult{}, fmt.Errorf("bgpdepth: unreadable ASN %q: %w", clip(asn, 20), err)
	}
	if n == 0 {
		return ASPAResult{}, fmt.Errorf("bgpdepth: invalid ASN %q — AS0 is reserved (RFC 7607) and never identifies a customer AS", clip(asn, 20))
	}
	u, err := SafeOutboundURL(p.Base)
	if err != nil {
		return ASPAResult{}, err
	}
	q := u.Query()
	q.Set("asn", strconv.FormatUint(n, 10))
	u.RawQuery = q.Encode()
	body, err := p.F.Get(ctx, u.String(), ASPARespCap)
	if err != nil {
		return ASPAResult{}, fmt.Errorf("aspa provider: %w", err)
	}
	var raw struct {
		CustomerASN json.RawMessage `json:"customer_asn"`
		Providers   []struct {
			ASN json.RawMessage `json:"asn"`
			AFI string          `json:"afi"`
		} `json:"providers"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return ASPAResult{}, fmt.Errorf("aspa provider: unparsable payload: %w", err)
	}
	cust, ok := ParseASNValue(raw.CustomerASN)
	if !ok {
		return ASPAResult{}, errors.New("aspa provider: missing or invalid customer_asn")
	}
	if uint64(cust) != n {
		// A source answering about a DIFFERENT AS is a bug or an attack; either
		// way the answer must not be shown against the AS we asked about.
		return ASPAResult{}, fmt.Errorf("aspa provider: answered for AS%d, asked AS%d", cust, n)
	}
	out := ASPAResult{CustomerASN: cust, Found: true, Source: clip(raw.Source, 60), FetchedAt: p.Now()}
	if out.Source == "" {
		out.Source = "configured"
	}
	for _, pr := range raw.Providers {
		if len(out.Providers) >= aspaMaxProviders {
			out.Truncated = true
			break
		}
		v, outcome := parseASNValue(pr.ASN)
		switch outcome {
		case asnUnreadable:
			// A FAULT in the source, not an absence: drop the row (never guess
			// it) and COUNT it, so the failure is visible in the response.
			out.ProvidersUnreadable++
			continue
		case asnReserved:
			// A well-formed "no AS here" (AS0 is reserved, RFC 7607). Nothing
			// failed; there is simply no provider on this row.
			continue
		}
		afi := strings.ToLower(clip(pr.AFI, 8))
		switch afi {
		case "ipv4", "ipv6", "any", "":
		default:
			afi = ""
		}
		out.Providers = append(out.Providers, ASPAProviderEntry{ASN: v, AFI: afi})
	}
	if len(out.Providers) == 0 && out.ProvidersUnreadable > 0 {
		// An empty Providers list is the CLAIM "this AS authorizes nobody". A
		// source that wrote only unreadable rows has made no such claim, so the
		// honest answer is an ERROR the status card renders as a failed
		// provider — never a verdict an operator could act on.
		return ASPAResult{}, fmt.Errorf("aspa provider: %d unreadable provider entries and none that could be read", out.ProvidersUnreadable)
	}
	return out, nil
}

// ASPAStatus is the small, honest payload the API hands the UI when no source
// is configured. It is deliberately NOT an ASPAResult: there is no verdict.
type ASPAStatus struct {
	Configured bool `json:"configured"`
	// Host is the configured provider's HOSTNAME only — never the full URL,
	// which may carry a token (§8: no secrets in responses or logs).
	Host   string `json:"host,omitempty"`
	Reason string `json:"reason"`
	HowTo  string `json:"how_to,omitempty"`
}

// NotConfiguredStatus explains the gap in operator language.
func NotConfiguredStatus() ASPAStatus {
	return ASPAStatus{
		Configured: false,
		Reason: "No ASPA data source is configured. ASPA objects are not served by any public per-ASN API " +
			"(RIPEstat has no ASPA data call; rpki-client's console publishes them only inside a ~104 MB global dump), " +
			"so this panel shows nothing rather than guessing an AS_PATH verdict.",
		HowTo: "Point " + EnvASPAProviderURL + " at an ASPA endpoint from your own RPKI validator " +
			"(Routinator / rpki-client / StayRTR) — it is called as <url>?asn=<n> and must return " +
			`{"customer_asn":N,"providers":[{"asn":N,"afi":"any"}],"source":"…"}.`,
	}
}

// ConfiguredStatus describes a live provider WITHOUT echoing its URL.
func ConfiguredStatus(base string) ASPAStatus {
	return ASPAStatus{
		Configured: true,
		Host:       aspaBaseHost(base),
		Reason:     "ASPA verdicts come from the operator-configured provider.",
	}
}

// aspaBaseHost echoes the configured host without leaking a full URL (which
// could carry a token) into a response or a log.
func aspaBaseHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// ParseASNValue reads an ASN that a JSON source may have written as a number
// (3333) OR as a string ("3333") — both occur in the wild. Anything else, and
// anything outside the 32-bit non-zero range (AS0 is reserved, RFC 7607), is a
// MISS: the caller drops that row rather than guessing at it.
//
// It is the boolean shim over parseASNValue for callers that only need "usable
// or not". A caller that must REPORT a broken source (rather than silently
// shortening a list) uses parseASNValue and its three states directly.
func ParseASNValue(raw json.RawMessage) (uint32, bool) {
	v, outcome := parseASNValue(raw)
	return v, outcome == asnOK
}

// asnParse says WHY a JSON ASN value was not usable. "We could not read it"
// (a fault in the source) and "it is the reserved AS0 / absent" (a well-formed
// value that names no AS) are DIFFERENT facts, and a caller that collapses
// them reports a broken upstream as a shorter list (CLAUDE.md §10).
type asnParse int

const (
	asnOK asnParse = iota
	// asnUnreadable: the source wrote something that is not an ASN. A FAULT.
	asnUnreadable
	// asnReserved: empty, or AS0 (reserved, RFC 7607). Well-formed, not a fault.
	asnReserved
)

// parseASNValue is the three-state core of ParseASNValue.
func parseASNValue(raw json.RawMessage) (uint32, asnParse) {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" {
		return 0, asnReserved
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(s), "AS"), 10, 32)
	if err != nil {
		return 0, asnUnreadable
	}
	if v == 0 {
		return 0, asnReserved
	}
	return uint32(v), asnOK
}
