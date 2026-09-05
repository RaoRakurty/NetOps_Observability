package dem

// model.go — the experience identity model and the target catalogue record.
//
// Two types carry the whole domain:
//
//	Identity     — WHO/WHAT an experience measurement is about. Source-agnostic
//	               on purpose: a synthetic check, an SD-WAN tunnel SLA sample, a
//	               wireless client's RF experience, a flow-derived app response
//	               time, an endpoint agent result and a browser RUM beacon all
//	               reduce to the same (tenant, subject, kind, site, app, source).
//	Target       — a synthetic check the operator DECLARED. It is one producer
//	               of Identity, not the identity itself; that distinction is the
//	               reason the later sources need no schema change.
//
// Validation is at the boundary AND here (§3: never trust the caller, including
// our own HTTP layer). Every bound is a refusal, never a silent truncation.

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Kind is what is being measured for one subject.
//
// The first four are the synthetic prober's check types. The rest are declared
// NOW, unused, so that the later sources map onto this vocabulary instead of
// inventing a parallel one (docs/design/DEM_DATA_MODEL_2026-09-05.md).
const (
	KindICMP = "icmp" // reachability + RTT + loss
	KindTCP  = "tcp"  // connect time to host:port
	KindDNS  = "dns"  // name resolution time + answer sanity
	KindHTTP = "http" // status + TTFB + phase timings

	// Reserved for the non-synthetic sources. No producer emits them yet; they
	// exist so the score maths and the series labels are already correct when
	// one does.
	KindTunnel     = "tunnel"      // SD-WAN per-app SLA over one tunnel/site pair
	KindWLANClient = "wlan_client" // wireless client experience (RSSI/SNR/retries/roams)
	KindFlowApp    = "flow_app"    // flow-derived application response time
	KindAgentCheck = "agent_check" // endpoint-agent probe result
	KindPageLoad   = "page_load"   // browser RUM beacon
)

// Source is the evidence class that produced a measurement. It is a label on
// EVERY series and every score, because "the synthetic said the app was fine"
// and "the user's browser said it was not" are different claims and an RCA that
// conflates them is lying.
const (
	SourceSynthetic = "synthetic"
	SourceSDWAN     = "sdwan"
	SourceWireless  = "wireless"
	SourceFlow      = "flow"
	SourceAgent     = "agent"
	SourceRUM       = "rum"
)

// syntheticKinds is the closed set a CATALOGUE target may declare. The reserved
// kinds above are not creatable by an operator — they arrive from a controller
// or an agent, and letting the CRUD surface mint one would create a target
// nothing will ever measure.
var syntheticKinds = map[string]bool{
	KindICMP: true, KindTCP: true, KindDNS: true, KindHTTP: true,
}

// knownSources is the closed set of measurement sources.
var knownSources = map[string]bool{
	SourceSynthetic: true, SourceSDWAN: true, SourceWireless: true,
	SourceFlow: true, SourceAgent: true, SourceRUM: true,
}

// ValidKind reports whether k is a kind an operator may declare on a target.
func ValidKind(k string) bool { return syntheticKinds[k] }

// ValidSource reports whether s is a known measurement source.
func ValidSource(s string) bool { return knownSources[s] }

// Identity is the subject of one experience measurement. Every field is a
// metric LABEL; together they are the series key.
//
// Subject is the stable id of the thing whose experience is measured — a
// catalogue target id for synthetics, and (when those sources land) a
// tunnel/site-pair id, a client MAC-derived id, an app id or a page id. It is
// deliberately opaque: nothing in the score maths parses it.
type Identity struct {
	Tenant  string `json:"tenant"`
	Subject string `json:"target"` // series label is `target` (stable wire name)
	Kind    string `json:"kind"`
	Site    string `json:"site,omitempty"`
	App     string `json:"app,omitempty"`
	Source  string `json:"source"`
}

// Measurement is one observation of one Identity. Zero timings mean "that phase
// did not occur / was not measured" and are omitted — never rendered as 0 ms.
type Measurement struct {
	Identity
	At        time.Time `json:"at"`
	OK        bool      `json:"ok"`
	LatencyMs float64   `json:"latency_ms,omitempty"`
	JitterMs  float64   `json:"jitter_ms,omitempty"`
	LossPct   float64   `json:"loss_pct"`
	// FailReason is the honest "why" when OK is false: dns | tls |
	// connect_refused | connect_timeout | timeout | reset | status | nxdomain |
	// no_answer | unknown. Empty when OK.
	FailReason string `json:"fail_reason,omitempty"`
	// PathHash fingerprints the observed forward path when the source measured
	// one (traceroute-backed kinds). Empty = path not measured, which is NOT
	// the same as "the path never changed" — the score reports it as such.
	PathHash string `json:"path_hash,omitempty"`
}

// Bounds (§9). Catalogue input is operator input, and operator input is still
// untrusted input.
const (
	MaxTargetsPerTenant = 500 // the perf budget the page and the prober are sized for
	MaxNameBytes        = 120
	MaxHostBytes        = 300 // a URL with a path; longer never came from the UI
	MaxLabelBytes       = 64  // site / app
	MinIntervalSec      = 15
	MaxIntervalSec      = 3600
	DefaultIntervalSec  = 60
	MaxLatencyBudgetMs  = 60000
)

// ErrCatalogueFull is returned when a tenant is at MaxTargetsPerTenant and
// creates a NEW target. Updating an existing one always succeeds.
var ErrCatalogueFull = fmt.Errorf("dem: target catalogue is full (max %d targets per tenant)", MaxTargetsPerTenant)

// ErrNotFound is the store's miss. The HTTP layer turns it into 404 — including
// for a cross-tenant id, so another tenant's id is never confirmed to exist.
var ErrNotFound = errors.New("dem: target not found")

// Target is one declared synthetic check.
//
// The JSON shape is the API's response shape AND the Postgres `data` column's
// shape, byte for byte, so both backends answer identically.
type Target struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"` // icmp | tcp | dns | http

	// Host is the check destination: a hostname/IP (icmp), host[:port] (tcp),
	// the name to resolve (dns) or an absolute http(s) URL (http).
	Host string `json:"host"`
	// Port applies to tcp when Host carries no port. 0 = use Host's port.
	Port int `json:"port,omitempty"`
	// Resolver optionally pins the DNS server for a dns check (host[:port]).
	// Empty = the prober's system resolver, which is itself the thing most
	// worth measuring.
	Resolver string `json:"resolver,omitempty"`

	IntervalSec int    `json:"interval_sec"`
	Site        string `json:"site,omitempty"`
	App         string `json:"app,omitempty"`

	// ExpectStatus is the HTTP status the check must see. 0 = any 2xx/3xx.
	ExpectStatus int `json:"expect_status,omitempty"`
	// LatencyBudgetMs is the target's latency SLO. 0 = no latency budget
	// declared, and the score then reports latency as measured-but-unbudgeted
	// rather than inventing a threshold.
	LatencyBudgetMs float64 `json:"latency_budget_ms,omitempty"`
	// AvailabilityBudgetPct is the success-ratio SLO (e.g. 99.0). 0 = none
	// declared; DefaultAvailabilityBudgetPct is used for the verdict and the
	// response says which was applied.
	AvailabilityBudgetPct float64 `json:"availability_budget_pct,omitempty"`

	// Paused stops the prober scheduling it WITHOUT deleting its history, so a
	// noisy target can be silenced without losing the record of why.
	Paused bool `json:"paused"`

	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DefaultAvailabilityBudgetPct is applied when a target declares none. It is
// deliberately modest: a default that pages is worse than one that informs.
const DefaultAvailabilityBudgetPct = 99.0

// Identity projects a target onto the source-agnostic identity every
// measurement of it is stamped with.
func (t Target) Identity() Identity {
	return Identity{
		Tenant: t.TenantID, Subject: t.ID, Kind: t.Kind,
		Site: t.Site, App: t.App, Source: SourceSynthetic,
	}
}

// EffectiveAvailabilityBudget returns the budget to score against and whether
// the operator declared it.
func (t Target) EffectiveAvailabilityBudget() (pct float64, declared bool) {
	if t.AvailabilityBudgetPct > 0 {
		return t.AvailabilityBudgetPct, true
	}
	return DefaultAvailabilityBudgetPct, false
}

// Interval clamps the configured interval into the accepted range. A stored 0
// (an older row) becomes the default rather than a busy loop.
func (t Target) Interval() time.Duration {
	s := t.IntervalSec
	switch {
	case s <= 0:
		s = DefaultIntervalSec
	case s < MinIntervalSec:
		s = MinIntervalSec
	case s > MaxIntervalSec:
		s = MaxIntervalSec
	}
	return time.Duration(s) * time.Second
}

// normTenant is this package's ONE tenant-key normalization, matching the API
// boundary's (lowercase, trimmed). Duplicated rather than shared through a
// "utils" package (CLAUDE.md §2 forbids the dumping ground).
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// concreteTenant fails CLOSED on an access that has no single tenant to scope
// to. "" and "*" are refused at the store, so no future caller can reintroduce
// a wildcard (§3a; the bgpwatch precedent).
func concreteTenant(t string) (string, error) {
	n := normTenant(t)
	if n == "" || n == "*" {
		return "", errors.New("dem: a concrete tenant is required (cross-tenant access is refused)")
	}
	return n, nil
}

// clip bounds an untrusted string WITHOUT splitting a UTF-8 rune.
func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.ToValidUTF8(s[:cut], "")
}

// labelSafe bounds a site/app label and strips the characters that would break
// a metric label or let a caller forge a second label in an exposition line.
func labelSafe(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.', r == ' ':
			return r
		default:
			return -1
		}
	}, s)
	return clip(strings.TrimSpace(s), MaxLabelBytes)
}

// Validate normalizes a target in place and reports the first refusal.
//
// It is called by BOTH the HTTP layer and the store: the store does not trust
// its callers, and a target that reached the store by any other path (an import,
// a future API) gets the same checks.
func (t *Target) Validate() error {
	t.TenantID = normTenant(t.TenantID)
	if _, err := concreteTenant(t.TenantID); err != nil {
		return err
	}
	t.Name = clip(strings.TrimSpace(t.Name), MaxNameBytes)
	if t.Name == "" {
		return errors.New("name is required")
	}
	t.Kind = strings.ToLower(strings.TrimSpace(t.Kind))
	if !ValidKind(t.Kind) {
		return fmt.Errorf("kind must be one of icmp, tcp, dns, http (got %q)", clip(t.Kind, 32))
	}
	t.Host = strings.TrimSpace(t.Host)
	if len(t.Host) > MaxHostBytes {
		return fmt.Errorf("host/url must be at most %d bytes", MaxHostBytes)
	}
	if t.Host == "" {
		return errors.New("host/url is required")
	}
	if err := t.validateDestination(); err != nil {
		return err
	}
	t.Site, t.App = labelSafe(t.Site), labelSafe(t.App)
	if t.IntervalSec == 0 {
		t.IntervalSec = DefaultIntervalSec
	}
	if t.IntervalSec < MinIntervalSec || t.IntervalSec > MaxIntervalSec {
		return fmt.Errorf("interval_sec must be %d..%d", MinIntervalSec, MaxIntervalSec)
	}
	if t.Port < 0 || t.Port > 65535 {
		return errors.New("port must be 0..65535")
	}
	if t.ExpectStatus != 0 && (t.ExpectStatus < 100 || t.ExpectStatus > 599) {
		return errors.New("expect_status must be 0 or a 100..599 HTTP status")
	}
	if t.Kind != KindHTTP && t.ExpectStatus != 0 {
		return errors.New("expect_status applies only to an http target")
	}
	if t.LatencyBudgetMs < 0 || t.LatencyBudgetMs > MaxLatencyBudgetMs {
		return fmt.Errorf("latency_budget_ms must be 0..%d", MaxLatencyBudgetMs)
	}
	if t.AvailabilityBudgetPct < 0 || t.AvailabilityBudgetPct > 100 {
		return errors.New("availability_budget_pct must be 0..100")
	}
	return nil
}

// validateDestination checks the destination is well formed FOR ITS KIND. This
// is a parse, not a reachability test: an unparseable destination is a target
// that can never produce a measurement, and accepting it would show the
// operator a permanently "not measured" row with no explanation.
func (t *Target) validateDestination() error {
	switch t.Kind {
	case KindHTTP:
		u, err := url.Parse(t.Host)
		if err != nil {
			return errors.New("url is not parseable")
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return errors.New("url scheme must be http or https")
		}
		if u.Hostname() == "" {
			return errors.New("url has no host")
		}
		t.Host = u.String()
		return nil
	case KindTCP:
		host := t.Host
		if h, p, err := net.SplitHostPort(t.Host); err == nil {
			host = h
			if t.Port == 0 {
				pn, serr := strconv.Atoi(p)
				if serr != nil || pn < 1 || pn > 65535 {
					return errors.New("port in host:port is not a valid port")
				}
				t.Port = pn
			}
			t.Host = host
		}
		if t.Port == 0 {
			return errors.New("a tcp target needs a port (host:port, or the port field)")
		}
		return validHostname(host)
	case KindDNS:
		if t.Resolver != "" {
			rh := t.Resolver
			if h, _, err := net.SplitHostPort(t.Resolver); err == nil {
				rh = h
			}
			if err := validHostname(rh); err != nil {
				return fmt.Errorf("resolver: %w", err)
			}
		}
		return validHostname(strings.TrimSuffix(t.Host, "."))
	default: // icmp
		return validHostname(t.Host)
	}
}

// validHostname accepts an IP literal or a syntactically valid DNS name. It
// deliberately does NOT resolve: name resolution at write time would make the
// catalogue's acceptance depend on the api's DNS, which is not the vantage the
// check runs from.
func validHostname(h string) error {
	h = strings.TrimSpace(h)
	if h == "" {
		return errors.New("host is required")
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return nil
	}
	if len(h) > 253 {
		return errors.New("hostname is too long")
	}
	for _, lbl := range strings.Split(h, ".") {
		if lbl == "" || len(lbl) > 63 {
			return errors.New("hostname has an empty or over-long label")
		}
		for i, r := range lbl {
			ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
				(r == '-' && i != 0 && i != len(lbl)-1) || r == '_'
			if !ok {
				return errors.New("hostname contains an invalid character")
			}
		}
	}
	return nil
}

// sortTargets orders a listing deterministically: site, then name, then id. A
// stable order is what makes the page's 500-target budget a scroll rather than
// a reshuffle on every poll.
func sortTargets(list []Target) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Site != list[j].Site {
			return list[i].Site < list[j].Site
		}
		if list[i].Name != list[j].Name {
			return list[i].Name < list[j].Name
		}
		return list[i].ID < list[j].ID
	})
}
