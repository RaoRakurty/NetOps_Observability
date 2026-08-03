// Package adapter is the vendor-neutral ingestion framework for the Application
// Identity Fusion Layer (#81, Phase 2). An Adapter turns ONE raw vendor event into a
// normalized appid.ApplicationObservation — preserving the original vendor values,
// namespacing the vendor app-id, stamping source authority, redacting sensitive
// fields. New vendors are added by registering an Adapter; the fusion core (appid.Fuse)
// never changes.
//
// Design rules (spec §7):
//   - A malformed/unsupported event is a controlled FAILURE (Result.Err set), never a
//     panic — the caller dead-letters it; the pipeline keeps running.
//   - A recognized event that simply carries no app identity returns ok=false, err=nil
//     (it is not an error, just not an observation).
//   - The ORIGINAL vendor app-id and name are always preserved on the observation.
package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/appid"
)

// Result is the outcome of parsing one raw event.
type Result struct {
	Obs appid.ApplicationObservation
	OK  bool  // a usable observation was produced
	Err error // malformed/invalid → dead-letter (never crash the pipeline)
}

// Adapter parses one vendor's events into normalized observations. Implementations
// are pure (no IO) and stateless so they are trivially testable and concurrency-safe.
type Adapter interface {
	Name() string    // stable adapter id, e.g. "fortigate"
	Vendor() string  // "fortinet" | "paloalto" | "cisco"
	Product() string // "fortios" | "panos" | "secure-firewall" | "nbar2"
	Version() string // parser version, stamped on every observation it produces
	// Detect cheaply reports whether this adapter recognizes the raw event.
	Detect(ev map[string]any) bool
	// Parse normalizes a recognized event → observation.
	Parse(ev map[string]any, tenant string, ingest time.Time) Result
}

// Registry holds the registered adapters and routes a raw event to the first that
// detects it. Deterministic: adapters are tried in registration order.
type Registry struct{ adapters []Adapter }

// New returns a registry with all production adapters registered. Registration order
// is detection precedence; add new adapters here (the fusion core never changes).
func New() *Registry {
	r := &Registry{}
	// More-specific vendor matchers first; NBAR/IPFIX last (its markers are generic).
	r.Register(fortiGate{})
	r.Register(paloAlto{})
	r.Register(ciscoFW{})
	r.Register(nbarIPFIX{})
	return r
}

// Register adds an adapter (call once at startup; not concurrency-safe with Parse).
func (r *Registry) Register(a Adapter) { r.adapters = append(r.adapters, a) }

// Names returns the registered adapter ids (for /status + metrics).
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.adapters))
	for _, a := range r.adapters {
		out = append(out, a.Name())
	}
	return out
}

// Parse routes ev to the first adapter that detects it. Returns the result and the
// adapter name ("" when no adapter recognized the event — caller counts unsupported).
func (r *Registry) Parse(ev map[string]any, tenant string, ingest time.Time) (Result, string) {
	for _, a := range r.adapters {
		if a.Detect(ev) {
			return a.Parse(ev, tenant, ingest), a.Name()
		}
	}
	return Result{}, ""
}

// ── shared helpers for adapters ──────────────────────────────────────────────

// str returns ev[key] as a trimmed string, trying alternative spellings in order.
func str(ev map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := ev[k]; ok && v != nil {
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if s != "" {
				return s
			}
		}
	}
	return ""
}

// intv returns ev[key] as an int (0 when absent/non-numeric).
func intv(ev map[string]any, keys ...string) int {
	s := str(ev, keys...)
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		// tolerate floats like "443.0"
		if f, e2 := strconv.ParseFloat(s, 64); e2 == nil {
			return int(f)
		}
		return 0
	}
	return n
}

// int64v returns ev[key] as int64 (0 when absent/non-numeric).
func int64v(ev map[string]any, keys ...string) int64 {
	s := str(ev, keys...)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		if f, e2 := strconv.ParseFloat(s, 64); e2 == nil {
			return int64(f)
		}
		return 0
	}
	return n
}

// protoName maps an IANA protocol number (string or numeric) to a name; passes
// through an already-named proto. "" when absent.
func protoName(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "6", "tcp":
		return "tcp"
	case "17", "udp":
		return "udp"
	case "1", "icmp":
		return "icmp"
	case "":
		return ""
	default:
		return strings.ToLower(s)
	}
}

// rawHash is the integrity hash of the raw event (sorted keys → stable) — stored
// instead of the raw body so an observation links back without copying the log.
func rawHash(ev map[string]any) string {
	keys := make([]string, 0, len(ev))
	for k := range ev {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		if k == "raw_hash" {
			continue
		}
		fmt.Fprintf(h, "%s=%v\n", k, ev[k])
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// notApp reports whether a vendor app value is a non-identity placeholder.
func notApp(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "n/a", "na", "unknown", "unscanned", "-":
		return true
	default:
		return false
	}
}

func errMissing(msg string) error { return errors.New(msg) }

// eventTime extracts the source event time, tolerating the common encodings
// (FortiGate `eventtime` epoch-ns/s, RFC3339 `ts`/`timestamp`). Falls back to ingest
// time — an honest substitute, never a guess.
func eventTime(ev map[string]any, ingest time.Time) time.Time {
	if et := str(ev, "eventtime", "fgt.eventtime"); et != "" {
		if n, err := strconv.ParseInt(et, 10, 64); err == nil && n > 0 {
			if n > 1e15 { // nanoseconds
				return time.Unix(0, n).UTC()
			}
			return time.Unix(n, 0).UTC() // seconds
		}
	}
	if ts := str(ev, "ts", "timestamp", "@timestamp"); ts != "" {
		s := strings.Replace(ts, " ", "T", 1)
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.UTC()
			}
		}
	}
	return ingest.UTC()
}

// deterministicUUID renders a stable UUID (v5-shaped) from its parts via SHA-256 —
// stdlib-only, no uuid dependency. Same inputs → same id (idempotent re-ingest).
func deterministicUUID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5-ish (cosmetic; uniqueness comes from the hash)
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// observationID is the deterministic, idempotent id for one observation.
func observationID(adapterName, session, src, dst, app string, t time.Time) string {
	return deterministicUUID(adapterName, session, src, dst, app, t.UTC().Format(time.RFC3339Nano))
}

// iface renders a directional interface label ("src→dst", or whichever is present).
func iface(src, dst string) string {
	switch {
	case src != "" && dst != "":
		return src + "→" + dst
	case dst != "":
		return dst
	default:
		return src
	}
}

// redactUser is the seam for user/endpoint minimization (spec §13). Pass-through by
// default; config-gated hashing is added in hardening (P7) so PII handling is explicit.
func redactUser(u string) string { return u }
