package appid

import "sort"

// ExplanationCode is a STABLE, machine-readable reason a fused identity reached its
// state/confidence (#81 fusion layer). UI, API and runbooks key off these strings,
// so they are part of the contract: never renumber or repurpose a code — deprecate
// and add. Each code has a human description (surfaced in the "why this identity?"
// drawer); the set is pinned by a contract test.
type ExplanationCode string

const (
	ExSessionUpstream       ExplanationCode = "EXACT_SESSION_UPSTREAM_CLASSIFICATION" // a firewall/NBAR/NDR/proxy classified THIS exact session
	ExVendorAliasCanon      ExplanationCode = "VENDOR_ALIAS_CANONICALIZED"            // a vendor app-id/name mapped to the canonical app
	ExWorkloadMatch         ExplanationCode = "WORKLOAD_IDENTITY_MATCH"               // workload/process identity tied to the endpoint
	ExDNSTLSCorroboration   ExplanationCode = "DNS_TLS_CORROBORATION"                 // DNS + TLS-SNI/HTTP-host agree
	ExMultiIndependent      ExplanationCode = "MULTIPLE_INDEPENDENT_SOURCES"          // independent compatible sources raised confidence
	ExProviderOnlyIP        ExplanationCode = "PROVIDER_ONLY_IP_MATCH"                // only a provider/cloud IP range matched (coarse)
	ExPortOnlyFallback      ExplanationCode = "PORT_ONLY_FALLBACK"                    // only port/protocol — a service class, not the app
	ExAuthoritativeConflict ExplanationCode = "AUTHORITATIVE_SOURCE_CONFLICT"         // two authoritative sources disagree → conflicted
	ExStaleDNS              ExplanationCode = "STALE_DNS_EVIDENCE"                    // DNS evidence older than its TTL/window → rejected
	ExNATAmbiguity          ExplanationCode = "NAT_AMBIGUITY"                         // a NAT-collapsed source could not be attributed
	ExSharedCDNAmbiguity    ExplanationCode = "SHARED_CDN_AMBIGUITY"                  // shared CDN/cloud IP cannot prove the app alone
	ExDuplicateIgnored      ExplanationCode = "DUPLICATE_EVIDENCE_IGNORED"            // duplicate copies did not inflate confidence
	ExInsufficient          ExplanationCode = "INSUFFICIENT_EVIDENCE"                 // nothing admissible → unknown (first-class)
)

// explanationDescriptions is the authoritative registry. The contract test asserts
// every constant above is present here (and vice-versa) so the set can never drift.
var explanationDescriptions = map[ExplanationCode]string{
	ExSessionUpstream:       "An upstream system (firewall / NBAR / NDR / proxy) classified this exact session.",
	ExVendorAliasCanon:      "A vendor application id/name was mapped to the Correlix canonical application.",
	ExWorkloadMatch:         "Workload or process identity tied to the endpoint identified the application.",
	ExDNSTLSCorroboration:   "DNS and TLS-SNI/HTTP-host evidence agree on the application.",
	ExMultiIndependent:      "Multiple independent, compatible sources agreed, raising confidence.",
	ExProviderOnlyIP:        "Only a provider/cloud IP range matched — the provider is known, the application is not.",
	ExPortOnlyFallback:      "Only port/protocol was available — this names a service class, not a business application.",
	ExAuthoritativeConflict: "Two authoritative sources disagree — the identity is conflicted and not asserted.",
	ExStaleDNS:              "DNS evidence was older than its TTL/observation window and was rejected.",
	ExNATAmbiguity:          "A NAT-collapsed source could not be attributed to a single endpoint.",
	ExSharedCDNAmbiguity:    "A shared CDN/cloud IP cannot independently prove the application.",
	ExDuplicateIgnored:      "Duplicate copies of the same observation did not inflate confidence or impact.",
	ExInsufficient:          "No admissible evidence — the application is unknown (a first-class outcome).",
}

// Valid reports whether c is a known, supported explanation code.
func (c ExplanationCode) Valid() bool { _, ok := explanationDescriptions[c]; return ok }

// Description returns the human-facing explanation ("" for an unknown code).
func (c ExplanationCode) Description() string { return explanationDescriptions[c] }

// ExplanationCodes returns the full registry, sorted — the API enumerates this so
// clients can render a legend without hard-coding the set.
func ExplanationCodes() []ExplanationCode {
	out := make([]ExplanationCode, 0, len(explanationDescriptions))
	for c := range explanationDescriptions {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
