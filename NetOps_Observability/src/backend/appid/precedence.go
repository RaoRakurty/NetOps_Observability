// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

// precedence.go — per-tenant attribution precedence (Wave 4 #11 slice 3).
//
// The precedence CLASSES are the operator-meaningful groups of the source
// ladder (verdict.go). A tenant may reorder them — e.g. trust its firewall DPI
// over cloud tags — and the resolver then picks the WINNER by that order.
// Reordering never touches trust semantics: tier, contradiction detection and
// confidence still come from each source's intrinsic strength, so a tenant can
// change who wins a disagreement but can never make a weak source claim
// "confirmed".

import (
	"fmt"
	"strings"
)

// minRank is the candidate-rank floor sentinel (classless precedence ranks are
// negative; see precedenceRank).
const minRank = -100

// Precedence class names — the closed vocabulary the editor permutes.
const (
	ClassOperator      = "operator"       // operator-declared selector / SoT (internal authority)
	ClassCloudTag      = "cloud_tag"      // cloud resource tags + workload identity
	ClassFirewallAppID = "firewall_appid" // on-path DPI: NGFW app-id / IPFIX applicationId
	ClassCloudGraph    = "cloud_graph"    // cloud resource-graph naming
	ClassDomain        = "domain"         // DNS-flow correlation / TLS SNI
	ClassIPCatalog     = "ip_catalog"     // vendor-published IP/prefix ranges
)

// PrecedenceClasses returns the classes in their DEFAULT order (a fresh copy —
// callers may mutate). The default mirrors the intrinsic ladder: authoritative
// internal declarations, then cloud tags, then on-path DPI, then the strong
// inferences, then the coarse catalog.
func PrecedenceClasses() []string {
	return []string{ClassOperator, ClassCloudTag, ClassFirewallAppID, ClassCloudGraph, ClassDomain, ClassIPCatalog}
}

// classOf buckets a source into its precedence class ("" = classless: weak /
// hint sources — ASN, port — which are never reorderable and always rank below
// every class).
func classOf(s Source) string {
	switch s {
	case SrcOperator, SrcSoT:
		return ClassOperator
	case SrcCloudTag, SrcWorkload:
		return ClassCloudTag
	case SrcNGFWAppID, SrcIPFIXAppID:
		return ClassFirewallAppID
	case SrcCloudGraph:
		return ClassCloudGraph
	case SrcDNS, SrcSNI:
		return ClassDomain
	case SrcIPCatalog:
		return ClassIPCatalog
	}
	return ""
}

// NormalizePrecedence validates a caller-supplied ordering: it must be exactly
// a permutation of PrecedenceClasses() (every class once, nothing else).
// Entries are trimmed/lowercased. Returns the normalized order.
func NormalizePrecedence(order []string) ([]string, error) {
	known := PrecedenceClasses()
	if len(order) != len(known) {
		return nil, fmt.Errorf("attribution_precedence must order all %d classes (%s)", len(known), strings.Join(known, ", "))
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(order))
	for _, c := range order {
		cls := strings.ToLower(strings.TrimSpace(c))
		valid := false
		for _, k := range known {
			if cls == k {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("attribution_precedence: unknown class %q", c)
		}
		if seen[cls] {
			return nil, fmt.Errorf("attribution_precedence: duplicate class %q", cls)
		}
		seen[cls] = true
		out = append(out, cls)
	}
	return out, nil
}

// IsDefaultPrecedence reports whether order equals the default class order.
func IsDefaultPrecedence(order []string) bool {
	def := PrecedenceClasses()
	if len(order) != len(def) {
		return false
	}
	for i := range def {
		if order[i] != def[i] {
			return false
		}
	}
	return true
}

// precedenceRank builds the winner-selection rank for a class order: first
// class ranks highest; classless (weak/hint) sources keep their relative
// intrinsic order but always rank below every class.
func precedenceRank(order []string) func(Source) int {
	pos := make(map[string]int, len(order))
	for i, c := range order {
		pos[c] = len(order) - i // 1..n, first = highest
	}
	return func(s Source) int {
		if r, ok := pos[classOf(s)]; ok {
			return r
		}
		return s.strength() - 10 // negative: below every class, asn still > port
	}
}

// FuseWithPrecedence fuses signals with a TENANT-ordered precedence. A nil /
// empty order means "no override" and behaves exactly like Fuse (the intrinsic
// ladder, including its confidence tie-breaks between same-strength sources).
// The order is assumed validated (NormalizePrecedence); an unsanctioned order
// falls back to Fuse rather than guessing.
func FuseWithPrecedence(signals []Signal, order []string) Verdict {
	if len(order) == 0 {
		return Fuse(signals)
	}
	if _, err := NormalizePrecedence(order); err != nil {
		return Fuse(signals)
	}
	return fuseRanked(signals, precedenceRank(order))
}
