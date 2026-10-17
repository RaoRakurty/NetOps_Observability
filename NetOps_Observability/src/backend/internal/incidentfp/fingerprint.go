// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package incidentfp is historical incident intelligence (tracker 337 N-F4):
// "have we seen this before?"
//
// A FINGERPRINT is what an incident looked like — its signature (the engine's
// top hypothesis template), owner domain and seam, the entities it touched,
// the observation kinds along its causal chain, and its symptom kinds. Recall
// finds earlier CLOSED incidents of the SAME tenant that share exact keys with
// it, then reranks them by a documented score.
//
// HONEST OUTPUT. Below the threshold the answer is "no similar incident" — the
// nearest weak match is NOT returned in any form. A domain or provider match
// alone can never make two incidents similar (a hard gate). Similar is not
// the same cause: every match is labelled as context, never as confirmation.
//
// §3a. Candidates always come from the subject incident's own tenant; this
// package never sees another tenant's rows (the stores are tenant-keyed and
// Postgres is FORCE-RLS).
//
// Stdlib + pgx (CLAUDE.md §6 allowlist).
package incidentfp

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// FPVersion is the fingerprint derivation version (a change re-derives).
const FPVersion = 1

// Bounds.
const (
	maxEntities = 16
	maxKinds    = 24
	maxValueLen = 200
)

// Fingerprint is one incident's shape.
type Fingerprint struct {
	TenantID      string    `json:"-"`
	CorrelationID string    `json:"correlation_id"`
	Version       int       `json:"fp_version"`
	Signature     string    `json:"signature,omitempty"`
	OwnerDomain   string    `json:"owner_domain,omitempty"`
	SeamType      string    `json:"seam_type,omitempty"`
	Provider      string    `json:"provider,omitempty"` // the seam-owner CLASS (isp, cloud_provider…), not a carrier name
	Devices       []string  `json:"devices,omitempty"`
	Interfaces    []string  `json:"interfaces,omitempty"`
	Sites         []string  `json:"sites,omitempty"`
	Services      []string  `json:"services,omitempty"`
	Seams         []string  `json:"seams,omitempty"`
	Paths         []string  `json:"paths,omitempty"`
	ChainKinds    []string  `json:"chain_kinds,omitempty"`
	ChainKey      string    `json:"chain_key,omitempty"`
	SymptomKinds  []string  `json:"symptom_kinds,omitempty"`
	VerdictTier   string    `json:"verdict_tier,omitempty"`
	State         string    `json:"state,omitempty"`
	OccurredAt    time.Time `json:"occurred_at"`
	ComputedAt    time.Time `json:"computed_at"`
}

// Parts are the inputs a fingerprint is derived from (the caller reads them
// from the incident's RCA report and its time-metrics row).
type Parts struct {
	TenantID, CorrelationID                 string
	Signature, OwnerDomain, SeamType, Owner string
	Devices, Interfaces, Sites, Services    []string
	Seams, Paths                            []string
	ChainStepKinds                          [][]string // per causal step, in order
	ChainContradicted                       bool
	SymptomKinds                            []string
	VerdictTier, State                      string
	OccurredAt                              time.Time
}

// undetermined signatures never count as a signature match.
func usableSignature(s string) string {
	s = norm(s)
	switch s {
	case "", "undetermined", "unknown", "none":
		return ""
	}
	return s
}

func norm(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > maxValueLen {
		s = s[:maxValueLen]
	}
	return s
}

func normSet(in []string, max int) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = norm(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// FromParts derives a fingerprint. A contradicted primary chain contributes no
// chain (it is the hypothesis that turned out wrong).
func FromParts(p Parts, now time.Time) Fingerprint {
	f := Fingerprint{
		TenantID: p.TenantID, CorrelationID: p.CorrelationID, Version: FPVersion,
		Signature: usableSignature(p.Signature), OwnerDomain: norm(p.OwnerDomain), SeamType: norm(p.SeamType), Provider: norm(p.Owner),
		Devices: normSet(p.Devices, maxEntities), Interfaces: normSet(p.Interfaces, maxEntities), Sites: normSet(p.Sites, maxEntities),
		Services: normSet(p.Services, maxEntities), Seams: normSet(p.Seams, maxEntities), Paths: normSet(p.Paths, maxEntities),
		SymptomKinds: normSet(p.SymptomKinds, maxKinds), VerdictTier: norm(p.VerdictTier), State: norm(p.State),
		OccurredAt: p.OccurredAt.UTC(), ComputedAt: now.UTC(),
	}
	if !p.ChainContradicted {
		var chain []string
		for _, step := range p.ChainStepKinds {
			for _, k := range step {
				k = norm(k)
				if k != "" && (len(chain) == 0 || chain[len(chain)-1] != k) {
					chain = append(chain, k)
				}
			}
		}
		if len(chain) > maxKinds {
			chain = chain[:maxKinds]
		}
		if len(chain) > 0 {
			f.ChainKinds = chain
			h := sha256.Sum256([]byte(strings.Join(chain, ">")))
			f.ChainKey = hex.EncodeToString(h[:8])
		}
	}
	return f
}

// Partial reports a fingerprint missing its chain or its symptoms (scored
// with those components at zero — never renormalised).
func (f Fingerprint) Partial() bool { return len(f.ChainKinds) == 0 || len(f.SymptomKinds) == 0 }
