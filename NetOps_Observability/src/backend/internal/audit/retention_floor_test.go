// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package audit

// retention_floor_test.go — the Postgres retention floor must protect EXACTLY
// the rows the file backend's retained trail protects, and no others.
//
// THE DEFECT (3.7-03). platformFloorSQL matched "mutating method + platform
// path prefix" and stopped there, while IsPlatformPath checks
// platformPathExclusions FIRST. /api/auth/login, /api/auth/refresh,
// /api/copilot/chat and /api/integrations/webhook/… therefore sat under the
// PLATFORM horizon on Postgres and under the configured retention everywhere
// else: the two backends retained different rows for different times, and the
// rows the SQL over-retained were the authentication and LLM ones — the highest
// volume on the platform and the ones data minimisation cares about most.
//
// WHAT THIS FILE CAN AND CANNOT PROVE. There is no Postgres in this package's
// test environment (audit_retention_floor_pg_test.go, the real end-to-end
// proof, lives in the root package and skips without DATABASE_URL_TEST). So
// this captures the REAL statement and the REAL bound arrays out of
// SweepRetention through a fake Tx and evaluates the captured predicate against
// the same paths IsPlatformChange sees. It proves the two classifications
// AGREE; it does not prove Postgres parses the statement — that is what the
// root package's PG test does, and the exclusion rows were added there too.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// capturedTx records the one statement SweepRetention issues. Only Exec is
// implemented: any other call is a change in what the sweeper does and must
// fail loudly rather than be silently absorbed.
type capturedTx struct {
	pgx.Tx
	query string
	args  []any
}

func (c *capturedTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	c.query, c.args = sql, args
	return pgconn.CommandTag{}, nil
}

// capturingRunner is the TxRunner seam with no database behind it.
type capturingRunner struct{ tx capturedTx }

func (r *capturingRunner) WithTenant(_ context.Context, _ string, cross bool, fn func(pgx.Tx) error) error {
	if !cross {
		// Retention is a platform-wide policy over a cross-tenant trail; a
		// scoped sweep would silently stop deleting other tenants' rows.
		return errNotCrossTenant
	}
	return fn(&r.tx)
}

var errNotCrossTenant = errors.New("sweep must run under platform (cross-tenant) scope")

// sweepArgs runs one sweep against the capturing runner and returns the bound
// arrays the floor predicate is evaluated over.
func sweepArgs(t *testing.T) (query string, methods, prefixes, exclusions []string) {
	t.Helper()
	r := &capturingRunner{}
	if _, err := SweepRetention(context.Background(), r, 30, 90); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	args := r.tx.args
	if len(args) < 6 {
		t.Fatalf("the sweep binds %d parameters; the platform floor must bind the EXCLUSION list too "+
			"(login/refresh/copilot/webhook are not platform config changes), so it must bind 6. "+
			"With five, every /api/auth/login row is retained for the PLATFORM horizon instead of "+
			"the configured retention. query=%s", len(args), r.tx.query)
	}
	as := func(i int) []string {
		v, ok := args[i].([]string)
		if !ok {
			t.Fatalf("parameter $%d is %T, want a bound []string — a spliced list would be SQL, not data", i+1, args[i])
		}
		return v
	}
	return r.tx.query, as(2), as(3), as(5)
}

// likeAny evaluates `s LIKE ANY(pats)` for the patterns this package renders:
// a literal prefix with an optional trailing '%'. Literalness is not assumed —
// TestPlatformPrefixesAreLiteralForLIKE and TestPlatformExclusionsAreLiteralForLIKE
// pin it, and this helper re-checks it so a metacharacter can never make the
// simulation quietly diverge from Postgres.
func likeAny(t *testing.T, s string, pats []string) bool {
	t.Helper()
	hit := false
	for _, p := range pats {
		body := strings.TrimSuffix(p, "%")
		if strings.ContainsAny(body, `%_\`) {
			t.Fatalf("pattern %q carries a LIKE metacharacter; this simulation is only valid for literal prefixes", p)
		}
		if p == body { // no wildcard: an exact match
			hit = hit || s == body
			continue
		}
		hit = hit || strings.HasPrefix(s, body)
	}
	return hit
}

// TestTheSQLFloorClassifiesExactlyLikeTheFileTrail is the finding's test: the
// bound predicate and IsPlatformChange must agree on every path, and in
// particular on the excluded ones.
func TestTheSQLFloorClassifiesExactlyLikeTheFileTrail(t *testing.T) {
	_, methods, prefixes, exclusions := sweepArgs(t)

	floor := func(method, path string) bool {
		m := false
		for _, want := range methods {
			m = m || want == method
		}
		if !m || !likeAny(t, path, prefixes) {
			return false
		}
		return !likeAny(t, path, exclusions)
	}

	for _, tc := range []struct {
		method, path string
	}{
		// The rows the defect over-retained. Each is a mutating method on a
		// path that sits UNDER a retained prefix but is excluded by name.
		{"POST", "/api/auth/login"},
		{"POST", "/api/auth/refresh"},
		{"POST", "/api/auth/logout"},
		{"POST", "/api/auth/change-password"},
		{"POST", "/api/auth/mfa/verify"},
		{"POST", "/api/auth/sso/login"},
		{"POST", "/api/auth/ldap/login"},
		{"POST", "/api/auth/tacacs/login"},
		{"POST", "/api/copilot/chat"},
		{"POST", "/api/integrations/webhook/servicenow"},
		{"PUT", "/api/notify/contact-points/x"},
		{"POST", "/api/system/licence/usage"},
		// …and the rows the floor exists for, which must stay classified.
		{"PUT", "/api/system/backup/schedule"},
		{"POST", "/api/auth/oidc/config"},
		{"PUT", "/api/copilot/config"},
		{"DELETE", "/api/notify/channels/1"},
		{"POST", "/api/notify"},
		{"POST", "/api/orgs"},
		{"PATCH", "/api/tenants/t1"},
		// Ordinary traffic, both directions.
		{"GET", "/api/system/backup/schedule"},
		{"POST", "/api/devices"},
		{"GET", "/api/devices"},
		{"POST", "/api/auth/loginish"},
	} {
		got := floor(tc.method, tc.path)
		want := IsPlatformChange(Event{Method: tc.method, Path: tc.path})
		if got != want {
			verb := "is NOT"
			if got {
				verb = "IS"
			}
			t.Errorf("%s %s: the SQL floor says it %s a platform change, the file trail says %v — "+
				"the two backends retain different rows for the same configured retention",
				tc.method, tc.path, verb, want)
		}
	}
}

// TestTheSweepStillBindsEveryListRatherThanSplicingIt — the exclusion list is
// operator-facing route text; it must arrive as a parameter like the other two.
func TestTheSweepStillBindsEveryListRatherThanSplicingIt(t *testing.T) {
	query, _, _, exclusions := sweepArgs(t)
	if len(exclusions) == 0 {
		t.Fatal("no exclusion patterns were bound")
	}
	for _, p := range exclusions {
		if strings.Contains(query, strings.TrimSuffix(p, "%")) {
			t.Errorf("exclusion %q appears in the statement text; it must be BOUND, never spliced", p)
		}
	}
	// `x NOT LIKE ANY(arr)` is "there exists a pattern x does not match" — true
	// for almost every path — and would disable the floor entirely.
	if strings.Contains(query, "NOT LIKE ANY") {
		t.Errorf("the statement uses `NOT LIKE ANY`, which is an existential, not a negation: %s", query)
	}
}

// TestPlatformExclusionsAreLiteralForLIKE is the exclusions' half of the
// guarantee TestPlatformPrefixesAreLiteralForLIKE makes for the prefixes: a '%'
// or '_' in one would widen (or narrow) what the floor refuses to protect.
func TestPlatformExclusionsAreLiteralForLIKE(t *testing.T) {
	for _, p := range platformPathExclusions {
		if strings.ContainsAny(p, `%_\`) {
			t.Errorf("exclusion %q carries a LIKE metacharacter — escape it or the SQL floor stops meaning what it reads", p)
		}
		if !strings.HasPrefix(p, "/api/") {
			t.Errorf("exclusion %q is not an /api route prefix", p)
		}
	}
}

// TestLikePatternsCarryTheBareRouteToo — matchesPrefix treats "/api/notify/" as
// also matching the bare "/api/notify"; the rendered patterns must, or the SQL
// and the Go predicate disagree on exactly the routes the table spells with a
// trailing slash. Asserted over the REAL rendered lists, not a sample, so a
// prefix added later with a trailing slash is covered too.
func TestLikePatternsCarryTheBareRouteToo(t *testing.T) {
	_, _, prefixPatterns, exclusionPatterns := sweepArgs(t)
	for _, tc := range []struct {
		name     string
		prefixes []string
		rendered []string
	}{
		{"platform prefixes", platformPathPrefixes, prefixPatterns},
		{"exclusions", platformPathExclusions, exclusionPatterns},
	} {
		t.Run(tc.name, func(t *testing.T) {
			have := map[string]bool{}
			for _, p := range tc.rendered {
				have[p] = true
			}
			for _, p := range tc.prefixes {
				if !have[p+"%"] {
					t.Errorf("%q renders no subtree pattern", p)
				}
				bare := strings.TrimSuffix(p, "/")
				if bare != p && !have[bare] {
					t.Errorf("%q renders no BARE-route pattern %q — matchesPrefix matches it, the SQL would not",
						p, bare)
				}
			}
		})
	}
}
