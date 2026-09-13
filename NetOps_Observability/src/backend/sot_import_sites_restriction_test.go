// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// sot_import_sites_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test
// for the SITES half of the external-SoT import (tracker 298).
//
// Section 5 of inventory_lists_restriction_test.go closed the device_sites half:
// its resolver reads the caller's VISIBLE inventory, so a guessed identifier
// cannot confirm a restricted tenant's device. The SITES half decided
// create-vs-conflict from an UNFILTERED store read, which made a CSV a read
// oracle over a restricted tenant's site names — and the conflict detail went
// further than "exists" by naming WHICH FIELDS would change, i.e. a comparison
// against contents the caller may not read. With overwrite the same unfiltered
// read then WROTE over that tenant's row.
//
// The architect's decision is a THIRD outcome, `refused`: when the slug resolves
// to a site the caller may not read the import writes NOTHING, creates no shadow
// row under that slug, and reports existence and nothing else — no field names,
// no values, no tenant id. Existence alone is accepted disclosure, because a
// silent create would collide with the row that is already there.
//
// This test asserts the same five things every other restriction test asserts:
// a baseline, the Global view, the as_tenant walk, the unrestricted neighbour,
// and the restricted tenant's OWN view — plus, because this is a WRITE path,
// that the store is byte-for-byte unmoved afterwards.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// acme's headquarters: the row the operator must not be able to read, with a
// distinctive name and a distinctive street address in the owner field so the
// assertions can grep for the CONTENTS, not only for the outcome.
const (
	acmeHQSlug  = "hq"
	acmeHQName  = "Acme HQ Vaultstreet"
	acmeHQOwner = "Acme Facilities, 1 Vault Street"
)

// The field names siteChangeDetail would print. Each one is a comparison against
// a value the caller may not read, so a response naming any of them has leaked
// the contents of a hidden row — not merely its existence.
var siteChangeFieldNames = []string{"name", "status", "owner", "coordinates"}

// sitesImport runs the REAL POST /api/sot/import for kind=sites and returns
// action-by-line plus the raw body. The plan is the oracle, so the assertions
// need the bytes as well as the typed actions.
func (f *listFixture) sitesImport(t *testing.T, claims jwtClaims, csv string, overwrite, dryRun bool) (map[string]string, string) {
	t.Helper()
	body := f.call(t, f.s.handleSoTImport, http.MethodPost, "/api/sot/import",
		mustJSON(t, map[string]any{"kind": "sites", "format": "csv", "data": csv,
			"dry_run": dryRun, "overwrite": overwrite}), claims)
	var res importResult
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("decode sites import: %v (%s)", err, body)
	}
	out := map[string]string{}
	for _, row := range res.Rows {
		out[fmt.Sprintf("line%d", row.Line)] = row.Action
	}
	return out, body
}

// siteRowsBySlug renders the WHOLE store (every tenant) as slug → owning tenant,
// so an assertion can say both "nothing was written" and "nothing was written
// UNDER THAT SLUG for somebody else".
func (f *listFixture) siteRowsBySlug(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, st := range f.s.sites.All(TenantGlobal, true) {
		out[st.Slug] = st.TenantID
	}
	return out
}

func TestSoTSitesImportRefusesASlugTheCallerMayNotRead(t *testing.T) {
	f := newListFixture(t)
	owner, acmeUser := f.owner(), f.acmeUser()
	if _, err := f.s.sites.Upsert(Site{TenantID: f.acme, Slug: acmeHQSlug,
		Name: acmeHQName, Owner: acmeHQOwner, Status: "active"}); err != nil {
		t.Fatalf("seed acme hq: %v", err)
	}

	// One CSV, two rows: acme's slug with every field different (so a conflict
	// detail would name all four), and a slug nobody has declared (so a fix that
	// refuses everything is not a fix).
	csv := "slug,name,status,owner,lat,lng\n" +
		acmeHQSlug + ",Imported HQ,planned,netops,1.5,2.5\n" +
		"brand-new,Brand New,active,netops,,\n"
	// The unrestricted neighbour's own slug, changed the same way.
	csvGlobex := "slug,name,status,owner\nglobex-lon,Globex Renamed,planned,netops\n"

	// ── baseline: before the switch the operator may read acme, so the slug is
	//    an ordinary conflict and the unknown slug an ordinary create.
	base, _ := f.sitesImport(t, owner, csv, false, true)
	if base["line2"] != "conflict" || base["line3"] != "create" {
		t.Fatalf("baseline sites plan = %v, want conflict for %q and create for brand-new — "+
			"the fixture does not reach the planner", base, acmeHQSlug)
	}
	// acme's own answer BEFORE the switch, to compare against after it.
	beforeOwn, _ := f.sitesImport(t, acmeUser, csv, false, true)
	if beforeOwn["line2"] != "conflict" {
		t.Fatalf("acme's own sites plan = %v, want conflict for its own %q", beforeOwn, acmeHQSlug)
	}
	before := f.siteRowsBySlug(t)
	rowsBefore := f.s.sites.kv.Count()

	f.restrictAcme(t)

	// ── half 1: the Global view. The plan must say only that the slug is taken.
	got, body := f.sitesImport(t, owner, csv, false, true)
	if got["line2"] != "refused" {
		t.Errorf("RESTRICTION LEAK: the sites plan answered %q for a restricted tenant's slug %q, want \"refused\" — "+
			"deciding create-vs-conflict from an unfiltered read makes the CSV a read oracle.", got["line2"], acmeHQSlug)
	}
	if got["line3"] != "create" {
		t.Errorf("restricting acme changed the plan for an undeclared slug: %q, want create", got["line3"])
	}
	for _, field := range siteChangeFieldNames {
		if strings.Contains(body, field) {
			t.Errorf("RESTRICTION LEAK: the sites plan names the changed field %q for a row the caller may not read "+
				"— that is a comparison against contents, not existence. body: %s", field, body)
		}
	}
	for _, secret := range []string{acmeHQName, acmeHQOwner, f.acme} {
		if strings.Contains(body, secret) {
			t.Errorf("RESTRICTION LEAK: the sites plan body names %q: %s", secret, body)
		}
	}

	// ── the same row, APPLIED with overwrite: still refused, and the store is
	//    unmoved — no clobber of acme's row, and no shadow row under its slug.
	appliedPlan, appliedBody := f.sitesImport(t, owner, csv, true, false)
	if appliedPlan["line2"] != "refused" {
		t.Errorf("RESTRICTION LEAK: overwrite apply answered %q for %q, want \"refused\" — "+
			"an operator who may not READ the row must not be able to WRITE it.", appliedPlan["line2"], acmeHQSlug)
	}
	for _, field := range siteChangeFieldNames {
		if strings.Contains(appliedBody, field) {
			t.Errorf("RESTRICTION LEAK: the overwrite apply names the changed field %q: %s", field, appliedBody)
		}
	}
	hq, ok := f.s.sites.Get(f.acme, false, acmeHQSlug)
	if !ok || hq.Name != acmeHQName || hq.Owner != acmeHQOwner || hq.TenantID != f.acme {
		t.Errorf("CROSS-TENANT WRITE: acme's %q row was changed by an operator that may not read it: %+v", acmeHQSlug, hq)
	}
	after := f.siteRowsBySlug(t)
	if after[acmeHQSlug] != f.acme {
		t.Errorf("CROSS-TENANT WRITE: slug %q is now owned by %q, want %q — a refused row must not create a shadow site",
			acmeHQSlug, after[acmeHQSlug], f.acme)
	}
	// brand-new is the one row this apply was allowed to write.
	if after["brand-new"] != TenantGlobal {
		t.Errorf("the allowed row was not created: slug brand-new owned by %q, want %q", after["brand-new"], TenantGlobal)
	}
	if rows := f.s.sites.kv.Count(); rows != rowsBefore+1 {
		t.Errorf("the store grew by %d rows, want exactly 1 (brand-new): before %v, after %v",
			rows-rowsBefore, before, after)
	}

	// ── half 2: the operator walks in with as_tenant=acme. Same refusal.
	if got, body := f.sitesImport(t, ownerActing(owner, f.acme), csv, false, true); got["line2"] != "refused" {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme sites plan = %q for %q, want \"refused\": %s",
			got["line2"], acmeHQSlug, body)
	}

	// ── the unrestricted tenant is unmoved: its slug is still an ordinary
	//    conflict, field names and all.
	if got, _ := f.sitesImport(t, ownerActing(owner, f.globex), csvGlobex, false, true); got["line2"] != "conflict" {
		t.Errorf("as_tenant=globex sites plan = %q for globex-lon, want conflict — restricting acme must not move globex", got["line2"])
	}

	// ── acme's OWN import is unchanged: the switch hides a tenant from the
	//    platform, never from itself.
	if afterOwn, _ := f.sitesImport(t, acmeUser, csv, false, true); afterOwn["line2"] != beforeOwn["line2"] {
		t.Errorf("acme's own sites plan changed when acme restricted itself: %q → %q",
			beforeOwn["line2"], afterOwn["line2"])
	}
}
