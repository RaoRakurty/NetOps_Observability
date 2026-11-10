// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build pgintegration

package tenantrunbook

// pg_integration_test.go — storage-layer proof for migration 0066, against a real
// PostgreSQL as a NOBYPASSRLS role: FORCE-RLS confines every statement to the
// tenant; the DATABASE refuses a self-approval, a rewrite of submitted text and an
// unproven activation even when the application is bypassed; the lifecycle
// round-trips; the bounds hold under concurrency; the migration goes up and down.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/ai"
	"netops/backend/internal/orgcontext"
	"netops/backend/internal/platformdb"
)

// provisionAppRole is the root package's helper of the same name: tests there are
// not importable from here. It leaves a clean schema and a non-superuser DSN.
func provisionAppRole(ctx context.Context, t *testing.T, adminDSN string) string {
	t.Helper()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() {
		if err := admin.Close(ctx); err != nil {
			t.Logf("admin close: %v", err)
		}
	}()
	const role, pass = "netops_app_test", "apppw"
	for _, s := range []string{
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()",
		"DO $do$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '" + role + "') THEN EXECUTE 'DROP OWNED BY " + role + "'; END IF; END $do$",
		"DROP SCHEMA IF EXISTS public CASCADE",
		"CREATE SCHEMA public",
		"GRANT USAGE, CREATE ON SCHEMA public TO PUBLIC",
		"DROP ROLE IF EXISTS " + role,
		"CREATE ROLE " + role + " LOGIN PASSWORD '" + pass + "' NOSUPERUSER",
		"GRANT ALL ON SCHEMA public TO " + role,
	} {
		if _, err := admin.Exec(ctx, s); err != nil {
			t.Fatalf("provision (%s): %v", s, err)
		}
	}
	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatalf("parse adminDSN: %v", err)
	}
	u.User = url.UserPassword(role, pass)
	return u.String()
}

func pgFixture(t *testing.T) (*platformdb.PGStore, *PGStore, *fakeHarness, string) {
	t.Helper()
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	dsn := provisionAppRole(ctx, t, adminDSN)
	ps, err := platformdb.NewPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ps.DB().Close)
	h := newFake()
	return ps, NewPGStore(ps.DB(), Config{Harness: h, ToolNames: ai.ToolNames}), h, dsn
}

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func TestTenantRunbookRLSIsolationPG(t *testing.T) {
	ps, st, _, _ := pgFixture(t)
	ctx := context.Background()
	r := create(t, st, "acme", "alice", good())
	activate(t, st, "acme", r.ID, "alice", "bob")
	if _, err := st.PutLink(ctx, "acme", r.ID, "alice", LinkAlert, "BgpDown"); err != nil {
		t.Fatal(err)
	}

	if _, err := st.Get(ctx, "globex", r.ID); !errors.Is(err, orgcontext.ErrNotFound) {
		t.Fatalf("RLS LEAK: globex read acme's runbook (%v)", err)
	}
	for _, k := range []orgcontext.OpKind{orgcontext.OpDraft, orgcontext.OpSubmit, orgcontext.OpApprove, orgcontext.OpRollback, orgcontext.OpRetire} {
		if _, err := st.Do(ctx, "globex", r.ID, orgcontext.Op{Kind: k, Actor: "mallory", Body: edited("x"), Version: 1, ToVersion: 1, Reason: "r"}); !errors.Is(err, orgcontext.ErrNotFound) {
			t.Fatalf("RLS LEAK: globex %s on acme's runbook (%v)", k, err)
		}
	}
	if _, err := st.Links(ctx, "globex", r.ID); !errors.Is(err, orgcontext.ErrNotFound) {
		t.Fatalf("RLS LEAK: globex read acme's links (%v)", err)
	}
	if _, err := st.PutLink(ctx, "globex", r.ID, "mallory", LinkAlert, "x"); !errors.Is(err, orgcontext.ErrNotFound) {
		t.Fatalf("RLS LEAK: globex linked acme's runbook (%v)", err)
	}
	if got, err := st.Search(ctx, "globex", "carrier", 10); err != nil || len(got) != 0 {
		t.Fatalf("RLS LEAK: globex searched %+v (%v)", got, err)
	}
	if got, err := st.ListByLink(ctx, "globex", LinkAlert, "BgpDown"); err != nil || len(got) != 0 {
		t.Fatalf("RLS LEAK: globex found by link %+v (%v)", got, err)
	}
	if got, err := st.Search(ctx, "acme", "carrier", 10); err != nil || len(got) != 1 {
		t.Fatalf("acme's search: %+v (%v)", got, err)
	}

	for _, table := range []string{"tenant_runbooks", "tenant_runbook_versions", "tenant_runbook_links"} {
		var n int
		if err := ps.DB().WithTenant(ctx, "globex", false, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n)
		}); err != nil || n != 0 {
			t.Fatalf("RLS LEAK: globex's session counts %d rows in %s (%v)", n, table, err)
		}
		var mine int
		if err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&mine)
		}); err != nil || mine == 0 {
			t.Fatalf("acme's session counts %d rows in %s (%v): the check above would pass vacuously", mine, table, err)
		}
	}
	// An insert into another tenant is refused by WITH CHECK on all three tables.
	for name, sql := range map[string]string{
		"runbooks": `INSERT INTO tenant_runbooks (tenant_id, id, name, kind, created_by)
		    VALUES ('globex', gen_random_uuid(), 'forged', 'mop', 'mallory')`,
		"versions": `INSERT INTO tenant_runbook_versions (tenant_id, runbook_id, version, skill_md, body_sha256, state, author_sub)
		    VALUES ('globex', '` + r.ID + `', 9, 'x', '` + orgcontext.BodySHA256("x") + `', 'draft', 'mallory')`,
		"links": `INSERT INTO tenant_runbook_links (tenant_id, runbook_id, link_type, link_key, created_by)
		    VALUES ('globex', '` + r.ID + `', 'alert', 'forged', 'mallory')`,
	} {
		err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		})
		if pgCode(err) != "42501" {
			t.Fatalf("WITH CHECK must refuse a forged tenant in %s, got %v", name, err)
		}
	}
}

// The database holds the rules even when the application is bypassed.
func TestTenantRunbookDatabaseGuardsPG(t *testing.T) {
	ps, st, _, _ := pgFixture(t)
	ctx := context.Background()
	raw := func(sql string, args ...any) error {
		return ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		})
	}
	const versions = `UPDATE tenant_runbook_versions SET `
	const one = ` WHERE runbook_id = $1::uuid`

	// A row submitted straight to the table: pending, with no harness result.
	unproven := create(t, st, "acme", "alice", named("unproven"))
	if err := raw(versions+`state = 'pending'`+one, unproven.ID); err != nil {
		t.Fatalf("draft → pending: %v", err)
	}
	if code := pgCode(raw(versions+`state = 'active', approver_sub = 'bob'`+one, unproven.ID)); code != "42501" {
		t.Fatalf("pending → active without harness_passed: code %q, want 42501 (trigger)", code)
	}
	if code := pgCode(raw(versions+`state = 'active', approver_sub = 'bob', harness_passed = true`+one, unproven.ID)); code != "42501" {
		t.Fatalf("claiming the pass in the same statement as the approval: code %q, want 42501 (trigger)", code)
	}

	// A row that came through the store: pending, proven.
	r := create(t, st, "acme", "alice", good())
	r = do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: "alice"})
	v, _ := r.Open()
	if code := pgCode(raw(versions+`state = 'active', approver_sub = 'alice'`+one, r.ID)); code != "23514" {
		t.Fatalf("a self-approval written straight to the table: code %q, want 23514 (CHECK)", code)
	}
	if code := pgCode(raw(versions+`state = 'active'`+one, r.ID)); code != "23514" {
		t.Fatalf("an active version with no approver: code %q, want 23514", code)
	}
	if code := pgCode(raw(versions+`skill_md = 'swapped after review'`+one, r.ID)); code != "42501" {
		t.Fatalf("rewriting a submitted text: code %q, want 42501 (trigger)", code)
	}
	if code := pgCode(raw(versions+`cases_yaml = 'swapped after review'`+one, r.ID)); code != "42501" {
		t.Fatalf("rewriting submitted cases: code %q, want 42501 (trigger)", code)
	}
	if code := pgCode(raw(versions+`body_sha256 = $2`+one, r.ID, orgcontext.BodySHA256("x"))); code != "42501" {
		t.Fatalf("rewriting a submitted hash: code %q, want 42501 (trigger)", code)
	}
	if code := pgCode(raw(versions+`harness_fingerprint = 'forged'`+one, r.ID)); code != "42501" {
		t.Fatalf("rewriting a submitted result: code %q, want 42501 (trigger)", code)
	}
	if code := pgCode(raw(`DELETE FROM tenant_runbook_versions`+one, r.ID)); code != "42501" {
		t.Fatalf("deleting a submitted version: code %q, want 42501", code)
	}
	do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: "bob", Version: v.Version, BodySHA256: v.BodySHA256})
	if code := pgCode(raw(versions+`approver_sub = 'carol'`+one, r.ID)); code != "42501" {
		t.Fatalf("re-attributing an approval: code %q, want 42501", code)
	}
	if code := pgCode(raw(versions+`state = 'pending'`+one, r.ID)); code != "42501" {
		t.Fatalf("active → pending: code %q, want 42501", code)
	}
	if code := pgCode(raw(versions+`harness_passed = false`+one, r.ID)); code != "42501" {
		t.Fatalf("rewriting an active version's result: code %q, want 42501 (trigger)", code)
	}

	// The rollback path INSERTs: an unproven active row is refused by the CHECK.
	code := pgCode(raw(`INSERT INTO tenant_runbook_versions (tenant_id, runbook_id, version, skill_md, body_sha256, state, author_sub, approver_sub)
	    VALUES ('acme', $1::uuid, 99, 'x', $2, 'active', 'alice', 'bob')`, unproven.ID, orgcontext.BodySHA256("x")))
	if code != "23514" {
		t.Fatalf("an unproven active row inserted directly: code %q, want 23514", code)
	}

	// The remaining CHECKs.
	id, err := orgcontext.NewID()
	if err != nil {
		t.Fatal(err)
	}
	for what, c := range map[string]struct {
		sql  string
		args []any
	}{
		"a name that is not the shape": {`INSERT INTO tenant_runbooks (tenant_id, id, name, kind, created_by) VALUES ('acme', $1::uuid, 'Not A Name', 'mop', 'a')`, []any{id}},
		"an unknown kind":              {`INSERT INTO tenant_runbooks (tenant_id, id, name, kind, created_by) VALUES ('acme', $1::uuid, 'k', 'persona', 'a')`, []any{id}},
		"an unknown link type":         {`INSERT INTO tenant_runbook_links (tenant_id, runbook_id, link_type, link_key, created_by) VALUES ('acme', $1::uuid, 'device', 'x', 'a')`, []any{r.ID}},
		"an empty link key":            {`INSERT INTO tenant_runbook_links (tenant_id, runbook_id, link_type, link_key, created_by) VALUES ('acme', $1::uuid, 'alert', '', 'a')`, []any{r.ID}},
		"an oversize link key":         {`INSERT INTO tenant_runbook_links (tenant_id, runbook_id, link_type, link_key, created_by) VALUES ('acme', $1::uuid, 'alert', repeat('k', 129), 'a')`, []any{r.ID}},
		"an oversize skill_md":         {versions + `skill_md = repeat('a', 16385)` + one, []any{unproven.ID}},
	} {
		got := pgCode(raw(c.sql, c.args...))
		if got != "23514" && !(what == "an oversize skill_md" && got == "42501") {
			t.Errorf("%s: code %q, want 23514", what, got)
		}
	}
	draft := create(t, st, "acme", "alice", named("still-a-draft"))
	if code := pgCode(raw(versions+`skill_md = repeat('a', 16385)`+one, draft.ID)); code != "23514" {
		t.Errorf("an oversize skill_md on a draft: code %q, want 23514", code)
	}
	if code := pgCode(raw(versions+`cases_yaml = repeat('a', 32769)`+one, draft.ID)); code != "23514" {
		t.Errorf("oversize cases on a draft: code %q, want 23514", code)
	}
	if code := pgCode(raw(versions+`body_sha256 = 'nope'`+one, draft.ID)); code != "23514" {
		t.Errorf("a malformed hash: code %q, want 23514", code)
	}
}

func TestTenantRunbookLifecyclePG(t *testing.T) {
	_, st, h, _ := pgFixture(t)
	ctx := context.Background()
	r := create(t, st, "acme", "alice", good())
	r = do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: "alice"})
	v, _ := r.Open()
	if _, err := st.Do(ctx, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: "alice", Version: 1, BodySHA256: v.BodySHA256}); !errors.Is(err, orgcontext.ErrSelfApproval) {
		t.Fatalf("self-approval: %v", err)
	}
	if _, err := st.Do(ctx, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: "bob", Version: 1, BodySHA256: orgcontext.BodySHA256("other")}); !errors.Is(err, orgcontext.ErrStale) {
		t.Fatalf("wrong hash: %v", err)
	}
	h.set(func(f *fakeHarness) { f.fp = "fp-2" })
	if _, err := st.Do(ctx, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: "bob", Version: 1, BodySHA256: v.BodySHA256}); !errors.Is(err, ErrHarnessStale) {
		t.Fatalf("a stale fingerprint: %v", err)
	}
	do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpWithdraw, Actor: "alice"})
	got, err := st.Get(ctx, "acme", r.ID)
	if err != nil || len(got.Harness) != 0 {
		t.Fatalf("a withdrawal clears the result: %+v %v", got.Harness, err)
	}
	do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: "alice"})
	r = do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: "bob", Version: 1, BodySHA256: v.BodySHA256})

	do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: "carol", Body: edited("Second text.")})
	do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: "carol", Body: edited("Second text, edited.")})
	r = activate(t, st, "acme", r.ID, "carol", "alice")
	if a, _ := r.Active(); a.Version != 2 || a.Body != edited("Second text, edited.") {
		t.Fatalf("v2: %+v", r.Versions)
	}

	h.set(func(f *fakeHarness) { f.fp, f.fail = "fp-3", true })
	var he *HarnessError
	if _, err := st.Do(ctx, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpRollback, Actor: "carol", ToVersion: 1, Reason: "v2 was wrong"}); !errors.As(err, &he) {
		t.Fatalf("a rollback that fails its cases: %v", err)
	}
	h.set(func(f *fakeHarness) { f.fail = false })
	do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpRollback, Actor: "carol", ToVersion: 1, Reason: "v2 was wrong"})
	got, err = st.Get(ctx, "acme", r.ID)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := got.Active()
	if a.Version != 3 || a.RestoredFrom != 1 || a.Author != "alice" || a.Approver != "bob" || a.ActivatedBy != "carol" || len(got.Versions) != 3 {
		t.Fatalf("rollback round trip: %+v", got.Versions)
	}
	if st3 := got.Harness[3]; !st3.Passed || st3.Fingerprint != "fp-3" || st3.At == nil {
		t.Fatalf("the restored version's stamp: %+v", st3)
	}
	do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpRetire, Actor: "bob", Reason: "decommissioned"})
	if got, _ := st.Get(ctx, "acme", r.ID); func() bool { _, ok := got.Active(); return ok }() {
		t.Fatal("a retired runbook stayed active")
	}

	// A MOP round-trips n/a.
	m := create(t, st, "acme", "alice", mop())
	m = do(t, st, "acme", m.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: "alice"})
	mv, _ := m.Open()
	m = do(t, st, "acme", m.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: "bob", Version: mv.Version, BodySHA256: mv.BodySHA256})
	got, err = st.Get(ctx, "acme", m.ID)
	if err != nil || got.Harness[1].Fingerprint != FingerprintNotApplicable || !got.Harness[1].Passed || got.RunbookKind != KindMOP {
		t.Fatalf("mop: %+v %v", got, err)
	}

	// Discarding the only draft removes the runbook and its links, and frees the name.
	d := create(t, st, "acme", "alice", named("scratch"))
	if _, err := st.PutLink(ctx, "acme", d.ID, "alice", LinkEntity, "edge-1"); err != nil {
		t.Fatal(err)
	}
	do(t, st, "acme", d.ID, orgcontext.Op{Kind: orgcontext.OpDiscard, Actor: "alice"})
	if _, err := st.Get(ctx, "acme", d.ID); !errors.Is(err, orgcontext.ErrNotFound) {
		t.Fatalf("discarded runbook: %v", err)
	}
	create(t, st, "acme", "alice", named("scratch"))
	if _, err := st.Create(ctx, "acme", "bob", named("scratch")); !errors.Is(err, orgcontext.ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestTenantRunbookSearchPG(t *testing.T) {
	_, st, _, _ := pgFixture(t)
	ctx := context.Background()
	draft := create(t, st, "acme", "alice", named("drafted-one"))
	active := create(t, st, "acme", "alice", named("approved-one"))
	active = activate(t, st, "acme", active.ID, "alice", "bob")

	found, err := st.Search(ctx, "acme", "brownout", 10)
	if err != nil || len(found) != 2 {
		t.Fatalf("search: %+v %v", found, err)
	}
	if found[0].ID != active.ID || found[0].Authority != AuthorityApproved || found[0].ApprovedAt == nil {
		t.Fatalf("equal rank, so active first: %+v", found)
	}
	if found[1].ID != draft.ID || found[1].Authority != AuthorityUnapproved || found[1].ApprovedAt != nil {
		t.Fatalf("the draft: %+v", found[1])
	}
	d := found[0]
	if d.Tenant != "acme" || d.Type != "runbook" || d.Source != "customer" || d.Scope != orgcontext.ScopeTenant || d.Name != "approved-one" || d.Snippet == "" || d.CreatedAt.IsZero() {
		t.Fatalf("retrieval fields: %+v", d)
	}
	// By name, on the hyphen-split words the simple config indexes.
	if got, _ := st.Search(ctx, "acme", "approved", 10); len(got) != 1 || got[0].ID != active.ID {
		t.Fatalf("search by name: %+v", got)
	}
	// Every word must match; rank orders the rest.
	if got, _ := st.Search(ctx, "acme", "brownout nothing", 10); len(got) != 0 {
		t.Fatalf("plainto_tsquery ANDs its words: %+v", got)
	}
	// The body is not indexed; a query is data, not a tsquery expression.
	if got, _ := st.Search(ctx, "acme", "portal", 10); len(got) != 0 {
		t.Fatalf("the method's body must not be searched: %+v", got)
	}
	for _, hostile := range []string{"' OR 1=1 --", "brownout & | !", "()", ":*", "   "} {
		if _, err := st.Search(ctx, "acme", hostile, 10); err != nil {
			t.Errorf("search %q: %v", hostile, err)
		}
	}
	if got, _ := st.Search(ctx, "acme", "brownout", 1); len(got) != 1 {
		t.Fatalf("limit: %+v", got)
	}

	// An unapproved edit does not move what an approved runbook is found by.
	do(t, st, "acme", active.ID, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: "carol", Body: phrased("approved-one", "unreviewed phrase")})
	if got, _ := st.Search(ctx, "acme", "unreviewed", 10); len(got) != 0 {
		t.Fatalf("an unapproved phrase is searchable on an approved runbook: %+v", got)
	}
	activate(t, st, "acme", active.ID, "carol", "alice")
	if got, _ := st.Search(ctx, "acme", "unreviewed", 10); len(got) != 1 {
		t.Fatalf("once approved it is searchable: %+v", got)
	}

	// Links.
	if _, err := st.PutLink(ctx, "acme", draft.ID, "alice", LinkSignature, "sig-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutLink(ctx, "acme", active.ID, "alice", LinkSignature, "sig-1"); err != nil {
		t.Fatal(err)
	}
	if ls, err := st.PutLink(ctx, "acme", active.ID, "alice", LinkSignature, "sig-1"); err != nil || len(ls) != 1 {
		t.Fatalf("adding it twice: %+v %v", ls, err)
	}
	linked, err := st.ListByLink(ctx, "acme", LinkSignature, "sig-1")
	if err != nil || len(linked) != 2 || linked[0].ID != active.ID || linked[0].Authority != AuthorityApproved {
		t.Fatalf("by link, active first: %+v %v", linked, err)
	}
	if ls, err := st.DeleteLink(ctx, "acme", draft.ID, LinkSignature, "sig-1"); err != nil || len(ls) != 0 {
		t.Fatalf("delete: %+v %v", ls, err)
	}
	if _, err := st.DeleteLink(ctx, "acme", draft.ID, LinkSignature, "sig-1"); !errors.Is(err, orgcontext.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

// phrased is the fixture under name with one searchable phrase replaced.
func phrased(name, phrase string) string {
	in := named(name)
	body, err := CanonicalBody(Source{SkillMD: strings.Replace(in.Source.SkillMD, "acme wan brownout", phrase, 1), CasesYAML: in.Source.CasesYAML})
	if err != nil {
		panic(err)
	}
	return body
}

func TestTenantRunbookConcurrencyPG(t *testing.T) {
	_, st, _, _ := pgFixture(t)
	ctx := context.Background()
	r := create(t, st, "acme", "alice", good())
	r = do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: "alice"})
	v, _ := r.Open()
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := st.Do(ctx, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: fmt.Sprintf("reviewer-%d", i), Version: v.Version, BodySHA256: v.BodySHA256})
			if err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d concurrent approvals succeeded, want 1", wins)
	}

	// The per-tenant cap holds under concurrent creates.
	created := 1
	for i := 0; i < MaxRunbooksPerTenant+15; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := st.Create(ctx, "acme", "alice", named(fmt.Sprintf("rb-%d", i)))
			switch {
			case err == nil:
				mu.Lock()
				created++
				mu.Unlock()
			case !errors.Is(err, orgcontext.ErrFull):
				t.Errorf("create %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if created != MaxRunbooksPerTenant {
		t.Fatalf("%d runbooks exist, the cap is %d", created, MaxRunbooksPerTenant)
	}

	// The per-runbook link cap holds under the row lock.
	linked := 0
	for i := 0; i < MaxLinksPerRunbook+10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := st.PutLink(ctx, "acme", r.ID, "alice", LinkAlert, fmt.Sprintf("alert-%d", i))
			switch {
			case err == nil:
				mu.Lock()
				linked++
				mu.Unlock()
			case !errors.Is(err, orgcontext.ErrFull):
				t.Errorf("link %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if linked != MaxLinksPerRunbook {
		t.Fatalf("%d links exist, the cap is %d", linked, MaxLinksPerRunbook)
	}
}

// The version cap, on the real rows.
func TestTenantRunbookVersionCapPG(t *testing.T) {
	_, st, _, _ := pgFixture(t)
	ctx := context.Background()
	r := create(t, st, "acme", "alice", good())
	for i := 1; i < MaxVersionsPerRunbook; i++ {
		do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: "alice"})
		do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpReject, Actor: "bob", Version: i, Reason: "no"})
		do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: "alice", Body: edited(fmt.Sprintf("Try %d.", i))})
	}
	do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: "alice"})
	do(t, st, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpReject, Actor: "bob", Version: MaxVersionsPerRunbook, Reason: "no"})
	if _, err := st.Do(ctx, "acme", r.ID, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: "alice", Body: edited("One more.")}); !errors.Is(err, orgcontext.ErrFull) {
		t.Fatalf("version %d: %v", MaxVersionsPerRunbook+1, err)
	}
}

// Migration up and down: the rollback removes what the migration made and its own
// schema_migrations row, and the migration then applies cleanly again.
func TestTenantRunbookMigrationUpAndDownPG(t *testing.T) {
	ps, st, _, dsn := pgFixture(t)
	ctx := context.Background()
	create(t, st, "acme", "alice", good())

	down, err := os.ReadFile("../platformdb/migrations/rollback/0066_tenant_runbooks.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(ctx); err != nil {
			t.Logf("close: %v", err)
		}
	}()
	if _, err := conn.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	var tables, funcs, rows int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_tables WHERE tablename LIKE 'tenant_runbook%'`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_proc WHERE proname = 'tenant_runbook_versions_guard'`).Scan(&funcs); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version = '0066_tenant_runbooks.sql'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if tables != 0 || funcs != 0 || rows != 0 {
		t.Fatalf("after down: %d tables, %d functions, %d schema_migrations rows", tables, funcs, rows)
	}
	if err := ps.DB().Migrate(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	r := create(t, st, "acme", "alice", good())
	activate(t, st, "acme", r.ID, "alice", "bob")
	// And RLS is back on.
	var forced int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relname LIKE 'tenant_runbook%' AND relkind = 'r' AND relrowsecurity AND relforcerowsecurity`).Scan(&forced); err != nil {
		t.Fatal(err)
	}
	if forced != 3 {
		t.Fatalf("%d of 3 tables have FORCE RLS after the re-apply", forced)
	}
}
