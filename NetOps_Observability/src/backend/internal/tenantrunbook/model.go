// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package tenantrunbook stores a customer's own runbooks and MOPs (tracker 337
// N-F2, design D7): a method written in the dialect of the compiled skills, that
// reaches Iris only when a second person has approved exactly the text they
// reviewed and that text's behavioural cases have passed.
//
// WHAT IS NOT NEW. The version lifecycle is orgcontext's. A Runbook embeds
// orgcontext.Doc and every transition goes through orgcontext.Apply, so the
// two-person rule, rollback and the frozen history cannot differ between the two
// stores. Doc.Key holds the name; Version.Body holds the canonical text
// (CanonicalBody), whose hash is what an approval binds to.
//
// WHAT IS ADDED. Around Apply: a submit and a rollback run the case harness and
// refuse on failure, and an approval refuses a result that is not a pass under the
// CURRENT fingerprint. Plus the bounds, links to what a runbook is about, and
// search over its name and when-to-use.
//
// A harness run takes up to ten seconds, so it runs BEFORE the row lock, against a
// snapshot, and the locked step refuses if the text moved. Nothing holds a database
// transaction open across a run.
//
// §3a. Every method takes the tenant from the authenticated principal; the Postgres
// store runs inside WithTenant(tenant, false) under FORCE-RLS tenant_iso. A runbook
// of another tenant and one that does not exist are the same ErrNotFound.
//
// Stdlib + pgx (CLAUDE.md §6 allowlist).
package tenantrunbook

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"netops/backend/internal/orgcontext"
)

// The bounds. The text sizes are also CHECKs in migration 0066. The case count is
// the parser's own (ai.ParseSkillSource refuses a 41st before parsing it); the
// value here is what the API tells a client, and TestBounds pins that they agree.
const (
	MaxRunbooksPerTenant  = 30
	MaxVersionsPerRunbook = 50
	MaxCasesPerRunbook    = 40
	MaxLinksPerRunbook    = 20
	MaxLinkKeyBytes       = 128
	MaxSearchQueryBytes   = 256
	DefaultSearchLimit    = 10
	MaxSearchLimit        = 30
)

// Kind is what a runbook is for.
type Kind string

const (
	KindInvestigative Kind = "investigative" // gathers evidence; proven by its cases
	KindMOP           Kind = "mop"           // a procedure for a human; never executed
)

// ValidKind reports whether k is a known kind.
func ValidKind(k Kind) bool { return k == KindInvestigative || k == KindMOP }

// FingerprintNotApplicable is what a MOP stores: nothing runs one, so no system
// prompt, tool or model can make its result stale.
const FingerprintNotApplicable = "n/a"

// Source is the two texts an author writes.
type Source struct {
	SkillMD   string `json:"skill_md"`
	CasesYAML string `json:"cases_yaml"`
}

// bodySeparator joins a Source into the one text a version's hash covers.
const bodySeparator = "\n--- CASES ---\n"

// CanonicalBody is the text an approval binds to. It refuses a skill_md that would
// make the join ambiguous, so one hash can never stand for two pairs of texts.
func CanonicalBody(s Source) (string, error) {
	body := s.SkillMD + bodySeparator + s.CasesYAML
	if strings.Index(body, bodySeparator) != len(s.SkillMD) {
		return "", orgcontext.Problem{Field: "skill_md", Rule: "separator", Say: "a runbook may not contain the line --- CASES ---"}
	}
	return body, nil
}

// SplitBody is CanonicalBody's inverse.
func SplitBody(body string) (Source, error) {
	md, cases, ok := strings.Cut(body, bodySeparator)
	if !ok {
		return Source{}, errors.New("tenantrunbook: a version's text has no cases separator")
	}
	return Source{SkillMD: md, CasesYAML: cases}, nil
}

// Stamp is a version's harness result.
type Stamp struct {
	Passed      bool
	Fingerprint string
	At          *time.Time
}

// Runbook is one document with its version history.
type Runbook struct {
	orgcontext.Doc
	RunbookKind Kind
	// WhenToUse is the searchable text: the active version's while there is one.
	WhenToUse string
	// Harness is each proven version's result, by version number. Frozen once
	// submitted (migration 0066's trigger).
	Harness map[int]Stamp
	// Recheck is each active version's re-checks under later fingerprints
	// (migration 0072), by version then fingerprint. Never over Harness.
	Recheck map[int]map[string]Stamp
}

// Name is the runbook's unique, immutable name.
func (r Runbook) Name() string { return r.Key }

func (r Runbook) clone() Runbook {
	r.Versions = append([]orgcontext.Version(nil), r.Versions...)
	h := make(map[int]Stamp, len(r.Harness))
	for k, v := range r.Harness {
		h[k] = v
	}
	r.Harness = h
	rc := make(map[int]map[string]Stamp, len(r.Recheck))
	for v, byFP := range r.Recheck {
		m := make(map[string]Stamp, len(byFP))
		for fp, st := range byFP {
			m[fp] = st
		}
		rc[v] = m
	}
	r.Recheck = rc
	return r
}

func (r Runbook) version(n int) (orgcontext.Version, bool) {
	for _, v := range r.Versions {
		if v.Version == n {
			return v, true
		}
	}
	return orgcontext.Version{}, false
}

func (r Runbook) draft() (orgcontext.Version, bool) {
	v, ok := r.Open()
	return v, ok && v.State == orgcontext.StateDraft
}

func (r Runbook) latest() int {
	n := 0
	for _, v := range r.Versions {
		if v.Version > n {
			n = v.Version
		}
	}
	return n
}

// NewRunbook is what a create carries; the tenant and author come from the
// principal, never from here.
type NewRunbook struct {
	Name   string
	Kind   Kind
	Source Source
}

// LinkType is what a link points at.
type LinkType string

const (
	LinkAlert     LinkType = "alert"
	LinkSignature LinkType = "signature"
	LinkEntity    LinkType = "entity"
	LinkIncident  LinkType = "incident"
)

// ValidLinkType reports whether t is a known link type.
func ValidLinkType(t LinkType) bool {
	switch t {
	case LinkAlert, LinkSignature, LinkEntity, LinkIncident:
		return true
	}
	return false
}

// Link associates a runbook with what it is about.
type Link struct {
	Type      LinkType  `json:"link_type"`
	Key       string    `json:"link_key"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// CheckLinkKey validates a link's key. It may ride into a prompt with the runbook,
// so it passes the same rule as prose.
func CheckLinkKey(key string) error {
	if strings.TrimSpace(key) == "" {
		return orgcontext.Problem{Field: "link_key", Rule: "required", Say: "say what the link points at"}
	}
	if len(key) > MaxLinkKeyBytes {
		return orgcontext.Problem{Field: "link_key", Rule: "too_long", Say: fmt.Sprintf("the key is %d bytes; the limit is %d", len(key), MaxLinkKeyBytes)}
	}
	if strings.ContainsAny(key, "\n\r") {
		return orgcontext.Problem{Field: "link_key", Rule: "one_line", Say: "the key must be one line"}
	}
	return orgcontext.CheckText("link_key", key, nil, "")
}

// Authority says whether a retrieved runbook's text was approved by two people.
const (
	AuthorityApproved   = "approved"
	AuthorityUnapproved = "unapproved"
)

// The retrieval object's fixed fields.
const (
	retrievalType   = "runbook"
	retrievalSource = "customer"
)

// RetrievalDoc is a runbook as retrieval sees it, so N-F3 needs nothing from these
// tables. Snippet is customer-written data. Only AuthorityApproved text has been
// through two people: anything that renders a RetrievalDoc into a prompt must
// filter on Authority first.
type RetrievalDoc struct {
	ID         string     `json:"id"`
	Tenant     string     `json:"tenant"`
	Type       string     `json:"type"`
	Source     string     `json:"source"`
	Name       string     `json:"name"`
	Authority  string     `json:"authority"`
	Scope      string     `json:"scope"`
	CreatedAt  time.Time  `json:"created_at"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	Snippet    string     `json:"snippet"`
}

// Errors beyond orgcontext's set, which this package reuses.
var (
	// ErrHarnessStale: the version's result is not a pass under the current
	// fingerprint. It has to be submitted again.
	ErrHarnessStale = errors.New("tenantrunbook: the cases have not passed against the current platform")
	// ErrHarnessBusy: too many runs are in flight. Nothing was decided.
	ErrHarnessBusy = errors.New("tenantrunbook: too many case runs are in progress")
)

// CaseProblem is one thing the harness refused.
type CaseProblem struct {
	Case    string `json:"case"`
	Message string `json:"message"`
}

// HarnessError is a harness refusal: the state did not change.
type HarnessError struct{ Problems []CaseProblem }

func (e *HarnessError) Error() string {
	return fmt.Sprintf("tenantrunbook: the runbook's cases did not pass (%d problems)", len(e.Problems))
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)

// ValidName mirrors the database's CHECK.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// ValidID reports whether id is a lower-case UUID.
func ValidID(id string) bool { return orgcontext.ValidID(id) }
