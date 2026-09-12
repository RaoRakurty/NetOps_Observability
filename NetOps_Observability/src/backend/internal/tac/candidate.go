// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// candidate.go — a TAC answer, turned into a signature CANDIDATE.
//
// THE LOOP THIS CLOSES (TAC_ESCALATION_2026-09-05 §1.3, §6 W3). A case is
// opened, the vendor answers, and the answer dies in a ticket. The knowledge in
// it — "this log line on this platform means that" — is exactly the shape of a
// detection rule Correlix does not have. This type is where an operator writes
// that answer down in the vocabulary the merge pipeline already speaks.
//
// CANDIDATE MEANS CANDIDATE. Nothing here is ever loaded by the api, matched
// against anything, or shown as knowledge Correlix holds. The ONLY exit is
// ExportResearch → a YAML file a human reads, reviews and feeds to
// `scripts/tac-merge-research.py`, which applies its own refusals and stamps
// every binding `verified: doc_claimed`. Three properties follow, and each is
// deliberate:
//
//   · the live catalogue cannot change because somebody clicked promote;
//   · the V1 replay pin (`Version`) is untouched by a candidate;
//   · the `doc_claimed` gate stays exactly where it is — the merge script, not
//     this file, decides what a command's verification level is.
//
// WHAT IS REFUSED HERE, BEFORE ANYTHING IS STORED. §7's output-only policy is
// not relaxed by one line for a candidate: every command passes the SAME
// TemplateValidator the review and collect paths use, so a forbidden command
// cannot be laundered into the research corpus through this door. A source must
// be https. Free text is redacted and bounded. A class outside the taxonomy is
// allowed but must be EXPORTED as `proposed_class: true`, which is what the
// merge script demands of one.

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/protocoldiag"
)

// Candidate bounds (§9). Every one of them is a cap on text that came from a
// device or a vendor and is written to a file somebody else reads.
const (
	// MaxCandidatesPerTenant bounds a tenant's backlog of proposals.
	MaxCandidatesPerTenant = 200
	// MaxCandidateCommands bounds one candidate's command list.
	MaxCandidateCommands = 24
	// MaxCandidateItems bounds each free-text list (symptoms, causes, lines).
	MaxCandidateItems = 12
	// maxCandidateLine is one list entry's length.
	maxCandidateLine = 300
	// maxCandidateText is a title / first-look / answer's length.
	maxCandidateText = 4 << 10
	// MaxCandidateSources bounds the citations one candidate may carry.
	MaxCandidateSources = 6
)

// CandidateStatus is where a proposal stands. It is operator state, not engine
// state: nothing in the api behaves differently because of it.
type CandidateStatus string

const (
	// CandidateProposed — written down, not yet reviewed.
	CandidateProposed CandidateStatus = "proposed"
	// CandidateExported — carried out to a research file.
	CandidateExported CandidateStatus = "exported"
	// CandidateRejected — reviewed and declined; kept so it is not re-proposed.
	CandidateRejected CandidateStatus = "rejected"
)

// CandidateStatuses is every status, in a stable order.
func CandidateStatuses() []CandidateStatus {
	return []CandidateStatus{CandidateProposed, CandidateExported, CandidateRejected}
}

// CandidateSource is one citation: the vendor page or the case the answer came
// from. `retrieved` is optional and is the date a human read it.
type CandidateSource struct {
	Title     string `json:"title,omitempty"`
	URL       string `json:"url"`
	Retrieved string `json:"retrieved,omitempty"`
}

// CandidateCommand is one command the answer says to run. Intent is the
// vendor-neutral concept; Command is the dialect's rendering.
type CandidateCommand struct {
	Intent  string `json:"intent"`
	Command string `json:"command"`
}

// Candidate is one proposed issue signature, in the research vocabulary.
type Candidate struct {
	ID       string `json:"id"`
	TenantID string `json:"-"`
	// IssueID is the research file's issue id (a kebab slug).
	IssueID string `json:"issue_id"`
	Dialect string `json:"dialect"`
	// ClassID is the TAC issue class. Proposed is set by the SERVER when that
	// class is not in the taxonomy — a client cannot claim either way.
	ClassID  string `json:"class_id"`
	Proposed bool   `json:"proposed_class"`

	Title         string             `json:"title"`
	Symptoms      []string           `json:"symptoms,omitempty"`
	LogSignatures []string           `json:"log_signatures,omitempty"`
	LikelyCauses  []string           `json:"likely_causes,omitempty"`
	Commands      []CandidateCommand `json:"commands,omitempty"`
	TACFirstLook  string             `json:"tac_first_look,omitempty"`
	Sources       []CandidateSource  `json:"sources,omitempty"`

	// Answer is the vendor's reply, redacted. It travels to the research file as
	// `notes:` — provenance for the reviewer, never a detection rule.
	Answer string `json:"answer,omitempty"`
	// FromIncident / FromRecord tie a proposal back to the collection that
	// prompted it, so a reviewer can read the output that was not recognised.
	FromIncident string `json:"from_incident,omitempty"`
	FromRecord   string `json:"from_record,omitempty"`

	Status    CandidateStatus `json:"status"`
	CreatedBy string          `json:"created_by,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

var (
	// ErrCandidateNotFound is an id this tenant does not have. A candidate owned
	// by another tenant returns this too — never a 403 (§3a rule 1).
	ErrCandidateNotFound = errors.New("tac: signature candidate not found")
	// ErrCandidateInvalid is a proposal that failed validation.
	ErrCandidateInvalid = errors.New("tac: this signature candidate cannot be saved")
	// ErrCandidateLimit is the per-tenant ceiling.
	ErrCandidateLimit = errors.New("tac: this tenant already holds the maximum number of signature candidates")
)

var (
	// candIDRE is a candidate id's shape. slugRE (tac.go) is reused for class,
	// dialect and issue ids so this file cannot drift from the vocabulary the
	// rest of the pack validates against.
	candIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

// ── validation ──────────────────────────────────────────────────────────────

// ValidateCandidate normalises a proposal and refuses one that cannot be
// exported. It is the ONLY way a candidate is created or updated.
//
// `cat` supplies the taxonomy (is this class real?) and `v` the command
// validator (is this line output-only and read-only?). Both are required: a
// candidate validated without the policy would be a hole in §7 wearing a
// different name.
func ValidateCandidate(in Candidate, cat *Catalog, v *TemplateValidator) (Candidate, []LineVerdict, error) {
	if cat == nil || v == nil {
		return Candidate{}, nil, errors.New("tac: a candidate cannot be validated without the catalog and the command validator")
	}
	out := in
	out.Dialect = strings.ToLower(strings.TrimSpace(out.Dialect))
	out.ClassID = strings.ToLower(strings.TrimSpace(out.ClassID))
	out.IssueID = strings.ToLower(strings.TrimSpace(out.IssueID))
	out.Title = cleanText(out.Title, maxCandidateText)
	out.TACFirstLook = cleanText(out.TACFirstLook, maxCandidateText)
	out.Answer = cleanText(out.Answer, maxCandidateText)

	if !slugRE.MatchString(out.Dialect) {
		return out, nil, wrapCandidate("name the CLI dialect this answer is about")
	}
	if out.Title == "" {
		return out, nil, wrapCandidate("a candidate needs a one-line title")
	}
	if out.ClassID == "" || !slugRE.MatchString(out.ClassID) {
		return out, nil, wrapCandidate("the issue class must be a kebab-case slug")
	}
	if out.ClassID == GenericClassID {
		// The merge script refuses this and says why; refusing it here means the
		// operator learns it at the moment of writing, not at ingestion.
		return out, nil, wrapCandidate(
			"`generic` is what \"nothing matched\" MEANS — it can carry no detection rule; file this under a real class or propose one")
	}
	// Proposed is DERIVED, never accepted: the taxonomy decides.
	_, known := cat.Class(out.ClassID)
	out.Proposed = !known

	if out.IssueID == "" {
		out.IssueID = deriveIssueID(out.ClassID, out.Title)
	}
	if !slugRE.MatchString(out.IssueID) {
		return out, nil, wrapCandidate("the issue id must be a kebab-case slug")
	}

	out.Symptoms = cleanList(out.Symptoms)
	out.LogSignatures = cleanList(out.LogSignatures)
	out.LikelyCauses = cleanList(out.LikelyCauses)
	out.Sources = cleanSources(out.Sources)
	for _, s := range out.Sources {
		if !strings.HasPrefix(s.URL, "https://") {
			return out, nil, wrapCandidate("a citation must be an https link (" + clip(s.URL, 60) + " is not)")
		}
	}

	// Commands: the same four checks the review and collect paths apply.
	cmds := make([]CandidateCommand, 0, len(out.Commands))
	lines := make([]string, 0, len(out.Commands))
	for _, c := range out.Commands {
		intent := strings.ToLower(strings.TrimSpace(c.Intent))
		cmd := strings.TrimSpace(oneLine(c.Command))
		if cmd == "" {
			continue
		}
		if intent != "" && !intentRE.MatchString(intent) {
			return out, nil, wrapCandidate("intent " + clip(intent, 60) + " is not an intent id")
		}
		if len(cmds) >= MaxCandidateCommands {
			break
		}
		cmds = append(cmds, CandidateCommand{Intent: intent, Command: cmd})
		lines = append(lines, cmd)
	}
	out.Commands = cmds
	res := v.Validate(out.Dialect, lines)
	if !res.OK {
		return out, res.Lines, ErrCandidateInvalid
	}
	// A session-scoped setter is admitted only WITH its teardown, which a flat
	// command list cannot express (§8.1). A candidate never carries one.
	for _, lv := range res.Lines {
		if lv.SessionScoped {
			return out, res.Lines, wrapCandidate(
				"a session-scoped setter is only ever run with its documented teardown, which a candidate cannot express")
		}
	}
	if out.Status == "" {
		out.Status = CandidateProposed
	}
	if !validCandidateStatus(out.Status) {
		return out, nil, wrapCandidate("unknown status " + clip(string(out.Status), 40))
	}
	return out, res.Lines, nil
}

func validCandidateStatus(s CandidateStatus) bool {
	for _, k := range CandidateStatuses() {
		if k == s {
			return true
		}
	}
	return false
}

func wrapCandidate(why string) error {
	return errors.New(ErrCandidateInvalid.Error() + ": " + why)
}

// deriveIssueID builds a stable kebab id from the class and the title, so an
// operator is not made to invent one. It is only used when none was given.
func deriveIssueID(class, title string) string {
	var b strings.Builder
	b.WriteString(class)
	n := 0
	prevDash := true
	for _, r := range strings.ToLower(title) {
		if n >= 40 {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			if prevDash {
				b.WriteByte('-')
				prevDash = false
			}
			b.WriteRune(r)
			n++
		default:
			prevDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// cleanText redacts, flattens to one line and clips. Everything an operator
// pastes here may have come off a device or out of a vendor mail.
func cleanText(s string, max int) string {
	return strings.TrimSpace(clip(oneLine(protocoldiag.RedactOutput(s)), max))
}

// oneLine collapses every control character and newline to a space. The
// research format is line-oriented; a newline inside a scalar would not merely
// look wrong, it would change the document's structure.
func oneLine(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || (r < 0x20) || r == 0x7f {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}

func cleanList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		v := cleanText(s, maxCandidateLine)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
		if len(out) >= MaxCandidateItems {
			break
		}
	}
	return out
}

func cleanSources(in []CandidateSource) []CandidateSource {
	out := make([]CandidateSource, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		u := strings.TrimSpace(oneLine(s.URL))
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, CandidateSource{
			Title:     cleanText(s.Title, maxCandidateLine),
			URL:       clip(u, maxCandidateLine),
			Retrieved: cleanText(s.Retrieved, 32),
		})
		if len(out) >= MaxCandidateSources {
			break
		}
	}
	return out
}

// SortCandidates orders a listing deterministically.
func SortCandidates(c []Candidate) {
	sort.SliceStable(c, func(i, j int) bool {
		if c[i].Dialect != c[j].Dialect {
			return c[i].Dialect < c[j].Dialect
		}
		if c[i].ClassID != c[j].ClassID {
			return c[i].ClassID < c[j].ClassID
		}
		return c[i].ID < c[j].ID
	})
}

// ── export ──────────────────────────────────────────────────────────────────

// ExportResearch renders candidates for ONE dialect as the research document
// `scripts/tac-merge-research.py` consumes.
//
// It writes only the fields that script's `only_fields` admits, in the shape it
// parses (a line-oriented YAML subset: block maps, block sequences, and
// single-quoted scalars with `”` escaping). Anything the script would refuse is
// refused HERE — the export is a proposal a human hands over, and one that
// bounces at the door teaches nothing.
//
// The output is deterministic for the same input, which is what lets a test
// hold the exact bytes and a reviewer diff two exports.
func ExportResearch(dialect string, cands []Candidate, generated time.Time) (string, error) {
	d := strings.ToLower(strings.TrimSpace(dialect))
	if !slugRE.MatchString(d) {
		return "", errors.New("tac: export needs a dialect slug")
	}
	mine := make([]Candidate, 0, len(cands))
	for _, c := range cands {
		if strings.EqualFold(c.Dialect, d) && c.Status != CandidateRejected {
			mine = append(mine, c)
		}
	}
	if len(mine) == 0 {
		return "", errors.New("tac: no signature candidates for " + d)
	}
	SortCandidates(mine)

	var b strings.Builder
	b.WriteString("# TAC signature candidates — exported from Correlix, NOT yet knowledge.\n")
	b.WriteString("# Review every line, then merge with scripts/tac-merge-research.py.\n")
	b.WriteString("# Every command below is output-only and read-only: it passed the same\n")
	b.WriteString("# policy the collector applies at the wire (design §7).\n")
	b.WriteString("# generated: " + generated.UTC().Format(time.RFC3339) + "\n")
	b.WriteString("vendor: " + q(d) + "\n")
	b.WriteString("dialect: " + q(d) + "\n")
	b.WriteString("schema_version: '1'\n")

	// The file-level bibliography: every candidate's citations, deduped.
	fileSources := []CandidateSource{}
	seen := map[string]bool{}
	for _, c := range mine {
		for _, s := range c.Sources {
			if !seen[s.URL] {
				seen[s.URL] = true
				fileSources = append(fileSources, s)
			}
		}
	}
	if len(fileSources) > 0 {
		b.WriteString("sources:\n")
		for _, s := range fileSources {
			b.WriteString("  - url: " + q(s.URL) + "\n")
			if s.Title != "" {
				b.WriteString("    title: " + q(s.Title) + "\n")
			}
			if s.Retrieved != "" {
				b.WriteString("    retrieved: " + q(s.Retrieved) + "\n")
			}
		}
	}

	b.WriteString("issues:\n")
	ids := map[string]int{}
	for _, c := range mine {
		id := c.IssueID
		// Two candidates may legitimately propose the same id; the merge script
		// treats a duplicate as one issue merged twice, which silently loses the
		// second. Suffixing keeps both, visibly.
		ids[id]++
		if n := ids[id]; n > 1 {
			id = id + "-" + itoaTAC(n)
		}
		b.WriteString("  - id: " + q(id) + "\n")
		b.WriteString("    class: " + q(c.ClassID) + "\n")
		if c.Proposed {
			b.WriteString("    proposed_class: 'true'\n")
		}
		b.WriteString("    title: " + q(c.Title) + "\n")
		writeList(&b, "symptoms", c.Symptoms)
		writeList(&b, "log_signatures", c.LogSignatures)
		writeList(&b, "likely_causes", c.LikelyCauses)
		if len(c.Commands) > 0 {
			b.WriteString("    commands:\n")
			for _, cmd := range c.Commands {
				b.WriteString("      - cmd: " + q(cmd.Command) + "\n")
				if cmd.Intent != "" {
					b.WriteString("        intent: " + q(cmd.Intent) + "\n")
				}
			}
		}
		if c.TACFirstLook != "" {
			b.WriteString("    tac_first_look: " + q(c.TACFirstLook) + "\n")
		}
		if len(c.Sources) > 0 {
			b.WriteString("    sources:\n")
			for _, s := range c.Sources {
				b.WriteString("      - url: " + q(s.URL) + "\n")
				if s.Title != "" {
					b.WriteString("        title: " + q(s.Title) + "\n")
				}
			}
		}
		if note := candidateNote(c); note != "" {
			b.WriteString("    notes: " + q(note) + "\n")
		}
	}
	return b.String(), nil
}

// candidateNote is the provenance a reviewer needs: where the proposal came
// from, and what the vendor actually said.
func candidateNote(c Candidate) string {
	parts := []string{}
	if c.Answer != "" {
		parts = append(parts, "TAC answer: "+c.Answer)
	}
	if c.FromIncident != "" {
		parts = append(parts, "proposed from incident "+c.FromIncident)
	}
	parts = append(parts, "candidate only — not verified by Correlix on this platform")
	return clip(strings.Join(parts, " · "), maxCandidateText)
}

func writeList(b *strings.Builder, key string, items []string) {
	if len(items) == 0 {
		return
	}
	b.WriteString("    " + key + ":\n")
	for _, it := range items {
		b.WriteString("      - " + q(it) + "\n")
	}
}

// q renders a single-quoted YAML scalar. Single quotes are doubled, which is
// the ONLY escape the subset parser applies inside them, and the value is
// already newline-free (oneLine ran at validation). Quoting unconditionally
// means no value can ever be read as a flow collection, a comment or a key.
func q(s string) string {
	return "'" + strings.ReplaceAll(oneLine(s), "'", "''") + "'"
}
