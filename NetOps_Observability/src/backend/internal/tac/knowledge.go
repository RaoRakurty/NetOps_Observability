package tac

// knowledge.go — the COVERAGE VIEW behind Iris → Knowledge.
//
// It answers, per vendor dialect, the question the escalation screen raises and
// then cannot dwell on: what does Correlix actually know here? Which classes can
// it plan for, which intents are bound, which are not, how many commands are
// verified against a real capture versus taken from a vendor's documentation.
//
// It is deliberately unflattering. A dialect with no plan appears with zero
// bound intents and every class unplannable, rather than being left out of the
// list — a coverage page that only shows what works is a marketing page.

import "sort"

// IntentCoverage is one intent's status on one dialect.
type IntentCoverage struct {
	Intent   string   `json:"intent"`
	Title    string   `json:"title"`
	Area     string   `json:"area"`
	Bound    bool     `json:"bound"`
	Command  string   `json:"command,omitempty"`
	Verified Verified `json:"verified,omitempty"`
	Sources  []Source `json:"sources,omitempty"`
}

// ClassCoverage is one class's status on one dialect.
type ClassCoverage struct {
	ClassID  string `json:"class_id"`
	Title    string `json:"title"`
	Protocol string `json:"protocol"`
	// Bound / Total count the class's deep-dive intents on this dialect.
	Bound   int      `json:"bound"`
	Total   int      `json:"total"`
	Missing []string `json:"missing"`
}

// DialectCoverage is one dialect's whole picture.
type DialectCoverage struct {
	Dialect     string `json:"dialect"`
	Display     string `json:"display"`
	Profile     string `json:"profile"`
	HasPlan     bool   `json:"has_plan"`
	PlanVersion string `json:"plan_version,omitempty"`

	BaselineIntents int `json:"baseline_intents"`
	OptionalIntents int `json:"optional_intents"`
	BoundIntents    int `json:"bound_intents"`
	TotalIntents    int `json:"total_intents"`
	Verified        int `json:"verified_commands"`
	DocClaimed      int `json:"doc_claimed_commands"`

	Classes []ClassCoverage  `json:"classes"`
	Intents []IntentCoverage `json:"intents"`
}

// Knowledge is the whole coverage document.
type Knowledge struct {
	CatalogVersion string            `json:"catalog_version"`
	EngineVersion  string            `json:"engine_version"`
	Classes        []Class           `json:"classes"`
	Intents        []Intent          `json:"intents"`
	Dialects       []DialectCoverage `json:"dialects"`
	// UnplannedDialects are vendorprofile platforms Correlix recognises but has
	// authored NO plan for. Naming them is the honest half of coverage.
	UnplannedDialects []DialectCoverage `json:"unplanned_dialects"`
}

// Knowledge builds the coverage document. It is pure and cheap; the caller may
// compute it per request.
func (c *Catalog) Knowledge(knownDialects []DialectRef) Knowledge {
	k := Knowledge{
		CatalogVersion: c.Version, EngineVersion: Version,
		Classes: c.Classes(), Intents: c.Intents(),
		Dialects: []DialectCoverage{}, UnplannedDialects: []DialectCoverage{},
	}
	planned := map[string]bool{}
	for _, d := range c.planOrder {
		planned[d] = true
		k.Dialects = append(k.Dialects, c.coverage(c.plans[d]))
	}
	for _, ref := range knownDialects {
		if planned[ref.Slug] {
			continue
		}
		cov := DialectCoverage{
			Dialect: ref.Slug, Display: ref.Display, Profile: ref.Profile,
			HasPlan: false, TotalIntents: len(c.intentOrder),
			Classes: []ClassCoverage{}, Intents: []IntentCoverage{},
		}
		for _, cl := range c.Classes() {
			if cl.ID == GenericClassID {
				continue
			}
			cov.Classes = append(cov.Classes, ClassCoverage{
				ClassID: cl.ID, Title: cl.Title, Protocol: cl.Protocol,
				Bound: 0, Total: len(cl.Intents), Missing: append([]string(nil), cl.Intents...),
			})
		}
		k.UnplannedDialects = append(k.UnplannedDialects, cov)
	}
	sort.SliceStable(k.UnplannedDialects, func(i, j int) bool {
		return k.UnplannedDialects[i].Dialect < k.UnplannedDialects[j].Dialect
	})
	return k
}

// DialectRef is one platform the vendorprofile registry knows about. The caller
// supplies the list so this package does not have to decide which of the
// registry's profiles are "network devices" — that judgement belongs upstream.
type DialectRef struct {
	Slug    string
	Display string
	Profile string
}

func (c *Catalog) coverage(p *DialectPlan) DialectCoverage {
	cov := DialectCoverage{
		Dialect: p.Dialect, Display: p.Display, Profile: p.Profile,
		HasPlan: true, PlanVersion: p.Version,
		BaselineIntents: len(p.Baseline), OptionalIntents: len(p.Optional),
		TotalIntents: len(c.intentOrder),
		Classes:      []ClassCoverage{}, Intents: []IntentCoverage{},
	}
	for _, id := range c.intentOrder {
		in := c.intents[id]
		row := IntentCoverage{Intent: id, Title: in.Title, Area: in.Area}
		if b, ok := p.Bindings[id]; ok {
			row.Bound = true
			row.Command = b.Command
			row.Verified = b.Verified
			row.Sources = b.Sources
			cov.BoundIntents++
			if b.Verified == VerifiedCapture {
				cov.Verified++
			} else {
				cov.DocClaimed++
			}
		}
		cov.Intents = append(cov.Intents, row)
	}
	for _, cl := range c.Classes() {
		if cl.ID == GenericClassID {
			continue
		}
		cc := ClassCoverage{ClassID: cl.ID, Title: cl.Title, Protocol: cl.Protocol,
			Total: len(cl.Intents), Missing: []string{}}
		for _, in := range cl.Intents {
			if _, ok := p.Bindings[in]; ok {
				cc.Bound++
				continue
			}
			cc.Missing = append(cc.Missing, in)
		}
		cov.Classes = append(cov.Classes, cc)
	}
	return cov
}
