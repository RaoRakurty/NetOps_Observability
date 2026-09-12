// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package entitlement_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// no_price_test.go — a price is a commercial term, never a runtime one.
//
// Owner decision, 2026-09-05 (tracker 260, launch pricing approved as
// hypotheses):
//
//	"Pricing stays SEPARATE from runtime entitlement semantics: NO dollar
//	 figures anywhere in the entitlement engine or licence files. Licence files
//	 carry features, ceilings, customer, expiry, support only."
//
// The reason the separation has to be GUARDED rather than merely intended:
// the approved figures are market-entry hypotheses that get reviewed once real
// conversion data exists. A price baked into a signed licence file, or into the
// code that reads one, would outlive the hypothesis — every already-issued
// licence would carry a stale number, and re-pricing would mean re-issuing
// files that are otherwise still correct. Keeping money out of the entitlement
// path means a price change is an order-form change and nothing else.
//
// So this test reads the source on disk and fails on any currency or price
// literal in the three trees that decide, carry or verify an entitlement.
// It scans EVERY file in them, not just .go, so a licence schema, a testdata
// document or a fixture added later is covered the day it lands.
//
// The customer-facing figures live in docs-portal/docs/reference/pricing.md.

// priceScanDirs are the trees a price must never reach, each annotated with
// what it carries. Paths are relative to src/backend.
var priceScanDirs = map[string]string{
	"internal/entitlement": "the entitlement engine: the feature and ceiling decisions",
	"internal/licence":     "the licence document, its verification, state, overage and signer",
	"cmd/correlix-licence": "the offline licence and usage-report verifier",
}

// pricePatterns is the precise half of the guard: shapes that are money, not
// shapes that merely discuss commerce. The word "priced" in a comment about
// which act consumes an entitlement, and the word "billing" in a comment about
// what a soft overage means, are both legitimate and must keep passing — the
// invariant is about figures, not about vocabulary. "Order form" is absent for
// the same reason: internal/entitlement and internal/licence both use the
// phrase to explain that a device is never refused during an incident because
// of a number on one, which is the invariant being stated rather than broken.
var pricePatterns = []struct {
	re  *regexp.Regexp
	why string
}{
	{regexp.MustCompile(`[$\x{20AC}\x{A3}\x{A5}]\s?\d`), "a currency amount"},
	{regexp.MustCompile(`(?i)\b(usd|eur|gbp)\b`), "a currency code"},
	{regexp.MustCompile(`\b(ARR|MRR)\b`), "a recurring-revenue commitment"},
	{regexp.MustCompile(`(?i)\bper\s+(monitored\s+)?(device|node|seat|tenant)\s+per\s+(month|year)\b`), "a per-unit rate"},
	{regexp.MustCompile(`(?i)\b(list price|price per|unit price|msrp|starter pack|volume discount|annual contract value)\b`), "pricing vocabulary"},
}

// dollarSign is checked on its own, because a figure can be written in a form
// no pattern above anticipates. Nothing in these three trees has ever needed
// the character.
const dollarSign = '$'

// dollarAllowlist names the files permitted to contain a bare currency sign and
// the reason each one needs it. The only case anticipated is a shell or
// template format string, where the character is syntax rather than money.
//
// It is EMPTY, and an entry is a reviewed decision rather than a way past a
// failing test: an entry exempts the file from the bare-sign check only, never
// from pricePatterns above. Keys are paths relative to src/backend.
var dollarAllowlist = map[string]string{}

// selfExempt is this file. A guard has to name the literals it forbids in its
// own patterns and messages, so scanning itself would report the guard as the
// violation. The exemption is exactly one file, its presence is asserted below
// so a rename cannot silently widen it, and TestPriceDetectorIsNotVacuous
// proves the detector still fires on the shapes this file contains.
const selfExempt = "internal/entitlement/no_price_test.go"

// scanForPrice returns the reasons a file's contents fail the guard.
func scanForPrice(rel, content string) []string {
	var problems []string
	for _, p := range pricePatterns {
		if m := p.re.FindString(content); m != "" {
			problems = append(problems, p.why+": "+strings.TrimSpace(m))
		}
	}
	if _, allowed := dollarAllowlist[rel]; !allowed && strings.ContainsRune(content, dollarSign) {
		problems = append(problems, "a bare currency sign")
	}
	return problems
}

func TestNoPriceLiteralsInLicenceCode(t *testing.T) {
	root := backendRoot(t)

	if _, err := os.Stat(filepath.Join(root, selfExempt)); err != nil {
		t.Fatalf("the self-exemption %s does not resolve to a file: %v — "+
			"if this guard was renamed, update selfExempt; do not widen it", selfExempt, err)
	}

	total := 0
	for dir, carries := range priceScanDirs {
		dir, carries := dir, carries
		t.Run(dir, func(t *testing.T) {
			abs := filepath.Join(root, dir)
			info, err := os.Stat(abs)
			if err != nil || !info.IsDir() {
				t.Fatalf("%s (%s) is not a directory: %v — if the package moved, update priceScanDirs; do not delete the entry", dir, carries, err)
			}

			scanned := 0
			err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				rel, relErr := filepath.Rel(root, path)
				if relErr != nil {
					return relErr
				}
				rel = filepath.ToSlash(rel)
				if rel == selfExempt {
					return nil
				}
				b, readErr := os.ReadFile(path)
				if readErr != nil {
					return readErr
				}
				// A compiled artefact is not source. The documented build line
				// (`go build -o correlix-licence ./src/backend/cmd/correlix-licence`)
				// invites a binary into one of these directories, and a binary
				// contains every byte value including the currency sign. Skip
				// it rather than report a false violation, and do not count it
				// towards the scanned total.
				if bytes.IndexByte(b, 0) >= 0 {
					return nil
				}
				scanned++
				for _, problem := range scanForPrice(rel, string(b)) {
					t.Errorf("%s contains %s.\n\n"+
						"%s carries %s. A licence file and the code that reads one carry features, ceilings,\n"+
						"customer, expiry and support — never price (owner decision, 2026-09-05). Launch prices are\n"+
						"reviewable hypotheses; a figure embedded here would outlive the hypothesis and every issued\n"+
						"licence would carry a stale number. Put the figure in the order form and in\n"+
						"docs-portal/docs/reference/pricing.md instead.", rel, problem, dir, carries)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("walk %s: %v", dir, err)
			}
			if scanned == 0 {
				t.Fatalf("scanned 0 files under %s — the guard proved nothing", dir)
			}
			total += scanned
			t.Logf("scanned %d files under %s", scanned, dir)
		})
	}

	if total < 10 {
		t.Fatalf("scanned only %d files across %d trees — too few for the guard to be meaningful", total, len(priceScanDirs))
	}
}

// TestPriceDetectorIsNotVacuous proves the detector fires on money and stays
// quiet on the commercial vocabulary the packages legitimately use. Without it,
// a broken regex would turn the guard above into a test that passes by finding
// nothing because it can find nothing.
func TestPriceDetectorIsNotVacuous(t *testing.T) {
	// Deliberately synthetic figures. No real Correlix price appears in Go
	// source, not even inside a fixture: the guard would be a poor advertisement
	// for its own rule if it carried the numbers it exists to keep out.
	catch := []string{
		"const packPrice = 777 // USD per month",
		"// the tier is priced at 11 to 13 per box.\nvar floor = \"99k ARR\"",
		"// the rate is 42 per monitored device per month",
		"// the figure is 777 GBP",
		"cost := \"\u20AC777\"",
	}
	for _, sample := range catch {
		if got := scanForPrice("sample.go", sample); len(got) == 0 {
			t.Errorf("detector missed a price literal in %q", sample)
		}
	}

	// These are the real comments in internal/entitlement and internal/licence.
	// The guard forbids figures, not the words that explain what an entitlement
	// is for. A change that makes either of these fail has widened the rule
	// past the owner's decision.
	pass := []string{
		"// consumes no allowance; collecting from one is the priced act.",
		"// monitored devices on a paid tier). A SOFT overage is a billing fact.",
		"// tier=team, customer=\"Acme Networks\", ceilings=250 devices",
	}
	for _, sample := range pass {
		if got := scanForPrice("sample.go", sample); len(got) != 0 {
			t.Errorf("detector fired on legitimate prose %q: %v", sample, got)
		}
	}
}
