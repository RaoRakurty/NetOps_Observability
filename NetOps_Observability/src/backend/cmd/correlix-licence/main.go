// Command correlix-licence issues and inspects Correlix licence files.
//
//	correlix-licence keygen  --dir <dir> [--name <base>]
//	correlix-licence sign    --key <priv> --customer <name> --tier <t> [--expires <date>] \
//	                         [--trial] [--ceilings k=v,…] [--features a,b] [--grace-days N] [--out <file>]
//	correlix-licence verify  [--pubkey <base64>] [--at <time>] <file>
//	correlix-licence show    <file>
//	correlix-licence usage-verify [--pubkey <base64>] <file>
//
// CLAUDE.md §2: an entrypoint holds NO business logic. Everything below is
// argument parsing and printing; key generation, signing and verification live
// in internal/licence and internal/licence/signer, which is also what the api
// and the tests use — so there is exactly one implementation of "is this
// licence valid", and the customer-facing `verify` exercises the same code the
// product does.
//
// Never prints private key material. `keygen` prints the PUBLIC key and the
// path of the private one; reading the private key is a deliberate act with
// `cat`, not a side effect of running a tool.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/entitlement"
	"netops/backend/internal/licence"
	"netops/backend/internal/licence/signer"
	"netops/backend/internal/metering"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "correlix-licence: "+err.Error())
		os.Exit(1)
	}
}

const usage = `correlix-licence — issue and inspect Correlix licence files

  keygen --dir <dir> [--name <base>]
      Generate an ed25519 signing keypair. The private key is written 0600 and
      is never printed; the public key is printed for embedding in keys.go and
      publishing in docs/runbooks/licensing.md.

  sign --key <priv> --customer <name> --tier community|team|enterprise
       [--expires <RFC3339 or YYYY-MM-DD>] [--trial] [--issued <t>]
       [--licence-id <id>] [--ceilings devices=250,watched_prefixes=100,…]
       [--features a,b,…] [--grace-days N] [--support-level <s>]
       [--support-contact <s>] [--out <file>]
      Issue a licence. Ceilings not named default to the tier's reference
      values; -1 means unlimited.

      GRACE (owner policy, 2026-09-05): --grace-days defaults to 30 for a paid
      tier (team, enterprise), 7 with --trial, and 0 for community. An explicit
      --grace-days always wins. The default is applied HERE, by the issuer, and
      lands in the file as a number — the format itself still has no default, so
      a licence issued before this policy existed is never reinterpreted by it.

      --trial issues a 30-day evaluation licence: expiry defaults to 30 days
      from issue, the document is marked trial, and grace defaults to 7 days.
      Trials are Team/Enterprise (there is nothing to evaluate at community).
      --expires still wins if you give one.

  verify [--pubkey <base64>] [--at <RFC3339>] <file>
      Verify a licence against the embedded public keys (or one supplied with
      --pubkey) and print the evaluated state. Exit 1 if it does not verify.
      Flags come BEFORE the file: flag parsing stops at the first non-flag
      argument, so "verify <file> --pubkey <key>" is refused.

  show <file>
      Print a licence's contents WITHOUT verifying it. For inspecting a file
      that will not verify — which is usually why you are looking at it.

  usage-verify [--pubkey <base64>] <file>
      Verify a downloaded USAGE REPORT offline and re-derive its totals from
      its own daily rows. Two checks, both independent of us:
        * the ed25519 signature over the report's canonical bytes, against the
          public key embedded in the document (or the one given with --pubkey,
          which is how you confirm WHICH installation produced it);
        * the period totals, recomputed from the daily rows in the file — so
          the summary a customer quotes is arithmetic anyone can repeat, not a
          number to be taken on trust.
      Exit 1 if either check fails. A usage report is signed by the
      INSTALLATION's own key, generated on that host; it is not, and must never
      be, the key Correlix signs licences with.
`

func run(args []string, out *os.File) error {
	if len(args) == 0 {
		fmt.Fprint(out, usage)
		return errors.New("no command given")
	}
	switch args[0] {
	case "keygen":
		return cmdKeygen(args[1:], out)
	case "sign":
		return cmdSign(args[1:], out)
	case "verify":
		return cmdVerify(args[1:], out)
	case "show":
		return cmdShow(args[1:], out)
	case "usage-verify":
		return cmdUsageVerify(args[1:], out)
	case "-h", "--help", "help":
		fmt.Fprint(out, usage)
		return nil
	}
	fmt.Fprint(out, usage)
	return fmt.Errorf("unknown command %q", args[0])
}

// ── keygen ───────────────────────────────────────────────────────────────────

func cmdKeygen(args []string, out *os.File) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	dir := fs.String("dir", "", "directory to write the keypair into (required)")
	name := fs.String("name", "signing-key", "base filename for the keypair")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*dir) == "" {
		return errors.New("keygen: --dir is required")
	}
	kp, err := signer.GenerateKey()
	if err != nil {
		return err
	}
	priv := filepath.Join(*dir, *name+".ed25519")
	if err := signer.WritePrivateKey(priv, kp); err != nil {
		return err
	}
	pub := filepath.Join(*dir, *name+".pub")
	// #nosec G306 -- a PUBLIC key is public by construction: it is embedded in
	// the shipped binary and published in the runbook so customers can verify
	// offline. 0600 here would only make it harder to copy where it must go.
	if err := os.WriteFile(pub, []byte(kp.PublicBase64()+"\n"), 0o644); err != nil {
		return err
	}
	// The private key's CONTENT is never printed — only where it went, so the
	// operator can move it to its custody location.
	fmt.Fprintf(out, "key id:      %s\n", kp.ID)
	fmt.Fprintf(out, "public key:  %s\n", kp.PublicBase64())
	fmt.Fprintf(out, "private key: %s (mode 0600 — move it to offline custody; never commit it)\n", priv)
	fmt.Fprintf(out, "public file: %s\n\n", pub)
	fmt.Fprintf(out, "To trust this key, add to src/backend/internal/licence/keys.go:\n")
	fmt.Fprintf(out, "\t{base64: %q, role: licence.RoleCurrent, note: \"...ceremony...\"},\n", kp.PublicBase64())
	return nil
}

// ── sign ─────────────────────────────────────────────────────────────────────

func cmdSign(args []string, out *os.File) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := fs.String("key", "", "path to the ed25519 private key (required, mode 0600)")
	customer := fs.String("customer", "", "customer name (required)")
	tier := fs.String("tier", "", "community|team|enterprise (required)")
	expires := fs.String("expires", "", "expiry, RFC3339 or YYYY-MM-DD (required)")
	issued := fs.String("issued", "", "issue time, RFC3339 or YYYY-MM-DD (default: now)")
	id := fs.String("licence-id", "", "licence id (default: derived from customer + issue date)")
	ceilings := fs.String("ceilings", "", "comma-separated name=value overrides; -1 = unlimited")
	features := fs.String("features", "", "comma-separated feature names")
	grace := fs.Int("grace-days", licence.GraceDaysUnset, "grace days after expiry; unset = 30 for a paid tier, 7 with --trial, 0 for community")
	trial := fs.Bool("trial", false, "issue a 30-day evaluation licence (marks the document as a trial; grace defaults to 7 days)")
	supportLevel := fs.String("support-level", "", "support entitlement level (informational)")
	supportContact := fs.String("support-contact", "", "support contact (informational)")
	outPath := fs.String("out", "", "write the licence here instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case strings.TrimSpace(*keyPath) == "":
		return errors.New("sign: --key is required")
	case strings.TrimSpace(*customer) == "":
		return errors.New("sign: --customer is required")
	case strings.TrimSpace(*tier) == "":
		return errors.New("sign: --tier is required")
	case strings.TrimSpace(*expires) == "" && !*trial:
		return errors.New("sign: --expires is required (or --trial, which sets a 30-day expiry)")
	}
	if *grace < licence.GraceDaysUnset {
		return errors.New("sign: --grace-days cannot be negative")
	}

	t := entitlement.Tier(strings.ToLower(strings.TrimSpace(*tier)))
	if !entitlement.ValidTier(t) {
		return fmt.Errorf("sign: unknown tier %q (want one of %s)", *tier, tierList())
	}
	issuedAt := time.Now().UTC()
	if strings.TrimSpace(*issued) != "" {
		v, err := parseTime(*issued)
		if err != nil {
			return fmt.Errorf("sign: --issued: %w", err)
		}
		issuedAt = v
	}
	// A trial's expiry is derived from its ISSUE time, not from "now": with
	// --issued given, the file's own two dates stay consistent with each other.
	expiresAt := issuedAt.AddDate(0, 0, licence.TrialDays)
	if strings.TrimSpace(*expires) != "" {
		v, err := parseTime(*expires)
		if err != nil {
			return fmt.Errorf("sign: --expires: %w", err)
		}
		expiresAt = v
	}
	if *trial && t == entitlement.TierCommunity {
		// Community is free and has no expiry; a "community trial" is a
		// document that would expire into the tier it already is. Refusing is
		// the honest answer — an issuer who typed this meant team or enterprise.
		return errors.New("sign: --trial is for team or enterprise; community needs no evaluation licence")
	}

	// Ceilings start at the tier's reference values so an issuer states only
	// what differs; -1 means unlimited.
	base, ok := entitlement.TierCeilings(t)
	if !ok {
		return fmt.Errorf("sign: no reference ceilings for tier %q", t)
	}
	if err := applyCeilings(&base, *ceilings); err != nil {
		return fmt.Errorf("sign: --ceilings: %w", err)
	}

	feats, err := parseFeatures(*features)
	if err != nil {
		return fmt.Errorf("sign: --features: %w", err)
	}

	licenceID := strings.TrimSpace(*id)
	if licenceID == "" {
		licenceID = defaultLicenceID(*customer, issuedAt)
	}

	doc := licence.Document{
		LicenceID: licenceID,
		Customer:  strings.TrimSpace(*customer),
		Tier:      t,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		Ceilings:  base,
		Features:  feats,
		Support:   licence.Support{Level: strings.TrimSpace(*supportLevel), Contact: strings.TrimSpace(*supportContact)},
		GraceDays: licence.DefaultGraceDays(t, *trial, *grace),
		Trial:     *trial,
	}

	priv, err := signer.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	signed, err := signer.Sign(doc, priv)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if strings.TrimSpace(*outPath) != "" {
		// #nosec G306 -- a licence is not a secret. Its integrity is protected by
		// the ed25519 signature, not by the file mode, and it is a document the
		// issuer emails to a customer who then copies it onto their platform.
		if err := os.WriteFile(*outPath, body, 0o644); err != nil {
			return err
		}
		kind := "licence"
		if signed.Trial {
			kind = "evaluation licence"
		}
		fmt.Fprintf(out, "wrote %s %s (licence_id=%s, tier=%s, expires=%s, grace=%d days, key=%s)\n",
			*outPath, kind, signed.LicenceID, signed.Tier,
			signed.ExpiresAt.UTC().Format(time.RFC3339), signed.GraceDays, signed.KeyID)
		return nil
	}
	_, err = out.Write(body)
	return err
}

// applyCeilings parses "name=value,…" onto c, refusing any name outside the
// closed vocabulary — a typo must not silently leave the default in place.
func applyCeilings(c *entitlement.Ceilings, spec string) error {
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, found := strings.Cut(part, "=")
		if !found {
			return fmt.Errorf("%q is not name=value", part)
		}
		name = strings.TrimSpace(name)
		n, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if !entitlement.ValidCeiling(name) {
			return fmt.Errorf("unknown ceiling %q (want one of %s)", name, strings.Join(entitlement.CeilingNames(), ", "))
		}
		switch name {
		case entitlement.CeilingDevices:
			c.Devices = n
		case entitlement.CeilingTenants:
			c.Tenants = n
		case entitlement.CeilingOrgs:
			c.Orgs = n
		case entitlement.CeilingRetentionDays:
			c.RetentionDays = n
		case entitlement.CeilingWatchedPrefixes:
			c.WatchedPrefixes = n
		case entitlement.CeilingSkills:
			c.Skills = n
		case entitlement.CeilingProviderTokensPerDay:
			c.ProviderTokensPerDay = n
		}
	}
	return nil
}

func parseFeatures(spec string) ([]entitlement.Feature, error) {
	var out []entitlement.Feature
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		f := entitlement.Feature(part)
		if !entitlement.ValidFeature(f) {
			return nil, fmt.Errorf("unknown feature %q (want one of %s)", part, featureList())
		}
		out = append(out, f)
	}
	return out, nil
}

func defaultLicenceID(customer string, at time.Time) string {
	slug := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		}
		return '-'
	}, customer)
	for strings.Contains(slug, "--") {
		slug = strings.ReplaceAll(slug, "--", "-")
	}
	return strings.Trim(slug, "-") + "-" + at.UTC().Format("20060102")
}

// ── verify ───────────────────────────────────────────────────────────────────

func cmdVerify(args []string, out *os.File) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubkey := fs.String("pubkey", "", "verify against this base64 public key instead of the embedded ones")
	at := fs.String("at", "", "evaluate expiry as at this RFC3339 time (default: now)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("verify: exactly one licence file is required")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if strings.TrimSpace(*at) != "" {
		v, err := parseTime(*at)
		if err != nil {
			return fmt.Errorf("verify: --at: %w", err)
		}
		now = v
	}

	v := licence.DefaultVerifier()
	if strings.TrimSpace(*pubkey) != "" {
		pub, err := licence.ParsePublicKey(*pubkey)
		if err != nil {
			return err
		}
		v = licence.NewVerifier(licence.NewPublicKey(pub, licence.RoleCurrent, "supplied with --pubkey"))
	}
	st, err := v.Verify(raw, now)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "VERIFIED  %s\n", fs.Arg(0))
	fmt.Fprintf(out, "  %s\n", st.Summary())
	printState(out, st)
	return nil
}

// ── usage-verify ─────────────────────────────────────────────────────────────

// cmdUsageVerify checks a downloaded usage report: the signature, and the
// arithmetic.
//
// Both halves matter and they answer different questions. The signature says
// the file is exactly what the installation produced. Re-deriving the totals
// from the daily rows says the summary follows from the detail — which is the
// half a true-up conversation actually turns on, and the reason the report
// carries the daily rows at all.
func cmdUsageVerify(args []string, out *os.File) error {
	fs := flag.NewFlagSet("usage-verify", flag.ContinueOnError)
	pubkey := fs.String("pubkey", "", "verify against this base64 public key instead of the one embedded in the report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage-verify: exactly one usage-report file is required")
	}
	raw, err := os.ReadFile(fs.Arg(0)) // #nosec G304 -- the file the operator named IS the argument of this command
	if err != nil {
		return err
	}
	var pub ed25519.PublicKey
	if strings.TrimSpace(*pubkey) != "" {
		parsed, perr := licence.ParsePublicKey(*pubkey)
		if perr != nil {
			return perr
		}
		pub = parsed
	}
	rep, err := metering.VerifyReport(raw, pub)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "VERIFIED  %s\n", fs.Arg(0))
	scope := rep.Scope
	if rep.Tenant != "" {
		scope += " " + rep.Tenant
	}
	fmt.Fprintf(out, "  period:     %s .. %s (%d daily row(s))\n", rep.From, rep.To, len(rep.Days))
	fmt.Fprintf(out, "  scope:      %s\n", scope)
	fmt.Fprintf(out, "  tier:       %s (device ceiling %s)\n", orNone(rep.Licence.Tier), ceilingText(rep.Licence.Devices))
	if rep.Licence.Customer != "" {
		fmt.Fprintf(out, "  customer:   %s\n", rep.Licence.Customer)
	}
	if *pubkey != "" {
		fmt.Fprintf(out, "  signed by:  %s (matches the key supplied with --pubkey)\n", rep.Key.ID)
	} else {
		fmt.Fprintf(out, "  signed by:  %s (the key embedded in the report — supply --pubkey to confirm WHICH installation)\n", rep.Key.ID)
	}
	fmt.Fprintf(out, "  generated:  %s\n\n", rep.GeneratedAt.UTC().Format(time.RFC3339))

	derived, disagree := metering.RecomputeTotals(rep)
	fmt.Fprintf(out, "Totals, RE-DERIVED from the daily rows in this file:\n")
	for _, mv := range derived {
		if mv.Value == nil {
			fmt.Fprintf(out, "  %-38s not measured — %s\n", mv.Meter, mv.Reason)
			continue
		}
		fmt.Fprintf(out, "  %-38s %v %s\n", mv.Meter, *mv.Value, mv.Unit)
	}
	if len(disagree) > 0 {
		fmt.Fprintf(out, "\nThe totals stated in the file do NOT follow from its own daily rows:\n")
		for _, d := range disagree {
			fmt.Fprintf(out, "  %s\n", d)
		}
		return errors.New("usage-verify: the report's totals disagree with its daily rows")
	}
	fmt.Fprintf(out, "\nThe totals stated in the file match the ones re-derived above.\n")
	for _, n := range rep.Notes {
		fmt.Fprintf(out, "  · %s\n", n)
	}
	return nil
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(none stated)"
	}
	return s
}

func ceilingText(n int) string {
	if n == entitlement.Unlimited {
		return "unlimited"
	}
	return strconv.Itoa(n)
}

// ── show ─────────────────────────────────────────────────────────────────────

func cmdShow(args []string, out *os.File) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("show: exactly one licence file is required")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	doc, err := licence.Parse(raw)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "NOT VERIFIED (use `verify` to authenticate this file)\n\n")
	fmt.Fprintf(out, "  licence_id:  %s\n", doc.LicenceID)
	fmt.Fprintf(out, "  customer:    %s\n", doc.Customer)
	fmt.Fprintf(out, "  tier:        %s\n", doc.Tier)
	fmt.Fprintf(out, "  issued_at:   %s\n", doc.IssuedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(out, "  expires_at:  %s\n", doc.ExpiresAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(out, "  grace_days:  %d\n", doc.GraceDays)
	fmt.Fprintf(out, "  trial:       %t\n", doc.Trial)
	fmt.Fprintf(out, "  key_id:      %s\n", doc.KeyID)
	printCeilings(out, doc.Ceilings)
	printFeatures(out, doc.Features)
	if err := doc.Validate(); err != nil {
		fmt.Fprintf(out, "\n  SHAPE PROBLEM: %v\n", err)
	}
	return nil
}

// ── shared printing ──────────────────────────────────────────────────────────

func printState(out *os.File, st licence.State) {
	fmt.Fprintf(out, "  state:     %s\n", st.Phase)
	if st.Trial {
		fmt.Fprintf(out, "  trial:     yes — evaluation licence\n")
	}
	if !st.GraceEndsAt.IsZero() {
		fmt.Fprintf(out, "  grace:     %d day(s), until %s\n", st.GraceDays, st.GraceEndsAt.UTC().Format(time.RFC3339))
	}
	printCeilings(out, st.Ceilings)
	printFeatures(out, st.Features)
	if st.InGrace {
		fmt.Fprintf(out, "  IN GRACE:  %s\n", st.Reason)
	}
	if st.Degraded {
		fmt.Fprintf(out, "  PAST GRACE: %s\n", st.Reason)
		// The features the lapsed licence granted are the ones whose EXISTING
		// data stays readable. Printing them is how an operator sees that the
		// data is still there, which is the first thing they ask.
		if len(st.LapsedFeatures) > 0 {
			fmt.Fprintf(out, "  still readable (existing data only):\n")
			printFeatures(out, st.LapsedFeatures)
		}
	}
}

func printCeilings(out *os.File, c entitlement.Ceilings) {
	fmt.Fprintf(out, "  ceilings:\n")
	for _, n := range entitlement.CeilingNames() {
		v, _ := c.Get(n)
		val := strconv.Itoa(v)
		if v == entitlement.Unlimited {
			val = "unlimited"
		}
		note := "  (carried, not enforced)"
		if entitlement.Enforced(n) {
			note = ""
		}
		fmt.Fprintf(out, "    %-24s %s%s\n", n, val, note)
	}
}

func printFeatures(out *os.File, fs []entitlement.Feature) {
	if len(fs) == 0 {
		fmt.Fprintf(out, "  features:  none\n")
		return
	}
	fmt.Fprintf(out, "  features:\n")
	for _, f := range fs {
		fmt.Fprintf(out, "    %-24s %s\n", string(f), entitlement.FeatureLabel(f))
	}
}

func tierList() string {
	ts := entitlement.Tiers()
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, string(t))
	}
	return strings.Join(out, ", ")
}

func featureList() string {
	fs := entitlement.Features()
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, string(f))
	}
	return strings.Join(out, ", ")
}

// parseTime accepts RFC3339 or a bare date, which is what an issuer actually
// types. A bare date means midnight UTC.
func parseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("%q is neither RFC3339 nor YYYY-MM-DD", s)
}
