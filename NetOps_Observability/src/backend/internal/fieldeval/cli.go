// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package fieldeval

// cli.go — the body of cmd/iriseval: the platform owner's host-side tools for
// the per-install field-eval store. Neither command prints question text.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"netops/backend/internal/iristriage"
)

const usage = `iriseval — the per-install store of customer-derived Iris eval cases

  field-import --tenant <id> --candidates export.json [--root data/iris-eval]
  field-list [--root data/iris-eval]

field-import files a REVIEWED candidates export (GET /api/ai/triage/candidates)
under the store (default data/iris-eval, which git ignores). Every case is held
out; write expected_route on a case to make it scorable. field-list prints
counts per tenant, never question text. The store refuses a root inside the
repository unless the path passes through a data/ directory.

Exit status: 0 ok, 2 usage or I/O error.
`

// CLI is the command's body, so that cmd/iriseval holds no logic.
func CLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "field-import":
		err = cliImport(args[1:], stdout, stderr)
	case "field-list":
		err = cliList(args[1:], stdout, stderr)
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		fmt.Fprintf(stderr, "iriseval: %v\n%s", err, usage)
		return 2
	}
	return 0
}

func cliImport(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("field-import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "the tenant the export came from")
	candidates := fs.String("candidates", "", "a reviewed export of GET /api/ai/triage/candidates")
	root := fs.String("root", DefaultRoot, "the field-eval store (must not be inside the repository)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenant == "" || *candidates == "" {
		return errors.New("field-import needs --tenant and --candidates")
	}
	st, err := Open(*root)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*candidates) // #nosec G304 -- an operator-named file on this command line
	if err != nil {
		return err
	}
	var export iristriage.CandidateFile
	if err := json.Unmarshal(raw, &export); err != nil {
		return fmt.Errorf("--candidates: %w", err)
	}
	path, n, err := st.Import(*tenant, export, time.Now())
	if err != nil {
		return err
	}
	if n == 0 {
		fmt.Fprintln(stdout, "nothing new: every question is already in the store")
		return nil
	}
	fmt.Fprintf(stdout, "filed %d held-out case(s) for %s in %s; write expected_route on a case to make it scorable\n", n, *tenant, path)
	return nil
}

func cliList(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("field-list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", DefaultRoot, "the field-eval store")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := Open(*root)
	if err != nil {
		return err
	}
	counts, err := st.Counts()
	if err != nil {
		return err
	}
	blob, err := json.MarshalIndent(counts, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, string(blob))
	return nil
}
