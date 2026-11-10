// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisreplay

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const usage = `irisreplay — Iris Incident Replay (offline leg)

  run --cases <dir> --report out.json [--markdown out.md] [--engine-semver V] [--catalog-version V] [--prices prices.json]
  compare a.json b.json [--json]
  fingerprint [--cases <dir>] [--engine-semver V]

Offline only: the model is scripted, the engine is not re-run, no store and no
provider is reached. Exit status: 0 ok, 1 a case failed, 2 usage or I/O error.
`

// CLI is the command's body, so that cmd/irisreplay holds no logic.
func CLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var (
		code int
		err  error
	)
	switch args[0] {
	case "run":
		code, err = cliRun(ctx, args[1:], stdout, stderr)
	case "compare":
		code, err = cliCompare(args[1:], stdout, stderr)
	case "fingerprint":
		code, err = cliFingerprint(args[1:], stdout, stderr)
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		fmt.Fprintf(stderr, "irisreplay: %v\n%s", err, usage)
		return 2
	}
	return code
}

func cliRun(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cases := fs.String("cases", "", "directory of case files")
	report := fs.String("report", "", "write the JSON report here")
	markdown := fs.String("markdown", "", "write the Markdown report here")
	engine := fs.String("engine-semver", "", "ENGINE_SEMVER the reader runs now, compared with each case's pin")
	catalog := fs.String("catalog-version", "", "catalog version the reader runs now, compared with each case's pin")
	prices := fs.String("prices", "", `JSON {"<provider>/<name>":{"input_per_mtok":N,"output_per_mtok":N}}; without it cost is censored`)
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	if *cases == "" || *report == "" {
		return 0, errors.New("run needs --cases and --report")
	}
	loaded, err := LoadCases(*cases)
	if err != nil {
		return 0, err
	}
	opt := Options{EngineSemver: *engine, CatalogVersion: *catalog}
	if *prices != "" {
		raw, err := os.ReadFile(*prices) // #nosec G304 -- an operator-named file on this command line
		if err != nil {
			return 0, err
		}
		if err := json.Unmarshal(raw, &opt.Prices); err != nil {
			return 0, fmt.Errorf("--prices: %w", err)
		}
	}
	rep, err := Run(ctx, loaded, opt)
	if err != nil {
		return 0, err
	}
	blob, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := writePrivate(*report, blob); err != nil {
		return 0, err
	}
	if *markdown != "" {
		if err := writePrivate(*markdown, []byte(Markdown(rep))); err != nil {
			return 0, err
		}
	}
	a := rep.Aggregate
	fmt.Fprintf(stdout, "%d cases: %d pass, %d xfail, %d fail, %d xpass; fingerprint %s\n", a.Cases,
		a.Results[ResultPass], a.Results[ResultXFail], a.Results[ResultFail], a.Results[ResultXPass], rep.Fingerprint.SHA256)
	if a.Results[ResultFail]+a.Results[ResultXPass] > 0 {
		return 1, nil
	}
	return 0, nil
}

func cliCompare(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print the delta as JSON")
	// The two report paths come first in the documented form; flags may follow.
	var paths []string
	for len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		paths = append(paths, args[0])
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	paths = append(paths, fs.Args()...)
	if len(paths) != 2 {
		return 0, errors.New("compare needs two report files")
	}
	var reps [2]Report
	for i, p := range paths {
		raw, err := os.ReadFile(p) // #nosec G304 -- an operator-named file on this command line
		if err != nil {
			return 0, err
		}
		reps[i], err = ReadReport(raw)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", p, err)
		}
	}
	d, err := Compare(reps[0], reps[1])
	if err != nil {
		return 0, err
	}
	if *asJSON {
		blob, err := json.MarshalIndent(d, "", "  ")
		if err != nil {
			return 0, err
		}
		fmt.Fprintln(stdout, string(blob))
		return 0, nil
	}
	fmt.Fprint(stdout, DeltaMarkdown(d))
	return 0, nil
}

func cliFingerprint(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cases := fs.String("cases", "", "directory of case files (adds their pins and models)")
	engine := fs.String("engine-semver", "", "ENGINE_SEMVER the reader runs now")
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	var loaded []Case
	if *cases != "" {
		var err error
		if loaded, err = LoadCases(*cases); err != nil {
			return 0, err
		}
	}
	in, err := CurrentInputs(loaded, Options{EngineSemver: *engine}, ScriptedLeg{})
	if err != nil {
		return 0, err
	}
	fp := ComputeFingerprint(in)
	blob, err := json.MarshalIndent(struct {
		SHA256     string            `json:"sha256"`
		Components map[string]string `json:"components"`
	}{fp.SHA256, fp.Components}, "", "  ")
	if err != nil {
		return 0, err
	}
	fmt.Fprintln(stdout, string(blob))
	return 0, nil
}

// writePrivate writes a report only its owner can read: a report over field cases
// describes a customer's incident.
func writePrivate(path string, b []byte) error {
	return os.WriteFile(path, b, 0o600)
}
