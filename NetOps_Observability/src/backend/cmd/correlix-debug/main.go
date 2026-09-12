// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Command correlix-debug traces one record through the Correlix pipeline and
// packages the evidence (docs/design/PIPELINE_DEBUGGER_2026-09-04.md).
//
// §2: /cmd holds NO business logic — everything lives in the importable
// internal/pipedebug/cli package, which returns an exit code so every path is
// testable without building a binary. This file exists only to be the process.
package main

import (
	"os"

	"netops/backend/internal/pipedebug/cli"
)

func main() { os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr)) }
