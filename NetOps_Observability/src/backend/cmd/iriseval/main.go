// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Command iriseval files and lists customer-derived Iris eval cases in the
// per-install field-eval store (tracker 337 N-H3). All logic is in
// internal/fieldeval.
package main

import (
	"os"

	"netops/backend/internal/fieldeval"
)

func main() {
	os.Exit(fieldeval.CLI(os.Args[1:], os.Stdout, os.Stderr))
}
