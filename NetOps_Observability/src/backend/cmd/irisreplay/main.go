// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Command irisreplay replays frozen incidents through Iris offline and compares
// runs. All logic is in internal/irisreplay.
package main

import (
	"context"
	"os"

	"netops/backend/internal/irisreplay"
)

func main() {
	os.Exit(irisreplay.CLI(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
