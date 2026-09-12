// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Command api is the Correlix backend entrypoint (§2: /cmd holds NO business
// logic — the whole application lives in the importable backend package; the
// P2 W5 /cmd split).
package main

import backend "netops/backend"

func main() { backend.Run() }
