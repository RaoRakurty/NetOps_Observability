// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bmp

import (
	"fmt"
	"net/netip"
)

// cidrN gives a deterministic, distinct prefix per index.
func cidrN(i int) string { return fmt.Sprintf("10.0.%d.0/24", i) }

// peerAddrN gives a deterministic, distinct peer address per index.
func peerAddrN(i int) string { return fmt.Sprintf("10.%d.%d.1", i/256, i%256) }

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// netipAddr aliases netip.Addr so the test fixtures can spell the
// ResolveDevice signature without repeating the import in every file.
type netipAddr = netip.Addr

// netipPrefix aliases netip.Prefix for the fuzz assertions.
type netipPrefix = netip.Prefix
