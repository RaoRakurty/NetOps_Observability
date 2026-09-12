// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package gqlparse

// parse_test.go — the parser subset contract: what parses, what is refused by
// NAME (never silence), and the depth/width bounds. The handler-level tests
// (RBAC gate, tenant isolation, argument application) stay with the integrator
// in package main.

import (
	"fmt"
	"testing"
)

func TestParseSubset(t *testing.T) {
	op, err := Parse(`query Q($a: Int = 3, $b: [String!]!) {
		# a comment that mentions devices and must not dispatch anything
		alias: devices(limit: $a, offset: 10) { id name labels }
		health { status }
	}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if op.Name != "Q" || len(op.VarNames) != 2 {
		t.Fatalf("op = %+v", op)
	}
	if len(op.Sel) != 2 {
		t.Fatalf("want 2 root fields, got %d", len(op.Sel))
	}
	d := op.Sel[0]
	if d.Name != "devices" || d.Alias != "alias" {
		t.Fatalf("field = %+v", d)
	}
	if d.Args["limit"].Kind != Var || d.Args["limit"].Str != "a" {
		t.Fatalf("limit arg = %+v", d.Args["limit"])
	}
	if d.Args["offset"].Kind != Int || d.Args["offset"].Int != 10 {
		t.Fatalf("offset arg = %+v", d.Args["offset"])
	}
	if len(d.Sel) != 3 {
		t.Fatalf("want 3 subfields, got %d", len(d.Sel))
	}
}

// TestParseCommentsDoNotDispatch is the direct answer to the substring
// dispatcher: a comment (or a string literal) mentioning `devices` used to make
// the endpoint return the whole inventory.
func TestParseCommentsDoNotDispatch(t *testing.T) {
	op, err := Parse("{ health { status } # devices\n }")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range op.Sel {
		if f.Name == "devices" {
			t.Fatal("a comment mentioning `devices` selected the devices field")
		}
	}
}

func TestParseBoundsDepthAndWidth(t *testing.T) {
	deep := ""
	for i := 0; i < maxDepth+3; i++ {
		deep += "{a"
	}
	deep += "{b}"
	for i := 0; i < maxDepth+3; i++ {
		deep += "}"
	}
	if _, err := Parse(deep); err == nil {
		t.Error("an arbitrarily deep document must be refused (stack-exhaustion DoS, §9)")
	}
	wide := "{"
	for i := 0; i < maxFields+10; i++ {
		wide += fmt.Sprintf("f%d ", i)
	}
	wide += "}"
	if _, err := Parse(wide); err == nil {
		t.Error("an arbitrarily wide document must be refused")
	}
}
