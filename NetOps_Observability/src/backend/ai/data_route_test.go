// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// data_route_test.go — the question router's data arm (tracker 337 N-G4).
//
// Pinned: a question the data arm claims is answered as ModeDataQuery with the
// server's text and payload; a diagnostic question, an explicit problem id, a
// "not mine" answer and a failing arm all leave the classic path to answer;
// and an unwired arm changes nothing.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type dataCall struct {
	n    int
	opts []DataOpts
}

func dataArm(c *dataCall, d DataAnswer, err error) NLQueryFunc {
	return func(_ context.Context, _ Principal, _ string, opts DataOpts) (DataAnswer, error) {
		c.opts = append(c.opts, opts)
		c.n++
		return d, err
	}
}

func TestTheDataArmAnswersWhatItClaims(t *testing.T) {
	var c dataCall
	o := newOrch(newMockDS())
	o.NLQuery = dataArm(&c, DataAnswer{Status: DataAnswered, Intent: "query_metric", Text: "CPU on edge-1: latest 40%.",
		Payload: json.RawMessage(`{"result":{}}`), Citations: []Citation{{ID: "query:q1", Kind: "query"}}}, nil)
	ans, err := o.Ask(context.Background(), tenantA(), "show cpu on edge-1 for the last hour", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeDataQuery || ans.Text != "CPU on edge-1: latest 40%." || string(ans.Data) != `{"result":{}}` || len(ans.Citations) != 1 {
		t.Fatalf("data answer = %+v", ans)
	}
	if ans.Disclaimers == nil {
		t.Fatal("disclaimers must be an empty list, never null")
	}
}

func TestTheClassicPathKeepsWhatTheDataArmDoesNotClaim(t *testing.T) {
	for name, tc := range map[string]struct {
		q   string
		ui  map[string]string
		d   DataAnswer
		err error
		arm bool // whether the arm may even be consulted
	}{
		"diagnostic":      {q: "why is cpu high on edge-1", d: DataAnswer{Status: DataAnswered}, arm: false},
		"root cause":      {q: "what is the root cause of the loss in dallas", d: DataAnswer{Status: DataAnswered}, arm: false},
		"problem id":      {q: "show cpu", ui: map[string]string{"problem_id": "p-1"}, d: DataAnswer{Status: DataAnswered}, arm: false},
		"not data":        {q: "how do I add a device", d: DataAnswer{Status: DataNotData}, arm: true},
		"arm failed":      {q: "show cpu on edge-1", err: errors.New("vm down"), arm: true},
		"unknown outcome": {q: "show cpu on edge-1", d: DataAnswer{Status: "maybe"}, arm: true},
	} {
		var c dataCall
		o := newOrch(newMockDS())
		o.NLQuery = dataArm(&c, tc.d, tc.err)
		ans, err := o.Ask(context.Background(), tenantA(), tc.q, tc.ui)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ans.Mode == ModeDataQuery {
			t.Errorf("%s: the data arm must not answer, got %+v", name, ans)
		}
		if !tc.arm && c.n != 0 {
			t.Errorf("%s: the data arm must not even be consulted", name)
		}
	}
}

func TestAnUnwiredDataArmChangesNothing(t *testing.T) {
	q := "show cpu on edge-1 for the last hour"
	a, err := newOrch(newMockDS()).Ask(context.Background(), tenantA(), q, nil)
	if err != nil {
		t.Fatal(err)
	}
	o := newOrch(newMockDS())
	o.NLQuery = dataArm(&dataCall{}, DataAnswer{Status: DataNotData}, nil)
	b, err := o.Ask(context.Background(), tenantA(), q, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Mode != b.Mode || a.Intent != b.Intent || a.Text != b.Text {
		t.Fatalf("a declining data arm changed the classic answer: %v/%v vs %v/%v", a.Mode, a.Intent, b.Mode, b.Intent)
	}
}

// The model fallback is not spent on questions the classifier already knows
// are product help; the grammar still runs for them (a misrouted data
// question is still caught key-free).
func TestTheModelIsNotSpentOnProductHelp(t *testing.T) {
	var c dataCall
	o := newOrch(newMockDS())
	o.NLQuery = dataArm(&c, DataAnswer{Status: DataNotData}, nil)
	if _, err := o.Ask(context.Background(), tenantA(), "how do I add a device", nil); err != nil {
		t.Fatal(err)
	}
	if c.n != 1 || c.opts[0].AllowModel {
		t.Fatalf("product help: consulted %d times with %+v", c.n, c.opts)
	}
	c = dataCall{}
	if _, err := o.Ask(context.Background(), tenantA(), "show p95 utilization per site today", nil); err != nil {
		t.Fatal(err)
	}
	if c.n != 1 || !c.opts[0].AllowModel {
		t.Fatalf("a data-shaped question may use the model: %+v", c.opts)
	}
}
