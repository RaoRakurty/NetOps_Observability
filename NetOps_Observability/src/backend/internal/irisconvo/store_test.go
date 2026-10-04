// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisconvo

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/nlquery/ast"
)

var bg = context.Background()

func turn(q string) Turn { return Turn{Question: q, Outcome: OutcomeAnswered} }

func TestOnlyTheOwnerInTheSameScopeSeesAConversation(t *testing.T) {
	m := NewMemStore()
	c, err := m.Create(bg, "acme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !ValidID(c.ID) {
		t.Fatalf("id %q is not a UUID", c.ID)
	}
	if _, err := m.Get(bg, "acme", "alice", c.ID); err != nil {
		t.Fatalf("owner must see it: %v", err)
	}
	for _, who := range [][2]string{{"acme", "bob"}, {"globex", "alice"}, {"global", "alice"}} {
		if _, err := m.Get(bg, who[0], who[1], c.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("%v must get ErrNotFound, got %v", who, err)
		}
		if _, err := m.Append(bg, who[0], who[1], c.ID, turn("x"), State{}); !errors.Is(err, ErrNotFound) {
			t.Errorf("%v must not extend it, got %v", who, err)
		}
	}
}

func TestAConversationNeedsAPrincipal(t *testing.T) {
	m := NewMemStore()
	for _, p := range [][2]string{{"", "alice"}, {"acme", ""}, {" ", " "}} {
		if _, err := m.Create(bg, p[0], p[1]); !errors.Is(err, ErrInvalid) {
			t.Errorf("%v: want ErrInvalid, got %v", p, err)
		}
	}
}

func TestTurnsAreCappedAndOutcomesClosed(t *testing.T) {
	m := NewMemStore()
	c, _ := m.Create(bg, "acme", "alice")
	if _, err := m.Append(bg, "acme", "alice", c.ID, Turn{Question: "q", Outcome: "great"}, State{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an unknown outcome must be refused, got %v", err)
	}
	for i := 0; i < MaxTurns; i++ {
		if _, err := m.Append(bg, "acme", "alice", c.ID, turn("q"), State{}); err != nil {
			t.Fatalf("turn %d: %v", i, err)
		}
	}
	if _, err := m.Append(bg, "acme", "alice", c.ID, turn("one more"), State{}); !errors.Is(err, ErrFull) {
		t.Fatalf("want ErrFull past %d turns, got %v", MaxTurns, err)
	}
}

func TestIdleConversationsExpire(t *testing.T) {
	m := NewMemStore()
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	c, _ := m.Create(bg, "acme", "alice")
	now = now.Add(TTL + time.Minute)
	if _, err := m.Get(bg, "acme", "alice", c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an idle conversation must expire, got %v", err)
	}
}

func TestAnOwnerKeepsAtMostMaxPerOwner(t *testing.T) {
	m := NewMemStore()
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { now = now.Add(time.Second); return now }
	first, _ := m.Create(bg, "acme", "alice")
	other, _ := m.Create(bg, "acme", "bob")
	for i := 0; i < MaxPerOwner; i++ {
		if _, err := m.Create(bg, "acme", "alice"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Get(bg, "acme", "alice", first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("the least recently used conversation must be evicted")
	}
	if _, err := m.Get(bg, "acme", "bob", other.ID); err != nil {
		t.Fatal("one owner's cap must never evict another owner's conversation")
	}
}

func TestStateIsBoundedAndDeduplicated(t *testing.T) {
	var st State
	for i := 0; i < 3*MaxEntities; i++ {
		st.Entities = append(st.Entities, ast.EntityRef{Type: "device", ID: "device:d" + strings.Repeat("x", i%5)})
		st.Actors = append(st.Actors, "a"+strings.Repeat("y", i))
		st.ChangeIDs = append(st.ChangeIDs, "chg-"+strings.Repeat("z", i))
	}
	st.Entities = append(st.Entities, ast.EntityRef{Type: "", ID: "x"}, ast.EntityRef{Type: "device", ID: strings.Repeat("l", MaxIDLen+1)})
	n := NormalizeState(st)
	if len(n.Entities) != 5 {
		t.Errorf("duplicates and invalid refs must go: %d entities", len(n.Entities))
	}
	if len(n.Actors) != MaxActors || len(n.ChangeIDs) != MaxChangeIDs {
		t.Errorf("caps: %d actors, %d change ids", len(n.Actors), len(n.ChangeIDs))
	}
}

func TestReturnedConversationsAreCopies(t *testing.T) {
	m := NewMemStore()
	c, _ := m.Create(bg, "acme", "alice")
	c, _ = m.Append(bg, "acme", "alice", c.ID, turn("q1"), State{Actors: []string{"alice"}, LastAST: &ast.AST{V: 1, Type: ast.ChangeList}})
	c.Turns[0].Question = "tampered"
	c.State.Actors[0] = "mallory"
	c.State.LastAST.Type = ast.MetricTopK
	got, _ := m.Get(bg, "acme", "alice", c.ID)
	if got.Turns[0].Question != "q1" || got.State.Actors[0] != "alice" || got.State.LastAST.Type != ast.ChangeList {
		t.Fatalf("a caller mutated the stored conversation: %+v", got)
	}
}

func TestQuestionsAreClipped(t *testing.T) {
	tn, err := NormalizeTurn(Turn{Question: strings.Repeat("é", MaxQuestionLen+50), Outcome: OutcomeUnparsed, Rows: -3})
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(tn.Question)) != MaxQuestionLen || tn.Rows != 0 || tn.At.IsZero() {
		t.Fatalf("normalize: %d runes, rows %d", len([]rune(tn.Question)), tn.Rows)
	}
}

func TestConcurrentAppendsNeverExceedTheCap(t *testing.T) {
	m := NewMemStore()
	c, _ := m.Create(bg, "acme", "alice")
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 2*MaxTurns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Append(bg, "acme", "alice", c.ID, turn("q"), State{}); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != MaxTurns {
		t.Fatalf("%d appends succeeded, want exactly %d", ok, MaxTurns)
	}
}

func TestValidID(t *testing.T) {
	id, _ := NewID()
	for s, want := range map[string]bool{
		id: true, "11111111-2222-4333-8444-555555555555": true,
		"11111111-2222-4333-8444-55555555555G": false, "11111111222243338444555555555555": false,
		"../../etc/passwd": false, "": false, "11111111-2222-4333-8444-55555555555A": false,
	} {
		if ValidID(s) != want {
			t.Errorf("ValidID(%q) = %v", s, !want)
		}
	}
}
