package ai

// skill_select_test.go — selection must be DETERMINISTIC and reproducible by an
// operator. These tests pin the exact skill each phrasing resolves to, prove the
// excluded intents can never be pre-empted, and prove the fallback rule (an
// unmatched OPERATIONAL complaint gets the entry method; an unmatched question
// that is not a complaint gets no skill at all).

import "testing"

func loadTestSkills(t *testing.T) *SkillSet {
	t.Helper()
	set, err := LoadSkills()
	if err != nil {
		t.Fatalf("LoadSkills: %v", err)
	}
	return set
}

// planWithIntent is the classifier output SelectSkill sees. "troubleshoot" is a
// non-excluded intent, so these cases exercise selection itself.
func planWithIntent(intent string) Plan { return Plan{Intent: intent, Mode: ModeUnavailable} }

func TestSelectSkillPerSkill(t *testing.T) {
	set := loadTestSkills(t)
	cases := []struct {
		question string
		want     string
	}{
		{"bgp neighbor down on edge-1, peer is idle", "bgp-session-down"},
		{"prefix missing on the ebgp peer — route not advertised to us", "bgp-prefix-missing"},
		{"ospf neighbor stuck in exstart on core-2", "ospf-adjacency"},
		{"isis adjacency down between the two level-2 routers", "isis-adjacency"},
		{"uplink interface down on dist-3, no link", "interface-down"},
		{"crc errors climbing on the sfp, light level looks low", "optics-degraded"},
		{"spanning tree topology change storm, root bridge moved", "stp-topology"},
		{"mac address flapping between two access ports, duplicate mac", "mac-flap"},
		{"packet loss and latency on the isp handoff, is it the network", "path-seam-handoff"},
		{"users get 502 and 504 from the load balancer, app team says network", "app-edge-5xx"},
		{"what is our exposure, any security finding or cve on this device", "security-exposure-context"},
		{"show me the logs, what is the device logging right now", "log-confirmation"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			m, ok := SelectSkill(set, tc.question, planWithIntent("troubleshoot"))
			if !ok {
				t.Fatalf("no skill selected for %q", tc.question)
			}
			if m.Skill.Name != tc.want {
				t.Fatalf("%q selected %q, want %q (matched %v, score %d)",
					tc.question, m.Skill.Name, tc.want, m.Matched, m.Score)
			}
			if m.Reason == "" {
				t.Error("selection must always state a reason (it is shown and audited)")
			}
			if len(m.Matched) == 0 {
				t.Error("a keyword win must report which phrases fired")
			}
			// Determinism: same input, same answer, every time.
			for i := 0; i < 5; i++ {
				again, ok2 := SelectSkill(set, tc.question, planWithIntent("troubleshoot"))
				if !ok2 || again.Skill.Name != m.Skill.Name || again.Score != m.Score {
					t.Fatalf("selection is not deterministic: %v/%v", m, again)
				}
			}
		})
	}
}

func TestSelectSkillNeverPreemptsExcludedIntents(t *testing.T) {
	set := loadTestSkills(t)
	// A question that WOULD match a skill outright, under every excluded intent.
	const q = "bgp neighbor down on edge-1, packet loss on the isp handoff"
	if _, ok := SelectSkill(set, q, planWithIntent("troubleshoot")); !ok {
		t.Fatal("precondition: this question must match a skill under a normal intent")
	}
	for intent := range skillExcludedIntents {
		if m, ok := SelectSkill(set, q, planWithIntent(intent)); ok {
			t.Errorf("intent %q was pre-empted by skill %q", intent, m.Skill.Name)
		}
	}
}

func TestSelectSkillFallback(t *testing.T) {
	set := loadTestSkills(t)
	cases := []struct {
		name     string
		question string
		want     string // "" = no skill
	}{
		{"operational complaint falls to the entry method", "the site is not working and users are complaining", "osi-bisection"},
		{"vague outage falls to the entry method", "something is broken, no idea where to start", "osi-bisection"},
		{"unreachable falls to the entry method", "branch 14 is unreachable this morning", "osi-bisection"},
		{"non-complaint yields no skill", "who is on call next tuesday", ""},
		{"pleasantry yields no skill", "thanks, that was helpful", ""},
		{"empty question yields no skill", "   ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := SelectSkill(set, tc.question, planWithIntent("troubleshoot"))
			if tc.want == "" {
				if ok {
					t.Fatalf("expected no skill, got %q", m.Skill.Name)
				}
				return
			}
			if !ok {
				t.Fatalf("expected the entry method, got none")
			}
			if m.Skill.Name != tc.want {
				t.Fatalf("got %q, want %q", m.Skill.Name, tc.want)
			}
			if m.Score != 0 {
				t.Errorf("the fallback must score 0 (it is not a keyword win), got %d", m.Score)
			}
			if m.Skill.Layer != LayerMethod {
				t.Errorf("the fallback must be the method-layer skill, got layer %q", m.Skill.Layer)
			}
		})
	}
}

func TestSelectSkillNilOrEmptySet(t *testing.T) {
	if _, ok := SelectSkill(nil, "bgp neighbor down", planWithIntent("troubleshoot")); ok {
		t.Fatal("a nil SkillSet must select nothing (skills disabled)")
	}
	if _, ok := SelectSkill(&SkillSet{byName: map[string]*Skill{}}, "bgp down", planWithIntent("troubleshoot")); ok {
		t.Fatal("an empty SkillSet must select nothing")
	}
}

// TestSelectSkillTieBreakIsStable pins the documented order: score, then layer
// rank (bottom-up bisection), then name. A tie must never depend on map order.
func TestSelectSkillTieBreakIsStable(t *testing.T) {
	physical := &Skill{Name: "z-physical", Layer: LayerPhysical, Version: 1,
		WhenToUse: []string{"tiebreak"}, SymptomKinds: []string{"none"}}
	bgp := &Skill{Name: "a-bgp", Layer: LayerBGP, Version: 1,
		WhenToUse: []string{"tiebreak"}, SymptomKinds: []string{"none"}}
	alsoBGP := &Skill{Name: "b-bgp", Layer: LayerBGP, Version: 1,
		WhenToUse: []string{"tiebreak"}, SymptomKinds: []string{"none"}}
	method := &Skill{Name: "m-method", Layer: LayerMethod, Version: 1,
		WhenToUse: []string{"tiebreak"}, SymptomKinds: []string{"none"}}
	set := &SkillSet{
		byName: map[string]*Skill{
			physical.Name: physical, bgp.Name: bgp, alsoBGP.Name: alsoBGP, method.Name: method,
		},
		order: []string{alsoBGP.Name, bgp.Name, method.Name, physical.Name},
	}
	for i := 0; i < 20; i++ {
		m, ok := SelectSkill(set, "a tiebreak case", planWithIntent("troubleshoot"))
		if !ok {
			t.Fatal("expected a match")
		}
		// Lower layer rank wins over an equal score; the method skill is excluded
		// from the keyword race entirely.
		if m.Skill.Name != "z-physical" {
			t.Fatalf("tie-break picked %q, want z-physical (lowest layer rank)", m.Skill.Name)
		}
	}
	// Remove the physical skill: now the two bgp skills tie and NAME decides.
	delete(set.byName, physical.Name)
	set.order = []string{alsoBGP.Name, bgp.Name, method.Name}
	m, ok := SelectSkill(set, "a tiebreak case", planWithIntent("troubleshoot"))
	if !ok || m.Skill.Name != "a-bgp" {
		t.Fatalf("same-layer tie must break on name, got %+v", m)
	}
}

func TestPhraseMatchesWordBoundaries(t *testing.T) {
	cases := []struct {
		question string
		phrase   string
		want     bool
	}{
		{" arp instability ", "arp", true},
		{" please sharpen the image ", "arp", false}, // no substring hit inside a word
		{" the warp core is down ", "arp", false},    // interior match rejected
		{" bgp down on edge-1 ", "bgp down", true},   // multi-word matches as substring
		{" we saw a bgpdown event ", "bgp", false},   // suffix-attached rejected
		{" stp is churning ", "stp", true},           // start-of-token
		{" mtu is 1500 ", "mtu", true},               //
		{" errors ", "error", false},                 // plural is a different token
		{" mac flap seen ", "mac flap", true},        // multi-word
		{" is-is adjacency ", "is-is", true},         // hyphen counts as multi-word
		{" nothing here ", "", false},                // empty phrase never matches
		{" ospf ", "ospf", true},                     // whole padded question
		{" 10.1.0.0/16 prefix missing ", "prefix", true},
	}
	for _, tc := range cases {
		if got := phraseMatches(tc.question, tc.phrase); got != tc.want {
			t.Errorf("phraseMatches(%q, %q) = %v, want %v", tc.question, tc.phrase, got, tc.want)
		}
	}
}
