package cloud

import (
	"reflect"
	"testing"
)

func TestMissingTagsDefaults(t *testing.T) {
	req := DefaultRequiredTags()
	// Fully tagged via alias keys (Application / TEAM / stage) — nothing missing.
	tags := map[string]string{"Application": "billing", "TEAM": "payments", "stage": "prod"}
	if got := MissingTags(tags, req); len(got) != 0 {
		t.Fatalf("alias-tagged resource reported missing %v", got)
	}
	// app_id counts as app (the resolve.go convention MUST be honored here too).
	if got := MissingTags(map[string]string{"app_id": "x", "owner": "y", "env": "z"}, req); len(got) != 0 {
		t.Fatalf("app_id-tagged resource reported missing %v", got)
	}
	// Untagged → everything missing, in required order.
	if got := MissingTags(nil, req); !reflect.DeepEqual(got, []string{"app", "owner", "env"}) {
		t.Fatalf("untagged = %v", got)
	}
	// Whitespace-only values do not satisfy a requirement.
	if got := MissingTags(map[string]string{"app": "  "}, req); len(got) != 3 {
		t.Fatalf("blank value counted as present: %v", got)
	}
}

func TestMissingTagsCustomList(t *testing.T) {
	req := []string{"app", "cost_center"}
	tags := map[string]string{"service": "api", "Cost_Center": "cc-42"}
	if got := MissingTags(tags, req); len(got) != 0 {
		t.Fatalf("custom key must match case-insensitively, missing %v", got)
	}
	if got := MissingTags(map[string]string{"service": "api"}, req); !reflect.DeepEqual(got, []string{"cost_center"}) {
		t.Fatalf("got %v, want [cost_center]", got)
	}
	// Empty required list: nothing can be missing.
	if got := MissingTags(nil, nil); got != nil {
		t.Fatalf("empty requirement produced %v", got)
	}
}

func TestTagCompliance(t *testing.T) {
	res := []CloudResource{
		{Tags: map[string]string{"app": "a", "owner": "o", "env": "prod"}},
		{Tags: map[string]string{"app": "a"}},
		{},
	}
	rep := TagCompliance(res, DefaultRequiredTags())
	if rep.Total != 3 || rep.FullyTagged != 1 {
		t.Fatalf("total/fully = %d/%d, want 3/1", rep.Total, rep.FullyTagged)
	}
	if rep.MissingByTag["owner"] != 2 || rep.MissingByTag["env"] != 2 || rep.MissingByTag["app"] != 1 {
		t.Fatalf("missing_by_tag = %v", rep.MissingByTag)
	}
}
