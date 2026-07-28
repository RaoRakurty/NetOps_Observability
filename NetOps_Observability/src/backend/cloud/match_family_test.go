package cloud

import "testing"

// Moved from the integrator with the store (matchResource is store contract).
func TestMatchCloudResourceFamily(t *testing.T) {
	cases := []struct {
		typ, family string
		want        bool
	}{
		{"eks:cluster", "k8s", true},
		{"containerservice:managedCluster", "k8s", true}, // case-insensitive bucketing
		{"lambda:function", "serverless", true},
		{"run:service", "serverless", true},
		{"rds:instance", "db", true},
		{"sqladmin:instance", "db", true},
		{"ec2:instance", "k8s", false},
		{"acme:quantum-router", "other", true}, // unknown types stay reachable
		{"eks:cluster", "other", false},
	}
	for _, c := range cases {
		r := CloudResource{ResourceType: c.typ}
		if got := matchResource(r, ResourceFilter{Family: c.family}); got != c.want {
			t.Errorf("family=%q type=%q: got %v want %v", c.family, c.typ, got, c.want)
		}
	}
}
