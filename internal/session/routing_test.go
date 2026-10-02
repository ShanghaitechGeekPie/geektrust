package session

import (
	"reflect"
	"testing"

	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
)

func TestGatewaySelectionCompatibility(t *testing.T) {
	policy := &sdpc.Resource{Gateways: []string{"a:441", "b:441"}, NodeGroups: map[string][]string{"g": {"a:441"}}, AppNodeGroups: map[string]string{"app": "g"}, MajorNodeGroup: "g"}
	for _, tt := range []struct {
		name, group        string
		override, fallback bool
		configured, want   []string
	}{
		{"assigned", "g", false, false, []string{"a:441", "b:441"}, []string{"a:441"}},
		{"configured intersection", "g", true, true, []string{"a:441", "b:441"}, []string{"a:441"}},
		{"explicit alternate rejected", "g", true, true, []string{"alternate:441"}, nil},
		{"enabled missing group", "missing", false, true, []string{"a:441", "b:441"}, []string{"a:441", "b:441"}},
		{"missing group with filter", "missing", true, true, []string{"b:441"}, []string{"b:441"}},
		{"missing group excludes unassigned", "missing", true, true, []string{"other:441"}, nil},
		{"strict missing group", "missing", false, false, []string{"a:441", "b:441"}, nil},
		{"no group", "", false, false, []string{"a:441", "b:441"}, []string{"a:441", "b:441"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &Credential{Policy: policy, Gateways: tt.configured, GatewayOverride: tt.override, MissingGatewayGroupFallback: tt.fallback}
			if got := c.GatewaysForGroup(tt.group); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}
