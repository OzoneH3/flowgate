package daemon

import (
	"errors"
	"flowgate/internal/policy"
	"net"
	"testing"
)

func TestRuleInterfacesFreshEvaluation(t *testing.T) {
	stored := []policy.Rule{
		{Filter: policy.Filter{InterfaceName: "link-a", InterfaceIndex: 7}},
		{Disabled: true, Filter: policy.Filter{InterfaceName: "link-a"}},
		{Filter: policy.Filter{InterfaceName: "missing"}},
		{Filter: policy.Filter{InterfaceName: "missing"}},
		{Filter: policy.Filter{InterfaceIndex: 9}},
	}
	index := 11
	for _, phase := range []string{"present", "renamed", "recreated"} {
		calls := 0
		rules := append([]policy.Rule(nil), stored...)
		resolveRuleInterfaces(rules, func() ([]net.Interface, error) {
			calls++
			if phase == "renamed" {
				return []net.Interface{{Name: "other", Index: index}}, nil
			}
			return []net.Interface{{Name: "link-a", Index: index}}, nil
		})
		if calls != 1 {
			t.Fatalf("%s lookup count: %d", phase, calls)
		}
		if rules[0].Disabled != (phase == "renamed") || !rules[1].Disabled || !rules[2].Disabled || !rules[3].Disabled {
			t.Fatalf("%s rules: %+v", phase, rules)
		}
		if phase != "renamed" && (rules[0].Filter.InterfaceIndex != uint32(index) || rules[1].Filter.InterfaceIndex != uint32(index)) {
			t.Fatalf("stale interface in %s", phase)
		}
		if rules[4].Filter.InterfaceIndex != 9 || rules[4].Disabled || stored[0].Filter.InterfaceIndex != 7 || stored[0].Disabled {
			t.Fatal("changed unscoped or stored rule")
		}
		index++
	}
}

func TestRuleInterfacesUnavailableRefuses(t *testing.T) {
	for _, interfaces := range [][]net.Interface{nil, {{Name: "link-a", Index: 0}}, {{Name: "link-a", Index: -1}}} {
		rules := []policy.Rule{{Filter: policy.Filter{InterfaceName: "link-a", InterfaceIndex: 10}}}
		resolveRuleInterfaces(rules, func() ([]net.Interface, error) { return interfaces, nil })
		if !rules[0].Disabled {
			t.Fatal("invalid interface remained active")
		}
	}
	rules := []policy.Rule{{Filter: policy.Filter{InterfaceName: "link-a"}}, {Filter: policy.Filter{InterfaceName: "link-b"}}}
	calls := 0
	resolveRuleInterfaces(rules, func() ([]net.Interface, error) {
		calls++
		return []net.Interface{{Name: "link-a", Index: 2}}, errors.New("partial snapshot")
	})
	if calls != 1 || !rules[0].Disabled || !rules[1].Disabled {
		t.Fatal("failed snapshot remained active", calls, rules)
	}
	resolveRuleInterfaces([]policy.Rule{{}}, func() ([]net.Interface, error) { t.Fatal("unscoped rules queried links"); return nil, nil })
}
