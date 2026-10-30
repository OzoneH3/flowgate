package hostfirewall

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func interfaceRule(chain, key, right string) []byte {
	return []byte(fmt.Sprintf(`{"nftables":[{"rule":{"family":"inet","table":"flowgate_host","chain":%q,"comment":"flowgate-socket:0123456789abcdef0123456789abcdef","expr":[{"match":{"op":"==","left":{"meta":{"key":%q}},"right":%s}}]}}]}`, chain, key, right))
}
func TestInterfaceDigestTracksIndexAcrossRenameAndDeletion(t *testing.T) {
	var expected string
	for _, tc := range []struct {
		right string
		links map[string]uint32
	}{
		{`"uplink"`, map[string]uint32{"uplink": 2}},
		{`"renamed"`, map[string]uint32{"renamed": 2}},
		{`"2"`, map[string]uint32{}},
	} {
		raw, err := canonicalInterfaceMatches(interfaceRule("socket_output", "oif", tc.right), tc.links, tc.links)
		if err != nil {
			t.Fatal(err)
		}
		digest, _ := digestTableJSON(raw)
		if expected == "" {
			expected = digest
		} else if digest != expected {
			t.Fatal("same kernel index changed digest")
		}
	}
	links := map[string]uint32{"uplink": 3}
	raw, err := canonicalInterfaceMatches(interfaceRule("socket_output", "oif", `"uplink"`), links, links)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := digestTableJSON(raw)
	if digest == expected {
		t.Fatal("same-name different index concealed")
	}
}
func TestInterfaceDigestRejectsChurnAndAmbiguity(t *testing.T) {
	for _, tc := range []struct {
		right         string
		before, after map[string]uint32
	}{
		{`"uplink"`, map[string]uint32{"uplink": 2}, map[string]uint32{"uplink": 3}},
		{`"missing"`, map[string]uint32{}, map[string]uint32{}},
		{`"2"`, map[string]uint32{"2": 2}, map[string]uint32{"2": 2}},
	} {
		_, err := canonicalInterfaceMatches(interfaceRule("socket_output", "oif", tc.right), tc.before, tc.after)
		if !errors.Is(err, errAuditInconclusive) {
			t.Fatal("uncertainty accepted", tc, err)
		}
	}
}
func TestInterfaceDigestDoesNotRewriteOtherScopes(t *testing.T) {
	links := map[string]uint32{"uplink": 2}
	for _, tc := range []struct{ chain, key string }{{"output", "oif"}, {"socket_output", "oifname"}} {
		raw, err := canonicalInterfaceMatches(interfaceRule(tc.chain, tc.key, `"uplink"`), links, links)
		if err != nil || !strings.Contains(string(raw), `"right":"uplink"`) {
			t.Fatal("unrelated scope changed", string(raw), err)
		}
	}
}
