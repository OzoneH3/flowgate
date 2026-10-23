package hostfirewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"flowgate/internal/essential"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
)

// Interface hotplug against real links in a disposable namespace: discovery
// uses the real interface lookup, NetworkManager answers are the only fixture.
// Mirrors the protection loop: refresh on a changed successful discovery,
// retain the active scopes when discovery fails.
func TestEssentialDHCPHotplugLifecycle(t *testing.T) {
	if os.Getenv("FLOWGATE_ESSENTIAL_PRIVATE_NETNS") == "" || os.Getenv("FLOWGATE_ESSENTIAL_PRIVATE_NETNS") == identity.NetNS() {
		t.Skip("explicit disposable namespace required")
	}
	run := func(name string, args ...string) {
		t.Helper()
		if b, e := exec.Command(name, args...).CombinedOutput(); e != nil {
			t.Fatalf("%s %v: %s %v", name, args, b, e)
		}
	}
	addLink := func(name string) {
		run("ip", "link", "add", name, "type", "dummy")
		run("ip", "link", "set", name, "up")
	}
	addLink("hp0")
	addLink("hp1") // present but never an active NetworkManager connection
	defer exec.Command("ip", "link", "del", "hp0").Run()
	defer exec.Command("ip", "link", "del", "hp1").Run()

	c := exec.Command("nft", "-f", "-")
	c.Stdin = strings.NewReader(profileRules("test", "both"))
	if b, e := c.CombinedOutput(); e != nil {
		t.Fatalf("nft %v %s", e, b)
	}
	defer exec.Command("nft", "delete", "table", "inet", Table).Run()
	digest, err := tableDigest()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	record := Record{Token: "test", TableDigest: digest}

	active := []string{"hp0"}
	var nmErr error
	env := essential.Environment{Run: func(_ context.Context, command string, args ...string) ([]byte, error) {
		if command != "nmcli" {
			t.Fatalf("unexpected command %s", command)
		}
		if nmErr != nil {
			return nil, nmErr
		}
		if args[0] == "-t" {
			lines := []string{}
			for i, name := range active {
				lines = append(lines, fmt.Sprintf("uuid-%d:%s", i, name))
			}
			return []byte(strings.Join(lines, "\n")), nil
		}
		return []byte("auto\nauto"), nil
	}}
	var current []policy.BootstrapInterface
	step := func(label string, want map[string]bool) {
		t.Helper()
		next, err := essential.AutomaticBootstrap(context.Background(), env, nil)
		if err != nil {
			t.Fatalf("%s: discovery %v", label, err)
		}
		if err = refreshBootstrap(context.Background(), dir, &record, next); err != nil {
			t.Fatalf("%s: refresh %v", label, err)
		}
		current = next
		for _, chain := range []string{"dhcp_input", "dhcp_output"} {
			dump, err := nft("list", "chain", "inet", Table, chain)
			if err != nil {
				t.Fatal(err)
			}
			for name, present := range want {
				if strings.Contains(string(dump), fmt.Sprintf("%q", name)) != present {
					t.Fatalf("%s: %s %s present=%v\n%s", label, chain, name, !present, dump)
				}
			}
		}
	}
	step("initial", map[string]bool{"hp0": true, "hp1": false})
	run("ip", "link", "del", "hp0")
	step("removed link", map[string]bool{"hp0": false, "hp1": false})
	addLink("hp0")
	step("re-added link", map[string]bool{"hp0": true, "hp1": false})
	active = []string{"hp0", "hp1"}
	step("second connection", map[string]bool{"hp0": true, "hp1": true})
	active = []string{"hp1"}
	step("connection deactivated", map[string]bool{"hp0": false, "hp1": true})

	// A NetworkManager failure is surfaced; the loop keeps the last verified scopes.
	nmErr = errors.New("NetworkManager restarting")
	if _, err := essential.AutomaticBootstrap(context.Background(), env, nil); !errors.Is(err, nmErr) {
		t.Fatalf("discovery failure hidden: %v", err)
	}
	dump, err := nft("list", "chain", "inet", Table, "dhcp_output")
	if err != nil || !strings.Contains(string(dump), `"hp1"`) || len(current) != 1 {
		t.Fatalf("scopes not retained across discovery failure: %v\n%s", err, dump)
	}
	t.Log("PASS hotplug add/remove/re-add, second connection, deactivation and NetworkManager failure on real links; unlisted link never scoped")
}
