package essential

import (
	"context"
	"errors"
	"flowgate/internal/policy"
	"net"
	"reflect"
	"testing"
)

func TestAutomaticDHCPDiscoveryScopes(t *testing.T) {
	env := Environment{Run: func(_ context.Context, command string, args ...string) ([]byte, error) {
		if command != "nmcli" {
			t.Fatal("optional service discovery invoked", command)
		}
		if args[0] == "-t" {
			return []byte("a:linkA\nb:linkB\nc:static\nd:loop\ne:gone"), nil
		}
		switch args[len(args)-1] {
		case "a":
			return []byte("auto\ndisabled"), nil
		case "b":
			return []byte("manual\ndhcp"), nil
		case "c":
			return []byte("manual\nmanual"), nil
		default:
			t.Fatal("unexpected lookup", args)
			return nil, nil
		}
	}}
	lookup := func(name string) (*net.Interface, error) {
		if name == "gone" {
			return nil, errors.New("gone")
		}
		v := &net.Interface{Name: name, Index: 10}
		if name == "loop" {
			v.Flags = net.FlagLoopback
		}
		return v, nil
	}
	d, err := discoverDHCP(context.Background(), env, lookup)
	if err != nil {
		t.Fatal(err)
	}
	want := []policy.BootstrapInterface{{Name: "linkA", IPv4: true}, {Name: "linkB", IPv6: true}}
	if got := mergeBootstrap(nil, d); !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
	saved := []policy.BootstrapInterface{{Name: "linkA", IPv6: true}, {Name: "saved", IPv4: true}}
	got := mergeBootstrap(saved, d)
	if len(got) != 3 || !got[0].IPv4 || !got[0].IPv6 || saved[0].IPv4 {
		t.Fatalf("merge mutated/widened wrong scope: %+v", got)
	}
}

func TestAutomaticDHCPDiscoveryFailureRetainsOnlySaved(t *testing.T) {
	saved := []policy.BootstrapInterface{{Name: "saved", IPv4: true}}
	for _, response := range []string{"broken", ""} {
		env := Environment{Run: func(context.Context, string, ...string) ([]byte, error) {
			if response == "" {
				return nil, errors.New("unavailable")
			}
			return []byte(response), nil
		}}
		got, err := AutomaticBootstrap(context.Background(), env, saved)
		if err == nil || !reflect.DeepEqual(got, saved) {
			t.Fatalf("%+v %v", got, err)
		}
	}
}

func TestGuardBootstrapBeforeNetworkManager(t *testing.T) {
	got := guardInterfaces(nil, []net.Interface{{Name: "loop", Flags: net.FlagLoopback}, {Name: "wired", Index: 2}, {Name: "wifi", Index: 3}})
	want := []policy.BootstrapInterface{{Name: "wifi", IPv4: true, IPv6: true}, {Name: "wired", IPv4: true, IPv6: true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
}
