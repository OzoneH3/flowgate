package readiness

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeEnv() Environment {
	return Environment{Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "ip" {
			return []byte(`[{"ifname":"lo"}]`), nil
		}
		return []byte(`{"nftables":[]}`), nil
	}, Read: func(string) ([]byte, error) { return nil, os.ErrNotExist }}
}
func TestFirewallHealthyAndConflicts(t *testing.T) {
	for _, tc := range []struct{ name, value, code string }{{"healthy", "", ""}, {"vpn", `[{"ifname":"fixture-vpn","linkinfo":{"info_kind":"wireguard"}}]`, "firewall_conflict"}, {"table", `{"nftables":[{"table":{"name":"flowgate_host"}}]}`, "instance_or_foreign_table"}, {"mark", `{"nftables":[{"rule":{"mark":1}}]}`, "firewall_conflict"}, {"opaque-mark", `{"nftables":[{"rule":{"expr":[{"xt":{"name":"MARK","type":"target"}}]}}]}`, "firewall_conflict"}, {"opaque-copy", `{"nftables":[{"rule":{"expr":[{"xt":{"name":"CONNMARK","type":"target"}}]}}]}`, "firewall_conflict"}, {"queue", "101 0 0", "queue_occupied"}} {
		t.Run(tc.name, func(t *testing.T) {
			env := fakeEnv()
			original := env.Run
			env.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if tc.name == "vpn" && name == "ip" {
					return []byte(tc.value), nil
				}
				if (tc.name == "table" || tc.name == "mark" || strings.HasPrefix(tc.name, "opaque")) && name == "nft" {
					return []byte(tc.value), nil
				}
				return original(ctx, name, args...)
			}
			if tc.name == "queue" {
				env.Read = func(path string) ([]byte, error) {
					if path == "/proc/net/netfilter/nfnetlink_queue" {
						return []byte(tc.value), nil
					}
					return nil, os.ErrNotExist
				}
			}
			found := false
			for _, c := range Firewall(context.Background(), env) {
				if c.Status == Blocked {
					if c.Code != tc.code {
						t.Fatal(c)
					}
					found = true
				}
			}
			if found != (tc.code != "") {
				t.Fatal("conflict classification", found)
			}
		})
	}
}
func TestPermissionAndExternalTimeout(t *testing.T) {
	env := fakeEnv()
	env.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, os.ErrPermission }
	for _, c := range Firewall(context.Background(), env) {
		if c.ID == "firewall.ruleset" && (c.Status != Unchecked || c.Code != "permission_required") {
			t.Fatal(c)
		}
	}
	// Sleep is a subprocess under a hard context bound, never a timing-based race.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Run(ctx, "sleep", "10")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatal(err, time.Since(start))
	}
	if ProbeFailure("test", err).Code != "probe_timeout" {
		t.Fatal("timeout not distinguished")
	}
}
func TestOptionalHelperAndBTF(t *testing.T) {
	dir := t.TempDir()
	if c := Helper(filepath.Join(dir, "absent")); c.Status != Optional || c.Code != "helper_missing" {
		t.Fatal(c)
	}
	file := filepath.Join(dir, "helper")
	os.WriteFile(file, []byte("not ELF"), 0700)
	if c := Helper(file); c.Code != "helper_incompatible" {
		t.Fatal(c)
	}
	file = filepath.Join(dir, "btf")
	strings := []byte("\x00other_name\x00")
	h := make([]byte, 24)
	binary.LittleEndian.PutUint16(h, 0xeb9f)
	h[2] = 1
	binary.LittleEndian.PutUint32(h[4:], 24)
	binary.LittleEndian.PutUint32(h[20:], uint32(len(strings)))
	os.WriteFile(file, append(h, strings...), 0600)
	if c := BTFNames(file); c.Status != Optional || c.Code != "hook_missing" {
		t.Fatal(c)
	}
	strings = []byte("\x00btf_trace_sock_send_length\x00btf_trace_sock_recv_length\x00")
	binary.LittleEndian.PutUint32(h[20:], uint32(len(strings)))
	os.WriteFile(file, append(h, strings...), 0600)
	if c := BTFNames(file); c.Status != Ready {
		t.Fatal(c)
	}
}
