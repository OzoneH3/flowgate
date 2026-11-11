package identity

import (
	"errors"
	"fmt"
	"testing"
)

func TestWineActivityImageDiscoverySharingAndIsolation(t *testing.T) {
	for _, prefix := range []string{"/prefix-one", "/prefix-two"} {
		t.Run(prefix, func(t *testing.T) {
			keys := []wineImageKey{{"/images/alpha.exe", "alpha-revision"}, {"/images/beta.exe", "beta-revision"}}
			broker := Process{PID: 1, Start: "broker", UID: 1000, NetNS: "net", MountNS: "broker-mount"}
			base := Process{PID: 2, Start: "start", UID: 1000, NetNS: "net", MountNS: "image-mount", Application: Application{Kind: "wine", Prefix: prefix}}
			for _, scenario := range []string{"valid", "generation", "uid", "netns", "mountns", "prefix", "peer", "fd-error", "after-map", "wrong-revision", "deleted-later", "deleted-first", "other-prefix", "cancelled", "cancelled-mid", "process-error"} {
				t.Run(scenario, func(t *testing.T) {
					counts := map[string]int{}
					ops := wineImageDiscovery{
						processes: func() ([]int, error) {
							counts["processes"]++
							if scenario == "process-error" {
								return nil, errors.New("unreadable")
							}
							if scenario == "deleted-later" {
								return []int{2, 3}, nil
							}
							if scenario == "deleted-first" {
								return []int{3, 2}, nil
							}
							return []int{2}, nil
						},
						candidate: func(int, *Process) bool { return true },
						inspect: func(pid int) (Process, error) {
							counts[fmt.Sprint("inspect", pid)]++
							p := base
							p.PID = pid
							if scenario == "other-prefix" {
								p.Application.Prefix = "/different-prefix"
							}
							if counts[fmt.Sprint("inspect", pid)] == 2 {
								switch scenario {
								case "generation":
									p.Start = "reused"
								case "uid":
									p.UID++
								case "netns":
									p.NetNS = "other"
								case "mountns":
									p.MountNS = "other"
								case "prefix":
									p.Application.Prefix = "/different-prefix"
								}
							}
							return p, nil
						},
						maps: func(pid int) string {
							counts[fmt.Sprint("maps", pid)]++
							if pid == 3 {
								return "/images/alpha.exe (deleted)"
							}
							if scenario == "after-map" && counts["maps2"] == 2 {
								return "changed"
							}
							return "both mapped"
						},
						fds: func(pid int) (map[uint32]bool, error) {
							counts["fds"]++
							if scenario == "fd-error" {
								return nil, errors.New("unreadable")
							}
							if pid == 1 {
								return map[uint32]bool{11: true}, nil
							}
							return map[uint32]bool{22: true}, nil
						},
						peers: func() (map[uint32]uint32, error) {
							counts["peers"]++
							if scenario == "peer" {
								return map[uint32]uint32{22: 11}, nil
							}
							return map[uint32]uint32{22: 11, 11: 22}, nil
						},
						visible: func(p Process, k wineImageKey, maps string) bool {
							counts["visible"]++
							return p.Application.Prefix == prefix && maps == "both mapped" && (k == keys[0] || k == keys[1]) && !(scenario == "wrong-revision" && k == keys[1])
						},
					}
					proceed := func() bool { return scenario != "cancelled" && (scenario != "cancelled-mid" || counts["visible"] == 0) }
					got := discoverWineImages(&broker, prefix, keys, proceed, ops)
					switch scenario {
					case "valid":
						if !got[keys[0]] || !got[keys[1]] {
							t.Fatalf("images missing: %v", got)
						}
						if counts["processes"] != 1 || counts["inspect2"] != 2 || counts["maps2"] != 2 || counts["fds"] != 2 || counts["peers"] != 1 || counts["visible"] != 4 {
							t.Fatalf("discovery not shared or bookends missing: %v", counts)
						}
						// A second pass must perform every observation again.
						discoverWineImages(&broker, prefix, keys, proceed, ops)
						if counts["processes"] != 2 || counts["inspect2"] != 4 || counts["maps2"] != 4 {
							t.Fatalf("cross-pass cache: %v", counts)
						}
					case "deleted-later", "deleted-first", "wrong-revision":
						if (scenario == "deleted-later" || scenario == "deleted-first") && (got[keys[0]] || !got[keys[1]]) {
							t.Fatalf("deleted-image veto crossed or vanished: %v", got)
						}
						if scenario == "wrong-revision" && (!got[keys[0]] || got[keys[1]]) {
							t.Fatalf("image revision authority transferred: %v", got)
						}
					default:
						if len(got) != 0 {
							t.Fatalf("unsafe result %v", got)
						}
					}
				})
			}
		})
	}
}
