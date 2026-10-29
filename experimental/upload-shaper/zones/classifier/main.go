// Test-only stdin driver: production Manager and authoritative classifier, no
// listening API, daemon, alternative classifier, or firewall configuration.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"flowgate/internal/uploadshape"
)

func main() {
	parent := os.Getenv("FLOWGATE_PARENT_NETNS")
	current, namespaceErr := os.Readlink("/proc/self/ns/net")
	if namespaceErr != nil || parent == "" || current == parent {
		panic("classifier fixture requires a disposable child network namespace")
	}

	if len(os.Args) != 4 {
		panic("usage: classifier-driver INTERFACE HELPERS STATE")
	}
	var source atomic.Value
	initial, err := identity.NewNetworkZones([]string{"10.79.0.2/32"}, nil)
	if err != nil {
		panic(err)
	}
	source.Store(initial)
	e := daemon.New(time.Second)
	defer e.CloseProcessTargets()
	e.ZoneSource = func() identity.NetworkZones { return source.Load().(identity.NetworkZones) }
	m, err := uploadshape.New(uploadshape.Options{Interface: os.Args[1], Helpers: os.Args[2], State: os.Args[3], HostTrial: true, Zones: e.CurrentZones})
	if err != nil {
		panic(err)
	}
	defer m.Close()
	out := json.NewEncoder(os.Stdout)
	_ = out.Encode(map[string]any{"ready": true})
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var q struct {
			Op     string             `json:"op"`
			Zone   string             `json:"zone"`
			Config uploadshape.Config `json:"config"`
		}
		var result any
		if err = json.Unmarshal(scanner.Bytes(), &q); err == nil {
			switch q.Op {
			case "status":
				result = m.Snapshot()
			case "configure":
				result, err = m.Configure(m.Snapshot().Version, q.Config)
			case "zone":
				var local, internet []string
				switch q.Zone {
				case "local":
					local = []string{"10.79.0.2/32"}
				case "internet":
					internet = []string{"10.79.0.2/32"}
				case "":
				default:
					err = fmt.Errorf("unsupported fixture zone")
				}
				if err == nil {
					var z identity.NetworkZones
					z, err = identity.NewNetworkZones(local, internet)
					if err == nil {
						source.Store(z)
						result = e.CurrentZones()
					}
				}
			case "stop":
				m.Close()
				_ = out.Encode(map[string]any{"stopped": true})
				return
			default:
				err = fmt.Errorf("unsupported fixture operation")
			}
		}
		if err != nil {
			_ = out.Encode(map[string]any{"error": err.Error()})
		} else {
			_ = out.Encode(map[string]any{"result": result})
		}
	}
}
