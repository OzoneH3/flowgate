package hostfirewall

// The boot/crash guard has no queue, mark or routing mutations. An ACCEPT here
// never overrides a foreign DROP. New TCP SYN and unestablished UDP fail closed;
// pre-existing connections and narrowly defined DHCP bootstrap are preserved.
import (
	"encoding/json"
	"flowgate/internal/daemon"
	"fmt"
	"os"
)

const GuardTable = "flowgate_guard"
const guardComment = "flowgate:continuous-startup:v1"

func guardRules() string {
	return `add table inet flowgate_guard { comment "flowgate:continuous-startup:v1"; }
add chain inet flowgate_guard input { type filter hook input priority 9; policy accept; }
add chain inet flowgate_guard output { type filter hook output priority 9; policy accept; }
add rule inet flowgate_guard input meta nfproto ipv4 udp sport 67 udp dport 68 accept
add rule inet flowgate_guard input ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept
add rule inet flowgate_guard output meta nfproto ipv4 udp sport 68 udp dport 67 accept
add rule inet flowgate_guard output ip6 daddr { fe80::/10, ff02::1:2 } udp sport 546 udp dport 547 accept
add rule inet flowgate_guard input meta l4proto tcp tcp flags & (syn | ack) == syn drop
add rule inet flowgate_guard output meta l4proto tcp tcp flags & (syn | ack) == syn drop
add rule inet flowgate_guard input ct state established,related accept
add rule inet flowgate_guard output ct state established,related accept
add rule inet flowgate_guard input meta l4proto { tcp, udp } drop
add rule inet flowgate_guard output meta l4proto { tcp, udp } drop
`
}
func guardOwned() (bool, error) {
	b, err := nft("-j", "list", "tables")
	if err != nil {
		return false, err
	}
	var v struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if err = json.Unmarshal(b, &v); err != nil {
		return false, err
	}
	for _, o := range v.Objects {
		if t, ok := o["table"]; ok {
			var x struct{ Name, Family string }
			json.Unmarshal(t, &x)
			if x.Name == GuardTable && x.Family == "inet" {
				b, err = nft("-j", "list", "table", "inet", GuardTable)
				if err != nil {
					return false, err
				}
				var z struct {
					Objects []map[string]json.RawMessage `json:"nftables"`
				}
				if err = json.Unmarshal(b, &z); err != nil {
					return false, err
				}
				for _, p := range z.Objects {
					if t, ok := p["table"]; ok {
						var x struct{ Comment string }
						json.Unmarshal(t, &x)
						if x.Comment == guardComment {
							return true, nil
						}
					}
				}
				return false, fmt.Errorf("guard name occupied without exact FlowGate ownership; not modified")
			}
		}
	}
	return false, nil
}
func InstallGuard(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := daemon.SecureDirectory(dir); err != nil {
		return err
	}
	return evaluationLock(dir, func() error {
		yes, err := guardOwned()
		if err != nil || yes {
			return err
		}
		return batch(guardRules())
	})
}
func RemoveGuard(dir string) error {
	return evaluationLock(dir, func() error {
		yes, err := guardOwned()
		if err != nil || !yes {
			return err
		}
		_, err = nft("delete", "table", "inet", GuardTable)
		return err
	})
}

// RecoverContinuous never removes a live daemon's interception. It protects new
// admissions before reclaiming a stale exact-token record for the same netns.
func RecoverContinuous(dir string) error {
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	r, err := Read(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if r.State == "stopped" {
		return nil
	}
	if !r.Continuous {
		return fmt.Errorf("unfinished bounded evaluation requires explicit scoped recovery")
	}
	if r.Start != "" && startID(r.PID) == r.Start {
		return fmt.Errorf("continuous consumer still alive; refusing competing owner")
	}
	if err = InstallGuard(dir); err != nil {
		return err
	}
	return Recover(dir, r.Token)
}
