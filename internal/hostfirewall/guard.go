package hostfirewall

// The boot/crash guard has no queue, mark or routing mutations. An ACCEPT here
// never overrides a foreign DROP. New TCP SYN and unestablished UDP fail closed;
// pre-existing connections and narrowly defined DHCP bootstrap are preserved.
import (
	"encoding/json"
	"flowgate/internal/daemon"
	"flowgate/internal/decisionlog"
	"flowgate/internal/identity"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const GuardTable = "flowgate_guard"

type guardRecord struct {
	Token  string `json:"token"`
	NetNS  string `json:"netns"`
	Digest string `json:"digest"`
}

func guardMetadata(dir string) (guardRecord, error) {
	var r guardRecord
	path := filepath.Join(dir, "guard.json")
	st, err := os.Lstat(path)
	if err != nil {
		return r, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return r, fmt.Errorf("unsafe guard ownership metadata")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if len(b) > 4096 || json.Unmarshal(b, &r) != nil || !validNonce(r.Token) || r.NetNS != identity.NetNS() {
		return r, fmt.Errorf("invalid guard token/namespace metadata")
	}
	return r, nil
}
func saveGuard(dir string, r guardRecord) error {
	b, _ := json.Marshal(r)
	f, err := os.CreateTemp(dir, ".guard-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(dir, "guard.json"))
	}
	if err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func guardRules(token string) string {
	return strings.ReplaceAll(`add table inet flowgate_guard { comment "flowgate:guard:TOKEN"; }
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
`, "TOKEN", token)
}
func guardOwned(dir string) (bool, error) {
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
						r, er := guardMetadata(dir)
						if er != nil {
							return false, fmt.Errorf("unrecorded guard; refusing: %w", er)
						}
						if x.Comment == "flowgate:guard:"+r.Token {
							if r.Digest != "" {
								d, er := tableDigestFor(GuardTable)
								if er != nil {
									return false, er
								}
								if d != r.Digest {
									return false, fmt.Errorf("recorded guard structure changed; refusing automatic removal")
								}
							}
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
		yes, err := guardOwned(dir)
		if err != nil || yes {
			return err
		}
		r := guardRecord{Token: decisionlog.NewRecordID(), NetNS: identity.NetNS()}
		if err = saveGuard(dir, r); err != nil {
			return err
		}
		if err = batch(guardRules(r.Token)); err != nil {
			return err
		}
		r.Digest, err = tableDigestFor(GuardTable)
		if err != nil {
			return err
		}
		return saveGuard(dir, r)
	})
}
func RemoveGuard(dir string) error {
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		yes, er := guardOwned(dir)
		if er != nil {
			return er
		}
		if yes {
			return fmt.Errorf("guard exists without its private state")
		}
		return nil
	} else if err != nil {
		return err
	}
	return evaluationLock(dir, func() error {
		yes, err := guardOwned(dir)
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
