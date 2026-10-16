// Package hostfirewall owns the explicit incoming-first profile. Importing it
// does nothing; only the host-start CLI invokes activation.
package hostfirewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"flowgate/internal/queue"
	"flowgate/internal/store"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const Table = "flowgate_host"
const Queue = 101

type Record struct {
	Profile      string
	MarksOwned   bool
	TableDigest  string
	SocketInodes map[string]uint64
	Token        string
	PID          int
	Start        string
	NetNS        string
	State        string
	StopsAt      time.Time
	UID          uint32
	Socket       string
}

func nft(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft: %w: %s", err, out)
	}
	return out, nil
}
func batch(s string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "nft", "-f", "-")
	c.Stdin = strings.NewReader(s)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft transaction: %w: %s", err, out)
	}
	return nil
}
func startID(pid int) string {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return ""
	}
	i := strings.LastIndex(string(b), ")")
	if i < 0 {
		return ""
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return ""
	}
	return f[19]
}
func lock(dir string) (*os.File, error) {
	if err := daemon.SecureDirectory(dir); err != nil {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("state directory must be owned by daemon user, mode 0700, not a symlink")
	}
	fd, err := unix.Open(filepath.Join(dir, "lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "lock")
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("active instance holds state lock: %w", err)
	}
	return f, nil
}
func save(dir string, r Record) error {
	b, _ := json.MarshalIndent(r, "", "  ")
	p := filepath.Join(dir, "instance.json")
	f, e := os.OpenFile(p+".new", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer os.Remove(p + ".new")
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	f.Close()
	if e != nil {
		return e
	}
	return os.Rename(p+".new", p)
}
func Read(dir string) (Record, error) {
	if err := daemon.SecureDirectory(dir); err != nil {
		return Record{}, err
	}
	var r Record
	b, e := os.ReadFile(filepath.Join(dir, "instance.json"))
	if e != nil {
		return r, e
	}
	if len(b) > 8192 {
		return r, fmt.Errorf("invalid instance record")
	}
	e = json.Unmarshal(b, &r)
	if e != nil {
		return r, e
	}
	if len(r.Token) != 32 || r.NetNS != identity.NetNS() {
		return r, fmt.Errorf("invalid generation or different network namespace")
	}
	return r, nil
}
func owns(r Record) (bool, error) {
	b, e := nft("-j", "list", "tables")
	if e != nil {
		return false, e
	}
	var v struct {
		NFT []map[string]json.RawMessage `json:"nftables"`
	}
	if e = json.Unmarshal(b, &v); e != nil {
		return false, e
	}
	for _, o := range v.NFT {
		if t, ok := o["table"]; ok {
			var x struct{ Family, Name, Comment string }
			json.Unmarshal(t, &x)
			if x.Family == "inet" && x.Name == Table {
				if x.Comment != "flowgate:"+r.Token {
					return false, fmt.Errorf("table belongs to another instance; refusing removal")
				}
				return true, nil
			}
		}
	}
	return false, nil
}
func remove(r Record) error {
	yes, err := owns(r)
	if err != nil {
		return err
	}
	if yes {
		if _, err = nft("delete", "table", "inet", Table); err != nil {
			return err
		}
	}
	if r.MarksOwned {
		if err := clearMarks(); err != nil {
			return err
		}
	}
	for path, ino := range r.SocketInodes {
		if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSocket != 0 && st.Sys().(*syscall.Stat_t).Ino == ino {
			if err = os.Remove(path); err != nil {
				return err
			}
		}
	}
	return nil
}
func preflight() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	links, err := exec.CommandContext(ctx, "ip", "-j", "-d", "link", "show").Output()
	if err != nil {
		return fmt.Errorf("interface inspection: %w", err)
	}
	var interfaces []struct {
		Ifname   string
		Linkinfo struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if err = json.Unmarshal(links, &interfaces); err != nil {
		return err
	}
	for _, i := range interfaces {
		switch i.Linkinfo.Kind {
		case "wireguard", "tun", "xfrm":
			return fmt.Errorf("VPN/tunnel interface %s (%s): initial profile requires a separately reviewed integration", i.Ifname, i.Linkinfo.Kind)
		}
	}
	for _, p := range []string{"/proc/net/ip_tables_names", "/proc/net/ip6_tables_names"} {
		if b, e := os.ReadFile(p); e == nil && len(bytes.TrimSpace(b)) != 0 {
			return fmt.Errorf("legacy iptables tables detected; coexistence unsupported")
		}
	}

	b, err := nft("-j", "list", "ruleset")
	if err != nil {
		return err
	}
	if bytes.Contains(b, []byte(`"flowgate_host"`)) {
		return fmt.Errorf("FlowGate table already exists; inspect status/recover first")
	}
	// Deliberately conservative first profile: any existing mark manipulation or
	// queue rule needs a reviewed allocation, not a guessed unused bit.
	for _, term := range []string{`"mark"`, `"queue"`, `"notrack"`, `"zone"`} {
		if bytes.Contains(b, []byte(term)) {
			return fmt.Errorf("existing rules use %s; initial profile cannot establish collision-free coexistence", term)
		}
	}
	q, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "Queue census unavailable; exclusive NFQUEUE bind must succeed before activation:", err)
	}
	for _, line := range strings.Split(string(q), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == strconv.Itoa(Queue) {
			return fmt.Errorf("queue 101 occupied")
		}
	}
	fmt.Fprintf(os.Stderr, "Preflight: existing nft rules retained (%d bytes). Local TCP/UDP (input and optional output); queue 101; connmark mask 0x30000000; input/output priority 10. Other firewall chains/VPNs may deny delivery. No forwarding coverage.\n", len(b))
	return nil
}
func rules(token string) string { return profileRules(token, "incoming") }
func profileRules(token, profile string) string {
	r := fmt.Sprintf(`add table inet %s { comment "flowgate:%s"; }
add chain inet %s input { type filter hook input priority 10; policy accept; }
add chain inet %s output { type filter hook output priority 10; policy accept; }
add chain inet %s inspect
add rule inet %s inspect queue num 101
add chain inet %s admit { type filter hook input priority 11; policy accept; }
add rule inet flowgate_host admit meta l4proto { tcp, udp } ct mark set ct mark | 0x10000000
add rule inet %s output meta l4proto { tcp, udp } ct direction original ct mark set ct mark | 0x20000000
add rule inet %s input meta l4proto != { tcp, udp } accept
add rule inet %s input meta nfproto ipv4 udp sport 67 udp dport 68 accept
add rule inet %s input ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept
add rule inet %s input ct state invalid counter drop
add rule inet %s input ct direction reply ct mark & 0x30000000 != 0 accept
add rule inet %s input meta l4proto tcp tcp flags & (syn | ack) == syn jump inspect
add rule inet %s input ct mark & 0x20000000 != 0 accept
add rule inet %s input meta l4proto tcp ct mark & 0x10000000 != 0 ct state established accept
add rule inet %s input meta l4proto udp jump inspect
add rule inet %s input counter drop
`, Table, token, Table, Table, Table, Table, Table, Table, Table, Table, Table, Table, Table, Table, Table, Table, Table, Table)
	if profile == "both" {
		r = strings.Replace(r, "add rule inet flowgate_host output meta l4proto { tcp, udp } ct direction original ct mark set ct mark | 0x20000000\n", "", 1)
		r += `add chain inet flowgate_host admit_output { type filter hook output priority 11; policy accept; }
add rule inet flowgate_host admit_output meta l4proto { tcp, udp } ct mark set ct mark | 0x10000000
add rule inet flowgate_host output meta l4proto != { tcp, udp } accept
add rule inet flowgate_host output meta nfproto ipv4 udp sport 68 udp dport 67 accept
add rule inet flowgate_host output ip6 daddr { fe80::/10, ff02::1:2 } udp sport 546 udp dport 547 accept
add rule inet flowgate_host output ct state invalid counter drop
add rule inet flowgate_host output ct direction reply ct mark & 0x30000000 != 0 accept
add rule inet flowgate_host output meta l4proto tcp tcp flags & (syn | ack) == syn jump inspect
add rule inet flowgate_host output ct mark & 0x20000000 != 0 accept
add rule inet flowgate_host output meta l4proto tcp ct mark & 0x10000000 != 0 ct state established accept
add rule inet flowgate_host output meta l4proto udp jump inspect
add rule inet flowgate_host output counter drop
`
	}
	return r
}

func Run(ctx context.Context, dir, socket, database string, uid uint32, duration, timeout time.Duration) error {
	return RunProfile(ctx, dir, socket, database, uid, duration, timeout, "incoming")
}
func RunProfile(ctx context.Context, dir, socket, database string, uid uint32, duration, timeout time.Duration, profile string) error {
	if profile != "incoming" && profile != "both" {
		return fmt.Errorf("profile must be incoming or both")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("host-start requires CAP_NET_ADMIN and root in its namespace; GUI must remain unprivileged")
	}
	if duration < 10*time.Second || duration > 30*time.Minute {
		return fmt.Errorf("evaluation duration must be 10s–30m")
	}
	if timeout < time.Second || timeout > 60*time.Second {
		return fmt.Errorf("decision timeout must be 1s–60s")
	}
	l, err := lock(dir)
	if err != nil {
		return err
	}
	defer l.Close()
	if previous, er := Read(dir); er == nil && previous.State != "stopped" {
		return fmt.Errorf("previous instance not stopped; inspect/recover before restarting")
	} else if er != nil && !os.IsNotExist(er) {
		return er
	}
	if err = preflight(); err != nil {
		return err
	}
	if database == "" {
		database = filepath.Join(dir, "rules.db")
	}
	if err = daemon.SecureDirectory(filepath.Dir(database)); err != nil {
		return err
	}
	db, err := store.Open(database)
	if err != nil {
		return fmt.Errorf("storage unavailable: %w", err)
	}
	defer db.Close()
	rs, err := db.Load()
	if err != nil {
		return err
	}
	e := daemon.New(timeout)
	e.Mode = "host-enforcement"
	e.APIUID = &uid
	e.SaveRules = db.Replace
	if err = e.SetRules(rs); err != nil {
		return err
	}
	inodes := map[string]uint64{}
	r := Record{Profile: profile, SocketInodes: inodes, Token: e.Generation, PID: os.Getpid(), Start: startID(os.Getpid()), NetNS: identity.NetNS(), State: "starting", StopsAt: time.Now().Add(duration), UID: uid, Socket: socket}
	var mu sync.Mutex
	e.Enforcement = func() daemon.EnforcementStatus {
		mu.Lock()
		defer mu.Unlock()
		state := r.State
		if state == "active" {
			if ok, err := owns(r); err != nil || !ok {
				state = "degraded"
			} else if digest, err := tableDigest(); err != nil || digest != r.TableDigest {
				state = "degraded"
			}
		}
		return daemon.EnforcementStatus{Profile: profile, State: state, Detail: "Profile " + profile + ": selected new TCP/UDP connections require policy/decision; startup flows preserved. FlowGate Allow does not guarantee delivery.", StopsAt: r.StopsAt}
	}
	api, err := daemon.Serve(socket, e, false)
	if err != nil {
		return err
	}
	defer api.Close()
	monitor, err := daemon.Serve(socket+".monitor", e, true)
	if err != nil {
		return err
	}
	defer monitor.Close()
	for _, p := range []string{socket, socket + ".monitor"} {
		st, er := os.Lstat(p)
		if er != nil {
			return er
		}
		inodes[p] = st.Sys().(*syscall.Stat_t).Ino
	}
	if err = save(dir, r); err != nil {
		return err
	}
	// Arm the independent bounded cleanup before any firewall/conntrack mutation.
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	watch := exec.Command(exe, "host-watch", "--state", dir, "--token", r.Token)
	watch.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	watchLog, err := os.OpenFile(filepath.Join(dir, "watchdog.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer watchLog.Close()
	watch.Stdout = watchLog
	watch.Stderr = watchLog
	if err = watch.Start(); err != nil {
		return err
	}
	go watch.Wait()
	installed := false
	runctx, cancel := context.WithDeadline(ctx, r.StopsAt)
	defer cancel()
	err = queue.RunConfigured(runctx, e, profile, Queue, false, func() error {
		if er := bootstrap(func() error { r.MarksOwned = true; return save(dir, r) }); er != nil {
			return er
		}
		if er := batch(profileRules(r.Token, profile)); er != nil {
			clearMarks()
			return er
		}
		installed = true
		digest, er := tableDigest()
		if er != nil {
			return er
		}
		mu.Lock()
		r.TableDigest = digest
		r.State = "active"
		er = save(dir, r)
		mu.Unlock()
		if er != nil {
			return er
		}
		fmt.Printf("READY host-enforcement generation=%s automatic-stop=%s\n", r.Token, r.StopsAt.Format(time.RFC3339))
		return nil
	})
	mu.Lock()
	defer mu.Unlock()
	if err != nil && installed {
		r.State = "degraded"
		save(dir, r)
		return fmt.Errorf("queue failed; owned table retained fail-closed until recovery or evaluation deadline: %w", err)
	}
	if er := remove(r); er != nil {
		r.State = "degraded"
		save(dir, r)
		return er
	}
	r.State = "stopped"
	save(dir, r)
	if installed {
		fmt.Println("STOPPED: removed only FlowGate-owned enforcement; remaining firewall configuration applies")
	}
	return err
}
func Stop(dir string) error                  { return stopInstance(dir, "") }
func StopGeneration(dir, token string) error { return stopInstance(dir, token) }
func stopInstance(dir, token string) error {
	r, err := Read(dir)
	if err != nil {
		return err
	}
	if token != "" && r.Token != token {
		return fmt.Errorf("instance changed; stale timer stopped")
	}
	// pidfd prevents PID reuse between verification and signal delivery.
	fd, err := unix.PidfdOpen(r.PID, 0)
	if err == nil {
		defer unix.Close(fd)
		if startID(r.PID) == r.Start && r.State != "stopped" {
			if err = unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil {
				return err
			}
			for i := 0; i < 50; i++ {
				time.Sleep(100 * time.Millisecond)
				v, e := Read(dir)
				if e == nil && v.Token == r.Token && v.State == "stopped" {
					return nil
				}
			}
			return fmt.Errorf("stop not confirmed; inspect status, then recover after process exit")
		}
	}
	return Recover(dir, r.Token)
}
func Recover(dir, token string) error {
	l, err := lock(dir)
	if err != nil {
		return err
	}
	defer l.Close()
	r, err := Read(dir)
	if os.IsNotExist(err) {
		fmt.Println("No recorded FlowGate instance; nothing removed")
		return nil
	}
	if err != nil {
		return err
	}
	if token != "" && r.Token != token {
		return fmt.Errorf("instance changed; refusing stale cleanup")
	}
	if r.State == "stopped" {
		fmt.Println("Already stopped; nothing removed")
		return nil
	}
	if err = remove(r); err != nil {
		return err
	}
	r.State = "stopped"
	if err = save(dir, r); err != nil {
		return err
	}
	fmt.Println("Recovered recorded FlowGate table and reserved mark bits only; other firewall objects retained")
	return nil
}
func Watch(dir, token string) error {
	for {
		r, err := Read(dir)
		if err != nil {
			return err
		}
		if r.Token != token || r.State == "stopped" {
			return nil
		}
		if time.Now().After(r.StopsAt) {
			fmt.Println("Evaluation deadline: deliberate stop of this FlowGate generation")
			return stopInstance(dir, token)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
func Status(dir string) (any, error) {
	r, err := Read(dir)
	if err != nil {
		return nil, err
	}
	present, e := owns(r)
	if e != nil {
		return nil, e
	}
	live := startID(r.PID) == r.Start && r.Start != ""
	state := r.State
	if present && !live {
		state = "degraded: consumer absent; undecided traffic blocked"
	}
	if present && live && r.State == "active" {
		if d, e := tableDigest(); e != nil || d != r.TableDigest {
			state = "degraded: owned rules changed"
		}
	}
	if !present && state != "stopped" {
		state = "unavailable: owned interception table absent"
	}
	return map[string]any{"state": state, "record": r, "table_present": present, "process_alive": live}, nil
}

// Counters vary with traffic; structural mutations must invalidate Active.
func tableDigest() (string, error) {
	b, err := nft("-j", "list", "table", "inet", Table)
	if err != nil {
		return "", err
	}
	var v any
	if err = json.Unmarshal(b, &v); err != nil {
		return "", err
	}
	var clean func(any)
	clean = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			delete(x, "metainfo")
			delete(x, "handle")
			delete(x, "packets")
			delete(x, "bytes")
			for _, y := range x {
				clean(y)
			}
		case []any:
			for _, y := range x {
				clean(y)
			}
		}
	}
	clean(v)
	b, _ = json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
