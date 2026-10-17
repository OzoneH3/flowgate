package udpaccount

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/readiness"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Run starts only the explicitly selected helper; it never invokes nft or a shell.
// The helper/object is built into one executable (libbpf skeleton), with no pins.
func Run(ctx context.Context, path, helper string, uid uint32) error {
	if os.Geteuid() != 0 {
		return readiness.Fail("permission_required", "extended collector requires privileged BPF load; frontend must remain unprivileged", "Run doctor; use the explicit terminal authentication workflow only when authorized")
	}
	if _, err := os.Stat(path); err == nil {
		return readiness.Fail("instance_or_socket_exists", "collector socket already exists; refusing to replace it", "Inspect doctor and collector status; Stop the confirmed owned collector")
	}
	if check := readiness.Helper(helper); check.Status != readiness.Ready {
		return &readiness.Failure{Check: check}
	}
	ns, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return err
	}
	netns := ns.Sys().(*syscall.Stat_t).Ino
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, helper, strconv.FormatUint(uint64(uid), 10), strconv.FormatUint(netns, 10))
	input, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		return err
	}
	defer func() { input.Close(); cancel(); cmd.Wait() }()
	scan := bufio.NewScanner(output)
	scan.Buffer(make([]byte, 4096), 1024*1024)
	ready := make(chan bool, 1)
	go func() { ready <- scan.Scan() && scan.Text() == "READY" }()
	select {
	case ok := <-ready:
		if !ok {
			return readiness.Fail("bpf_load_failed", "UDP helper unavailable; BPF load/attach did not complete", "Run doctor --json; inspect the helper load error above for verifier, hook or permission details")
		}
	case <-time.After(5 * time.Second):
		return readiness.Fail("probe_timeout", "BPF helper startup timeout", "Run doctor; no automatic retry is performed")
	case <-ctx.Done():
		return ctx.Err()
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer listener.Close()

	if err = os.Chown(path, int(uid), -1); err != nil {
		return err
	}
	if err = os.Chmod(path, 0600); err != nil {
		return err
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	generation := hex.EncodeToString(token[:])
	since := map[string]time.Time{}
	monotonicStart := time.Now()
	var mu sync.Mutex
	state := identity.UDPSnapshot{UID: uid, NetNS: identity.NetNS(), State: "warming-up", Generation: generation, Reason: "Waiting for first cookie registration"}
	// One serialized sampler and a bounded API, no client-controlled registration.
	go func() {
		for ctx.Err() == nil {
			sockets, e := identity.SocketsLimited(2048)
			cookies := []string{}
			kept := map[string]bool{}
			if e != nil {
				mu.Lock()
				state = identity.UDPSnapshot{State: "unavailable", Reason: e.Error()}
				mu.Unlock()
				cancel()
				return
			}
			for _, s := range sockets {
				if s.Protocol != "udp" || s.UID != uid {
					continue
				}
				b, e := hex.DecodeString(s.Cookie)
				if e != nil || len(b) != 8 {
					continue
				}
				v := binary.NativeEndian.Uint64(b)
				if v == 0 || v == ^uint64(0) {
					continue
				}
				cookies = append(cookies, strconv.FormatUint(v, 10))
				kept[s.Cookie] = true
			}
			if _, e = fmt.Fprintln(input, strings.Join(cookies, " ")); e != nil {
				cancel()
				return
			}
			if !scan.Scan() {
				cancel()
				return
			}
			var raw struct {
				Rows []struct {
					Cookie     string `json:"cookie"`
					Uploaded   uint64 `json:"uploaded"`
					Downloaded uint64 `json:"downloaded"`
					New        bool   `json:"new"`
				}
				Missed uint64 `json:"missed_operations"`
			}
			if e = json.Unmarshal(scan.Bytes(), &raw); e != nil || len(raw.Rows) > 2048 {
				cancel()
				return
			}
			now := time.Now()
			next := identity.UDPSnapshot{UID: uid, NetNS: identity.NetNS(), State: "active", Generation: generation, Collected: now, SampleNS: time.Since(monotonicStart).Nanoseconds(), Missed: raw.Missed, Rows: map[string]identity.UDPCount{}, Reason: "UDP API-reported socket payload bytes; no per-peer split; not delivery evidence"}
			if raw.Missed > 0 {
				next.Reason += "; partial coverage: unregistered-cookie operations missed"
			}
			for _, r := range raw.Rows {
				v, e := strconv.ParseUint(r.Cookie, 16, 64)
				if e != nil {
					cancel()
					return
				}
				b := make([]byte, 8)
				binary.NativeEndian.PutUint64(b, v)
				k := hex.EncodeToString(b)
				if !kept[k] {
					cancel()
					return
				}
				if r.New || since[k].IsZero() {
					since[k] = now
				}
				next.Rows[k] = identity.UDPCount{Uploaded: r.Uploaded, Downloaded: r.Downloaded, Since: since[k]}
			}
			for k := range since {
				if !kept[k] {
					delete(since, k)
				}
			}
			mu.Lock()
			state = next
			mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}()
	go func() { <-ctx.Done(); listener.Close() }()
	fmt.Fprintln(os.Stderr, "READY extended-traffic: collection only; no firewall changes", path)
	slots := make(chan struct{}, 8)
	for {
		c, e := listener.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-slots; c.Close() }()
			c.SetDeadline(time.Now().Add(time.Second))
			u := c.(*net.UnixConn)
			raw, _ := u.SyscallConn()
			var cred *unix.Ucred
			raw.Control(func(fd uintptr) { cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
			if cred == nil || cred.Uid != uid {
				return
			}
			var q struct {
				Version   int
				Operation string
			}
			reader := bufio.NewReaderSize(c, 4096)
			line, _, err := reader.ReadLine()
			response := identity.UDPSnapshot{State: "error", Reason: "invalid collection-only request"}
			if err == nil && len(line) < 4096 && json.Unmarshal(line, &q) == nil && q.Version == 1 {
				switch q.Operation {
				case "list":
					mu.Lock()
					response = state
					mu.Unlock()
				case "stop":
					response.State = "stopped"
					response.Reason = "Only this collector stopped; firewall unchanged"
					defer cancel()
				}
			}
			response.Version = 1
			json.NewEncoder(c).Encode(response)
		}()
	}
}
