// Package tcpinit owns an optional native observational sockops helper.
// No policy, packets, network mutations or API server live here.
package tcpinit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flowgate/internal/identity"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type query struct {
	cookies []string
	reply   chan identity.InitiationEvents
}
type Collector struct {
	mu       sync.Mutex
	state    identity.InitiationEvents
	requests chan query
	cancel   context.CancelFunc
	done     chan struct{}
	pinned   string
}
type boundedError struct {
	mu sync.Mutex
	b  []byte
}

func (b *boundedError) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if len(b.b) < 4096 {
		b.b = append(b.b, p[:min(len(p), 4096-len(b.b))]...)
	}
	return n, nil
}
func (b *boundedError) String() string { b.mu.Lock(); defer b.mu.Unlock(); return string(b.b) }

type Options struct{ ObserveShared bool }

func New(parent context.Context, helper, cgroup, pinDir string) *Collector {
	return NewWithOptions(parent, helper, cgroup, pinDir, Options{})
}
func NewWithOptions(parent context.Context, helper, cgroup, pinDir string, options Options) *Collector {
	ctx, cancel := context.WithCancel(parent)
	c := &Collector{requests: make(chan query), cancel: cancel, done: make(chan struct{}), state: identity.InitiationEvents{State: "disabled", NetNS: identity.NetNS(), Reason: "Optional event source not configured; snapshot handshake sampling remains available"}}
	fail := func(err error) *Collector {
		c.state.State = "failed"
		c.state.Reason = err.Error()
		cancel()
		close(c.done)
		return c
	}
	if helper == "" {
		close(c.done)
		return c
	}
	if !filepath.IsAbs(helper) || !filepath.IsAbs(cgroup) {
		return fail(fmt.Errorf("absolute reviewed helper and cgroup-v2 paths required"))
	}
	f, err := os.Open(helper)
	if err != nil {
		return fail(err)
	}
	data, err := io.ReadAll(io.LimitReader(f, 32*1024*1024+1))
	f.Close()
	if err != nil || len(data) > 32*1024*1024 || !bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) || !bytes.Contains(data, []byte("FLOWGATE_TCP_INITIATION_PROTOCOL=1")) {
		return fail(fmt.Errorf("bounded ELF initiation helper protocol1 required"))
	}
	p, err := os.CreateTemp(pinDir, ".flowgate-initiation-")
	if err != nil {
		return fail(err)
	}
	c.pinned = p.Name()
	if err = p.Chmod(0700); err == nil {
		_, err = p.Write(data)
	}
	closeErr := p.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(c.pinned)
		return fail(err)
	}
	var nonce [16]byte
	rand.Read(nonce[:])
	c.state.Generation = hex.EncodeToString(nonce[:])
	c.state.State = "starting"
	c.state.Reason = "Waiting for actual cgroup sockops load/attach"
	go c.run(ctx, cgroup, options.ObserveShared)
	return c
}
func (c *Collector) status() identity.InitiationEvents {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state
	s.Rows = nil
	return s
}
func (c *Collector) Sample(sockets []identity.Socket) identity.InitiationEvents {
	state := c.status()
	if state.State != "active" {
		return state
	}
	keys := []string{}
	seen := map[string]bool{}
	for _, s := range sockets {
		if len(keys) >= 2048 {
			break
		}
		if s.Protocol != "tcp" || s.NetNS != state.NetNS || seen[s.Cookie] {
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
		keys = append(keys, strconv.FormatUint(v, 10))
		seen[s.Cookie] = true
	}
	q := query{keys, make(chan identity.InitiationEvents, 1)}
	timer := time.NewTimer(1500 * time.Millisecond)
	defer timer.Stop()
	select {
	case c.requests <- q:
	case <-c.done:
		return c.status()
	case <-timer.C:
		state.State = "unavailable"
		state.Reason = "Initiation query worker unavailable"
		return state
	}
	select {
	case s := <-q.reply:
		return s
	case <-c.done:
		return c.status()
	case <-timer.C:
		state.State = "unavailable"
		state.Reason = "Initiation query timed out; no old event evidence reused"
		return state
	}
}
func (c *Collector) Close() {
	c.cancel()
	<-c.done
	if c.pinned != "" {
		os.Remove(c.pinned)
	}
}
func (c *Collector) run(ctx context.Context, cgroup string, shared bool) {
	defer close(c.done)
	args := []string{cgroup}
	if shared {
		args = append(args, "--observe-shared")
	}
	cmd := exec.CommandContext(ctx, c.pinned, args...)
	cmd.WaitDelay = 200 * time.Millisecond
	input, err := cmd.StdinPipe()
	if err != nil {
		c.failed(err)
		return
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		c.failed(err)
		return
	}
	stderr := &boundedError{}
	cmd.Stderr = stderr
	if err = cmd.Start(); err != nil {
		input.Close()
		c.failed(err)
		return
	}
	defer func() { input.Close(); c.cancel(); cmd.Wait() }()
	scan := bufio.NewScanner(output)
	scan.Buffer(make([]byte, 4096), 512*1024)
	watchdog := time.AfterFunc(5*time.Second, c.cancel)
	ready := scan.Scan() && scan.Text() == "READY"
	watchdog.Stop()
	if !ready {
		c.failed(fmt.Errorf("initiation unavailable: helper did not attach: %s", stderr.String()))
		return
	}
	c.mu.Lock()
	c.state.State = "active"
	c.state.Partial = true
	c.state.Reason = "Actual sockops established callbacks; only sockets covered by the configured cgroup/current network namespace"
	if shared {
		c.state.Reason += "; explicit shared observation, no callback/tuning writes; evidence requires existing lifecycle notifications"
	}
	c.mu.Unlock()
	for {
		select {
		case <-ctx.Done():
			c.failed(ctx.Err())
			return
		case q := <-c.requests:
			watchdog = time.AfterFunc(time.Second, c.cancel)
			_, err = io.WriteString(input, strings.Join(q.cookies, " ")+"\n")
			if err == nil && !scan.Scan() {
				err = fmt.Errorf("helper disconnected: %s", stderr.String())
			}
			var state identity.InitiationEvents
			if err == nil {
				state, err = decode(scan.Bytes(), c.status(), q.cookies)
			}
			watchdog.Stop()
			if err != nil {
				c.failed(err)
				return
			}
			c.mu.Lock()
			c.state = state
			c.state.Rows = nil
			c.mu.Unlock()
			q.reply <- state
		}
	}
}
func (c *Collector) failed(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.State = "failed"
	c.state.Reason = err.Error()
	c.state.Rows = nil
}
func decode(b []byte, state identity.InitiationEvents, wanted []string) (identity.InitiationEvents, error) {
	var raw struct {
		Rows []struct {
			Cookie    string `json:"cookie"`
			Direction uint32 `json:"direction"`
			Observed  uint64 `json:"observed_ns"`
		} `json:"rows"`
		Lost uint64 `json:"lost_events"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return state, err
	}
	if len(raw.Rows) > 2048 {
		return state, fmt.Errorf("event response exceeds socket bound")
	}
	allow := map[uint64]bool{}
	for _, v := range wanted {
		n, _ := strconv.ParseUint(v, 10, 64)
		allow[n] = true
	}
	var mono unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono); err != nil {
		return state, err
	}
	now := time.Now()
	state.Collected = now
	state.Rows = map[string]identity.Initiation{}
	state.Lost = raw.Lost
	state.Partial = true // only post-attachment callbacks in the configured cgroup; no complete-history claim
	for _, r := range raw.Rows {
		key, err := strconv.ParseUint(r.Cookie, 16, 64)
		if err != nil || !allow[key] || r.Observed == 0 || r.Observed > uint64(mono.Nano()) || r.Direction < 1 || r.Direction > 3 {
			return state, fmt.Errorf("invalid/unrequested initiation evidence")
		}
		var bytes [8]byte
		binary.NativeEndian.PutUint64(bytes[:], key)
		cookie := hex.EncodeToString(bytes[:])
		if _, ok := state.Rows[cookie]; ok {
			return state, fmt.Errorf("duplicate event cookie")
		}
		at := now.Add(-time.Duration(uint64(mono.Nano()) - r.Observed))
		v := identity.Initiation{State: "known", Generation: state.Generation, ObservedAt: &at, Source: "cgroup-sockops-active-established", Direction: "outgoing", Reason: "Kernel active-established callback for this exact socket cookie; not byte direction or permission authority"}
		if r.Direction == 2 {
			v.Direction = "incoming"
			v.Source = "cgroup-sockops-passive-established"
			v.Reason = "Kernel passive-established callback for this exact accepted socket cookie; not inferred by port"
		}
		if r.Direction == 3 {
			v.State = "ambiguous"
			v.Direction = ""
			v.Reason = "Conflicting callbacks for the same cookie"
		}
		state.Rows[cookie] = v
	}
	return state, nil
}
