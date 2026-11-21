package udpaccount

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flowgate/internal/identity"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type session struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	state  identity.UDPSnapshot
	err    error
}

func generation() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func (s *session) snapshot() identity.UDPSnapshot { s.mu.Lock(); defer s.mu.Unlock(); return s.state }

// Only the daemon observer consumes final snapshots, once; status/API polling
// remains a pure read and cannot move an accounting cursor.
func (s *session) accountingSnapshot() identity.UDPSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state
	if time.Since(s.state.Collected) <= 4*time.Second {
		s.state.Retired = nil
	}
	return out
}
func (s *session) failure() error { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *session) close()         { s.cancel(); <-s.done }
func startPinnedSession(parent context.Context, pinned *os.File, uid uint32, machine bool) (*session, error) {
	// The first ExtraFiles entry becomes descriptor 3 in the child.
	return startSession(parent, "/proc/self/fd/3", uid, machine, pinned)
}

func startSession(parent context.Context, helper string, uid uint32, machine bool, files ...*os.File) (*session, error) {
	ns, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	target := strconv.FormatUint(uint64(uid), 10)
	if machine {
		target = "all"
	}
	cmd := exec.CommandContext(ctx, helper, target, strconv.FormatUint(ns.Sys().(*syscall.Stat_t).Ino, 10))
	cmd.ExtraFiles = files
	// A crashed daemon closes stdin; the native helper exits/detaches on EOF.
	cmd.WaitDelay = 200 * time.Millisecond
	input, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		cancel()
		return nil, err
	}
	stderr := &boundedError{}
	cmd.Stderr = stderr
	if err = cmd.Start(); err != nil {
		input.Close()
		cancel()
		return nil, err
	}
	s := &session{ctx: ctx, cancel: cancel, done: make(chan struct{}), state: identity.UDPSnapshot{Version: 1, UID: uid, Machine: machine, NetNS: identity.NetNS(), Generation: generation(), State: "warming-up", Reason: "Waiting for cookie registration"}}
	ready := make(chan error, 1)
	go func() {
		defer close(s.done)
		defer cancel()
		err := s.sample(input, output, ready)
		input.Close()
		cancel()
		waitErr := cmd.Wait()
		if err == nil && parent.Err() == nil {
			err = waitErr
		}
		if err != nil {
			s.mu.Lock()
			s.err = fmt.Errorf("%v; helper: %s", err, stderr.String())
			s.state.State = "unavailable"
			s.state.Reason = s.err.Error()
			s.state.Rows = nil
			s.mu.Unlock()
		}
	}()
	select {
	case err = <-ready:
		if err != nil {
			s.close()
			return nil, fmt.Errorf("%v; helper: %s", err, stderr.String())
		}
		return s, nil
	case <-time.After(5 * time.Second):
		s.close()
		return nil, fmt.Errorf("UDP helper startup timeout: %s", stderr.String())
	case <-parent.Done():
		s.close()
		return nil, parent.Err()
	}
}

// Bounds retained helper diagnostics; never retains packet payloads/process data.
type boundedError struct {
	mu sync.Mutex
	b  []byte
}

func (b *boundedError) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if len(b.b) < 4096 {
		left := 4096 - len(b.b)
		if len(p) > left {
			p = p[:left]
		}
		b.b = append(b.b, p...)
	}
	return n, nil
}
func (b *boundedError) String() string { b.mu.Lock(); defer b.mu.Unlock(); return string(b.b) }
func (s *session) sample(input io.Writer, output io.Reader, ready chan<- error) error {
	scan := bufio.NewScanner(output)
	scan.Buffer(make([]byte, 4096), 1024*1024)
	if !scan.Scan() || scan.Text() != "READY" {
		err := fmt.Errorf("BPF helper did not report READY")
		ready <- err
		return err
	}
	ready <- nil
	since := map[string]time.Time{}
	start := time.Now()
	for s.ctx.Err() == nil {
		sockets, err := identity.SocketsLimited(2048)
		if err != nil {
			return err
		}
		cookies := []string{}
		kept := map[string]bool{}
		state := s.snapshot()
		for _, socket := range sockets {
			if socket.Protocol != "udp" || (!state.Machine && socket.UID != state.UID) {
				continue
			}
			b, err := hex.DecodeString(socket.Cookie)
			if err != nil || len(b) != 8 {
				continue
			}
			v := binary.NativeEndian.Uint64(b)
			if v == 0 || v == ^uint64(0) {
				continue
			}
			if kept[socket.Cookie] {
				continue
			}
			kept[socket.Cookie] = true
			cookies = append(cookies, strconv.FormatUint(v, 10))
		}
		// Include pipe writes in the watchdog: a READY helper may stop reading.
		timer := time.AfterFunc(3*time.Second, s.cancel)
		if _, err = fmt.Fprintln(input, strings.Join(cookies, " ")); err != nil {
			timer.Stop()
			return err
		}
		// CommandContext cancels a wedged/crashed helper; bounded sampler watchdog.
		ok := scan.Scan()
		timer.Stop()
		if !ok {
			return fmt.Errorf("UDP helper snapshot unavailable: %v", scan.Err())
		}
		var raw struct {
			Rows []struct {
				Cookie     string `json:"cookie"`
				Uploaded   uint64 `json:"uploaded"`
				Downloaded uint64 `json:"downloaded"`
				New        bool   `json:"new"`
				Retired    bool   `json:"retired"`
			}
			Missed         uint64  `json:"missed_operations"`
			TracingSkipped *uint64 `json:"tracing_skipped_runs"`
		}
		if err = json.Unmarshal(scan.Bytes(), &raw); err != nil || len(raw.Rows) > 4096 {
			return fmt.Errorf("invalid/oversized UDP helper snapshot")
		}
		now := time.Now()
		state.State = "active"
		state.Collected = now
		state.SampleNS = time.Since(start).Nanoseconds()
		state.Missed = raw.Missed
		state.TracingSkipped = raw.TracingSkipped
		state.Rows = map[string]identity.UDPCount{}
		finals := map[string]identity.UDPCount{}
		state.Reason = sampleReason(state)
		for _, r := range raw.Rows {
			v, err := strconv.ParseUint(r.Cookie, 16, 64)
			if err != nil {
				return err
			}
			var b [8]byte
			binary.NativeEndian.PutUint64(b[:], v)
			key := hex.EncodeToString(b[:])
			if r.Retired {
				if kept[key] || since[key].IsZero() {
					return fmt.Errorf("unregistered final helper cookie")
				}
				if _, ok := finals[key]; ok {
					return fmt.Errorf("duplicate final helper cookie")
				}
				finals[key] = identity.UDPCount{Uploaded: r.Uploaded, Downloaded: r.Downloaded, Since: since[key]}
				continue
			}
			if !kept[key] {
				return fmt.Errorf("unregistered helper cookie")
			}
			if _, exists := state.Rows[key]; exists {
				return fmt.Errorf("duplicate helper cookie")
			}
			if r.New || since[key].IsZero() {
				since[key] = now
			}
			state.Rows[key] = identity.UDPCount{Uploaded: r.Uploaded, Downloaded: r.Downloaded, Since: since[key]}
		}
		if len(state.Rows) != len(kept) {
			return fmt.Errorf("helper omitted registered cookies")
		}
		for key := range since {
			if !kept[key] {
				delete(since, key)
			}
		}
		s.publishSnapshot(state, finals)
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return s.ctx.Err()
}

func (s *session) publishSnapshot(state identity.UDPSnapshot, finals map[string]identity.UDPCount) {
	s.mu.Lock()
	// Merge only under the publication mutex: a concurrent consume must not
	// resurrect final values copied at the beginning of this sampling pass.
	state.Retired = make(map[string]identity.UDPCount, len(s.state.Retired)+len(finals))
	for key, value := range s.state.Retired {
		state.Retired[key] = value
	}
	state.FinalsLost = s.state.FinalsLost
	for key, value := range finals {
		if len(state.Retired) >= 2048 {
			state.FinalsLost++
			continue
		}
		state.Retired[key] = value
	}
	if state.FinalsLost > 0 {
		state.Reason += "; partial coverage: final counter snapshot capacity exceeded"
	}
	s.state = state
	s.mu.Unlock()
}

func sampleReason(state identity.UDPSnapshot) string {
	reason := "UDP API-reported socket payload bytes; socket totals across all peers; not delivery evidence"
	if gap := state.TracingGapReason(); gap != "" {
		reason += "; " + gap
	}
	if state.Missed > 0 {
		reason += "; partial coverage: unregistered-cookie operations missed"
	}
	return reason
}
