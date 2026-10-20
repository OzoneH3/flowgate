package identity

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Instance is server-issued immutable native identity. Session prevents replay
// after daemon restart; a pidfd additionally pins the actual process lifetime.
type Instance struct {
	ID         string `json:"instance_id"`
	Session    string `json:"session"`
	BootID     string `json:"boot_id"`
	PID        int    `json:"pid"`
	Start      string `json:"start_ticks"`
	UID        uint32 `json:"uid"`
	NetNS      string `json:"netns"`
	MountNS    string `json:"mountns"`
	PIDNS      string `json:"pidns"`
	Executable string `json:"executable"`
	Revision   string `json:"revision"`
	// ExecutableRevision: the running file's stamp when it differs from the
	// application revision (a verified Electron app: runtime file vs bundle).
	// Empty for native processes, whose Revision is the running file's stamp.
	ExecutableRevision string `json:"executable_revision,omitempty"`
}

// fileRevision is the stamp the live /proc/PID/exe must have.
func (i Instance) fileRevision() string {
	if i.ExecutableRevision != "" {
		return i.ExecutableRevision
	}
	return i.Revision
}

func (i Instance) IsZero() bool { return i == Instance{} }

var bootOnce sync.Once
var bootID string

func BootID() string {
	bootOnce.Do(func() { bootID = strings.TrimSpace(string(readBound("/proc/sys/kernel/random/boot_id", 128))) })
	return bootID
}
func threadGroup(base string) int {
	for _, line := range strings.Split(string(readBound(base+"/status", 8192)), "\n") {
		if strings.HasPrefix(line, "Tgid:") {
			v, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Tgid:")))
			return v
		}
	}
	return 0
}
func BindInstance(session string, p Process) (Instance, error) {
	if session == "" || p.PID <= 0 || p.ThreadGroup != p.PID || p.BootID == "" || p.Start == "" || p.PIDNS == "" || p.NetNS == "" || p.MountNS == "" || !instanceIdentity(p) {
		return Instance{}, fmt.Errorf("live native thread-group leader with boot/namespace/executable identity required")
	}
	i := Instance{Session: session, BootID: p.BootID, PID: p.PID, Start: p.Start, UID: p.UID, NetNS: p.NetNS, MountNS: p.MountNS, PIDNS: p.PIDNS, Executable: p.Executable, Revision: p.ExecutableRevision}
	if p.Application.Kind == "electron" {
		i.Revision, i.ExecutableRevision = p.Application.Revision, p.ExecutableRevision
	}
	return i, nil
}
func (i Instance) Matches(p Process) bool {
	return i.PID == p.PID && i.Start == p.Start && i.UID == p.UID && i.BootID == p.BootID && i.NetNS == p.NetNS && i.MountNS == p.MountNS && i.PIDNS == p.PIDNS && i.Executable == p.Executable && i.fileRevision() == p.ExecutableRevision && i.Revision == p.Application.Revision && instanceIdentity(p) && p.ThreadGroup == i.PID
}

// instanceIdentity: a process whose instance may bind a process rule. Native:
// the application is the running file (same stamp). Verified Electron app: the
// instance pins the runtime file's own stamp; the bundle is the application.
func instanceIdentity(p Process) bool {
	if p.ExecutableRevision == "" || !LiveRuleable(p.Application) {
		return false
	}
	return p.Application.Kind == "electron" || p.ExecutableRevision == p.Application.Revision
}
func (i Instance) Check() error {
	base := fmt.Sprintf("/proc/%d", i.PID)
	start, _, err := processStat(base)
	if err != nil {
		return fmt.Errorf("process exited or became inaccessible")
	}
	st, err := os.Stat(base)
	if err != nil {
		return err
	}
	status := string(readBound(base+"/status", 8192))
	if strings.Contains(status, "State:\tZ") || threadGroup(base) != i.PID {
		return fmt.Errorf("process leader exited or thread-group identity changed")
	}
	if start != i.Start || i.BootID != BootID() || st.Sys().(*syscall.Stat_t).Uid != i.UID || link(base+"/ns/net") != i.NetNS || link(base+"/ns/mnt") != i.MountNS || link(base+"/ns/pid") != i.PIDNS || link(base+"/exe") != i.Executable || stamp(base+"/exe") != i.fileRevision() {
		return fmt.Errorf("process generation, executable, credentials or namespace changed")
	}
	if last, _, err := processStat(base); err != nil || last != i.Start {
		return fmt.Errorf("process changed during inspection")
	}
	return nil
}

type ProcessHandle struct {
	mu     sync.Mutex
	fd     int
	Target Instance
	reason string
}

func PinInstance(i Instance) (*ProcessHandle, error) {
	fd, err := unix.PidfdOpen(i.PID, 0)
	if err != nil {
		return nil, fmt.Errorf("pidfd unavailable: %w", err)
	}
	h := &ProcessHandle{fd: fd, Target: i}
	if err = h.Check(); err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}
func (h *ProcessHandle) Check() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.reason != "" {
		return fmt.Errorf("%s", h.reason)
	}
	if h.fd < 0 {
		return fmt.Errorf("process target handle closed")
	}
	fds := []unix.PollFd{{Fd: int32(h.fd), Events: unix.POLLIN}}
	_, err := unix.Poll(fds, 0)
	if err != nil {
		h.reason = "process liveness unavailable"
	} else if fds[0].Revents != 0 {
		h.reason = "process exited; this binding cannot be reused"
	} else if err = h.Target.Check(); err != nil {
		h.reason = err.Error()
	} else if _, err = unix.Poll(fds, 0); err != nil || fds[0].Revents != 0 {
		h.reason = "process exited during identity inspection"
	}
	if h.reason != "" {
		return fmt.Errorf("%s", h.reason)
	}
	return nil
}
func (h *ProcessHandle) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fd >= 0 {
		unix.Close(h.fd)
		h.fd = -1
	}
	if h.reason == "" {
		h.reason = "process handle closed"
	}
}
