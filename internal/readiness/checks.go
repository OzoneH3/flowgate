// Package readiness inspects prerequisites only. It never installs rules, binds
// queues, loads programs or prepares runtime directories.
package readiness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const Queue = 101
const Table = "flowgate_host"
const (
	Ready     = "ready"
	Blocked   = "blocked"
	Optional  = "optional_unavailable"
	Unchecked = "not_checked"
)

type Check struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
	Next   string `json:"next,omitempty"`
}
type Failure struct{ Check Check }

func (e *Failure) Error() string {
	s := fmt.Sprintf("[%s] %s", e.Check.Code, e.Check.Detail)
	if e.Check.Next != "" {
		s += " Next: " + e.Check.Next
	}
	return s
}
func Fail(code, detail, next string) error {
	return &Failure{Check{Status: Blocked, Code: code, Detail: detail, Next: next}}
}

type Environment struct {
	Run  func(context.Context, string, ...string) ([]byte, error)
	Read func(string) ([]byte, error)
}

func Default() Environment { return Environment{Run: Run, Read: Read} }
func Read(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if len(b) > 1024*1024 {
		return nil, fmt.Errorf("inspection size limit")
	}
	return b, e
}

type limitedBuffer struct {
	bytes.Buffer
	over bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	left := 1024*1024 - b.Len()
	if len(p) > left {
		p = p[:left]
		b.over = true
	}
	b.Buffer.Write(p)
	return n, nil
}
func Run(parent context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 100 * time.Millisecond
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	var b limitedBuffer
	cmd.Stdout = &b
	cmd.Stderr = &b
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if b.over {
		return nil, fmt.Errorf("probe output limit reached")
	}
	if err != nil {
		if bytes.Contains(bytes.ToLower(b.Bytes()), []byte("permitted")) || bytes.Contains(bytes.ToLower(b.Bytes()), []byte("permission denied")) {
			return nil, os.ErrPermission
		}
		return nil, err
	}
	return b.Bytes(), nil
}
func ProbeFailure(id string, err error) Check {
	c := Check{ID: id, Status: Unchecked, Code: "probe_failed", Detail: "Read-only probe failed; no startup readiness established", Next: "Run doctor --json for individual check states"}
	var ee *exec.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		c.Code = "probe_timeout"
		c.Detail = "Read-only probe timed out"
	case errors.Is(err, os.ErrPermission):
		c.Code = "permission_required"
		c.Detail = "Read-only inspection denied by current credentials"
		c.Next = "Optional explicit sudo .workspace/flowgate doctor --json enables permitted read-only inspections; it does not activate anything"
	case errors.As(err, &ee) && errors.Is(ee.Err, exec.ErrNotFound):
		c.Status = Blocked
		c.Code = "dependency_missing"
		c.Detail = "Required inspection executable is unavailable"
		c.Next = "Inspect the dependency check; install only through your normal approved package workflow"
	}
	return c
}

// Firewall is also startup's preflight. Each item is a completed read-only check,
// never an assertion that NFQUEUE binding/interception will succeed.
func Firewall(ctx context.Context, env Environment) []Check {
	return FirewallFor(ctx, env, "incoming", false)
}
func FirewallFor(ctx context.Context, env Environment, profile string, administrator bool) []Check {
	out := []Check{}
	links, err := env.Run(ctx, "ip", "-j", "-d", "link", "show")
	if err != nil {
		out = append(out, ProbeFailure("firewall.interfaces", err))
	} else {
		var interfaces []struct {
			Ifname   string
			Linkinfo struct {
				Kind string `json:"info_kind"`
			} `json:"linkinfo"`
		}
		if json.Unmarshal(links, &interfaces) != nil {
			out = append(out, Check{ID: "firewall.interfaces", Status: Unchecked, Code: "probe_invalid", Detail: "Invalid interface inspection response"})
		} else {
			c := Check{ID: "firewall.interfaces", Status: Ready, Code: "interfaces_inspected", Detail: "No currently refused tunnel interface type observed"}
			for _, i := range interfaces {
				switch i.Linkinfo.Kind {
				case "wireguard", "xfrm":
					c.Status = Blocked
					c.Code = "firewall_conflict"
					c.Detail = fmt.Sprintf("VPN/tunnel interface %.80s (%.24s): initial profile requires a separately reviewed integration", i.Ifname, i.Linkinfo.Kind)
					c.Next = "Keep read-only monitoring; review this integration before attempting evaluation"
				}
			}
			out = append(out, c)
		}
	}
	for _, p := range []string{"/proc/net/ip_tables_names", "/proc/net/ip6_tables_names"} {
		b, e := env.Read(p)
		c := Check{ID: "firewall.legacy." + strings.TrimPrefix(p, "/proc/net/"), Status: Ready, Code: "legacy_tables_absent", Detail: "No active legacy table names observed"}
		if e != nil && !os.IsNotExist(e) {
			c = ProbeFailure(c.ID, e)
		} else if len(bytes.TrimSpace(b)) > 0 {
			c.Status = Blocked
			c.Code = "firewall_conflict"
			c.Detail = "Legacy iptables tables detected; coexistence unsupported"
			c.Next = "Keep read-only monitoring; review coexistence without disabling existing security"
		}
		out = append(out, c)
	}
	b, err := env.Run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		out = append(out, ProbeFailure("firewall.ruleset", err))
	} else {
		c := Check{ID: "firewall.ruleset", Status: Ready, Code: "ruleset_inspected", Detail: "Existing rules inspected; no currently refused table/mark/queue/zone/notrack expression observed"}
		var value any
		if json.Unmarshal(b, &value) != nil {
			c.Status = Unchecked
			c.Code = "probe_invalid"
			c.Detail = "Invalid nft inspection response"
		} else if bytes.Contains(b, []byte(strconv.Quote(Table))) {
			c.Status = Blocked
			c.Code = "instance_or_foreign_table"
			c.Detail = "FlowGate table already exists; table name alone does not prove ownership"
			c.Next = "Inspect host-status; use scoped Stop/recovery only for a confirmed owned instance"
		} else {
			markCheck := compatibleFirewallRules(ctx, env, b)
			out = append(out, markCheck)
			if markCheck.Status != Ready {
				c.Status, c.Code, c.Detail, c.Next = markCheck.Status, markCheck.Code, markCheck.Detail, markCheck.Next
			}
		}
		out = append(out, c)
	}
	q, err := env.Read("/proc/net/netfilter/nfnetlink_queue")
	c := Check{ID: "firewall.queue_census", Status: Ready, Code: "queue_census", Detail: "Queue 101 not observed in current namespace; actual exclusive bind is not tested"}
	if err != nil {
		c = ProbeFailure(c.ID, err)
		c.Detail = "Queue census unavailable; startup must still perform an exclusive bind"
	}
	for _, line := range strings.Split(string(q), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == strconv.Itoa(Queue) {
			c.Status = Blocked
			c.Code = "queue_occupied"
			c.Detail = "Queue 101 occupied"
			c.Next = "Inspect the existing owner; do not terminate another consumer automatically"
		}
	}
	out = append(out, c)
	return out
}
