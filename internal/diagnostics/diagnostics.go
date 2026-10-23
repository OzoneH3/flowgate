// Package diagnostics collects bounded read-only evidence, never activation.
package diagnostics

import (
	"context"
	"flowgate/internal/daemon"
	"flowgate/internal/hostfirewall"
	"flowgate/internal/identity"
	"flowgate/internal/readiness"
	"flowgate/internal/udpaccount"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
)

type Options struct {
	Profile                                   string
	Administrator                             bool
	Helper, State, Controller, Collector, BTF string
	UID                                       uint32
}
type Report struct {
	Schema           int               `json:"schema_version"`
	Scope            string            `json:"scope"`
	Kernel           string            `json:"kernel"`
	Architecture     string            `json:"architecture"`
	UID              uint32            `json:"uid"`
	SelectedUID      uint32            `json:"selected_uid"`
	Namespaces       map[string]string `json:"namespaces"`
	CapEff           string            `json:"effective_capabilities"`
	Checks           []readiness.Check `json:"checks"`
	DurationMS       int64             `json:"duration_ms"`
	PrivilegedChecks []string          `json:"privileged_checks_performed"`
}

func Defaults() Options {
	exe, _ := os.Executable()
	uid := uint32(os.Getuid())
	return Options{Profile: "incoming", Helper: filepath.Join(filepath.Dir(exe), "udp-collector"), State: "/run/flowgate", Controller: "/run/flowgate-api/control.sock", Collector: fmt.Sprintf("/run/flowgate-traffic/%d/api.sock", uid), BTF: "/sys/kernel/btf/vmlinux", UID: uid}
}
func Collect(ctx context.Context, o Options) Report {
	at := time.Now()
	r := Report{Schema: 1, Scope: "read-only inspection; no queue bind, BPF load, activation or configuration changes", Architecture: runtime.GOARCH, UID: uint32(os.Getuid()), SelectedUID: o.UID, Namespaces: map[string]string{}, PrivilegedChecks: []string{}}
	add := func(c readiness.Check) { r.Checks = append(r.Checks, c) }
	b, _ := readiness.Read("/proc/sys/kernel/osrelease")
	r.Kernel = strings.TrimSpace(string(b))
	for _, ns := range []string{"net", "user", "mnt", "pid"} {
		s, _ := os.Readlink("/proc/self/ns/" + ns)
		r.Namespaces[ns] = s
	}
	status, _ := readiness.Read("/proc/self/status")
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			r.CapEff = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		}
	}
	caps, _ := strconv.ParseUint(r.CapEff, 16, 64)
	add(readiness.Check{ID: "activation.privileges", Status: readiness.Unchecked, Code: "permission_required", Detail: fmt.Sprintf("EUID %d; CAP_NET_ADMIN=%t, CAP_BPF=%t, CAP_PERFMON=%t, CAP_SYS_ADMIN=%t. Capability bits do not prove initial-namespace BPF load permission", os.Geteuid(), caps&(1<<12) != 0, caps&(1<<39) != 0, caps&(1<<38) != 0, caps&(1<<21) != 0), Next: "Explicit user-run sudo .workspace/flowgate doctor --json --uid YOUR_UID adds permitted read-only evidence; never activates"})
	for _, name := range []string{"ip", "nft"} {
		c := readiness.Check{ID: "dependency." + name, Status: readiness.Ready, Code: "executable_located", Detail: name + " executable located; operational probe reported separately"}
		if _, e := exec.LookPath(name); e != nil {
			c.Status = readiness.Blocked
			c.Code = "dependency_missing"
			c.Detail = "Required backend executable missing: " + name
			c.Next = "Use your normal approved package workflow; doctor installs nothing"
		}
		add(c)
	}
	if libs, _, e := readiness.Libraries("/proc/self/exe"); e == nil {
		add(readiness.Check{ID: "backend.libraries", Status: readiness.Ready, Code: "running_backend", Detail: "Running backend native dependencies: " + strings.Join(libs, ", ") + " (SQLite implementation is built into the Go driver)"})
	} else {
		add(readiness.ProbeFailure("backend.libraries", e))
	}
	c := identity.ActivityCollector{}
	snapshot := c.Collect()
	visibility := readiness.Check{ID: "monitor.visibility", Status: readiness.Ready, Code: "visibility_sampled", Detail: fmt.Sprintf("%d socket rows, %d visible tasks; %d inaccessible process directories; %d ms collection; ownership remains snapshot evidence", len(snapshot.Rows), len(snapshot.Processes), snapshot.Inaccessible, snapshot.DurationMS)}
	if snapshot.Error != "" {
		visibility.Status = readiness.Unchecked
		visibility.Code = "visibility_unavailable"
		visibility.Detail = "Socket/process snapshot unavailable"
	} else if !snapshot.Complete {
		visibility.Detail += "; partial visibility (unknown owners are not guessed)"
	}
	add(visibility)
	r.Checks = append(r.Checks, readiness.Runtime()...)
	r.Checks = append(r.Checks, readiness.FirewallFor(ctx, readiness.Default(), o.Profile, o.Administrator)...)
	modules, _ := readiness.Read("/proc/modules")
	for _, m := range []string{"nf_tables", "nf_conntrack", "nfnetlink_queue"} {
		c := readiness.Check{ID: "kernel." + m, Status: readiness.Unchecked, Code: "module_not_observed", Detail: m + " not observed as loaded; may be built in, absent or loadable (not tested)"}
		if strings.Contains(string(modules), m+" ") {
			c.Status = readiness.Ready
			c.Code = "module_observed"
			c.Detail = m + " observed loaded; operation is not proven by module presence"
		}
		add(c)
	}
	add(readiness.Check{ID: "firewall.activation", Status: readiness.Unchecked, Code: "not_attempted", Detail: "NFQUEUE exclusive binding, conntrack snapshot/mark updates and packet interception NOT attempted; startup preflight still required"})
	helper := readiness.Helper(o.Helper)
	add(helper)
	if helper.Status == readiness.Ready {
		libs, interpreter, e := readiness.Libraries(o.Helper)
		if e != nil {
			add(readiness.ProbeFailure("udp.libraries", e))
		} else {
			c := readiness.Check{ID: "udp.libraries", Status: readiness.Ready, Code: "library_names_resolved", Detail: "Helper direct dependencies: " + strings.Join(libs, ", ") + "; cache names only, transitive dependencies/ABI/load not executed"}
			cache, err := readiness.Run(ctx, "ldconfig", "-p")
			if err != nil {
				c = readiness.ProbeFailure(c.ID, err)
				if c.Code == "dependency_missing" {
					c.Status = readiness.Unchecked
					c.Code = "probe_failed"
					c.Detail = "Loader cache utility unavailable; optional helper library resolution not inspected"
				}
			} else {
				for _, lib := range libs {
					if !strings.Contains(string(cache), lib+" ") {
						c.Status = readiness.Optional
						c.Code = "library_unavailable"
						c.Detail = "Helper runtime dependency not found in loader cache: " + lib
						c.Next = "Inspect the loader configuration with your normal package workflow"
						break
					}
				}
			}
			if interpreter != "" {
				if _, err := os.Stat(interpreter); err != nil {
					c.Status = readiness.Optional
					c.Code = "library_unavailable"
					c.Detail = "Helper ELF interpreter unavailable"
				}
			}
			add(c)
		}
	}
	add(readiness.BTFNames(o.BTF))
	b, e := readiness.Read("/proc/sys/kernel/unprivileged_bpf_disabled")
	if e == nil {
		add(readiness.Check{ID: "udp.unprivileged_bpf", Status: readiness.Ready, Code: "setting_observed", Detail: "unprivileged_bpf_disabled=" + strings.TrimSpace(string(b)) + "; extended collector still requires explicit privileged startup"})
	}
	add(readiness.Check{ID: "udp.attachment", Status: readiness.Unchecked, Code: "not_attempted", Detail: "No BPF verifier/load/attach test performed; hook signatures, permissions and coexistence remain activation-time checks"})
	statePath := RuntimePath(o.State, 0700)
	add(statePath)
	add(RuntimePath(filepath.Dir(o.Controller), 0711))
	add(RuntimePath(filepath.Dir(o.Collector), 0755))
	if os.Geteuid() != 0 || statePath.Status != readiness.Ready {
		add(readiness.Check{ID: "controller.status", Status: readiness.Unchecked, Code: "permission_required", Detail: "Controller's private state record not inspected; use authorized API status or explicit privileged doctor"})
	} else if st, e := hostfirewall.Status(o.State); e != nil {
		c := readiness.ProbeFailure("controller.status", e)
		if os.IsNotExist(e) {
			c.Code = "no_instance_record"
			c.Detail = "No readable controller record at selected state path; this alone does not prove no firewall objects exist"
		}
		add(c)
	} else {
		// Do not serialize the private record (UIDs, executable paths, tokens).
		state := "status inspected"
		if m, ok := st.(map[string]any); ok {
			state = fmt.Sprint(m["state"])
		}
		c := readiness.Check{ID: "controller.status", Status: readiness.Ready, Code: "status_inspected", Detail: "Controller: " + state + "; ownership checks performed by host-status"}
		if m, ok := st.(map[string]any); ok {
			if rec, ok := m["record"].(hostfirewall.Record); ok && rec.State != "stopped" {
				c.Status = readiness.Blocked
				c.Code = "instance_active"
				c.Next = "Use existing authorized status/Stop/recovery; do not start a competing instance"
			}
		}
		add(c)
	}
	add(socketStatus(o.Controller, "controller.api", false))
	add(socketStatus(o.Collector, "udp.api", true))
	for _, c := range r.Checks {
		if (c.ID == "firewall.ruleset" && (c.Code == "ruleset_inspected" || c.Code == "instance_or_foreign_table" || c.Code == "firewall_conflict")) || (c.ID == "controller.status" && (c.Code == "status_inspected" || c.Code == "instance_active")) {
			r.PrivilegedChecks = append(r.PrivilegedChecks, c.ID)
		}
	}
	for i := range r.Checks {
		r.Checks[i].ID = bounded(r.Checks[i].ID, 128)
		r.Checks[i].Detail = bounded(r.Checks[i].Detail, 640)
		r.Checks[i].Next = bounded(r.Checks[i].Next, 320)
	}
	r.DurationMS = time.Since(at).Milliseconds()
	return r
}
func RuntimePath(path string, mode os.FileMode) readiness.Check {
	c := readiness.Check{ID: "runtime." + filepath.Base(path), Status: readiness.Ready, Code: "runtime_path_inspected", Detail: "Existing runtime directory passed ownership/mode/ancestor inspection"}
	st, e := os.Lstat(path)
	if os.IsNotExist(e) {
		c.Status = readiness.Unchecked
		c.Code = "runtime_absent"
		c.Detail = "Runtime directory absent; doctor does not create it"
		return c
	}
	if e != nil {
		return readiness.ProbeFailure(c.ID, e)
	}
	if !st.IsDir() || st.Mode().Perm() != mode || st.Sys().(*syscall.Stat_t).Uid != 0 {
		c.Status = readiness.Blocked
		c.Code = "runtime_path_invalid"
		c.Detail = "Runtime path must be a real root-owned directory with the documented mode"
		c.Next = "Inspect host-control/UDP path documentation; never blindly chmod or replace an existing path"
		return c
	}
	if os.Geteuid() == 0 {
		if e := daemon.SecureDirectory(path); e != nil {
			c.Status = readiness.Blocked
			c.Code = "runtime_path_invalid"
			c.Detail = "Runtime directory/ancestor validation refused by startup validator"
		}
		return c
	}
	// Same validation routine as startup, run as root only. An unprivileged caller
	// still checks ancestors without demanding ownership by its own UID.
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		s, e := os.Lstat(p)
		if e != nil {
			return readiness.ProbeFailure(c.ID, e)
		}
		uid := s.Sys().(*syscall.Stat_t).Uid
		if !s.IsDir() || s.Mode().Perm()&0022 != 0 || uid != 0 {
			c.Status = readiness.Blocked
			c.Code = "runtime_path_invalid"
			c.Detail = "Runtime ancestor is writable, non-root-owned or a symlink"
			return c
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return c
}
func socketStatus(path, id string, udp bool) readiness.Check {
	st, e := os.Lstat(path)
	if e != nil {
		c := readiness.ProbeFailure(id, e)
		if os.IsNotExist(e) {
			c.Code = "socket_absent"
			c.Detail = "Selected API socket not present; no backend started"
		}
		return c
	}
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0600 {
		return readiness.Check{ID: id, Status: readiness.Blocked, Code: "runtime_path_invalid", Detail: "API path is not a private mode-0600 Unix socket"}
	}
	if udp {
		u, e := udpaccount.Request(path, "list")
		if e != nil {
			return readiness.ProbeFailure(id, e)
		}
		return readiness.Check{ID: id, Status: readiness.Ready, Code: "api_inspected", Detail: fmt.Sprintf("Collector API reports %s (generation present=%t); inspection does not start collection", u.State, u.Generation != "")}
	}
	r, e := daemon.Call(path, daemon.Request{Version: 1, Operation: "list"})
	if e != nil {
		return readiness.ProbeFailure(id, e)
	}
	detail := "Authorized API reachable; mode=" + r.Mode
	if r.Enforcement != nil {
		detail += "; enforcement=" + r.Enforcement.State
	}
	return readiness.Check{ID: id, Status: readiness.Ready, Code: "api_inspected", Detail: detail}
}
func Human(w io.Writer, r Report) {
	fmt.Fprintf(w, "FlowGate doctor — %s / %s, UID %d (selected %d)\n%s\n", r.Kernel, r.Architecture, r.UID, r.SelectedUID, r.Scope)
	for _, c := range r.Checks {
		fmt.Fprintf(w, "%-20s %-29s [%s] %s\n", c.Status, c.ID, c.Code, c.Detail)
		if c.Next != "" {
			fmt.Fprintf(w, "  Next: %s\n", c.Next)
		}
	}
	fmt.Fprintf(w, "Completed in %d ms. Ready applies only to each completed check, never overall activation.\n", r.DurationMS)
}

func bounded(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
	if len(s) > n {
		return string([]rune(s)[:min(len([]rune(s)), n/4)]) + "… (bounded)"
	}
	return s
}
