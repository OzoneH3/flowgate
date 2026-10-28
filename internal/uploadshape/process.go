package uploadshape

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

func securePath(path string, directory bool) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("absolute shaping path required")
	}
	for p := path; ; p = filepath.Dir(p) {
		s, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st, ok := s.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("shaping helpers/state require root-owned non-writable paths: %s", p)
		}
		if p == path && directory && !s.IsDir() {
			return fmt.Errorf("directory required")
		}
		if p == "/" {
			break
		}
	}
	return nil
}
func validateDeploymentMode(o Options, ns string) error {
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`).MatchString(o.Interface) {
		return fmt.Errorf("explicit interface required")
	}
	if o.HostTrial {
		if o.ParentNetNS != "" {
			return fmt.Errorf("host-trial and lab parent namespace are mutually exclusive")
		}
		return nil
	}
	if !regexp.MustCompile(`^net:\[[0-9]+\]$`).MatchString(o.ParentNetNS) || ns == o.ParentNetNS {
		return fmt.Errorf("shaping requires disposable child namespace or explicit host-trial startup opt-in")
	}
	return nil
}
func validateOptions(o Options) error {
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	if err = validateDeploymentMode(o, ns); err != nil {
		return err
	}
	if err = securePath(o.Helpers, true); err != nil {
		return err
	}
	for _, f := range []string{"controller.py", "kernel", "probe", "classify.bpf.o"} {
		if err = securePath(filepath.Join(o.Helpers, f), false); err != nil {
			return err
		}
	}
	if !filepath.IsAbs(o.State) {
		return fmt.Errorf("absolute shaping state required")
	}
	return securePath(filepath.Dir(o.State), true)
}

type process struct {
	cmd     *exec.Cmd
	in      io.WriteCloser
	lines   chan json.RawMessage
	done    chan error
	stopped bool
	fault   string
}

func startProcess(o Options) (transport, error) { return startProcessMode(o, false) }
func cleanupProcess(o Options) error {
	if _, err := os.Lstat(filepath.Join(o.State, "owner.json")); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	p, err := startProcessMode(o, true)
	if err != nil {
		return err
	}
	return p.Close()
}
func startProcessMode(o Options, cleanup bool) (transport, error) {
	// Helpers are root startup configuration, never supplied by an API request.
	args := []string{"-I", filepath.Join(o.Helpers, "controller.py"), "--interface", o.Interface, "--state", o.State, "--helpers", o.Helpers}
	if o.HostTrial {
		args = append(args, "--host-trial")
	} else {
		args = append(args, "--lab-parent-netns", o.ParentNetNS)
	}
	cmd := exec.Command("python3", args...)
	if cleanup {
		cmd.Args = append(cmd.Args, "--cleanup-only")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		in.Close()
		out.Close()
		return nil, err
	}
	p := &process{cmd: cmd, in: in, lines: make(chan json.RawMessage, 2), done: make(chan error, 1)}
	go func() {
		scan := bufio.NewScanner(out)
		scan.Buffer(make([]byte, 4096), 2*1024*1024)
		for scan.Scan() {
			b := append(json.RawMessage(nil), scan.Bytes()...)
			select {
			case p.lines <- b:
			default:
				cmd.Process.Kill()
			}
		}
		close(p.lines)
		p.done <- cmd.Wait()
	}()
	raw, err := p.read()
	if err != nil {
		p.Close()
		return nil, err
	}
	var hello struct {
		Ready   bool `json:"ready"`
		Stopped bool `json:"stopped"`
	}
	if json.Unmarshal(raw, &hello) != nil || (!cleanup && !hello.Ready) || (cleanup && !hello.Stopped) {
		p.Close()
		return nil, fmt.Errorf("controller not ready: %s", raw)
	}
	return p, nil
}
func (p *process) read() (json.RawMessage, error) {
	return p.readWithin(20 * time.Second)
}

func (p *process) readWithin(timeout time.Duration) (json.RawMessage, error) {
	select {
	case b, ok := <-p.lines:
		if !ok {
			return nil, fmt.Errorf("controller exited; leases expire within5s")
		}
		var v struct {
			Error   string `json:"error"`
			Cleanup string `json:"cleanup_refused"`
			Status  string `json:"status"`
		}
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, err
		}
		if v.Status == "Unsupported" {
			p.fault = v.Error
		}
		if v.Error != "" {
			return nil, fmt.Errorf("%s", v.Error)
		}
		if v.Cleanup != "" {
			p.fault = v.Cleanup
			return nil, fmt.Errorf("cleanup refused: %s", v.Cleanup)
		}
		return b, nil
	case <-time.After(timeout):
		_ = p.cmd.Process.Kill()
		return nil, fmt.Errorf("controller timed out; leases expire within5s")
	}
}
func (p *process) Call(q map[string]any) (json.RawMessage, error) {
	if p.stopped {
		return nil, fmt.Errorf("controller stopped")
	}
	if err := json.NewEncoder(p.in).Encode(q); err != nil {
		return nil, err
	}
	// A full policy may update both trees for all configured applications.
	// Its controller performs verified lease checkpoints between mutations;
	// keep its deadline bounded without killing that work at the old 20s limit.
	if q["op"] == "policy" {
		return p.readWithin(45 * time.Second)
	}
	return p.read()
}
func (p *process) Close() error {
	if p.stopped {
		return nil
	}
	p.stopped = true
	_ = p.in.Close() // EOF performs verified cleanup; failure leaves leases to expire.
	select {
	case err := <-p.done:
		// Include any asynchronous cleanup refusal even if Python exited normally.
		for b := range p.lines {
			var v map[string]any
			_ = json.Unmarshal(b, &v)
			if v["cleanup_refused"] != nil {
				return fmt.Errorf("cleanup refused: %v", v["cleanup_refused"])
			}
		}
		if p.fault != "" {
			return fmt.Errorf("controller fault: %s", p.fault)
		}
		return err
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
		return fmt.Errorf("controller cleanup timed out; leases expire within5s")
	}
}
