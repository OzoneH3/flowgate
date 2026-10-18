package main

// Explicit, disposable acceptance peer. This is not a root command runner: the
// interface names, addresses, payload, destination and port range are fixed.
import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const testHostLink = "fg-accept-h"
const testPeerLink = "fg-accept-p"

type peerRequest struct {
	Op       string `json:"op"`
	Protocol string `json:"protocol,omitempty"`
	Port     int    `json:"port,omitempty"`
	V6       bool   `json:"v6,omitempty"`
}

func validatePeerRequest(q peerRequest) error {
	if (q.Op == "quit" || q.Op == "counts") && q.Port == 0 && q.Protocol == "" && !q.V6 {
		return nil
	}
	if q.Op != "send" || (q.Protocol != "udp" && q.Protocol != "tcp") || q.Port < 24680 || q.Port > 24709 {
		return fmt.Errorf("only send TCP/UDP to owned test address ports 24680..24709, or quit, is accepted")
	}
	return nil
}
func peerIP(ctx context.Context, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, "ip", args...)
	b, e := c.CombinedOutput()
	if e != nil {
		return nil, fmt.Errorf("ip %v: %w: %s", args, e, b)
	}
	return b, nil
}
func hostTestPeerCommand(op string, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("host-test-peer accepts no arguments")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("host-test-peer requires explicit root authorization")
	}
	if op == "host-test-peer-child" {
		return testPeerChild()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	for _, name := range []string{testHostLink, testPeerLink} {
		if _, e := net.InterfaceByName(name); e == nil {
			return fmt.Errorf("test interface %s already exists; refusing replacement", name)
		}
	}
	// Do not overlay any configured route, except the ordinary default. IPv4 and
	// IPv6 prefixes are test-only and no existing route is deleted or rewritten.
	for _, family := range []string{"-4", "-6"} {
		b, e := peerIP(ctx, family, "-j", "route", "show", "table", "all")
		if e != nil {
			return e
		}
		var rows []struct {
			Dst string `json:"dst"`
		}
		if e = json.Unmarshal(b, &rows); e != nil {
			return e
		}
		for _, r := range rows {
			_, network, e := net.ParseCIDR(r.Dst)
			if e != nil {
				continue
			}
			for _, ip := range []string{"192.0.2.1", "192.0.2.2", "fd79:6667::1", "fd79:6667::2"} {
				if network.Contains(net.ParseIP(ip)) {
					return fmt.Errorf("test addresses overlap an existing route; no changes made")
				}
			}
		}
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	child := exec.CommandContext(ctx, exe, "host-test-peer-child")
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	child.Stderr = os.Stderr
	in, e := child.StdinPipe()
	if e != nil {
		return e
	}
	out, e := child.StdoutPipe()
	if e != nil {
		return e
	}
	if e = child.Start(); e != nil {
		return e
	}
	defer func() {
		in.Close()
		if child.Process != nil {
			child.Process.Kill()
		}
		child.Wait()
	}()
	if _, e = peerIP(ctx, "link", "add", testHostLink, "type", "veth", "peer", "name", testPeerLink); e != nil {
		return e
	}
	owned, e := net.InterfaceByName(testHostLink)
	if e != nil {
		return e
	}
	defer func() {
		if current, er := net.InterfaceByName(testHostLink); er == nil && current.Index == owned.Index {
			cleanup, c := context.WithTimeout(context.Background(), 3*time.Second)
			defer c()
			if _, er = peerIP(cleanup, "link", "del", testHostLink); er != nil {
				fmt.Fprintln(os.Stderr, er)
			}
		}
	}()
	for _, a := range [][]string{{"link", "set", testPeerLink, "netns", strconv.Itoa(child.Process.Pid)}, {"addr", "add", "192.0.2.1/30", "dev", testHostLink}, {"-6", "addr", "add", "fd79:6667::1/64", "dev", testHostLink, "nodad"}, {"link", "set", testHostLink, "up"}} {
		if _, e = peerIP(ctx, a...); e != nil {
			return e
		}
	}
	enc := json.NewEncoder(in)
	scan := bufio.NewScanner(out)
	if e = enc.Encode(map[string]string{"op": "setup"}); e != nil {
		return e
	}
	if !scan.Scan() {
		return fmt.Errorf("test peer setup did not acknowledge")
	}
	fmt.Println(scan.Text())
	lines := make(chan string)
	go func() {
		defer close(lines)
		s := bufio.NewScanner(os.Stdin)
		s.Buffer(make([]byte, 1024), 4096)
		for s.Scan() {
			select {
			case lines <- s.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("test peer deadline/cancellation: %w", ctx.Err())
		case line, ok := <-lines:
			if !ok {
				return nil
			}
			var q peerRequest
			var raw map[string]json.RawMessage
			if json.Unmarshal([]byte(line), &raw) != nil || json.Unmarshal([]byte(line), &q) != nil {
				return fmt.Errorf("invalid test command")
			}
			for k := range raw {
				if k != "op" && k != "protocol" && k != "port" && k != "v6" {
					return fmt.Errorf("unknown test field")
				}
			}
			if e = validatePeerRequest(q); e != nil {
				return e
			}
			if q.Op == "quit" {
				return nil
			}
			if e = enc.Encode(q); e != nil {
				return e
			}
			if !scan.Scan() {
				return fmt.Errorf("test peer exited before acknowledgement")
			}
			fmt.Println(scan.Text())
		}
	}
}
func testPeerChild() error {
	// A directly invoked internal mode cannot configure the host namespace.
	if a, e := os.Readlink("/proc/self/ns/net"); e != nil {
		return e
	} else if b, er := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", os.Getppid())); er != nil || a == b {
		return fmt.Errorf("peer child must be in a separate network namespace")
	}
	dec := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20))
	var setup peerRequest
	if e := dec.Decode(&setup); e != nil || setup.Op != "setup" {
		return fmt.Errorf("peer setup required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	for _, a := range [][]string{{"link", "set", "lo", "up"}, {"addr", "add", "192.0.2.2/30", "dev", testPeerLink}, {"-6", "addr", "add", "fd79:6667::2/64", "dev", testPeerLink, "nodad"}, {"link", "set", testPeerLink, "up"}} {
		if _, e := peerIP(ctx, a...); e != nil {
			return e
		}
	}
	var countMu sync.Mutex
	counts := map[string]int{}
	for _, spec := range []struct{ network, addr string }{{"tcp4", "192.0.2.2:24688"}, {"tcp6", "[fd79:6667::2]:24688"}, {"udp4", "192.0.2.2:24689"}, {"udp6", "[fd79:6667::2]:24689"}} {
		spec := spec
		record := func() { countMu.Lock(); counts[spec.network]++; countMu.Unlock() }
		if spec.network[:3] == "tcp" {
			l, err := net.Listen(spec.network, spec.addr)
			if err != nil {
				return err
			}
			defer l.Close()
			go func() {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						c.SetDeadline(time.Now().Add(12 * time.Second))
						b := make([]byte, 128)
						if n, err := c.Read(b); err == nil && n > 0 {
							record()
							c.Write(b[:n])
						}
					}(c)
				}
			}()
		} else {
			u, err := net.ListenPacket(spec.network, spec.addr)
			if err != nil {
				return err
			}
			defer u.Close()
			go func() {
				b := make([]byte, 128)
				for {
					n, a, err := u.ReadFrom(b)
					if err != nil {
						return
					}
					record()
					u.WriteTo(b[:n], a)
				}
			}()
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.Encode(map[string]any{"ready": true, "scope": "temporary input-hook peer only", "host4": "192.0.2.1", "host6": "fd79:6667::1", "ports": "24680..24709", "deadline_seconds": 600})
	for {
		var q peerRequest
		if e := dec.Decode(&q); e != nil {
			return e
		}
		if e := validatePeerRequest(q); e != nil {
			return e
		}
		if q.Op == "quit" {
			return nil
		}
		if q.Op == "counts" {
			countMu.Lock()
			copy := map[string]int{}
			for k, v := range counts {
				copy[k] = v
			}
			countMu.Unlock()
			if err := enc.Encode(map[string]any{"counts": copy}); err != nil {
				return err
			}
			continue
		}
		go func(q peerRequest) {
			host := "192.0.2.1"
			family := "4"
			if q.V6 {
				host = "fd79:6667::1"
				family = "6"
			}
			d := net.Dialer{Timeout: 12 * time.Second}
			c, e := d.DialContext(ctx, q.Protocol+family, net.JoinHostPort(host, strconv.Itoa(q.Port)))
			if e != nil {
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(12 * time.Second))
			c.Write([]byte("flowgate-owned-host-acceptance"))
			if q.Protocol == "tcp" {
				c.Read(make([]byte, 128))
			}
		}(q)
		if e := enc.Encode(map[string]any{"submitted": true, "delivery": "not established by this acknowledgement", "protocol": q.Protocol, "port": q.Port, "v6": q.V6}); e != nil {
			return e
		}
	}
}
