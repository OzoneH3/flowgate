package daemon

import (
	"bufio"
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// In an isolated PID/network namespace, set FLOWGATE_TEST_WINE_HOLDER_IMAGES
// to the directory with the existing alpha.exe and beta.exe test images.
func TestConnectionAnalysisRechecksSameLoaderWineExec(t *testing.T) {
	images := os.Getenv("FLOWGATE_TEST_WINE_HOLDER_IMAGES")
	if images == "" {
		t.Skip("requires Windows image fixtures and an isolated PID/network namespace")
	}
	dir, err := os.MkdirTemp("", "fga-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	loader := filepath.Join(dir, "wine-preloader")
	if output, err := exec.Command("cc", "-Wall", "-Wextra", "-Werror", "-o", loader,
		"../../fixtures/ownership/wine-holder-exec.c").CombinedOutput(); err != nil {
		t.Fatalf("building the same-loader fixture: %v\n%s", err, output)
	}
	alpha, beta := filepath.Join(images, "alpha.exe"), filepath.Join(images, "beta.exe")
	prefixA, prefixB := filepath.Join(dir, "prefix-a"), filepath.Join(dir, "prefix-b")
	for _, prefix := range []string{prefixA, prefixB} {
		if err := os.Mkdir(prefix, 0700); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name, image, prefix, reason string
	}{
		{"image-only", beta, prefixA, "mapped Windows executable changed"},
		{"prefix-only", alpha, prefixB, "Wine prefix changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			fd, err := socket.File()
			if err != nil {
				t.Fatal(err)
			}
			defer fd.Close()

			pid, waitImage := startWineHolderExec(t, loader, fd, alpha, prefixA, tc.image, tc.prefix)
			stable, _ := startWineHolderExec(t, loader, fd, beta, prefixB)
			beforeImage, err := identity.Inspect(pid)
			if err != nil || beforeImage.Application.Executable != alpha || beforeImage.Application.Prefix != prefixA {
				t.Fatalf("before exec: %+v %v", beforeImage.Application, err)
			}
			f, err := identity.ParseFlow("udp", "incoming", socket.LocalAddr().String(), "192.0.2.30:45678")
			if err != nil {
				t.Fatal(err)
			}
			attributed := identity.Resolve(f)
			if attributed.Application != nil || len(attributed.Owners) != 3 {
				t.Fatalf("expected the parent and both fixture holders: %+v", attributed)
			}
			rule := policy.Rule{ID: "fixture-allow-prefix-a", Action: "allow", Executable: alpha,
				Filter: policy.Filter{Application: beforeImage.Application.Key, Revision: beforeImage.Application.Revision,
					UID: beforeImage.UID, Direction: f.Direction, Protocol: f.Protocol}}
			other := beforeImage.Application
			other.Prefix = prefixB
			other.Key = identity.ApplicationKey(beforeImage.UID, other)
			if !rule.MatchesApplication(beforeImage.Application.Key, beforeImage.Application.Revision, beforeImage.UID, beforeImage.Application) ||
				rule.MatchesApplication(other.Key, other.Revision, beforeImage.UID, other) {
				t.Fatal("prefix A rule did not stay exclusive to prefix A")
			}
			rules := []policy.Rule{rule}
			decision, policyID, _ := policy.Evaluate(rules, f, attributed, time.Now())
			if decision != "block" || policyID != "unsafe-attribution" {
				t.Fatalf("unexpected original policy: %s / %s", decision, policyID)
			}

			c := identity.ActivityCollector{}
			baseline := c.Collect()
			e := New(time.Second)
			e.Mode = "host-monitor"
			e.Activity = func() identity.ActivitySnapshot { return baseline }
			e.ConnectionSample = func(port uint16) identity.ConnectionSample {
				return identity.CollectConnectionSample(port, nil)
			}
			query := &ConnectionAnalysisQuery{LocalPort: f.Local.Port()}
			analyze := func(label string) *AnalyzedConnection {
				s, code, detail := e.analyzeConnections(query, beforeImage.UID, false, "user-visible")
				if code != "" || s == nil || len(s.Connections) != 1 {
					t.Fatalf("%s expected one shared socket: %+v %s %s", label, s, code, detail)
				}
				data, err := json.Marshal(s)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("%s %s", label, data)
				return s.Connections[0]
			}
			before := analyze("before")
			original := wineHolderByPID(t, before.Observations[len(before.Observations)-1], pid)
			if original.WindowsImage == nil || original.WindowsImage.Executable != alpha || original.WindowsImage.Prefix != prefixA {
				t.Fatalf("initial image was not verified: %+v", original)
			}
			var transitionErr error
			e.ConnectionSample = func(port uint16) identity.ConnectionSample {
				return identity.CollectConnectionSample(port, func(snapshot *identity.ActivitySnapshot) {
					var captured bool
					for _, p := range snapshot.Processes {
						if p.PID == pid && p.Application.Executable == alpha && p.Application.Prefix == prefixA {
							captured = true
							break
						}
					}
					if !captured {
						transitionErr = fmt.Errorf("earlier Windows holder was not captured")
						return
					}
					if transitionErr = syscall.Kill(pid, syscall.SIGUSR1); transitionErr == nil {
						transitionErr = waitImage(tc.image)
					}
				})
			}
			changed := analyze("transition")
			if transitionErr != nil {
				t.Fatal(transitionErr)
			}
			afterImage, err := identity.Inspect(pid)
			if err != nil || afterImage.Start != beforeImage.Start || afterImage.Executable != beforeImage.Executable ||
				afterImage.ExecutableRevision != beforeImage.ExecutableRevision || afterImage.UID != beforeImage.UID ||
				afterImage.NetNS != beforeImage.NetNS || afterImage.PIDNS != beforeImage.PIDNS || afterImage.MountNS != beforeImage.MountNS ||
				afterImage.Application.Executable != tc.image || afterImage.Application.Prefix != tc.prefix {
				t.Fatalf("same-loader fixture changed the wrong facts: %+v %v", afterImage, err)
			}
			e.ConnectionSample = func(port uint16) identity.ConnectionSample {
				return identity.CollectConnectionSample(port, nil)
			}
			later := analyze("later")
			now := identity.Resolve(f)
			afterDecision, afterPolicy, _ := policy.Evaluate(rules, f, now, time.Now())
			if now.Application != nil || len(now.Owners) != 3 || afterDecision != decision || afterPolicy != policyID {
				t.Fatalf("policy changed from %s / %s to %s / %s", decision, policyID, afterDecision, afterPolicy)
			}

			for _, record := range []*AnalyzedConnection{before, changed, later} {
				obs := record.Observations[len(record.Observations)-1]
				if identity.ConnectionKey(record.Socket) != identity.ConnectionKey(before.Socket) ||
					record.Socket.Cookie == "" || obs.Category != "shared" || obs.Application != nil || len(obs.Holders) != 3 {
					t.Fatalf("unexpected shared observation: %+v", record)
				}
				h := wineHolderByPID(t, obs, stable)
				if h.WindowsImage == nil || h.WindowsImage.Executable != beta || h.WindowsImage.Prefix != prefixB {
					t.Fatalf("stable holder lost its image: %+v", h)
				}
			}
			h := wineHolderByPID(t, changed.Observations[len(changed.Observations)-1], pid)
			if h.WindowsImage != nil || !strings.Contains(h.WindowsImageReason, tc.reason) ||
				h.Executable != beforeImage.Executable || h.Start != beforeImage.Start {
				t.Fatalf("stale image or wrong refusal: %+v", h)
			}
			h = wineHolderByPID(t, later.Observations[len(later.Observations)-1], pid)
			if h.WindowsImage == nil || h.WindowsImage.Executable != tc.image || h.WindowsImage.Prefix != tc.prefix {
				t.Fatalf("later sample did not verify new identity: %+v", h)
			}
			t.Logf("policy %s -> %s (%s); prefix-A Allow did not match prefix B", decision, afterDecision, policyID)
		})
	}
}

func wineHolderByPID(t *testing.T, obs ConnectionObservation, pid int) AnalysisHolder {
	t.Helper()
	for _, holder := range obs.Holders {
		if holder.PID == pid {
			return holder
		}
	}
	t.Fatalf("native holder %d is missing: %+v", pid, obs)
	return AnalysisHolder{}
}

func startWineHolderExec(t *testing.T, loader string, fd *os.File, image, prefix string, next ...string) (int, func(string) error) {
	t.Helper()
	cmd := exec.Command(loader)
	cmd.Args = append([]string{image}, next...)
	if len(next) == 0 {
		cmd.Args = append(cmd.Args, "stable")
	}
	cmd.Env = append(os.Environ(), "WINEPREFIX="+prefix)
	cmd.ExtraFiles = []*os.File{fd}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	lines := bufio.NewScanner(out)
	wait := func(image string) error {
		result := make(chan error, 1)
		go func() {
			if !lines.Scan() || lines.Text() != image {
				result <- fmt.Errorf("wanted holder image %s, got %q (%v)", image, lines.Text(), lines.Err())
				return
			}
			result <- nil
		}()
		select {
		case err := <-result:
			return err
		case <-time.After(3 * time.Second):
			return fmt.Errorf("holder image %s did not materialize", image)
		}
	}
	if err := wait(image); err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid, wait
}
