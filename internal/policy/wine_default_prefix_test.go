package policy

import (
	"bufio"
	"context"
	"flowgate/internal/identity"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Run inside an isolated PID/network namespace with the existing Windows UDP
// fixtures and owner observer. Ordinary Go tests do not require a Wine install.
func TestWineDefaultPrefixesKeepPermissionsSeparate(t *testing.T) {
	runner := os.Getenv("FLOWGATE_TEST_DEFAULT_WINE")
	if runner == "" {
		t.Skip("requires a Wine runner and compiled Windows fixtures")
	}
	fixtures, err := filepath.Abs("../../.workspace/windows")
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	if err := os.Chmod(scratch, 0700); err != nil {
		t.Fatal(err)
	}
	observer, err := identity.NewWineObservers(identity.WineObserverOptions{
		Discover: true, UID: uint32(os.Getuid()), Scratch: scratch,
		Helper: filepath.Join(fixtures, "table-probe.exe"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()

	var apps []identity.Application
	for range 2 {
		home := t.TempDir()
		for _, name := range []string{"alpha.exe", "beta.exe"} {
			socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			local := socket.LocalAddr().(*net.UDPAddr).AddrPort()
			socket.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			cmd := exec.CommandContext(ctx, runner, filepath.Join(fixtures, name), "u", strconv.Itoa(int(local.Port())))
			cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin", "WINEDEBUG=-all", "WINEDLLOVERRIDES=mscoree,mshtml="}
			out, err := cmd.StdoutPipe()
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				cancel()
				t.Fatal(err)
			}
			t.Cleanup(func() { cancel(); _ = cmd.Wait() })
			lines := bufio.NewScanner(out)
			if !lines.Scan() || lines.Text() != "READY" {
				t.Fatalf("%s did not bind its socket", name)
			}
			result := observer.Resolve(identity.Flow{Protocol: "udp", Direction: "outgoing", NetNS: identity.NetNS(),
				Local: local, Remote: netip.MustParseAddrPort("127.0.0.1:12345")})
			if result.Status != "corroborated-runtime-table" || result.Application == nil ||
				result.Application.Executable != filepath.Join(fixtures, name) || result.Application.Prefix != filepath.Join(home, ".wine") {
				t.Fatalf("%s in %s: %s (%s), application %+v", name, home, result.Status, result.Reason, result.Application)
			}
			apps = append(apps, *result.Application)
		}
	}
	uid := uint32(os.Getuid())
	for i, app := range apps {
		rule := Rule{Action: "allow", Executable: app.Executable, Filter: Filter{Application: app.Key, Revision: app.Revision, UID: uid}}
		for j, other := range apps {
			if rule.MatchesApplication(other.Key, other.Revision, uid, other) != (i == j) {
				t.Fatalf("rule for %s in %s matched incorrectly against %s in %s", app.Name, app.Prefix, other.Name, other.Prefix)
			}
		}
	}
}
