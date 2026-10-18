package tcpinit

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flowgate/internal/identity"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Private test executable protocol, not a production collector/source of kernel evidence.
func init() {
	mode := os.Getenv("FLOWGATE_TEST_INITIATION")
	if mode == "" {
		return
	}
	if mode == "require-shared" && (len(os.Args) != 3 || os.Args[2] != "--observe-shared") {
		fmt.Fprintln(os.Stderr, "explicit shared option required")
		os.Exit(2)
	}
	fmt.Println("READY")
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		if mode == "stall" {
			time.Sleep(time.Hour)
		}
		if mode == "malformed" {
			fmt.Println("broken")
			continue
		}
		rows := []map[string]any{}
		var mono unix.Timespec
		unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono)
		for _, k := range strings.Fields(s.Text()) {
			v, _ := strconv.ParseUint(k, 10, 64)
			rows = append(rows, map[string]any{"cookie": fmt.Sprintf("%016x", v), "direction": 1, "observed_ns": uint64(mono.Nano())})
		}
		b, _ := json.Marshal(map[string]any{"rows": rows, "lost_events": 2})
		fmt.Println(string(b))
	}
	os.Exit(0)
}
func waitState(t *testing.T, c *Collector, state string) {
	t.Helper()
	end := time.Now().Add(7 * time.Second)
	for time.Now().Before(end) {
		if c.status().State == state {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("state", c.status())
}
func TestHelperProtocolBindingFailureAndBoundedShutdown(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FLOWGATE_TEST_INITIATION", "ok")
	c := New(context.Background(), exe, "/sys/fs/cgroup", t.TempDir())
	waitState(t, c, "active")
	var cookieBytes [8]byte
	binary.NativeEndian.PutUint64(cookieBytes[:], 1)
	cookie := hex.EncodeToString(cookieBytes[:])
	// Use the same native-endian framing as inet_diag.
	socket := identity.Socket{Protocol: "tcp", Cookie: cookie, NetNS: identity.NetNS()}
	s := c.Sample([]identity.Socket{socket})
	if s.State != "active" || s.Rows[cookie].Direction != "outgoing" || s.Lost != 2 || !s.Partial {
		t.Fatal(s)
	}
	first := s.Generation
	pin := c.pinned
	c.Close()
	if _, err = os.Stat(pin); !os.IsNotExist(err) {
		t.Fatal("pin survived")
	}
	c = New(context.Background(), exe, "/sys/fs/cgroup", t.TempDir())
	waitState(t, c, "active")
	if c.status().Generation == first {
		t.Fatal("generation reused")
	}
	c.Close()
	for _, mode := range []string{"malformed", "stall"} {
		t.Setenv("FLOWGATE_TEST_INITIATION", mode)
		c = New(context.Background(), exe, "/sys/fs/cgroup", t.TempDir())
		waitState(t, c, "active")
		start := time.Now()
		s = c.Sample([]identity.Socket{socket})
		if s.State == "active" || len(s.Rows) != 0 {
			t.Fatal("failed helper kept evidence", s)
		}
		c.Close()
		if time.Since(start) > 3*time.Second {
			t.Fatal("shutdown/query unbounded")
		}
	}
}
func TestDecodeRejectsUnrequestedDuplicateFutureAndInvalid(t *testing.T) {
	var mono unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono)
	good := fmt.Sprintf(`{"rows":[{"cookie":"1","direction":2,"observed_ns":%d}],"lost_events":0}`, mono.Nano())
	s := identity.InitiationEvents{State: "active", Generation: "generation"}
	out, e := decode([]byte(good), s, []string{"1"})
	if e != nil || len(out.Rows) != 1 {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(good, `"cookie":"1"`, `"cookie":"2"`, 1), strings.Replace(good, `"direction":2`, `"direction":0`, 1), strings.Replace(good, fmt.Sprint(mono.Nano()), "18446744073709551615", 1), `{"rows":[{"cookie":"1","direction":1,"observed_ns":1},{"cookie":"1","direction":1,"observed_ns":1}]}`} {
		if _, e = decode([]byte(bad), s, []string{"1"}); e == nil {
			t.Fatal("invalid evidence accepted", bad)
		}
	}
	c := New(context.Background(), "", "", t.TempDir())
	if c.Sample(nil).State != "disabled" {
		t.Fatal("disabled source attempted attachment")
	}
	c.Close()
}

func TestSharedObservationRequiresExplicitOption(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FLOWGATE_TEST_INITIATION", "require-shared")
	strict := New(context.Background(), exe, "/sys/fs/cgroup", t.TempDir())
	waitState(t, strict, "failed")
	strict.Close()
	shared := NewWithOptions(context.Background(), exe, "/sys/fs/cgroup", t.TempDir(), Options{ObserveShared: true})
	waitState(t, shared, "active")
	shared.Close()
}
