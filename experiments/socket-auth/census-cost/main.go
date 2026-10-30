// Read-only holder-census cost probe. The launcher must supply a private network
// namespace while retaining the host PID/proc view. No sends, policy or Wine calls.
package main

import (
	"encoding/json"
	"flag"
	"flowgate/internal/identity"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// Counts are descriptive only, never ownership evidence. Leader FD entries are
// not unique open files and do not cover unshared thread descriptor tables.
func population() map[string]any {
	out := map[string]any{}
	procs, threads, fds, unreadable := 0, 0, 0, 0
	limited := false
	count := func(path string, limit int) int {
		f, e := os.Open(path)
		if e != nil {
			unreadable++
			return 0
		}
		defer f.Close()
		n := 0
		for n < limit {
			names, e := f.Readdirnames(min(256, limit-n))
			n += len(names)
			if e == io.EOF {
				return n
			}
			if e != nil {
				unreadable++
				return n
			}
		}
		limited = true
		return n
	}
	entries, e := os.ReadDir("/proc")
	if e != nil {
		out["error"] = e.Error()
		return out
	}
	for _, entry := range entries {
		if _, e := strconv.Atoi(entry.Name()); e != nil {
			continue
		}
		if procs >= 4096 || fds >= 131072 {
			limited = true
			break
		}
		procs++
		threads += count("/proc/"+entry.Name()+"/task", 4096)
		fds += count("/proc/"+entry.Name()+"/fd", min(16384, 131072-fds))
	}
	out["processes"] = procs
	out["tasks"] = threads
	out["leader_fd_entries"] = fds
	out["unreadable_directories"] = unreadable
	out["count_truncated"] = limited
	return out
}
func main() {
	helper := flag.String("helper", "", "reviewed root-owned iterator loader")
	out := flag.String("out", "", "workspace evidence directory")
	flag.Parse()
	if os.Getenv("FLOWGATE_HOST_CENSUS_APPROVED") != "1" {
		panic("requires explicit host-diagnostic approval")
	}
	parent := os.Getenv("FLOWGATE_PARENT_NETNS")
	if parent == "" || parent == identity.NetNS() {
		panic("private network namespace required")
	}
	runtime.GOMAXPROCS(1)
	must(unix.Setrlimit(unix.RLIMIT_CPU, &unix.Rlimit{Cur: 6, Max: 7}))
	must(unix.Setpriority(unix.PRIO_PROCESS, 0, 19))
	if !filepath.IsAbs(*out) {
		panic("absolute evidence path required")
	}
	closeIterator, err := identity.EnableHolderIterator(*helper, "91e62cdc339fd58fcc13b09bd9f88017226d93ca92650675c127ebc4554e55e8")
	must(err)
	defer closeIterator()
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	must(err)
	defer c.Close()
	local := c.LocalAddr().(*net.UDPAddr).AddrPort()
	flow := identity.Flow{Protocol: "udp", Direction: "outgoing", Local: local, Remote: netip.MustParseAddrPort("127.0.0.1:9"), NetNS: identity.NetNS()}
	counts := population()
	f, err := os.OpenFile(filepath.Join(*out, "cpu.pprof"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(err)
	must(pprof.StartCPUProfile(f))
	started := time.Now()
	var before, after unix.Rusage
	must(unix.Getrusage(unix.RUSAGE_SELF, &before))
	rows := make([]map[string]any, 0, 8)
	for i := 0; i < 8 && time.Since(started) < 4*time.Second; i++ {
		t := time.Now()
		a := identity.Resolve(flow)
		rows = append(rows, map[string]any{"elapsed_ms": float64(time.Since(t).Nanoseconds()) / 1e6, "status": a.Status, "reason_code": a.ReasonCode, "complete": a.VisibilityComplete, "owners": len(a.Owners), "sockets": len(a.Sockets)})
		time.Sleep(100 * time.Millisecond)
	}
	must(unix.Getrusage(unix.RUSAGE_SELF, &after))
	pprof.StopCPUProfile()
	must(f.Close())
	cpu := func(u unix.Rusage) float64 {
		return float64(u.Utime.Sec+u.Stime.Sec) + float64(u.Utime.Usec+u.Stime.Usec)/1e6
	}
	result := map[string]any{"scope": "Native test-owned socket, host PID/proc population, private network, zero sends. Not full Wine renewal or gameplay acceptance.", "population_before_samples": counts, "samples": rows, "cpu_seconds": cpu(after) - cpu(before), "elapsed_seconds": time.Since(started).Seconds(), "holder_enumeration": identity.HolderEnumeration()}
	b, err := json.MarshalIndent(result, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(*out, "result.json"), append(b, '\n'), 0600))
	fmt.Printf("census diagnostic: samples=%d cpu_s=%.3f; evidence=%s\n", len(rows), cpu(after)-cpu(before), *out)
}
