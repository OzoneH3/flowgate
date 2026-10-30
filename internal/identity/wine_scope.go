package identity

import (
	"fmt"
	"os"
	"syscall"
)

// Scope observations are exclusion filters only, not identity evidence. These
// are the exact proc UID and namespace sources Inspect uses. Every process is
// still enumerated; unknown or changing observations go through full inspection.
// This remains a non-atomic proc snapshot: setuid/setns after the final read can
// change scope, just as it can immediately after Inspect. No evidence is cached.
type wineScope struct {
	Start, Exe, NetNS, MountNS string
	UID                        uint32
}

func readWineScope(pid int, mount bool) (wineScope, error) {
	base := fmt.Sprintf("/proc/%d", pid)
	start, _, err := processStat(base)
	if err != nil {
		return wineScope{}, err
	}
	st, err := os.Stat(base)
	if err != nil {
		return wineScope{}, err
	}
	s := wineScope{Start: start, Exe: link(base + "/exe"), UID: st.Sys().(*syscall.Stat_t).Uid, NetNS: link(base + "/ns/net")}
	if mount {
		s.MountNS = link(base + "/ns/mnt")
	}
	if s.Exe == "" || s.NetNS == "" || mount && s.MountNS == "" {
		return s, fmt.Errorf("process scope unavailable")
	}
	end, _, err := processStat(base)
	if err != nil || end != start || s.Exe != link(base+"/exe") {
		return s, fmt.Errorf("process scope changed")
	}
	return s, nil
}

func wineScopeCandidate(b Process, mount bool, read func() (wineScope, error)) bool {
	if b.NetNS == "" || mount && b.MountNS == "" {
		return true
	}
	first, err := read()
	if err != nil {
		return true
	}
	if first.UID == b.UID && first.NetNS == b.NetNS && (!mount || first.MountNS == b.MountNS) {
		return true
	}
	// UID/namespaces can change without exec. Bookend them too before excluding.
	last, err := read()
	return err != nil || first != last
}

func mayShareWineScope(pid int, b *Process, mount bool) bool {
	return wineScopeCandidate(*b, mount, func() (wineScope, error) { return readWineScope(pid, mount) })
}
