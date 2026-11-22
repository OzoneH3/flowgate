package identity

import (
	"fmt"
	"maps"
	"slices"
	"time"
)

// ConnectionKey correlates observations within a live daemon. Inode changes
// (including TIME_WAIT) must not carry a holder from a previous observation.
func ConnectionKey(s Socket) string {
	key := directionKey(s)
	if key == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", key, s.Inode)
}

type ConnectionSample struct {
	Activity         ActivitySnapshot
	Confirmed        map[string]bool
	WineHolderChecks map[string]string // keyed by Activity process ID; an empty reason confirms the earlier image
}

// CollectConnectionSample bookends the Activity holder census with socket
// diagnostics. It never publishes Activity or calls admission.
func CollectConnectionSample(localPort uint16, annotate func(*ActivitySnapshot)) ConnectionSample {
	c := ActivityCollector{}
	snapshot := c.collect(localPort)
	if annotate != nil {
		annotate(&snapshot)
	}
	confirmed := make(map[string]bool)
	if snapshot.Error == "" && len(snapshot.Rows) != 0 {
		sockets, err := SocketsLimited(2048)
		for _, s := range sockets {
			if key := ConnectionKey(s); key != "" {
				confirmed[key] = true
			}
		}
		if err != nil {
			snapshot.Complete = false
			snapshot.Issues = append(snapshot.Issues, "Socket identity confirmation incomplete")
		}
	}
	wineHolders := make(map[string]string)
	deadline := time.Now().Add(defaultHolderLimits.Time)
	for _, id := range slices.Sorted(maps.Keys(snapshot.Processes)) {
		if time.Now().After(deadline) {
			break
		}
		p := snapshot.Processes[id]
		if p.Application.Kind == "wine" {
			wineHolders[id] = recheckConnectionWineHolder(p)
		}
	}
	snapshot.Collected = time.Now()
	snapshot.DurationMS = snapshot.Collected.Sub(snapshot.Started).Milliseconds()
	return ConnectionSample{Activity: snapshot, Confirmed: confirmed, WineHolderChecks: wineHolders}
}

// Re-run the process resolver without the Activity cache. An exec of the same
// native loader can preserve all proc identity fields and the socket descriptor
// while replacing the Windows image or prefix.
func recheckConnectionWineHolder(p ActivityProcess) string {
	current, err := Inspect(p.PID)
	if err != nil {
		return "The holder exited or was no longer inspectable before its Windows image could be rechecked"
	}
	facts, err := readHolderFacts(Holder{TGID: p.PID}, HolderMember{TID: p.PID, Start: p.Start})
	if err != nil || facts.UID != p.UID || facts.Exe != p.Executable ||
		facts.Revision != p.ExecutableRevision || facts.NetNS != p.NetNS ||
		facts.MountNS != p.MountNS || facts.PIDNS != p.PIDNS ||
		current.Start != p.Start || current.UID != p.UID || current.Executable != p.Executable ||
		current.ExecutableRevision != p.ExecutableRevision || current.NetNS != p.NetNS ||
		current.MountNS != p.MountNS || current.PIDNS != p.PIDNS {
		return "The holder exited or its process identity changed during collection"
	}

	old, fresh := p.Application, current.Application
	if fresh.Prefix == "" {
		return "The Wine prefix could no longer be verified"
	}
	if fresh.Kind != "wine" || fresh.Executable == "" || fresh.Revision == "" || fresh.Key == "" {
		return "The mapped Windows executable could no longer be verified"
	}
	prefixChanged := old.Prefix != fresh.Prefix
	imageChanged := old.Executable != fresh.Executable || old.Revision != fresh.Revision
	switch {
	case prefixChanged && imageChanged:
		return "The mapped Windows executable and Wine prefix changed during collection"
	case prefixChanged:
		return "The Wine prefix changed during collection"
	case imageChanged:
		return "The mapped Windows executable changed during collection"
	default:
		return ""
	}
}
