package identity

import "fmt"

// VerifyObservedNative reuses the bounded descriptor census and Inspect, without
// using caller metadata as an identity. This pins an executable for rule creation,
// not exclusive socket use or a verdict. Unseen descriptor manipulation remains
// outside the snapshot model. Foreign namespaces and runtime identities reject.
func VerifyObservedNative(rowID string, expected ActivityProcess) (Process, error) {
	var collector ActivityCollector
	return verifyObservedNativeSnapshot(rowID, expected, collector.Collect(), Inspect)
}

func verifyObservedNativeSnapshot(rowID string, expected ActivityProcess, s ActivitySnapshot, inspect func(int) (Process, error)) (Process, error) {
	if s.Error != "" {
		return Process{}, fmt.Errorf("fresh Activity collection unavailable")
	}
	var current *ActivityProcess
	var holderWitness string
	for _, row := range s.Rows {
		if row.ID != rowID {
			continue
		}
		if row.OwnershipCategory != "visible-holder" || len(row.Owners) != 1 || row.Owners[0] != expected.ID || row.Socket.NetNS != NetNS() || row.Socket.Cookie == "" || row.Socket.Inode == 0 {
			return Process{}, fmt.Errorf("socket is shared, changed, or lacks supported current ownership")
		}
		p, ok := s.Processes[expected.ID]
		if ok {
			current = &p
			holderWitness = row.HolderWitness
		}
		break
	}
	if current == nil || current.PID != expected.PID || current.Start != expected.Start || current.UID != expected.UID || !LiveRuleable(current.Application) || current.Application.Key != expected.Application.Key || current.Application.Revision != expected.Application.Revision {
		return Process{}, fmt.Errorf("observed native target exited or changed; refresh Activity")
	}
	p, err := inspect(current.PID)
	if err != nil {
		return Process{}, fmt.Errorf("live process inspection unavailable")
	}
	// Native identity comes from the live /proc/PID/exe inode, not a path opened
	// in the daemon's mount namespace. Sandboxed services may legitimately have a
	// private mount namespace; bind it to the observed target rather than requiring
	// the daemon's namespace. Network namespaces remain restricted to our hook scope.
	if p.Start != expected.Start || p.UID != expected.UID || !LiveRuleable(p.Application) || p.Application.Kind != expected.Application.Kind || p.Application.Key != expected.Application.Key || p.Application.Revision != expected.Application.Revision || (p.Application.Kind == "native" && !contentRevision(p.Application) && p.ExecutableRevision != p.Application.Revision) || p.NetNS != NetNS() || p.NetNS != expected.NetNS || p.MountNS == "" || p.MountNS != expected.MountNS || p.PIDNS != expected.PIDNS || p.BootID != expected.BootID {
		return Process{}, fmt.Errorf("process generation, executable, principal or namespace changed/unsupported")
	}
	// The fresh row, not the request or process-wide display map, carries
	// restrictions on this socket's holder topology.
	p.HolderWitness = holderWitness
	return p, nil
}
