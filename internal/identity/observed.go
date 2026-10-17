package identity

import "fmt"

// VerifyObservedNative reuses the bounded descriptor census and Inspect, without
// using caller metadata as an identity. This pins an executable for rule creation,
// not exclusive socket use or a verdict. Unseen descriptor manipulation remains
// outside the snapshot model. Foreign namespaces and runtime identities reject.
func VerifyObservedNative(rowID string, expected ActivityProcess) (Process, error) {
	var collector ActivityCollector
	s := collector.Collect()
	if s.Error != "" {
		return Process{}, fmt.Errorf("fresh Activity collection unavailable")
	}
	var current *ActivityProcess
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
		}
		break
	}
	if current == nil || current.PID != expected.PID || current.Start != expected.Start || current.UID != expected.UID || current.Application.Kind != "native" || current.Application.Key != expected.Application.Key || current.Application.Revision != expected.Application.Revision {
		return Process{}, fmt.Errorf("observed native target exited or changed; refresh Activity")
	}
	p, err := Inspect(current.PID)
	if err != nil {
		return Process{}, fmt.Errorf("live process inspection unavailable")
	}
	if p.Start != expected.Start || p.UID != expected.UID || p.Application.Kind != "native" || p.Application.Key == "" || p.Application.Key != expected.Application.Key || p.Application.Revision == "" || p.Application.Revision != expected.Application.Revision || p.ExecutableRevision != p.Application.Revision || p.NetNS != NetNS() || p.MountNS == "" || p.MountNS != link("/proc/self/ns/mnt") {
		return Process{}, fmt.Errorf("process generation, executable, principal or namespace changed/unsupported")
	}
	return p, nil
}
