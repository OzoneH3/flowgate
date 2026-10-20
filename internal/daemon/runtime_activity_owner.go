package daemon

import "flowgate/internal/identity"

// Runtime policy targeting uses the recorded broker generation as a witness,
// never the ordering of FD holders. The Windows executable remains the target.
func runtimeActivityOwner(s identity.ActivitySnapshot, row identity.ActivityRow) (identity.ActivityProcess, bool) {
	r := row.RuntimeApplication
	if r == nil || r.Application.Kind != "wine" || r.Application.Key == "" || r.Application.Revision == "" || row.Socket.Cookie == "" || r.Evidence.SocketCookie != row.Socket.Cookie || r.UID != r.Evidence.UID {
		return identity.ActivityProcess{}, false
	}
	for _, id := range row.Owners {
		p, ok := s.Processes[id]
		if ok && p.PID == r.Evidence.BrokerPID && p.Start == r.Evidence.BrokerStart && p.UID == r.UID {
			p.Application = r.Application
			return p, true
		}
	}
	return identity.ActivityProcess{}, false
}
