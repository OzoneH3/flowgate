package identity

import (
	"fmt"
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
	Activity  ActivitySnapshot
	Confirmed map[string]bool
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
	snapshot.Collected = time.Now()
	snapshot.DurationMS = snapshot.Collected.Sub(snapshot.Started).Milliseconds()
	return ConnectionSample{Activity: snapshot, Confirmed: confirmed}
}
