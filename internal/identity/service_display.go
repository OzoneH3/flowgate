package identity

import (
	"path"
	"strings"
)

// applyServiceDisplay is presentation only. A service cgroup is not evidence
// for an executable identity or for permission inheritance between its members.
func applyServiceDisplay(a *Application, cgroup string) {
	if a.Kind != "native" {
		return
	}
	name := ""
	for _, line := range strings.Split(cgroup, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || !(parts[0] == "0" && parts[1] == "" || parts[1] == "name=systemd") {
			continue
		}
		p := parts[2]
		if !strings.HasPrefix(p, "/") || path.Clean(p) != p {
			return
		}
		// Do not label arbitrary user sessions or nested app scopes after an
		// ancestor service such as user@1000.service.
		unit := path.Base(p)
		if !strings.HasSuffix(unit, ".service") {
			continue
		}
		candidate := strings.TrimSuffix(unit, ".service")
		if candidate == "" || len(candidate) > 240 || strings.ContainsAny(candidate, "\x00\r\n\t") {
			return
		}
		if name != "" && name != candidate {
			return
		}
		name = candidate
	}
	if name == "" || name == a.DisplayName {
		return
	}
	a.DisplayName = name + " (" + a.DisplayName + ")"
}
