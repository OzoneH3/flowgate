package identity

import (
	"encoding/hex"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
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
		candidate, ok := serviceDisplayUnit(strings.TrimSuffix(unit, ".service"))
		if !ok {
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

func serviceDisplayUnit(unit string) (string, bool) {
	var name strings.Builder
	for i := 0; i < len(unit); {
		if unit[i] != '\\' {
			name.WriteByte(unit[i])
			i++
			continue
		}
		if i+4 > len(unit) || unit[i+1] != 'x' {
			return "", false
		}
		b, err := hex.DecodeString(unit[i+2 : i+4])
		if err != nil {
			return "", false
		}
		name.WriteByte(b[0])
		i += 4
	}
	n := name.String()
	// XDG launches, D-Bus activation and user managers are launch context,
	// not service names for every descendant executable in their cgroup.
	if n == "" || len(n) > 240 || !utf8.ValidString(n) || strings.HasPrefix(n, "app-") || strings.HasPrefix(n, "dbus-") || strings.HasPrefix(n, "user@") || strings.HasSuffix(n, "@autostart") {
		return "", false
	}
	for _, r := range n {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '/' || r == '\\' {
			return "", false
		}
	}
	return n, true
}
