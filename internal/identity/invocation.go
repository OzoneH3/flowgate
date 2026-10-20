package identity

// Invocation is captured display context, never a permission target. A script
// argument and a readable file do not attest which code an interpreter executes.
import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

type Invocation struct {
	Mode        string       `json:"mode"`
	Name        string       `json:"name"`
	Path        string       `json:"path,omitempty"`
	HostPath    string       `json:"host_path,omitempty"`
	Revision    string       `json:"revision,omitempty"`
	Application *Application `json:"application,omitempty"`
}

var pythonRuntime = regexp.MustCompile(`^python(?:[23](?:\.[0-9]+)*)?$`)

func interpreterKind(exe string) string {
	name := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
	if pythonRuntime.MatchString(name) {
		return "python"
	}
	if name == "node" || name == "nodejs" {
		return "node"
	}
	return ""
}

// Deliberately bounded option parsing: unknown switches yield no guessed path.
// Inline source, arbitrary arguments and environment values are never retained.
func invocationArgument(exe string, args []string) (string, string) {
	kind := interpreterKind(exe)
	if kind == "" {
		return "", ""
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return "file", args[i+1]
			}
			return "", ""
		}
		if a == "-" {
			return "stdin", ""
		}
		if (kind == "python" && a == "-c") || (kind == "node" && (a == "-e" || a == "--eval" || a == "-p" || a == "--print")) {
			return "inline", ""
		}
		if kind == "python" && a == "-m" {
			return "module", ""
		}
		if !strings.HasPrefix(a, "-") {
			return "file", a
		}
		if kind == "python" && (a == "-u" || a == "-B" || a == "-I" || a == "-E" || a == "-s" || a == "-S" || a == "-O" || a == "-OO") {
			continue
		}
		if kind == "python" && (a == "-W" || a == "-X") {
			i++
			continue
		}
		if kind == "node" && (a == "--no-warnings" || a == "--enable-source-maps") {
			continue
		}
		return "", ""
	}
	return "", ""
}
func captureInvocation(n procNode) *Invocation {
	mode, arg := invocationArgument(n.exe, n.argv)
	if mode == "" {
		return nil
	}
	if mode != "file" {
		return &Invocation{Mode: mode, Name: mode + " interpreter input"}
	}
	if arg == "" || len(arg) > provenanceMaxString || strings.ContainsAny(arg, "\r\n\x00") {
		return nil
	}
	if !filepath.IsAbs(arg) {
		arg = filepath.Join(n.cwd, arg)
	}
	if !filepath.IsAbs(arg) {
		return nil
	}
	arg = filepath.Clean(arg)
	base := fmt.Sprintf("/proc/%d", n.pid)
	st, err := os.Stat(base + "/root" + arg)
	if err != nil || !st.Mode().IsRegular() {
		return &Invocation{Mode: "unverified-file", Name: filepath.Base(arg), Path: arg}
	}
	host, _, _ := hostBackingPath(n.pid, link(base+"/ns/mnt"), arg, st.Sys().(*syscall.Stat_t).Dev, st.Sys().(*syscall.Stat_t).Ino)
	inv := &Invocation{Mode: "file", Name: filepath.Base(arg), Path: arg, HostPath: host, Revision: statStamp(st)}
	if host != "" {
		a := Application{Kind: "native", Name: inv.Name, Executable: host, Revision: inv.Revision}
		a.Key = ApplicationKey(n.uid, a)
		inv.Application = &a
	}
	return inv
}
