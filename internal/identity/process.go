// Package identity provides conservative, host-side observations, not security attestations.
package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type Application struct {
	Key        string   `json:"key"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Executable string   `json:"executable"`
	Revision   string   `json:"revision"`
	Runtime    string   `json:"runtime,omitempty"`
	Prefix     string   `json:"prefix,omitempty"`
	SteamAppID string   `json:"steam_app_id,omitempty"`
	Evidence   []string `json:"evidence"`
}
type Process struct {
	ExecutableRevision string      `json:"executable_revision"`
	PID                int         `json:"pid"`
	Start              string      `json:"start_ticks"`
	UID                uint32      `json:"uid"`
	NetNS              string      `json:"netns"`
	MountNS            string      `json:"mountns"`
	Parent             int         `json:"parent_pid"`
	Executable         string      `json:"executable"`
	Cgroup             string      `json:"cgroup,omitempty"`
	Application        Application `json:"application"`
}

func readBound(path string, n int64) []byte {
	f, e := os.Open(path)
	if e != nil {
		return nil
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, n))
	return b
}
func link(path string) string { s, _ := os.Readlink(path); return s }
func digest(s string) string  { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func stamp(path string) string {
	st, e := os.Stat(path)
	if e != nil {
		return ""
	}
	s := st.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d:%d:%d:%d", s.Dev, s.Ino, st.Size(), st.ModTime().UnixNano(), s.Ctim.Nano())
}
func processStat(base string) (string, int, error) {
	s := string(readBound(base+"/stat", 8192))
	i := strings.LastIndex(s, ") ")
	if i < 0 {
		return "", 0, fmt.Errorf("process stat unavailable")
	}
	f := strings.Fields(s[i+2:])
	if len(f) < 20 {
		return "", 0, fmt.Errorf("short process stat")
	}
	p, _ := strconv.Atoi(f[1])
	return f[19], p, nil
}
func Inspect(pid int) (Process, error) {
	base := fmt.Sprintf("/proc/%d", pid)
	start, parent, e := processStat(base)
	if e != nil {
		return Process{}, e
	}
	p := Process{PID: pid, Start: start, Parent: parent, NetNS: link(base + "/ns/net"), MountNS: link(base + "/ns/mnt"), Executable: link(base + "/exe")}
	if p.Executable == "" {
		return p, fmt.Errorf("executable unreadable")
	}
	st, e := os.Stat(base)
	if e != nil {
		return p, e
	}
	p.UID = st.Sys().(*syscall.Stat_t).Uid
	p.ExecutableRevision = stamp(base + "/exe")
	p.Cgroup = strings.TrimSpace(string(readBound(base+"/cgroup", 4096)))
	a := Application{Kind: "native", Name: filepath.Base(p.Executable), Executable: p.Executable, Revision: stamp(base + "/exe"), Evidence: []string{"proc exe; PID plus start time"}}
	lower := strings.ToLower(p.Executable)
	// Runtime libraries are required as corroboration; arbitrary .exe arguments alone are insufficient.
	maps := string(readBound(base+"/maps", 2<<20))
	wine := strings.Contains(lower, "wine") || strings.Contains(maps, "/ntdll.so") || strings.Contains(maps, "/ntdll.dll")
	if wine {
		a.Kind = "wine-unresolved"
		a.Runtime = p.Executable
		a.Executable = ""
		a.Revision = ""
		a.Name = "Unresolved Wine process"
		env := map[string]string{}
		for _, v := range strings.Split(string(readBound(base+"/environ", 1<<20)), "\x00") {
			k, val, ok := strings.Cut(v, "=")
			if ok && (k == "WINEPREFIX" || k == "STEAM_COMPAT_DATA_PATH" || k == "SteamAppId") {
				env[k] = val
			}
		}
		prefix := env["WINEPREFIX"]
		if prefix == "" && env["STEAM_COMPAT_DATA_PATH"] != "" {
			prefix = filepath.Join(env["STEAM_COMPAT_DATA_PATH"], "pfx")
		}
		if canonical, err := filepath.EvalSymlinks(prefix); err == nil {
			prefix = canonical
		}
		a.SteamAppID = env["SteamAppId"]
		a.Prefix = prefix
		// Only argv[0], corroborated by an executable mapping, identifies the image. Arguments may name another program.
		args := strings.Split(string(readBound(base+"/cmdline", 65536)), "\x00")
		candidates := map[string]string{}
		for _, line := range strings.Split(maps, "\n") {
			f := strings.Fields(line)
			if len(f) < 6 {
				continue
			}
			path := strings.Join(f[5:], " ")
			if strings.HasSuffix(strings.ToLower(path), ".exe") || strings.HasSuffix(strings.ToLower(path), ".exe.so") {
				candidates[path] = f[4]
			}
		}
		if len(args) > 0 {
			arg := strings.ReplaceAll(args[0], "\\", "/")
			if len(arg) > 2 && arg[1] == ':' && prefix != "" {
				drive := strings.ToLower(arg[:1]) + ":"
				arg = filepath.Join(prefix, "dosdevices", drive, arg[2:])
			}
			if !filepath.IsAbs(arg) {
				arg = filepath.Join(link(base+"/cwd"), arg)
			}
			arg, _ = filepath.EvalSymlinks(arg)
			for path, mappedInode := range candidates {
				resolved, _ := filepath.EvalSymlinks(path)
				if (resolved == arg || resolved == arg+".so") && prefix != "" {
					st, err := os.Stat(base + "/root" + resolved)
					if err != nil || fmt.Sprint(st.Sys().(*syscall.Stat_t).Ino) != mappedInode {
						continue
					}
					a.Kind = "wine"
					a.Executable = resolved
					a.Revision = stamp(base + "/root" + resolved)
					a.Name = filepath.Base(resolved)
					a.Evidence = []string{"Wine runtime mapping", "argv[0] corroborated by mapped Windows image", "explicit prefix"}
				}
			}
		}
	}
	if a.Executable != "" && a.Revision != "" {
		a.Key = digest(fmt.Sprintf("%d|%s|%s|%s", p.UID, a.Kind, a.Prefix, a.Executable))
	}
	p.Application = a
	end, _, e := processStat(base)
	if e != nil || end != start {
		return Process{}, fmt.Errorf("process changed during inspection")
	}
	return p, nil
}
func fingerprint(owners []Process, sockets []Socket) string {
	var f []string
	for _, p := range owners {
		f = append(f, fmt.Sprintf("%d:%s:%s:%s", p.PID, p.Start, p.Application.Key, p.Application.Revision+":"+p.ExecutableRevision))
	}
	for _, s := range sockets {
		f = append(f, fmt.Sprintf("%s:%d:%s", s.NetNS, s.Inode, s.Cookie))
	}
	sort.Strings(f)
	return digest(strings.Join(f, "|"))
}
