package identity

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// wineEnvironmentRaw is shared with Inspect: last duplicate wins and
// WINEPREFIX takes precedence. It performs no filesystem operations.
func wineEnvironmentRaw(raw string) (prefix, steamAppID string) {
	env := map[string]string{}
	for _, v := range strings.Split(raw, "\x00") {
		k, val, ok := strings.Cut(v, "=")
		if ok && (k == "WINEPREFIX" || k == "STEAM_COMPAT_DATA_PATH" || k == "SteamAppId") {
			env[k] = val
		}
	}
	prefix = env["WINEPREFIX"]
	if prefix == "" && env["STEAM_COMPAT_DATA_PATH"] != "" {
		prefix = filepath.Join(env["STEAM_COMPAT_DATA_PATH"], "pfx")
	}
	return prefix, env["SteamAppId"]
}

func wineEnvironmentIdentity(raw string) (prefix, steamAppID string) {
	prefix, steamAppID = wineEnvironmentRaw(raw)
	if !filepath.IsAbs(prefix) {
		return "", steamAppID
	}
	if canonical, err := filepath.EvalSymlinks(prefix); err == nil {
		prefix = canonical
	}
	return prefix, steamAppID
}

// This fresh negative filter never identifies an application. Unknown reads or
// exec/generation changes reach full Inspect. Environment and symlink changes
// without exec retain the existing non-atomic /proc snapshot window.
func readWineEnvironment(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, (1<<20)+1))
}

func mayShareWinePrefix(pid int, prefix string) bool {
	return winePrefixCandidate(pid, prefix, processStat, link, readWineEnvironment)
}

// Before checking UID and namespaces, keep explicit prefix candidates and
// Wine loaders that could be using the default. Do not resolve their paths here.
func mayHaveWinePrefix(pid int, prefix string) bool {
	if prefix == "" || prefix == "." {
		return true
	}
	return wineEnvironmentCandidate(pid, func(raw string) bool {
		p, _ := wineEnvironmentRaw(raw)
		return p != "" || (defaultWinePath(raw) != "" && wineRuntimeHint(link(fmt.Sprintf("/proc/%d/exe", pid)), ""))
	}, processStat, link, readWineEnvironment)
}

func winePrefixCandidate(pid int, prefix string, stat func(string) (string, int, error), readLink func(string) string, read func(string) ([]byte, error)) bool {
	if prefix == "" {
		return true
	}
	return wineEnvironmentCandidate(pid, func(raw string) bool {
		observed, _ := wineEnvironmentIdentity(raw)
		if observed == "" {
			if candidate := defaultWinePath(raw); candidate != "" {
				observed, _ = filepath.EvalSymlinks(candidate)
			}
		}
		return observed == prefix
	}, stat, readLink, read)
}

func wineEnvironmentCandidate(pid int, matches func(string) bool, stat func(string) (string, int, error), readLink func(string) string, read func(string) ([]byte, error)) bool {
	base := fmt.Sprintf("/proc/%d", pid)
	start, _, err := stat(base)
	if err != nil {
		return true
	}
	exe := readLink(base + "/exe")
	if exe == "" {
		return true
	}
	raw, err := read(base + "/environ")
	if err != nil || len(raw) >= 1<<20 {
		return true
	}
	if matches(string(raw)) {
		return true
	}
	end, _, err := stat(base)
	return err != nil || start != end || exe != readLink(base+"/exe")
}
