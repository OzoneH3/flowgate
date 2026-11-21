package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWineEnvironmentSharedDerivation(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "prefix-a")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(dir, "broken")
	if err := os.Symlink(filepath.Join(dir, "missing"), broken); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, raw, want string }{
		{"last duplicate", "WINEPREFIX=/first\x00WINEPREFIX=/last\x00", "/last"},
		{"precedence", "STEAM_COMPAT_DATA_PATH=/data\x00WINEPREFIX=/explicit\x00", "/explicit"},
		{"empty last prefix", "WINEPREFIX=/first\x00WINEPREFIX=\x00STEAM_COMPAT_DATA_PATH=/data\x00", "/data/pfx"},
		{"symlink", "WINEPREFIX=" + alias + "\x00", real},
		{"broken symlink", "WINEPREFIX=" + broken + "\x00", broken},
		{"missing", "OTHER=value\x00", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, id := wineEnvironmentIdentity(tc.raw + "SteamAppId=1\x00SteamAppId=2\x00")
			if got != tc.want || id != "2" {
				t.Fatalf("%q %q", got, id)
			}
		})
	}
}

func TestWinePrefixFilterKeepsUnknownAndChangedProcesses(t *testing.T) {
	for _, mode := range []string{"match", "other-prefix", "missing", "unreadable", "truncated", "start-change", "exe-change", "gone", "exe-unreadable"} {
		t.Run(mode, func(t *testing.T) {
			calls, links := 0, 0
			stat := func(string) (string, int, error) {
				calls++
				if mode == "gone" {
					return "", 0, errors.New("gone")
				}
				if mode == "start-change" && calls > 1 {
					return "2", 0, nil
				}
				return "1", 0, nil
			}
			link := func(string) string {
				links++
				if mode == "exe-unreadable" {
					return ""
				}
				if mode == "exe-change" && links > 1 {
					return "new"
				}
				return "runtime"
			}
			read := func(string) ([]byte, error) {
				if mode == "unreadable" {
					return nil, errors.New("denied")
				}
				if mode == "truncated" {
					return []byte(strings.Repeat("x", 1<<20)), nil
				}
				if mode == "missing" {
					return nil, nil
				}
				if mode == "match" {
					return []byte("WINEPREFIX=/prefix-a\x00"), nil
				}
				return []byte("WINEPREFIX=/prefix-b\x00"), nil
			}
			got := winePrefixCandidate(123, "/prefix-a", stat, link, read)
			want := mode != "other-prefix" && mode != "missing"
			if got != want {
				t.Fatalf("candidate=%v want=%v", got, want)
			}
		})
	}
}

func TestWinePrefixFilterDoesNotExcludeMatchingDeletedImageOrNativeCandidate(t *testing.T) {
	// The filter has no maps/name predicate: a same-prefix deleted image must
	// reach imageRevisionVisible's negative check, and native-looking candidates
	// must still reach Inspect. Distinct applications in one prefix are not merged.
	for _, exe := range []string{"runtime", "runtime (deleted)", "native"} {
		if !winePrefixCandidate(1, "/prefix-a", func(string) (string, int, error) { return "1", 0, nil }, func(string) string { return exe }, func(string) ([]byte, error) { return []byte("WINEPREFIX=/prefix-a\x00"), nil }) {
			t.Fatal(exe)
		}
	}
}

func TestWineAbsentPrefixFilterDoesNotResolvePaths(t *testing.T) {
	// A symlink-like or remote-looking value must go to the scoped path; only
	// absent/empty prefix variables can be excluded without filesystem work.
	for _, raw := range []string{"WINEPREFIX=/untrusted/path\x00", "WINEPREFIX=relative\x00", "STEAM_COMPAT_DATA_PATH=/untrusted/data\x00"} {
		if !wineEnvironmentCandidate(1, func(raw string) bool { p, _ := wineEnvironmentRaw(raw); return p != "" }, func(string) (string, int, error) { return "1", 0, nil }, func(string) string { return "exe" }, func(string) ([]byte, error) { return []byte(raw), nil }) {
			t.Fatal("nonempty prefix was excluded", raw)
		}
	}
	if wineEnvironmentCandidate(1, func(raw string) bool { p, _ := wineEnvironmentRaw(raw); return p != "" }, func(string) (string, int, error) { return "1", 0, nil }, func(string) string { return "exe" }, func(string) ([]byte, error) { return []byte("OTHER=value\x00"), nil }) {
		t.Fatal("stable absent prefix not excluded")
	}
}

func TestDefaultWinePrefixDiscoveryInputs(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"HOME=/home/user\x00", "/home/user/.wine"},
		{"HOME=/first\x00HOME=/second\x00", "/second/.wine"},
		{"HOME=relative\x00", ""}, {"", ""},
		{"HOME=/home/user\x00WINEPREFIX=\x00", ""},
		{"HOME=/home/user\x00WINEPREFIX=relative\x00", ""},
		{"HOME=/home/user\x00WINEPREFIX=/other\x00", ""},
		{"HOME=/home/user\x00STEAM_COMPAT_DATA_PATH=/steam\x00", ""},
	} {
		if got := defaultWinePath(tc.raw); got != tc.want {
			t.Errorf("defaultWinePath(%q) = %q; want %q", tc.raw, got, tc.want)
		}
	}
}
