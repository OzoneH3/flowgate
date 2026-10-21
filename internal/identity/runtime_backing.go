package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// pressure-vessel creates disposable hard-linked runtime trees under var/tmp-*.
// A path pattern only locates candidates: the deployed source must be the exact
// device/inode currently executed. Never merge unrelated copies by name/hash.
func runtimeBackingSource(host string, dev, ino uint64) string {
	parts := strings.Split(filepath.Clean(host), string(os.PathSeparator))
	for i := 1; i+2 < len(parts); i++ {
		if parts[i] != "var" || !strings.HasPrefix(parts[i+1], "tmp-") {
			continue
		}
		root := strings.Join(parts[:i], string(os.PathSeparator))
		rel := filepath.Join(parts[i+2:]...)
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) > 128 {
			return ""
		}
		for _, e := range entries {
			if !e.IsDir() || e.Name() == "var" {
				continue
			}
			deployment := filepath.Join(root, e.Name())
			// The runtime deployment manifest distinguishes sources from temp trees.
			if st, err := os.Stat(filepath.Join(deployment, "usr-mtree.txt.gz")); err != nil || !st.Mode().IsRegular() {
				continue
			}
			for _, r := range []string{rel, strings.TrimPrefix(rel, "usr/")} {
				candidate := filepath.Join(deployment, "files", r)
				if sameFile(candidate, dev, ino) {
					canonical, err := filepath.EvalSymlinks(candidate)
					if err == nil {
						return canonical
					}
				}
			}
		}
	}
	return ""
}

// Content revisions avoid ctime changes caused solely by adding/removing a hard
// link. The key still contains the verified deployment path and user; content
// equality alone never merges identities. Hash cache is invalidated by ctime.
func runtimeContentRevision(target string) string {
	f, err := os.Open(target)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > MaxExecutableDigestBytes {
		return ""
	}
	stamp := statStamp(st)
	sum, ok := cachedDigest(stamp)
	if !ok {
		if !takeDigestBudget(st.Size()) {
			return ""
		}
		sum, err = hashOpened(f, stamp)
		if err != nil {
			return ""
		}
		storeDigest(stamp, sum)
	}
	return "sha256:" + sum
}

func contentRevision(a Application) bool {
	return a.Kind == "native" && a.HostExecutable != "" && strings.HasPrefix(a.Revision, "sha256:") && len(a.Revision) == 71
}

func validateApplicationRevision(a Application, target string, st os.FileInfo) error {
	actual := statStamp(st)
	if contentRevision(a) {
		actual = runtimeContentRevision(target)
	}
	if actual == "" || actual != a.Revision {
		return fmt.Errorf("executable changed since attribution")
	}
	return nil
}

func isRuntimeDeploymentFile(host string) bool {
	for dir := filepath.Dir(host); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if filepath.Base(dir) != "files" {
			continue
		}
		st, err := os.Stat(filepath.Join(filepath.Dir(dir), "usr-mtree.txt.gz"))
		return err == nil && st.Mode().IsRegular()
	}
	return false
}
