package identity

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ObsoleteNativeRevision is deliberately conservative: only an ordinary native
// executable replaced at its exact path qualifies. Missing files, runtime
// identities, incomplete process visibility and alternate mount views stay.
// This is a startup census, not proof against a future rollback/reinstallation.
func ObsoleteNativeRevision(path, key, revision string, uid uint32) bool {
	return NewObsoleteNativeChecker()(path, key, revision, uid)
}

// NewObsoleteNativeChecker shares one process census across a cleanup batch.
// The returned checker is for one sequential worker and must not be reused
// across startup/cleanup operations.
func NewObsoleteNativeChecker() func(string, string, string, uint32) bool {
	return newObsoleteNativeChecker("/proc")
}
func obsoleteNativeRevision(proc, path, key, revision string, uid uint32) bool {
	return newObsoleteNativeChecker(proc)(path, key, revision, uid)
}

type obsoleteProcessCensus struct {
	complete       bool
	inodes         map[string]bool
	alternateRoots []string
}

func newObsoleteNativeChecker(proc string) func(string, string, string, uint32) bool {
	var census *obsoleteProcessCensus
	return func(path, key, revision string, uid uint32) bool {

		if !filepath.IsAbs(path) || filepath.Clean(path) != path || key != ApplicationKey(uid, Application{Kind: "native", Executable: path}) {
			return false
		}
		// Content/runtime revisions must be checked by their own runtime mechanism.
		parts := strings.Split(revision, ":")
		if len(parts) != 4 {
			return false
		}
		for _, p := range parts {
			if _, err := strconv.ParseInt(p, 10, 64); err != nil {
				return false
			}
		}
		st, err := os.Stat(path)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
			return false
		}
		current := statStamp(st)
		if current == "" || current == revision {
			return false
		}

		if census == nil {
			c := collectObsoleteProcesses(proc)
			census = &c
		}
		if !census.complete || census.inodes[parts[0]] {
			return false
		}
		for _, root := range census.alternateRoots {
			if stamp(root+path) != current {
				return false
			}
		}

		// Avoid treating an executable replaced again during the census as evidence.
		return stamp(path) == current
	}
}

func collectObsoleteProcesses(proc string) obsoleteProcessCensus {
	result := obsoleteProcessCensus{inodes: map[string]bool{}}
	entries, err := os.ReadDir(proc)
	if err != nil {
		return result
	}
	ownNS, err := os.Readlink(filepath.Join(proc, "self/ns/mnt"))
	if err != nil {
		return result
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		base := filepath.Join(proc, entry.Name())
		raw, err := os.ReadFile(base + "/stat")
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return result
		}
		i := strings.LastIndex(string(raw), ") ")
		if i < 0 {
			return result
		}
		fields := strings.Fields(string(raw)[i+2:])
		if len(fields) < 7 {
			return result
		}
		flags, err := strconv.ParseUint(fields[6], 10, 64)
		if err != nil {
			return result
		}
		if fields[0] == "Z" || fields[0] == "X" || flags&0x200000 != 0 {
			continue
		}
		live := stamp(base + "/exe")
		if live == "" {
			if _, err := os.Stat(base); os.IsNotExist(err) {
				continue
			}
			return result
		}
		// Rename/unlink can change ctime on the running old inode. Retain
		// by inode as well, rather than requiring its old stamp verbatim.
		result.inodes[strings.Split(live, ":")[0]] = true
		ns, err := os.Readlink(base + "/ns/mnt")
		if err != nil {
			return result
		}
		if ns != ownNS || link(base+"/root") != "/" {
			// The same pathname can still name the old executable in a container.
			// Even an unavailable alternate view is insufficient evidence to delete.
			result.alternateRoots = append(result.alternateRoots, base+"/root")
		}
	}
	result.complete = true
	return result
}
