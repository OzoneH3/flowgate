package identity

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeHardlinksKeepIdentityAndRevision(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "deployment-1", "files", "bin", "interpreter")
	os.MkdirAll(filepath.Dir(source), 0700)
	os.WriteFile(filepath.Join(root, "deployment-1", "usr-mtree.txt.gz"), []byte("fixture"), 0600)
	os.WriteFile(source, []byte("runtime one"), 0700)
	st, _ := os.Stat(source)
	dev, ino := devIno(st)
	first := Application{Kind: "native", Executable: "/usr/bin/interpreter", HostExecutable: source, Revision: runtimeContentRevision(source)}
	first.Key = ApplicationKey(1000, first)
	ev := ExecutableEvidence{UID: 1000, Dev: dev, Inode: ino, Stamp: statStamp(st), Visibility: VisibilityHost, HostPath: source, SHA256: first.Revision[len("sha256:"):], DigestState: "done"}
	for _, name := range []string{"tmp-first", "tmp-second"} {
		temp := filepath.Join(root, "var", name, "usr", "bin", "interpreter")
		os.MkdirAll(filepath.Dir(temp), 0700)
		if err := os.Link(source, temp); err != nil {
			t.Fatal(err)
		}
		if got := runtimeBackingSource(temp, dev, ino); got != source {
			t.Fatalf("source=%q", got)
		}
		next := first
		next.HostExecutable = runtimeBackingSource(temp, dev, ino)
		next.Revision = runtimeContentRevision(temp)
		if ApplicationKey(1000, next) != first.Key || next.Revision != first.Revision {
			t.Fatal("hardlink churn changed application")
		}
		if err := VerifyRetainedEvidence(first, 1000, ev); err != nil {
			t.Fatal("hardlink ctime invalidated saved evidence:", err)
		}
		os.Remove(temp)
	}
	if ApplicationKey(1001, first) == first.Key {
		t.Fatal("users merged")
	}
	other := first
	other.HostExecutable = filepath.Join(root, "other", "interpreter")
	if ApplicationKey(1000, other) == first.Key {
		t.Fatal("independent deployment merged")
	}
	time.Sleep(5 * time.Millisecond)
	os.WriteFile(source, []byte("runtime two"), 0700)
	if runtimeContentRevision(source) == first.Revision {
		t.Fatal("content change reused revision")
	}
	if VerifyRetainedEvidence(first, 1000, ev) == nil {
		t.Fatal("modified file accepted")
	}
}

func TestRuntimeSourceRequiresSameFile(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "deployment", "files", "bin", "app")
	os.MkdirAll(filepath.Dir(source), 0700)
	os.WriteFile(source, []byte("same content"), 0700)
	os.WriteFile(filepath.Join(root, "deployment", "usr-mtree.txt.gz"), nil, 0600)
	temp := filepath.Join(root, "var", "tmp-test", "usr", "bin", "app")
	os.MkdirAll(filepath.Dir(temp), 0700)
	os.WriteFile(temp, []byte("same content"), 0700)
	st, _ := os.Stat(temp)
	dev, ino := devIno(st)
	if runtimeBackingSource(temp, dev, ino) != "" {
		t.Fatal("matching filename/content treated as hardlink proof")
	}
}
