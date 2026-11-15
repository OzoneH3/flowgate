package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAppImageHolderLargeUnrelatedEpoll(t *testing.T) {
	ep, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ep)
	for i := 0; i < 128; i++ {
		fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if err := unix.EpollCtl(ep, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}); err != nil {
			t.Fatal(err)
		}
	}
	base := fmt.Sprintf("/proc/%d", os.Getpid())
	raw, err := os.ReadFile(fmt.Sprintf("%s/fdinfo/%d", base, ep))
	if err != nil || len(raw) <= 4096 {
		t.Fatalf("epoll reproduction: %d bytes, %v", len(raw), err)
	}
	if _, err := appImageReadBound(fmt.Sprintf("%s/fdinfo/%d", base, ep), 4096); err == nil {
		t.Fatal("baseline limit did not refuse")
	}
	if holds, err := appImageConnectionHolder(base, 123456789); err != nil || holds {
		t.Fatalf("unrelated epoll prevents census: holds=%v err=%v", holds, err)
	}
}

func TestAppImageHolderNonAnonymousEvidenceStaysStrict(t *testing.T) {
	for _, tc := range []struct {
		name, target, info string
		want               bool
		bad                bool
	}{
		{"bound-fuse", "/dev/fuse", "fuse_connection: 42\n", true, false},
		{"renamed-device", "/arbitrary/device", "fuse_connection: 42\n", true, false},
		{"other-connection", "/dev/fuse", "fuse_connection: 43\n", false, false},
		{"malformed", "/dev/fuse", "fuse_connection: bad\n", false, true},
		{"oversized", "/dev/fuse", strings.Repeat("x", 4097), false, true},
		{"anonymous-looking-file", "/tmp/anon_inode:[eventpoll]", strings.Repeat("x", 4097), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			for _, d := range []string{"fd", "fdinfo"} {
				if err := os.Mkdir(filepath.Join(base, d), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(tc.target, filepath.Join(base, "fd/3")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(base, "fdinfo/3"), []byte(tc.info), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := appImageHolderScan(base, 42)
			if got != tc.want || (err != nil) != tc.bad {
				t.Fatalf("got %v,%v", got, err)
			}
			if err := os.Remove(filepath.Join(base, "fdinfo/3")); err != nil {
				t.Fatal(err)
			}
			if got, err := appImageHolderScan(base, 42); got || err != nil {
				t.Fatal("closed unobserved descriptor treated as holder/error")
			}
			if err := os.Mkdir(filepath.Join(base, "fdinfo/3"), 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := appImageHolderScan(base, 42); err == nil {
				t.Fatal("unreadable fdinfo accepted")
			}
		})
	}
}

func TestAppImageHolderRetryScope(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fail        int
		seen        bool
		err         error
		generations []string
		wantCalls   int
		wantError   bool
	}{
		{"transient-close", 1, false, os.ErrNotExist, []string{"1", "1", "1"}, 2, false},
		{"persistent-churn", 3, false, os.ErrNotExist, []string{"1", "1", "1", "1"}, 3, true},
		{"seen-holder-not-erased", 1, true, os.ErrNotExist, []string{"1", "1"}, 1, true},
		{"permission", 1, false, os.ErrPermission, []string{"1", "1"}, 1, true},
		{"other-error", 1, false, errors.New("oversize"), []string{"1", "1"}, 1, true},
		{"reuse", 1, false, os.ErrNotExist, []string{"1", "2"}, 1, true},
		{"disappearance", 1, false, os.ErrNotExist, []string{"1", ""}, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, gi := 0, 0
			_, err := appImageStableHolderScan(func() (bool, error) {
				calls++
				if calls <= tc.fail {
					return tc.seen, tc.err
				}
				return false, nil
			}, func() (string, error) {
				v := tc.generations[gi]
				gi++
				if v == "" {
					return "", os.ErrNotExist
				}
				return v, nil
			})
			if calls != tc.wantCalls || (err != nil) != tc.wantError {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestAppImageTableBudgetAndPartialEvidence(t *testing.T) {
	fixture := func(t *testing.T, n int) string {
		base := t.TempDir()
		for _, d := range []string{"fd", "fdinfo"} {
			if err := os.Mkdir(filepath.Join(base, d), 0700); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < n; i++ {
			name := fmt.Sprint(i + 3)
			if err := os.Symlink("/dev/fuse", filepath.Join(base, "fd", name)); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(base, "fdinfo", name), []byte("fuse_connection: 42\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return base
	}
	t.Run("budget-stops-before-read", func(t *testing.T) {
		base := fixture(t, 1)
		os.Remove(filepath.Join(base, "fdinfo/3"))
		calls := 0
		holds, err := appImageTableScan(base, 42, func(path, target string) bool { calls++; return false })
		if holds || err != nil || calls != 1 {
			t.Fatalf("holds=%v err=%v visits=%d", holds, err, calls)
		}
	})
	t.Run("partial-positive-survives-next-fd-disappearance", func(t *testing.T) {
		base := fixture(t, 2)
		attempts, matches := 0, 0
		holds, err := appImageTableScan(base, 42, func(path, target string) bool {
			if target != "" {
				matches++
			} else {
				attempts++
				if attempts == 2 {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
			}
			return true
		})
		if !holds || err != nil || attempts != 2 || matches != 1 {
			t.Fatalf("holds=%v err=%v attempts=%d matches=%d", holds, err, attempts, matches)
		}
	})
	t.Run("unobserved-closed-descriptor-is-charged", func(t *testing.T) {
		base := fixture(t, 1)
		attempts := 0
		holds, err := appImageStableHolderScan(func() (bool, error) {
			return appImageTableScan(base, 42, func(path, target string) bool {
				attempts++
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				return true
			})
		}, func() (string, error) {
			path := filepath.Join(base, "fd/3")
			if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
				if err := os.Symlink("/dev/fuse", path); err != nil {
					t.Fatal(err)
				}
			}
			return "same-generation", nil
		})
		if holds || err != nil || attempts != 1 {
			t.Fatalf("holds=%v err=%v attempts=%d", holds, err, attempts)
		}
	})
	t.Run("fdinfo-closed-before-observation", func(t *testing.T) {
		base := fixture(t, 1)
		if err := os.Remove(filepath.Join(base, "fdinfo/3")); err != nil {
			t.Fatal(err)
		}
		attempts := 0
		holds, err := appImageTableScan(base, 42, func(path, target string) bool { attempts++; return true })
		if holds || err != nil || attempts != 1 {
			t.Fatalf("holds=%v err=%v attempts=%d", holds, err, attempts)
		}
	})
	t.Run("known-holder-recheck-refuses-close-or-reuse", func(t *testing.T) {
		for _, changed := range []string{"closed", "reused", "unreadable"} {
			t.Run(changed, func(t *testing.T) {
				base := fixture(t, 1)
				f := &censusProc{groups: map[int]map[int]*censusTask{100: {100: {start: "1", table: 1}}}, tables: map[int]map[int]string{1: {3: "fuse-connection:[42]"}}}
				p := f.proc()
				p.fds = func(tgid, tid int, visit func(string, string) bool) error {
					_, err := appImageTableScan(base, 42, func(path, target string) bool { return visit("/proc/100/task/100/fd/"+filepath.Base(path), target) })
					return err
				}
				p.readlink = func(path string) (string, error) {
					if changed == "unreadable" && f.links > 0 {
						return "", os.ErrPermission
					}
					raw, err := appImageReadBound(filepath.Join(base, "fdinfo", filepath.Base(path)), 4096)
					if err != nil {
						return "", err
					}
					n, err := fuseConnection(string(raw))
					return fmt.Sprintf("fuse-connection:[%d]", n), err
				}
				c := p.census(map[string]bool{"fuse-connection:[42]": true}, defaultHolderLimits)
				if !c.Complete || len(c.Holders) != 1 {
					t.Fatalf("census incomplete: %+v", c)
				}
				if changed == "closed" {
					os.Remove(filepath.Join(base, "fdinfo/3"))
				} else if changed == "reused" {
					os.WriteFile(filepath.Join(base, "fdinfo/3"), []byte("fuse_connection: 43\n"), 0600)
				} else {
					f.links = 1
				}
				if c.Recheck() == nil {
					t.Fatal("changed known holder accepted")
				}
			})
		}
	})

}

func TestAppImageRuntimeMetadataIsNotCode(t *testing.T) {
	original := make([]byte, appImageRuntimeSize)
	expected := appImageRuntimeDigest(original)
	metadata := append([]byte(nil), original...)
	for i := 175704; i < 185960; i++ {
		metadata[i] = byte(i%255 + 1)
	}
	if appImageRuntimeDigest(metadata) != expected {
		t.Fatal("packaging metadata affected runtime digest")
	}
	for _, offset := range []int{0, 32, 40, 64, 4096, 173960, 175703, 185960, 188391} {
		changed := append([]byte(nil), metadata...)
		changed[offset] ^= 1
		if appImageRuntimeDigest(changed) == expected {
			t.Fatalf("code/layout byte %d not pinned", offset)
		}
	}
	if appImageRuntimeDigest(original[:len(original)-1]) != "" {
		t.Fatal("truncated runtime accepted")
	}
	if original[175704] != 0 {
		t.Fatal("caller bytes mutated")
	}
}

func TestAppImageMappedFileIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime")
	if err := os.WriteFile(path, []byte("runtime"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	dev, ino := devIno(info)
	calls := 0
	stat := func(string) (os.FileInfo, error) { calls++; return info, nil }
	if !appImageMappedFile(info, dev, ino, "mapping", stat) || calls != 0 {
		t.Fatal("direct identity")
	}
	if !appImageMappedFile(info, dev^1, ino, "mapping", stat) || calls != 1 {
		t.Fatal("proven subvolume mapping")
	}
	if appImageMappedFile(info, dev^1, ino+1, "mapping", stat) || calls != 1 {
		t.Fatal("wrong inode")
	}
	if appImageMappedFile(info, dev^1, ino, "mapping", func(string) (os.FileInfo, error) { return nil, os.ErrPermission }) {
		t.Fatal("unreadable mapping")
	}
	foreign := filepath.Join(dir, "other")
	if err := os.WriteFile(foreign, []byte("runtime"), 0600); err != nil {
		t.Fatal(err)
	}
	other, err := os.Stat(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if appImageMappedFile(info, dev^1, ino, "mapping", func(string) (os.FileInfo, error) { return other, nil }) {
		t.Fatal("foreign mapped file")
	}
}

func TestAppImageRuntimeCodeRange(t *testing.T) {
	if !appImageRuntimeCodeRange(0x400000, 0x42b000, 0, false) {
		t.Fatal("supported mapping refused")
	}
	for _, tc := range []struct {
		lo, hi, off uint64
		seen        bool
	}{
		{0x400000, 0x42b000, 0, true},
		{0x500000, 0x52b000, 0, false},
		{0x400000, 0x42c000, 0, false},
		{0x400000, 0x42b000, 4096, false},
		{0x500000, 0x501000, 176128, false},
	} {
		if appImageRuntimeCodeRange(tc.lo, tc.hi, tc.off, tc.seen) {
			t.Fatalf("accepted altered/metadata RX mapping: %+v", tc)
		}
	}
}
