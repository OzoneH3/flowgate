package identity

import (
	"errors"
	"syscall"
	"testing"
)

func TestHolderRecheckSeparatesIOFromTopology(t *testing.T) {
	for _, injected := range []error{syscall.EIO, syscall.EACCES, syscall.ENOENT, syscall.ESRCH} {
		for _, seam := range []string{"group-stat", "task-list", "member-stat", "shared-table", "distinct-table", "descriptor"} {
			t.Run(seam+"/"+injected.Error(), func(t *testing.T) {
				f := holderFixture()
				c := f.proc().census(censusWanted, defaultHolderLimits)
				if !c.Complete {
					t.Fatal(c.Issues)
				}
				p := c.src
				group := 10
				unreadable, changed := "", ""
				switch seam {
				case "group-stat":
					p.stat = func(int, int) (string, bool, error) { return "", false, injected }
					unreadable, changed = "group_unreadable", "group_changed"
				case "task-list":
					p.tasks = func(int, int) ([]int, error) { return nil, injected }
					unreadable, changed = "task_list_unreadable", "membership_changed"
				case "member-stat":
					original := p.stat
					p.stat = func(gid, tid int) (string, bool, error) {
						if tid == 11 {
							return "", false, injected
						}
						return original(gid, tid)
					}
					unreadable, changed = "task_unreadable", "membership_changed"
				case "shared-table", "distinct-table":
					if seam == "distinct-table" {
						group = 30
					}
					p.sameFiles = func(int, int) (bool, error) { return false, injected }
					unreadable, changed = "table_unreadable", "table_changed"
				case "descriptor":
					p.readlink = func(string) (string, error) { return "", injected }
					unreadable, changed = "descriptor_unreadable", "descriptor_changed"
				}
				err := p.recheckGroup(group, c.groups[group])
				want := unreadable
				if holderGone(injected) {
					want = changed
				}
				if err == nil || err.Error() != want {
					t.Fatalf("got %v want %s", err, want)
				}
				eligible := retryableHolderTopology(c, HolderRecheck{Groups: map[int]string{group: err.Error()}})
				if eligible != holderGone(injected) {
					t.Fatalf("retryable=%v for %v", eligible, injected)
				}
			})
		}
	}
}

func TestHolderStableGroupEndStatIOIsNotTopology(t *testing.T) {
	for _, injected := range []error{syscall.EIO, syscall.EACCES} {
		t.Run(injected.Error(), func(t *testing.T) {
			f := holderFixture()
			p := f.proc()
			original := p.stat
			calls := 0
			p.stat = func(gid, tid int) (string, bool, error) {
				if gid == 60 && tid == 60 {
					calls++
					if calls == 4 {
						return "", false, injected
					}
				}
				return original(gid, tid)
			}
			tasks, fds := 0, 0
			_, code := p.scanStableGroup(60, censusWanted, defaultHolderLimits, &tasks, &fds)
			if code != "group_unreadable" || holderTopologyChange(code) {
				t.Fatalf("end stat error: %q calls=%d", code, calls)
			}
		})
	}
}

func TestHolderNonholderIOCannotBeHiddenByRescan(t *testing.T) {
	for _, injected := range []error{syscall.EIO, syscall.EACCES} {
		t.Run(injected.Error(), func(t *testing.T) {
			f := holderFixture()
			c := f.proc().census(censusWanted, defaultHolderLimits)
			if !c.Complete {
				t.Fatal(c.Issues)
			}
			original := c.src.stat
			reads := 0
			c.src.stat = func(gid, tid int) (string, bool, error) {
				if gid == 60 {
					reads++
					if reads == 1 {
						return "", false, injected
					}
				}
				return original(gid, tid)
			}
			d := c.RecheckDetail()
			if d.Err == nil || d.Err.Error() != "group_unreadable" || reads != 1 || retryableHolderTopology(c, d) {
				t.Fatalf("hidden read failure: detail=%+v reads=%d", d, reads)
			}
		})
	}
}

func TestHolderScanFailureCannotBeErasedByLaterExit(t *testing.T) {
	f := holderFixture()
	p := f.proc()
	p.tasks = func(int, int) ([]int, error) { return nil, syscall.EIO }
	original := p.stat
	calls := 0
	p.stat = func(gid, tid int) (string, bool, error) {
		calls++
		if calls > 2 {
			return "", false, syscall.ENOENT
		}
		return original(gid, tid)
	}
	tasks, fds := 0, 0
	_, code := p.scanStableGroup(60, censusWanted, defaultHolderLimits, &tasks, &fds)
	if code != "task_list_unreadable" {
		t.Fatalf("I/O erased by exit: %q", code)
	}
}

func TestHolderTaskListBoundErrorDoesNotRetry(t *testing.T) {
	f := holderFixture()
	c := f.proc().census(censusWanted, defaultHolderLimits)
	c.src.tasks = func(int, int) ([]int, error) { return nil, errors.New("task list exceeds bound") }
	err := c.src.sameTopology(10, c.groups[10])
	if err == nil || holderTopologyChange(err.Error()) {
		t.Fatalf("bound treated as topology: %v", err)
	}
}
