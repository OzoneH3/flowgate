package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func oldHolderTaskStat(b []byte) (string, bool, error) {
	s := string(b)
	i := strings.LastIndex(s, ") ")
	if i < 0 {
		return "", false, fmt.Errorf("task stat unavailable")
	}
	f := strings.Fields(s[i+2:])
	if len(f) < 20 {
		return "", false, fmt.Errorf("short task stat")
	}
	return f[19], f[0] == "Z", nil
}
func statFixture(command, state, start string) []byte {
	fields := []string{state}
	for i := 1; i < 19; i++ {
		fields = append(fields, fmt.Sprint(i))
	}
	fields = append(fields, start, "ignored", "tail")
	return []byte("1 (" + command + ") " + strings.Join(fields, " ") + "\n")
}
func TestHolderTaskStatParserMatchesOriginal(t *testing.T) {
	cases := [][]byte{nil, []byte("broken"), []byte("1 (short) S 1 2"), statFixture("normal", "S", "123456"), statFixture("name with ) spaces) ( and ) ", "Z", "000123"), statFixture("utf8-ß-名", "S", "18446744073709551615"), statFixture("normal", "ZZ", "42"), statFixture("normal", "Z", "not-numeric")}
	for _, b := range append([][]byte{}, cases...) {
		cases = append(cases, []byte(strings.ReplaceAll(string(b), " ", "\u2003")), []byte(strings.ReplaceAll(string(b), " 1 ", "\t1\n")))
	}
	for i, b := range cases {
		want, wz, we := oldHolderTaskStat(b)
		got, gz, ge := parseHolderTaskStat(b)
		if got != want || gz != wz || (ge == nil) != (we == nil) {
			t.Fatalf("case%d: got%q/%v/%v want%q/%v/%v", i, got, gz, ge, want, wz, we)
		}
		if ge != nil && ge.Error() != we.Error() {
			t.Fatal(ge, we)
		}
	}
}
func TestHolderTaskStatReaderFreshAndBounded(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "stat")
	for _, start := range []string{"123", "456"} {
		if e := os.WriteFile(p, statFixture("fixture", "Z", start), 0600); e != nil {
			t.Fatal(e)
		}
		s, z, e := readHolderTaskStat(p)
		if e != nil || s != start || !z {
			t.Fatal(s, z, e)
		}
	}
	good := statFixture("fixture", "S", "42")
	for _, n := range []int{4096, 4097} {
		b := append(append([]byte{}, good...), []byte(strings.Repeat(" ", n-len(good)))...)
		os.WriteFile(p, b, 0600)
		s, _, e := readHolderTaskStat(p)
		if n == 4096 && (e != nil || s != "42") {
			t.Fatal(s, e)
		}
		if n == 4097 && e == nil {
			t.Fatal("oversize accepted")
		}
	}
	alias := filepath.Join(dir, "alias")
	os.Symlink(p, alias)
	if _, _, e := readHolderTaskStat(alias); e == nil {
		t.Fatal("stat symlink accepted")
	}
	os.Remove(p)
	if _, _, e := readHolderTaskStat(p); !os.IsNotExist(e) {
		t.Fatal(e)
	}
}

// Native procfs reads and CPU timings run in the approved guest, never on host.
func TestHolderTaskStatNativeEquivalenceAndCost(t *testing.T) {
	if os.Getenv("FLOWGATE_PARENT_NETNS") == "" {
		t.Skip("guest lab native fixture")
	}
	path := fmt.Sprintf("/proc/%d/task/%d/stat", os.Getpid(), os.Getpid())
	old := func() (string, bool, error) {
		b, e := os.ReadFile(path)
		if e != nil {
			return "", false, e
		}
		return oldHolderTaskStat(b)
	}
	want, wz, e := old()
	if e != nil {
		t.Fatal(e)
	}
	for _, phase := range []struct {
		name string
		read func() (string, bool, error)
	}{{"baseline", old}, {"candidate", func() (string, bool, error) { return readHolderTaskStat(path) }}, {"candidate", func() (string, bool, error) { return readHolderTaskStat(path) }}, {"baseline", old}} {
		var a, z unix.Rusage
		unix.Getrusage(unix.RUSAGE_SELF, &a)
		start := time.Now()
		for i := 0; i < 2000; i++ {
			s, z, e := phase.read()
			if e != nil || s != want || z != wz {
				t.Fatal(s, z, e)
			}
		}
		elapsed := time.Since(start)
		unix.Getrusage(unix.RUSAGE_SELF, &z)
		cpu := (z.Utime.Sec-a.Utime.Sec+z.Stime.Sec-a.Stime.Sec)*1000000 + (z.Utime.Usec - a.Utime.Usec + z.Stime.Usec - a.Stime.Usec)
		t.Logf("%s iterations2000 elapsed_us%d cpu_us%d", phase.name, elapsed.Microseconds(), cpu)
	}
}
