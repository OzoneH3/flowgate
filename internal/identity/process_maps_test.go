package identity

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestProcessMapsFreshSnapshotAndRuntimeClassification(t *testing.T) {
	for _, executable := range []string{"/native/alpha", "/runtime/wine64", "/runtime/wine-preloader (deleted)", "/native/beta"} {
		for _, data := range []string{"", "ordinary native mappings\n", "/runtime/ntdll.so\n", "/prefix/ntdll.dll\n", strings.Repeat("a", (64<<10)-4) + "/ntdll.so", strings.Repeat("b", processMapsLimit-10) + "/ntdll.dll"} {
			maps, hint, err := scanProcessMaps(strings.NewReader(data), executable)
			if err != nil || hint != wineRuntimeHint(executable, data) {
				t.Fatalf("classification changed: %s size=%d hint=%v err=%v", executable, len(data), hint, err)
			}
			if hint && maps != data || !hint && maps != "" {
				t.Fatal("runtime parser did not receive the exact snapshot")
			}
		}
	}
	// Reusing storage after a positive hint must not carry the old mapping into
	// a later, shorter snapshot. A returned Wine snapshot must remain stable.
	maps, hint, err := scanProcessMaps(strings.NewReader("/first/ntdll.so\n"), "/native/alpha")
	if err != nil || !hint {
		t.Fatal(hint, err)
	}
	for i := 0; i < 8; i++ {
		_, hint, err = scanProcessMaps(strings.NewReader("native\n"), "/native/beta")
		if err != nil || hint {
			t.Fatal("old mapping reused", hint, err)
		}
	}
	if maps != "/first/ntdll.so\n" {
		t.Fatal("returned snapshot changed")
	}
}

func TestProcessMapsRefusesTruncatedAndUnreadableEvidence(t *testing.T) {
	for _, size := range []int{processMapsLimit - 1, processMapsLimit, processMapsLimit + 1} {
		data := bytes.Repeat([]byte{'a'}, size)
		_, _, err := scanProcessMaps(bytes.NewReader(data), "/native/alpha")
		if (err != nil) != (size > processMapsLimit) {
			t.Fatalf("size=%d error=%v", size, err)
		}
	}
	// A runtime mapping beyond the bound cannot silently produce native identity.
	_, hint, err := scanProcessMaps(io.MultiReader(strings.NewReader(strings.Repeat("a", processMapsLimit)), strings.NewReader("/ntdll.so")), "/native/beta")
	if err == nil || hint {
		t.Fatal("oversize evidence accepted")
	}
	_, _, err = scanProcessMaps(&mapsFailureReader{}, "/native/alpha")
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("partial read accepted", err)
	}
	_, _, err = inspectProcessMaps(t.TempDir()+"/missing", "/native/beta")
	if err == nil {
		t.Fatal("unreadable maps accepted")
	}
}

type mapsFailureReader struct{}

func (*mapsFailureReader) Read(b []byte) (int, error) {
	return copy(b, "/ntdll.so"), io.ErrUnexpectedEOF
}
