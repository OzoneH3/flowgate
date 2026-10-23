package identity

import (
	"path/filepath"
	"testing"
)

func TestWineRuntimeHintIgnoresDirectoryNames(t *testing.T) {
	for _, path := range []string{"/wine-folder/native", "/games/wine-tools/alpha", "/a/WINE/beta", "/tmp/native"} {
		if wineRuntimeHint(path, "") {
			t.Fatalf("directory became runtime evidence: %s", path)
		}
	}
	for _, name := range []string{"wine", "wine64", "wine-preloader", "wine64-preloader", "wineserver"} {
		if !wineRuntimeHint("/runtime/"+name, "") || !wineRuntimeHint("/runtime/"+name+" (deleted)", "") {
			t.Fatalf("loader refusal hint lost: %s", name)
		}
	}
	for _, maps := range []string{"7f00-7f10 r-xp 000 01:01 7 /runtime/ntdll.so", "7f00-7f10 r-xp 000 01:01 8 /runtime/ntdll.dll"} {
		if !wineRuntimeHint("/renamed-loader", maps) {
			t.Fatal("mapped runtime hint lost")
		}
	}
}

func TestNativeInWineDirectoryKeepsIndependentExecutableIdentity(t *testing.T) {
	// Real processes, not invented Application values. Two separate executables
	// beneath wine-named directories must retain distinct native identities.
	var keys []string
	for _, name := range []string{"wine-folder/synthetic-alpha", "wine-folder/synthetic-beta"} {
		runtime := fakeRuntime(t, filepath.Join(name))
		_, child := startMain(t, runtime, "main", nil)
		p, err := Inspect(child)
		if err != nil {
			t.Fatal(err)
		}
		if p.Application.Kind != "native" || p.Application.Executable != runtime || !LiveRuleable(p.Application) {
			t.Fatalf("native runtime false positive: %+v", p.Application)
		}
		keys = append(keys, p.Application.Key)
	}
	if keys[0] == keys[1] {
		t.Fatal("distinct native executable permissions merged")
	}
}
