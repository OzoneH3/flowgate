package identity

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
)

// The observer is x86-64 PE. A generic Wine entry point can dispatch through
// a 32-bit start.exe /exec process, which itself keeps the prefix alive. Select
// the same runtime's architecture-specific loader so only the observer joins.
// Pair with WINELOADERNOEXEC=1: Wine's initial command-line dispatch can otherwise
// re-exec the 32-bit entry point even when this direct loader was selected.
func observerRunner(bin string) (string, error) {
	for _, p := range []string{filepath.Join(bin, "..", "lib", "wine", "x86_64-unix", "wine64"), filepath.Join(bin, "..", "lib64", "wine", "x86_64-unix", "wine64"), filepath.Join(bin, "wine64"), filepath.Join(bin, "..", "lib", "wine", "x86_64-unix", "wine"), filepath.Join(bin, "..", "lib64", "wine", "x86_64-unix", "wine")} {
		p = filepath.Clean(p)
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
			continue
		}
		f, err := elf.Open(p)
		if err != nil {
			continue
		}
		valid := f.Class == elf.ELFCLASS64 && f.Machine == elf.EM_X86_64
		f.Close()
		if valid {
			return p, nil
		}
	}
	return "", fmt.Errorf("runtime lacks a direct x86-64 observer loader; refusing a lifetime-holding launcher")
}
