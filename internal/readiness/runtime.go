package readiness

import (
	"flowgate/internal/identity"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Runtime checks optional attribution facilities separately from interception.
// Failure must not hide the control API or disable native firewall protection.
func Runtime() []Check {
	b, err := Read("/proc/sys/kernel/osrelease")
	return runtimeChecks(strings.TrimSpace(string(b)), err, os.Stat, identity.ProbeUnixPeers)
}

func runtimeChecks(kernel string, kernelErr error, stat func(string) (os.FileInfo, error), peers func() error) []Check {
	tree := Check{ID: "kernel.module_tree", Status: Ready, Code: "module_tree_present", Detail: "Running kernel module tree exists; this does not prove any capability is operational"}
	if kernelErr != nil || kernel == "" || filepath.Base(kernel) != kernel {
		tree = ProbeFailure(tree.ID, fmt.Errorf("running kernel release unavailable"))
	} else if st, err := stat(filepath.Join("/lib/modules", kernel)); err != nil || !st.IsDir() {
		tree.Status, tree.Code = Unchecked, "module_tree_unavailable"
		tree.Detail = "Running kernel " + kernel + " has no accessible module tree; unavailable facilities cannot be loaded from this tree"
		tree.Next = "If the kernel was upgraded, reboot into the installed kernel, then repeat doctor"
	}
	peer := Check{ID: "runtime.wine_unix_peers", Status: Ready, Code: "unix_peer_probe_passed", Detail: "Unix socket diagnostic dump succeeded; individual Wine broker relationships still require verification"}
	if err := peers(); err != nil {
		peer.Status, peer.Code = Optional, "unix_peer_probe_failed"
		peer.Detail = fmt.Sprintf("Wine/Proton attribution unavailable: Unix socket diagnostic probe failed: %v. Native interception can remain active", err)
		peer.Next = "Restore the running kernel's Unix socket diagnostics capability (unix_diag, or built-in support), then repeat doctor"
		if tree.Code == "module_tree_unavailable" {
			peer.Next = tree.Next
		}
	}
	return []Check{tree, peer}
}
