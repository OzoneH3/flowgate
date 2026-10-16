package diagnostics

import (
	"flowgate/internal/identity"
	"os"
	"os/exec"
	"strings"
)

func Report() map[string]any {
	read := func(path string) string {
		b, e := os.ReadFile(path)
		if e != nil {
			return e.Error()
		}
		return strings.TrimSpace(string(b))
	}
	exists := func(path string) bool { _, e := os.Stat(path); return e == nil }
	modules := read("/proc/modules")
	_, diagerr := identity.Sockets()
	diag := "available"
	if diagerr != nil {
		diag = diagerr.Error()
	}
	nft, e := exec.Command("nft", "-j", "list", "tables").CombinedOutput()
	nftstatus := string(nft)
	if e != nil {
		nftstatus = e.Error() + ": " + nftstatus
	}
	_, exeerr := os.Readlink("/proc/self/exe")
	return map[string]any{"scope": "read-only; current network namespace; no enforcement installed", "netns": identity.NetNS(), "socket_diagnostics": diag, "proc_self_exe_visible": exeerr == nil, "attribution": "reduced: /proc snapshots are racy; hidden/shared owners deny application permissions", "nftables_probe": nftstatus, "nf_tables_loaded": strings.Contains(modules, "nf_tables "), "nfqueue_module_loaded": strings.Contains(modules, "nfnetlink_queue "), "nfqueue_note": "loaded module is evidence only; actual queue binding tested by isolated harness", "conntrack_sysctl_visible": exists("/proc/sys/net/netfilter/nf_conntrack_count"), "conntrack_loaded": strings.Contains(modules, "nf_conntrack "), "user_namespace_map": read("/proc/self/uid_map"), "namespace_probe": "run scripts/check.sh for disposable user+network namespace validation", "btf": exists("/sys/kernel/btf/vmlinux"), "unprivileged_bpf_disabled": read("/proc/sys/kernel/unprivileged_bpf_disabled"), "ebpf": "not used; hooks and load permissions not probed", "coexistence": "table names reported if permitted; VPN routing and other firewall delivery effects unverified"}
}
