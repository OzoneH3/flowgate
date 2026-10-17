package readiness

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime"
)

const HelperMarker = "FLOWGATE_UDP_HELPER_PROTOCOL=1"

// Helper inspects, never executes, the explicitly selected executable. The
// marker is compatibility metadata, not a signature or code-trust attestation.
func Helper(path string) Check {
	c := Check{ID: "udp.helper", Status: Optional, Code: "helper_missing", Detail: "Optional UDP helper unavailable", Next: "Build with scripts/build-udp.sh; basic TCP monitoring remains available"}
	st, e := os.Stat(path)
	if e != nil {
		return c
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 || st.Size() > 32*1024*1024 {
		c.Code = "helper_incompatible"
		c.Detail = "UDP helper must be a bounded executable ELF file"
		return c
	}
	f, e := elf.Open(path)
	if e != nil {
		c.Code = "helper_incompatible"
		c.Detail = "UDP helper is not a readable compatible ELF"
		return c
	}
	defer f.Close()
	if (runtime.GOARCH == "amd64" && f.Machine != elf.EM_X86_64) || (runtime.GOARCH == "arm64" && f.Machine != elf.EM_AARCH64) {
		c.Code = "helper_incompatible"
		c.Detail = "Helper ELF architecture does not match running backend"
		return c
	}
	section := f.Section(".rodata")
	if section == nil || section.Size > 16*1024*1024 {
		c.Code = "helper_incompatible"
		c.Detail = "UDP helper protocol marker unavailable"
		return c
	}
	b, e := section.Data()
	if e != nil || !bytes.Contains(b, append([]byte(HelperMarker), 0)) {
		c.Code = "helper_incompatible"
		c.Detail = "UDP helper/backend protocol marker missing or mismatched"
		return c
	}
	c.Status = Ready
	c.Code = "helper_inspected"
	c.Detail = "UDP helper ELF and protocol marker match; not executed or attached"
	c.Next = "Use doctor library and tracing checks; successful BPF load is still untested"
	return c
}
func Libraries(path string) ([]string, string, error) {
	f, e := elf.Open(path)
	if e != nil {
		return nil, "", e
	}
	defer f.Close()
	for _, section := range f.Sections {
		if (section.Name == ".dynamic" || section.Name == ".dynstr") && section.Size > 1024*1024 {
			return nil, "", fmt.Errorf("ELF dependency metadata exceeds inspection bound")
		}
	}
	names, e := f.ImportedLibraries()
	if e != nil {
		return nil, "", e
	}
	if len(names) > 32 {
		return nil, "", fmt.Errorf("dependency limit")
	}
	interpreter := ""
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			b, e := io.ReadAll(io.LimitReader(p.Open(), 4097))
			if e != nil || len(b) > 4096 {
				return nil, "", fmt.Errorf("interpreter limit")
			}
			interpreter = string(bytes.TrimRight(b, "\x00"))
		}
	}
	return names, interpreter, nil
}

// BTFNames checks the documented BTF header/string table only. Names in BTF are
// necessary evidence for tp_btf, not a successful hook-attach test.
func BTFNames(path string) Check {
	c := Check{ID: "udp.btf_hooks", Status: Optional, Code: "btf_missing", Detail: "Kernel BTF unavailable", Next: "Keep basic TCP monitoring; inspect kernel BTF support without changing security settings"}
	f, e := os.Open(path)
	if e != nil {
		if os.IsPermission(e) {
			return ProbeFailure(c.ID, e)
		}
		return c
	}
	defer f.Close()
	h := make([]byte, 24)
	if _, e = io.ReadFull(f, h); e != nil {
		c.Code = "btf_invalid"
		c.Detail = "BTF header unavailable"
		return c
	}
	var order binary.ByteOrder = binary.LittleEndian
	if order.Uint16(h[:2]) != 0xeb9f {
		order = binary.BigEndian
	}
	if order.Uint16(h[:2]) != 0xeb9f || h[2] != 1 {
		c.Code = "btf_invalid"
		c.Detail = "Unsupported BTF header"
		return c
	}
	header := uint64(order.Uint32(h[4:8]))
	offset := uint64(order.Uint32(h[16:20]))
	length := uint64(order.Uint32(h[20:24]))
	if header < 24 || header > 4096 || length > 16*1024*1024 || offset > 64*1024*1024 {
		c.Status = Unchecked
		c.Code = "probe_limit"
		c.Detail = "BTF exceeds bounded inspection layout"
		return c
	}
	b, e := io.ReadAll(io.NewSectionReader(f, int64(header+offset), int64(length)))
	if e != nil || uint64(len(b)) != length {
		c.Code = "btf_invalid"
		c.Detail = "BTF string section incomplete"
		return c
	}
	for _, name := range []string{"btf_trace_sock_send_length", "btf_trace_sock_recv_length"} {
		if !bytes.Contains(b, []byte("\x00"+name+"\x00")) {
			c.Code = "hook_missing"
			c.Detail = "Required BTF hook name absent: " + name
			c.Next = "Optional UDP accounting is unavailable on this observed kernel; retain TCP monitoring"
			return c
		}
	}
	c.Status = Ready
	c.Code = "btf_names_present"
	c.Detail = "BTF readable; required sock send/receive trace hook names present (signatures/load/attach not verified)"
	c.Next = "BPF permissions and actual attachment remain separate startup checks"
	return c
}
