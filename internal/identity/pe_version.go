package identity

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"io"
	"strings"
	"unicode"
	"unicode/utf16"
)

// productName reads the ProductName (else FileDescription) string of a PE
// image's version resource. Display metadata only; every read is bounded and
// any malformed structure yields "".
func productName(path string) string {
	f, err := pe.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var rsrc *pe.Section
	for _, s := range f.Sections {
		if s.Name == ".rsrc" {
			rsrc = s
		}
	}
	if rsrc == nil || rsrc.Size == 0 {
		return ""
	}
	size := int64(rsrc.Size)
	read := func(off int64, n int) []byte {
		if off < 0 || n <= 0 || off+int64(n) > size || n > 1<<16 {
			return nil
		}
		b := make([]byte, n)
		if _, err := rsrc.ReadAt(b, off); err != nil && err != io.EOF {
			return nil
		}
		return b
	}
	// Resource directory: type (16 = RT_VERSION) -> first name -> first language.
	entry := func(dir int64, id int32) (uint32, bool) {
		h := read(dir, 16)
		if h == nil {
			return 0, false
		}
		count := int(binary.LittleEndian.Uint16(h[12:14])) + int(binary.LittleEndian.Uint16(h[14:16]))
		if count > 512 {
			return 0, false
		}
		for i := 0; i < count; i++ {
			e := read(dir+16+int64(i)*8, 8)
			if e == nil {
				return 0, false
			}
			name, off := binary.LittleEndian.Uint32(e[0:4]), binary.LittleEndian.Uint32(e[4:8])
			if id < 0 || name == uint32(id) {
				return off, true
			}
		}
		return 0, false
	}
	off, ok := entry(0, 16)
	for level := 0; ok && level < 2; level++ {
		if off&0x80000000 == 0 {
			return ""
		}
		off, ok = entry(int64(off&0x7fffffff), -1)
	}
	if !ok || off&0x80000000 != 0 {
		return ""
	}
	data := read(int64(off), 16)
	if data == nil {
		return ""
	}
	rva, n := binary.LittleEndian.Uint32(data[0:4]), binary.LittleEndian.Uint32(data[4:8])
	if n > 1<<16 || rva < rsrc.VirtualAddress {
		return ""
	}
	blob := read(int64(rva-rsrc.VirtualAddress), int(n))
	if blob == nil {
		return ""
	}
	for _, key := range []string{"ProductName", "FileDescription"} {
		if v := versionString(blob, key); v != "" {
			return v
		}
	}
	return ""
}

func utf16le(s string) []byte {
	var b bytes.Buffer
	for _, u := range utf16.Encode([]rune(s + "\x00")) {
		binary.Write(&b, binary.LittleEndian, u)
	}
	return b.Bytes()
}

// versionString finds a String structure's key and returns its value: the key
// is NUL-terminated UTF-16, the value starts at the next 32-bit boundary.
func versionString(blob []byte, key string) string {
	needle := utf16le(key)
	for from := 0; from < len(blob); {
		i := bytes.Index(blob[from:], needle)
		if i < 0 {
			return ""
		}
		i += from
		from = i + 2
		if i%2 != 0 || i < 6 {
			continue
		}
		start := i + len(needle)
		start = (start + 3) &^ 3
		var units []uint16
		for p := start; p+1 < len(blob) && len(units) < 256; p += 2 {
			u := binary.LittleEndian.Uint16(blob[p:])
			if u == 0 {
				break
			}
			units = append(units, u)
		}
		v := strings.TrimSpace(strings.Map(func(r rune) rune {
			if unicode.IsPrint(r) {
				return r
			}
			return -1
		}, string(utf16.Decode(units))))
		if len([]rune(v)) > 128 {
			v = string([]rune(v)[:128])
		}
		return v
	}
	return ""
}
