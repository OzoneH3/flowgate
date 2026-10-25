package identity

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

const processMapsLimit = 2 << 20

// Buffers contain scratch bytes, never reusable mapping evidence. Every call
// opens and reads the current file again. At most four buffers are retained,
// each bounded by the existing 2 MiB limit plus one overflow-detection byte.
var processMapsBuffers = make(chan []byte, 4)

func inspectProcessMaps(path, executable string) (string, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	return scanProcessMaps(f, executable)
}

func scanProcessMaps(r io.Reader, executable string) (string, bool, error) {
	var buf []byte
	select {
	case buf = <-processMapsBuffers:
	default:
		buf = make([]byte, 0, 64<<10)
	}
	buf = buf[:0]
	defer func() {
		select {
		case processMapsBuffers <- buf[:0]:
		default:
		}
	}()
	var err error
	buf, err = readProcessMaps(r, buf)
	if err != nil {
		return "", false, err
	}
	wine := wineRuntimeHint(executable, "") || bytes.Contains(buf, []byte("/ntdll.so")) || bytes.Contains(buf, []byte("/ntdll.dll"))
	if !wine {
		return "", false, nil
	}
	// Wine's image and prefix checks consume this exact snapshot. Copy only
	// this path's text so returning the scratch buffer cannot change it.
	return string(buf), true, nil
}

func readProcessMaps(r io.Reader, buf []byte) ([]byte, error) {
	const bound = processMapsLimit + 1
	empty := 0
	for {
		if len(buf) == cap(buf) {
			size := cap(buf) * 2
			if size == 0 {
				size = 64 << 10
			}
			if size > bound {
				size = bound
			}
			next := make([]byte, len(buf), size)
			copy(next, buf)
			buf = next
		}
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if len(buf) > processMapsLimit {
			return buf, fmt.Errorf("process mappings exceed %d-byte inspection limit", processMapsLimit)
		}
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return buf, err
		}
		if n == 0 {
			empty++
			if empty == 100 {
				return buf, io.ErrNoProgress
			}
		} else {
			empty = 0
		}
	}
}
