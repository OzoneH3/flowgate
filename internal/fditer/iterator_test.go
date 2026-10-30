package fditer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func records(values ...[3]uint64) []byte {
	var b bytes.Buffer
	for _, v := range values {
		var row [16]byte
		binary.NativeEndian.PutUint64(row[:], v[0])
		binary.NativeEndian.PutUint32(row[8:], uint32(v[1]))
		binary.NativeEndian.PutUint32(row[12:], uint32(v[2]))
		b.Write(row[:])
	}
	return b.Bytes()
}

type shortReader struct{ r io.Reader }

func (s shortReader) Read(b []byte) (int, error) { return s.r.Read(b[:min(len(b), 3)]) }

func TestDecodeRequiresCompleteOrderedBoundedStream(t *testing.T) {
	good := records([3]uint64{42, 3, 0}, [3]uint64{0, 8, 0}, [3]uint64{0, 0, 1})
	for _, tc := range []struct {
		name  string
		b     []byte
		limit int
		ok    bool
	}{
		{"valid", good, 2, true},
		{"empty", records([3]uint64{0, 0, 1}), 0, true},
		{"missing-trailer", good[:32], 2, false},
		{"short", good[:len(good)-1], 2, false},
		{"read-error-row", records([3]uint64{0, 3, 2}, [3]uint64{0, 0, 1}), 2, false},
		{"duplicate", records([3]uint64{42, 3, 0}, [3]uint64{42, 3, 0}, [3]uint64{0, 0, 1}), 2, false},
		{"descending", records([3]uint64{42, 8, 0}, [3]uint64{42, 3, 0}, [3]uint64{0, 0, 1}), 2, false},
		{"after-trailer", append(append([]byte{}, good...), good...), 4, false},
		{"nonsockets-count", good, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := decode(shortReader{bytes.NewReader(tc.b)}, tc.limit, time.Now().Add(time.Second), time.Now)
			if (err == nil) != tc.ok {
				t.Fatalf("rows=%v err=%v", rows, err)
			}
			if err != nil && rows != nil {
				t.Fatal("partial evidence escaped")
			}
		})
	}
}

func TestDecodeDeadlineAndLargeSequence(t *testing.T) {
	deadline := time.Now()
	if _, err := decode(bytes.NewReader(nil), 1, deadline, time.Now); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	var rows [][3]uint64
	for i := 0; i < 10000; i++ {
		rows = append(rows, [3]uint64{uint64(i + 1), uint64(i), 0})
	}
	rows = append(rows, [3]uint64{0, 0, 1})
	out, err := decode(bytes.NewReader(records(rows...)), 10000, time.Now().Add(time.Second), time.Now)
	if err != nil || len(out) != 10000 {
		t.Fatalf("count=%d err=%v", len(out), err)
	}
	if out, err = decode(bytes.NewReader(records(rows...)), 9999, time.Now().Add(time.Second), time.Now); !errors.Is(err, ErrBudget) || out != nil {
		t.Fatal(out, err)
	}
}
