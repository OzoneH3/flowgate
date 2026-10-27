package main

import (
	"bytes"
	"errors"
	"flowgate/internal/identity"
	"io"
	"strings"
	"testing"
)

func TestSocketWorkerFreshCensusAndFailureWithoutAck(t *testing.T) {
	var out bytes.Buffer
	calls := 0
	err := serveSockets(strings.NewReader("sockets -\nsockets -\nsockets -\n"), &out, func() ([]identity.Socket, error) {
		calls++
		if calls == 3 {
			return []identity.Socket{{Inode: 99}}, errors.New("partial census")
		}
		return []identity.Socket{{Inode: uint32(calls)}}, nil
	})
	if err == nil || calls != 3 || strings.Count(out.String(), "\x1eOK\n") != 2 || strings.Contains(out.String(), "99") {
		t.Fatalf("calls=%d err=%v output=%q", calls, err, out.String())
	}
	if !strings.Contains(out.String(), `"inode":1`) || !strings.Contains(out.String(), `"inode":2`) {
		t.Fatal("responses must reflect each fresh census")
	}
}

func TestSocketWorkerInputOutputBounds(t *testing.T) {
	for _, input := range []string{"bind -\n", strings.Repeat("x", 1024) + "\n"} {
		var out bytes.Buffer
		err := serveSockets(strings.NewReader(input), &out, func() ([]identity.Socket, error) {
			t.Fatal("invalid request reached census")
			return nil, nil
		})
		if err == nil || out.Len() != 0 {
			t.Fatal("invalid request accepted")
		}
	}
	var out bytes.Buffer
	err := serveSockets(strings.NewReader("sockets -\n"), &out, func() ([]identity.Socket, error) {
		return []identity.Socket{{Cookie: strings.Repeat("x", 2*1024*1024)}}, nil
	})
	if err == nil || out.Len() != 0 {
		t.Fatal("oversized response accepted")
	}
	err = serveSockets(strings.NewReader("sockets -\n"), shortWriter{}, func() ([]identity.Socket, error) { return nil, nil })
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short response not refused: %v", err)
	}
}

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 0, nil }
