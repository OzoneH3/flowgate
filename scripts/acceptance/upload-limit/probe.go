package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

var probeName string

type socket interface {
	SyscallConn() (syscall.RawConn, error)
}

func inode(s socket) (uint64, error) {
	raw, err := s.SyscallConn()
	if err != nil {
		return 0, err
	}
	var stat syscall.Stat_t
	var statErr error
	err = raw.Control(func(fd uintptr) { statErr = syscall.Fstat(int(fd), &stat) })
	return stat.Ino, errors.Join(err, statErr)
}

type request struct {
	Op, Label string
}

func probe(source, remote string) error {
	local := &net.TCPAddr{IP: net.ParseIP(source)}
	listener, err := net.ListenTCP("tcp4", local)
	if err != nil {
		return err
	}
	defer listener.Close()
	anchorInode, err := inode(listener)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return err
	}
	fields := strings.Fields(string(stat)[strings.LastIndexByte(string(stat), ')')+1:])
	if len(fields) <= 19 {
		return errors.New("process start time unavailable")
	}
	out := json.NewEncoder(os.Stdout)
	if err := out.Encode(map[string]any{
		"probe": probeName, "pid": os.Getpid(), "uid": os.Getuid(), "exe": exe,
		"start_ticks": fields[19], "anchor": listener.Addr().String(), "anchor_inode": anchorInode,
	}); err != nil {
		return err
	}

	var conn *net.TCPConn
	var sending chan error
	handle := func(q request) (map[string]any, error) {
		answer := map[string]any{}
		switch q.Op {
		case "open":
			if conn != nil || q.Label == "" || strings.ContainsAny(q.Label, "\r\n") {
				return nil, errors.New("need a new connection and a single-line label")
			}
			dialer := net.Dialer{LocalAddr: local, Timeout: 5 * time.Second}
			stream, err := dialer.Dial("tcp4", remote)
			if err != nil {
				return nil, err
			}
			conn = stream.(*net.TCPConn)
			if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return nil, err
			}
			if _, err := fmt.Fprintln(conn, q.Label); err != nil {
				return nil, err
			}
			i, err := inode(conn)
			if err != nil {
				return nil, err
			}
			answer["inode"], answer["local"], answer["remote"] = i, conn.LocalAddr().String(), conn.RemoteAddr().String()
		case "start":
			if conn == nil || sending != nil {
				return nil, errors.New("need an idle open stream")
			}
			if err := conn.SetWriteDeadline(time.Now().Add(20 * time.Second)); err != nil {
				return nil, err
			}
			sending = make(chan error, 1)
			go func(done chan<- error) {
				buf := make([]byte, 64<<10)
				for {
					if _, err := conn.Write(buf); err != nil {
						done <- err
						return
					}
				}
			}(sending)
		case "stop":
			if sending == nil {
				return nil, errors.New("no upload is running")
			}
			if err := conn.SetWriteDeadline(time.Now()); err != nil {
				return nil, err
			}
			err := <-sending
			sending = nil
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				return nil, fmt.Errorf("upload ended unexpectedly: %w", err)
			}
		default:
			return nil, fmt.Errorf("unknown operation %q", q.Op)
		}
		return answer, nil
	}
	scanner := bufio.NewScanner(os.Stdin)
	defer func() {
		if conn != nil {
			conn.Close()
			if sending != nil {
				<-sending
			}
		}
	}()
	for scanner.Scan() {
		var q request
		err := json.Unmarshal(scanner.Bytes(), &q)
		var result map[string]any
		if err == nil {
			result, err = handle(q)
		}
		if err != nil {
			result = map[string]any{"fixture_error": err.Error()}
		}
		if err := out.Encode(result); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: probe SOURCE_IP DESTINATION_IP:PORT")
		os.Exit(2)
	}
	if err := probe(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
