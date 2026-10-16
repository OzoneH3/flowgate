package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"syscall"
	"time"
)

type Request struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
	ID        string `json:"id,omitempty"`
	Action    string `json:"action,omitempty"`
	Scope     string `json:"scope,omitempty"`
}
type Response struct {
	Version    int       `json:"version"`
	Generation string    `json:"generation"`
	ReadOnly   bool      `json:"read_only"`
	Mode       string    `json:"mode"`
	ServerTime time.Time `json:"server_time"`
	PeerUID    uint32    `json:"peer_uid"`
	Events     []Event   `json:"events,omitempty"`
	Decision   *Event    `json:"decision,omitempty"`
	Error      string    `json:"error,omitempty"`
}

func Serve(path string, e *Engine, readonly bool) (net.Listener, error) {
	// Parent must be owned and inaccessible to other users; never unlink an existing path.
	parent := path[:len(path)-len(baseName(path))]
	st, err := os.Stat(parent)
	if err != nil || st.Mode().Perm()&0077 != 0 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("API socket parent must exist with mode 0700")
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		l.Close()
		return nil, err
	}
	slots := make(chan struct{}, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
				go func() {
					defer func() { <-slots }()
					defer c.Close()
					c.SetDeadline(time.Now().Add(3 * time.Second))
					u := c.(*net.UnixConn)
					raw, err := u.SyscallConn()
					if err != nil {
						return
					}
					var cred *unix.Ucred
					raw.Control(func(fd uintptr) { cred, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
					if err != nil || cred == nil {
						return
					}
					r := Response{Version: 1, Generation: e.Generation, ReadOnly: readonly, Mode: e.Mode, ServerTime: time.Now(), PeerUID: cred.Uid}
					var q Request
					scanner := bufio.NewScanner(c)
					scanner.Buffer(make([]byte, 1024), 4096)
					if !scanner.Scan() {
						return
					}
					if err = json.Unmarshal(scanner.Bytes(), &q); err != nil || q.Version != 1 {
						r.Error = "invalid v1 request"
					} else {
						switch q.Operation {
						case "list":
							r.Events = e.List(cred.Uid, cred.Uid == 0)
						case "decide":
							if readonly {
								r.Error = "read-only API"
							} else {
								v, err := e.Decide(q.ID, q.Action, q.Scope, cred.Uid, cred.Uid == 0)
								if err != nil {
									r.Error = err.Error()
								} else {
									r.Decision = &v
								}
							}
						default:
							r.Error = "unknown operation"
						}
					}
					json.NewEncoder(c).Encode(r)
				}()
			default:
				c.Close()
			}
		}
	}()
	return l, nil
}
func baseName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}
func Call(path string, q Request) (Response, error) {
	c, e := net.DialTimeout("unix", path, time.Second)
	if e != nil {
		return Response{}, e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if e = json.NewEncoder(c).Encode(q); e != nil {
		return Response{}, e
	}
	var r Response
	e = json.NewDecoder(c).Decode(&r)
	if e == nil && r.Error != "" {
		e = fmt.Errorf("%s", r.Error)
	}
	return r, e
}
