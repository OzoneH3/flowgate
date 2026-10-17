package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Request struct {
	Generation      string       `json:"generation,omitempty"`
	EventID         string       `json:"event_id,omitempty"`
	ExpectedVersion *uint64      `json:"expected_version,omitempty"`
	Rule            *policy.Rule `json:"rule,omitempty"`
	Version         int          `json:"version"`
	Operation       string       `json:"operation"`
	ID              string       `json:"id,omitempty"`
	Action          string       `json:"action,omitempty"`
	Scope           string       `json:"scope,omitempty"`
}
type EnforcementStatus struct {
	Profile string    `json:"profile"`
	State   string    `json:"state"`
	Detail  string    `json:"detail"`
	StopsAt time.Time `json:"stops_at"`
}
type Response struct {
	Capabilities []string                   `json:"capabilities,omitempty"`
	ErrorCode    string                     `json:"error_code,omitempty"`
	DeletedRule  *DeletedRule               `json:"deleted_rule,omitempty"`
	SavedRule    *policy.Rule               `json:"saved_rule,omitempty"`
	ScopePreview string                     `json:"scope_preview,omitempty"`
	Enforcement  *EnforcementStatus         `json:"enforcement,omitempty"`
	Rules        []policy.Rule              `json:"rules,omitempty"`
	Activity     *identity.ActivitySnapshot `json:"activity,omitempty"`
	Version      int                        `json:"version"`
	Generation   string                     `json:"generation"`
	ReadOnly     bool                       `json:"read_only"`
	Mode         string                     `json:"mode"`
	ServerTime   time.Time                  `json:"server_time"`
	PeerUID      uint32                     `json:"peer_uid"`
	Events       []Event                    `json:"events,omitempty"`
	Decision     *Event                     `json:"decision,omitempty"`
	Error        string                     `json:"error,omitempty"`
}

func Serve(path string, e *Engine, readonly bool) (net.Listener, error) {
	readonly = readonly || e.Mode == "host-monitor"
	// Parent must be owned and inaccessible to other users; never unlink an existing path.
	parent := path[:len(path)-len(baseName(path))]
	st, err := os.Lstat(filepath.Clean(parent))
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("API parent must be a real directory")
	}
	if e.APIUID != nil {
		// Host control sockets live in a daemon-owned directory. Only traversal is
		// granted to the GUI; the socket itself is 0600 and owned by the selected UID.
		if st.Mode().Perm()&0066 != 0 {
			return nil, fmt.Errorf("host API directory may grant traversal only (0711), not group/other read/write")
		}
		if err = SecureDirectory(parent); err != nil {
			return nil, err
		}
	} else if st.Mode().Perm()&0077 != 0 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("API socket parent must exist with mode 0700")
	}

	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if e.APIUID != nil {
		if err = os.Chown(path, int(*e.APIUID), -1); err != nil {
			l.Close()
			return nil, err
		}
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
					r := Response{Capabilities: []string{ConditionalDeleteCapability}, Version: 1, Generation: e.Generation, ReadOnly: readonly, Mode: e.Mode, ServerTime: time.Now(), PeerUID: cred.Uid}
					if e.APIUID != nil && cred.Uid != *e.APIUID && cred.Uid != 0 {
						continueResponse(c, r)
						return
					}
					if e.Enforcement != nil {
						state := e.Enforcement()
						r.Enforcement = &state
						if state.State != "active" {
							r.ReadOnly = true
						}
					}
					var q Request
					scanner := bufio.NewScanner(c)
					scanner.Buffer(make([]byte, 1024), 16384)
					if !scanner.Scan() {
						return
					}
					if err = json.Unmarshal(scanner.Bytes(), &q); err != nil || q.Version != 1 {
						r.Error = "invalid v1 request"
						r.ErrorCode = "invalid_request"
					} else {
						switch q.Operation {
						case "list":
							if e.Mode == "host-monitor" {
								if cred.Uid != uint32(os.Geteuid()) {
									r.Error = "not authorized"
								} else if e.Activity == nil {
									r.Error = "observer unavailable"
								} else {
									snapshot := e.Activity()
									r.Activity = &snapshot
								}
							} else {
								r.Events = e.List(cred.Uid, cred.Uid == 0)
								r.Rules = e.Rules(cred.Uid, cred.Uid == 0)
							}
						case "rule-preview", "rule-save":
							if r.ReadOnly {
								r.Error = "read-only API"
								r.ErrorCode = "read_only"
							} else if q.Generation != e.Generation {
								r.Error = "backend generation changed; reload"
								r.ErrorCode = "generation_conflict"
							} else if q.Rule == nil {
								r.Error = "rule document required"
								r.ErrorCode = "invalid_request"
							} else {
								rule, preview, err := e.EditRule(q.ID, q.EventID, q.ExpectedVersion, *q.Rule, cred.Uid, cred.Uid == 0, q.Operation == "rule-save")
								if err != nil {
									r.Error = err.Error()
									var typed *RuleMutationError
									if errors.As(err, &typed) {
										r.ErrorCode = typed.Code
									}
								} else {
									r.SavedRule = &rule
									r.ScopePreview = preview
								}
							}
						case "rule-delete":
							if r.ReadOnly {
								r.Error = "read-only API"
								r.ErrorCode = "read_only"
								if r.Enforcement != nil && r.Enforcement.State != "active" {
									r.Error = "enforcement backend unavailable"
									r.ErrorCode = "unavailable"
								}
							} else {
								deleted, err := e.DeleteRule(q.Generation, q.ID, q.ExpectedVersion, cred.Uid, cred.Uid == 0)
								if err != nil {
									r.Error = err.Error()
									var typed *RuleMutationError
									if errors.As(err, &typed) {
										r.ErrorCode = typed.Code
									}
								} else {
									r.DeletedRule = &deleted
								}
							}
						case "rule":
							if r.ReadOnly {
								r.Error = "read-only API"
							} else if err := e.ChangeRule(q.ID, q.Action, cred.Uid, cred.Uid == 0); err != nil {
								r.Error = err.Error()
							}
						case "decide":
							if r.ReadOnly {
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

func continueResponse(c net.Conn, r Response) {
	r.Error = "not authorized"
	r.ErrorCode = "forbidden"
	json.NewEncoder(c).Encode(r)
}

// SecureDirectory rejects writable/unowned ancestors before privileged path
// operations. Normal monitor/lab sockets retain their original user-only model.
func SecureDirectory(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		st, err := os.Lstat(path)
		if err != nil || !st.IsDir() || !trustedDirectoryOwner(st.Sys().(*syscall.Stat_t).Uid) || st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("privileged directory and ancestors must be daemon-owned, not symlinks or writable by other users: %s", path)
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func trustedDirectoryOwner(uid uint32) bool {
	if uid == uint32(os.Geteuid()) {
		return true
	}
	// In the existing single-user namespace harness, host-root ancestors are
	// unmapped. They remain non-writable to the mapped test user. Never applies to
	// a normal host-root daemon with the initial namespace's full UID map.
	b, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false
	}
	f := strings.Fields(string(b))
	return uid == 65534 && len(f) == 3 && f[0] == "0" && f[2] == "1"
}
