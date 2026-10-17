package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/readiness"
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
	BackendMode  string                     `json:"backend_mode,omitempty"`
	Stopping     bool                       `json:"stopping,omitempty"`
	Permissions  *Permissions               `json:"permissions,omitempty"`
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
	if e.AdministratorUID != nil && (os.Geteuid() != 0 || e.APIUID == nil || *e.AdministratorUID != *e.APIUID) {
		return nil, readiness.Fail("permission_required", "administrator grant requires a root daemon and the explicitly selected API UID", "Use privileged configuration; client requests cannot grant administrative authority")
	}
	// Parent must be owned and inaccessible to other users; never unlink an existing path.
	parent := path[:len(path)-len(baseName(path))]
	st, err := os.Lstat(filepath.Clean(parent))
	if err != nil || !st.IsDir() {
		return nil, readiness.Fail("runtime_path_invalid", "API parent must be a real directory", "Inspect configured runtime/socket paths with doctor")
	}
	if e.APIUID != nil {
		// Host control sockets live in a daemon-owned directory. Only traversal is
		// granted to the GUI; the socket itself is 0600 and owned by the selected UID.
		if st.Mode().Perm()&0066 != 0 {
			return nil, readiness.Fail("runtime_path_invalid", "host API directory may grant traversal only (0711), not group/other read/write", "Inspect host-control path ownership; do not widen socket permissions")
		}
		if err = SecureDirectory(parent); err != nil {
			return nil, err
		}
	} else if st.Mode().Perm()&0077 != 0 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, readiness.Fail("runtime_path_invalid", "API socket parent must exist with mode 0700", "Use a private observer directory; doctor does not repair permissions")
	}

	l, err := net.Listen("unix", path)
	if err != nil {
		if os.IsPermission(err) {
			return nil, readiness.Fail("permission_required", "API socket creation denied", "Inspect the intended runtime directory and peer user")
		}
		return nil, readiness.Fail("runtime_path_invalid", "API socket could not be created; path may be occupied", "Inspect existing instance/socket; never unlink another running instance")
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
					r := Response{Capabilities: []string{ConditionalDeleteCapability, "explicit-administrator-v1"}, Version: 1, Generation: e.Generation, ReadOnly: readonly, Mode: e.Mode, ServerTime: time.Now(), PeerUID: cred.Uid}
					// The companion exposes the existing read-only observation contract while
					// retaining the actual daemon mode for permission-aware clients.
					if e.Mode == "daemon-monitor" || (e.Mode == "host-enforcement" && e.Activity != nil) {
						r.BackendMode = e.Mode
						if readonly {
							r.Mode = "host-monitor"
						}
						if e.Mode == "daemon-monitor" && e.StopMonitoring != nil {
							r.Capabilities = append(r.Capabilities, "monitor-stop-v1")
						}
					}
					stopAfterResponse := false
					if e.APIUID != nil && cred.Uid != *e.APIUID && cred.Uid != 0 {
						continueResponse(c, r)
						return
					}
					if e.Enforcement != nil {
						state := e.Enforcement()
						r.Enforcement = &state
						if state.State != "active" && e.Mode != "daemon-monitor" {
							r.ReadOnly = true
						}
					}
					admin := e.administrator(cred.Uid)
					permissions := e.permissions(cred.Uid, r.ReadOnly)
					r.Permissions = &permissions
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
						case "monitor-stop":
							if r.ReadOnly {
								r.Error = "read-only API"
								r.ErrorCode = "read_only"
							} else if cred.Uid != 0 {
								r.Error = "daemon shutdown requires root peer"
								r.ErrorCode = "forbidden"
							} else if e.Mode != "daemon-monitor" || e.StopMonitoring == nil {
								r.Error = "non-enforcing monitor stop unavailable"
								r.ErrorCode = "unavailable"
							} else if q.Generation == "" || q.Generation != e.Generation {
								r.Error = "backend generation changed; inspect current daemon"
								r.ErrorCode = "generation_conflict"
							} else {
								r.Stopping = true
								stopAfterResponse = true
							}

						case "list":
							if e.Mode == "host-monitor" && e.APIUID == nil && cred.Uid != uint32(os.Geteuid()) {
								r.Error = "not authorized"
								r.ErrorCode = "forbidden"
							} else {
								if e.Activity != nil {
									snapshot := e.Activity()
									if e.APIUID != nil {
										snapshot = activityFor(snapshot, cred.Uid, admin)
									}
									r.Activity = &snapshot
								}
								if e.Mode != "host-monitor" {
									r.Events = e.List(cred.Uid, admin)
									r.Rules = e.Rules(cred.Uid, admin)
								} else if e.Activity == nil {
									r.Error = "observer unavailable"
								}
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
								rule, preview, err := e.EditRule(q.ID, q.EventID, q.ExpectedVersion, *q.Rule, cred.Uid, admin, q.Operation == "rule-save")
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
								if r.Enforcement != nil && r.Enforcement.State != "active" && e.Mode != "daemon-monitor" {
									r.Error = "enforcement backend unavailable"
									r.ErrorCode = "unavailable"
								}
							} else {
								deleted, err := e.DeleteRule(q.Generation, q.ID, q.ExpectedVersion, cred.Uid, admin)
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
							} else if err := e.ChangeRule(q.ID, q.Action, cred.Uid, admin); err != nil {
								r.Error = err.Error()
							}
						case "decide":
							if !permissions.CanDecide {
								r.Error = "decision unavailable in non-enforcing/read-only mode"
								r.ErrorCode = "unavailable"
							} else if r.ReadOnly {
								r.Error = "read-only API"
							} else {
								v, err := e.Decide(q.ID, q.Action, q.Scope, cred.Uid, admin)
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
					if stopAfterResponse {
						e.StopMonitoring()
					}
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
