package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"flowgate/internal/decisionlog"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/readiness"
	"flowgate/internal/udpaccount"
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
	ZoneTarget          *ZoneTarget     `json:"zone_target,omitempty"`
	ZoneRevision        string          `json:"zone_revision,omitempty"`
	EvaluationID        string          `json:"evaluation_id,omitempty"`
	RequestID           string          `json:"request_id,omitempty"`
	Profile             string          `json:"profile,omitempty"`
	DecisionQuery       json.RawMessage `json:"decision_query,omitempty"`
	DecisionID          string          `json:"decision_id,omitempty"`
	CollectorGeneration string          `json:"collector_generation,omitempty"`
	ObservedTarget      *ObservedTarget `json:"observed_target,omitempty"`
	ObservedDraft       *ObservedDraft  `json:"observed_draft,omitempty"`
	PreviewToken        string          `json:"preview_token,omitempty"`

	ExpectedPolicyToken string       `json:"expected_policy_token,omitempty"`
	EventIDs            []string     `json:"event_ids,omitempty"`
	Generation          string       `json:"generation,omitempty"`
	EventID             string       `json:"event_id,omitempty"`
	ExpectedVersion     *uint64      `json:"expected_version,omitempty"`
	Rule                *policy.Rule `json:"rule,omitempty"`
	Version             int          `json:"version"`
	Operation           string       `json:"operation"`
	ID                  string       `json:"id,omitempty"`
	Action              string       `json:"action,omitempty"`
	Scope               string       `json:"scope,omitempty"`
}
type EnforcementStatus struct {
	Profile string    `json:"profile"`
	State   string    `json:"state"`
	Detail  string    `json:"detail"`
	StopsAt time.Time `json:"stops_at"`
}
type Response struct {
	NetworkZones    *identity.NetworkZones     `json:"network_zones,omitempty"`
	ZonePreview     *ZonePreview               `json:"zone_preview,omitempty"`
	RuleStates      map[string]RuleTargetState `json:"rule_states,omitempty"`
	Evaluation      *EvaluationStatus          `json:"evaluation,omitempty"`
	DecisionLog     *decisionlog.Page          `json:"decision_log,omitempty"`
	DecisionRecord  *decisionlog.Record        `json:"decision_record,omitempty"`
	TrafficMonitor  *udpaccount.Status         `json:"traffic_monitor,omitempty"`
	ObservedPreview *ObservedPreview           `json:"observed_preview,omitempty"`
	Replayed        bool                       `json:"replayed,omitempty"`

	PolicyView         *PolicyView                `json:"policy_view,omitempty"`
	PolicyExplanations *PolicyExplanations        `json:"policy_explanations,omitempty"`
	BackendMode        string                     `json:"backend_mode,omitempty"`
	Stopping           bool                       `json:"stopping,omitempty"`
	Permissions        *Permissions               `json:"permissions,omitempty"`
	Capabilities       []string                   `json:"capabilities,omitempty"`
	ErrorCode          string                     `json:"error_code,omitempty"`
	DeletedRule        *DeletedRule               `json:"deleted_rule,omitempty"`
	SavedRule          *policy.Rule               `json:"saved_rule,omitempty"`
	ScopePreview       string                     `json:"scope_preview,omitempty"`
	Enforcement        *EnforcementStatus         `json:"enforcement,omitempty"`
	Rules              []policy.Rule              `json:"rules,omitempty"`
	Activity           *identity.ActivitySnapshot `json:"activity,omitempty"`
	Version            int                        `json:"version"`
	Generation         string                     `json:"generation"`
	ReadOnly           bool                       `json:"read_only"`
	Mode               string                     `json:"mode"`
	ServerTime         time.Time                  `json:"server_time"`
	PeerUID            uint32                     `json:"peer_uid"`
	Events             []Event                    `json:"events,omitempty"`
	Decision           *Event                     `json:"decision,omitempty"`
	Error              string                     `json:"error,omitempty"`
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
					if !readonly && e.Mode != "host-monitor" {
						r.Capabilities = append(r.Capabilities, PolicyExplanationCapability, ObservedRuleCapability, ProcessRuleCapability, ObservedAnyProtocolCapability)
					}
					if e.Evaluation != nil {
						r.Capabilities = append(r.Capabilities, EvaluationCapability)

					}
					if e.Traffic != nil {
						r.Capabilities = append(r.Capabilities, "daemon-udp-monitor-v1")
					}
					if e.Decisions != nil {
						r.Capabilities = append(r.Capabilities, DecisionLogCapability)
					}
					if e.Activity != nil {
						r.Capabilities = append(r.Capabilities, "activity-initiation-v1", "application-display-metadata-v1")
					}
					stopAfterResponse := false
					if e.APIUID != nil && cred.Uid != *e.APIUID && cred.Uid != 0 {
						continueResponse(c, r)
						return
					}
					if e.Evaluation != nil {
						v := e.Evaluation.Status()
						r.Evaluation = &v
					}
					if r.Evaluation != nil {
						state := EnforcementStatus{State: r.Evaluation.State, Profile: r.Evaluation.Profile, StopsAt: r.Evaluation.StopsAt, Detail: r.Evaluation.Reason}
						r.Enforcement = &state
					} else if e.Enforcement != nil {
						state := e.Enforcement()
						r.Enforcement = &state
						if state.State != "active" && e.Mode != "daemon-monitor" {
							r.ReadOnly = true
						}
					}
					admin := e.administrator(cred.Uid)
					permissions := e.permissions(cred.Uid, r.ReadOnly)
					if r.Evaluation != nil {
						permissions.CanDecide = !readonly && r.Evaluation.State == "active"
					}
					r.Permissions = &permissions
					if e.Traffic != nil {
						s := trafficStatusFor(e.Traffic.Status(), admin)
						r.TrafficMonitor = &s
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
						r.NetworkZones = &e.Zones
						r.Capabilities = append(r.Capabilities, NetworkZoneCapability)
						switch q.Operation {
						case "evaluation-readiness", "evaluation-start", "evaluation-stop":
							if e.Evaluation == nil {
								r.ErrorCode, r.Error = "unavailable", "Daemon evaluation unavailable"
							} else if q.Operation != "evaluation-readiness" && !permissions.CanControlEvaluation {
								r.ErrorCode, r.Error = "forbidden", "Explicit evaluation permission on primary endpoint required"
							} else if q.Generation != e.Generation {
								r.ErrorCode, r.Error = "generation_conflict", "Daemon generation changed; refresh authoritative state"
							} else if q.Operation != "evaluation-stop" && q.Profile != "incoming" {
								r.ErrorCode, r.Error = "invalid_request", "Only explicit incoming profile is supported"
							} else {
								v := e.Evaluation.Status()
								var err error
								r.NetworkZones = &e.Zones
								r.Capabilities = append(r.Capabilities, NetworkZoneCapability)
								switch q.Operation {
								case "evaluation-readiness":
									v = e.Evaluation.Readiness()
								case "evaluation-start":
									v, err = e.Evaluation.Start(q.EvaluationID, q.RequestID)
								case "evaluation-stop":
									v, err = e.Evaluation.Stop(q.EvaluationID)
								}
								r.Evaluation = &v
								state := EnforcementStatus{State: v.State, Profile: v.Profile, StopsAt: v.StopsAt, Detail: v.Reason}
								r.Enforcement = &state
								permissions.CanDecide = !readonly && v.State == "active"
								r.Permissions = &permissions
								if err != nil {
									r.Error = err.Error()
									r.ErrorCode = "evaluation_conflict"
									var typed *RuleMutationError
									if errors.As(err, &typed) {
										r.ErrorCode = typed.Code
									}
								}
							}
						case "decision-log", "decision-log-get":
							// Read-only history on either endpoint; no mutation, deletion or
							// administration exists. Visibility follows observation scope.
							if e.Decisions == nil {
								r.ErrorCode, r.Error = "unavailable", "Decision log not configured for this daemon"
							} else if q.Operation == "decision-log" {
								dq, err := decisionlog.DecodeQuery(q.DecisionQuery)
								if err == nil {
									var page decisionlog.Page
									page, err = e.Decisions.Query(dq, cred.Uid, admin)
									if err == nil {
										r.DecisionLog = &page
									}
								}
								decisionError(&r, err)
							} else {
								rec, err := e.Decisions.Get(q.DecisionID, cred.Uid, admin)
								if err == nil {
									r.DecisionRecord = &rec
								}
								decisionError(&r, err)
							}
						case "traffic-status", "traffic-start", "traffic-stop":
							if e.Traffic == nil {
								r.ErrorCode, r.Error = "unavailable", "Daemon-owned UDP collector unavailable"
							} else if q.Operation != "traffic-status" && (readonly || !permissions.CanControlTraffic) {
								r.ErrorCode, r.Error = "forbidden", "Explicit collector lifecycle permission on primary endpoint required"
							} else if q.Operation != "traffic-status" && q.Generation != e.Generation {
								r.ErrorCode, r.Error = "generation_conflict", "Backend generation changed; refresh collector state"
							} else {
								var s udpaccount.Status
								var err error
								r.NetworkZones = &e.Zones
								r.Capabilities = append(r.Capabilities, NetworkZoneCapability)
								switch q.Operation {
								case "traffic-start":
									s, err = e.Traffic.Start(q.CollectorGeneration)
								case "traffic-stop":
									s, err = e.Traffic.Stop(q.CollectorGeneration)
								default:
									s = e.Traffic.Status()
								}
								s = trafficStatusFor(s, admin)
								r.TrafficMonitor = &s
								if err != nil {
									r.ErrorCode, r.Error = "collector_unavailable", err.Error()
									if errors.Is(err, udpaccount.ErrCollectorGeneration) {
										r.ErrorCode = "collector_conflict"
									}
								}
							}
						case "zone-rule-preview", "zone-rule-save":
							if readonly || !permissions.CanManageRules {
								r.ErrorCode, r.Error = "read_only", "Rule management unavailable"
							} else if q.ZoneTarget == nil || q.ObservedDraft == nil {
								r.ErrorCode, r.Error = "invalid_request", "Explicit zone_target/observed_draft required"
							} else {
								var err error
								if q.Operation == "zone-rule-preview" {
									var v ZonePreview
									v, err = e.PreviewZoneRule(q.Generation, q.ZoneRevision, *q.ZoneTarget, *q.ObservedDraft, cred.Uid, admin, r.Enforcement)
									if err == nil {
										r.ZonePreview = &v
									}
								} else {
									var v policy.Rule
									v, r.ScopePreview, r.Replayed, err = e.SaveZoneRule(q.Generation, q.ZoneRevision, q.PreviewToken, *q.ZoneTarget, *q.ObservedDraft, cred.Uid, admin)
									if err == nil {
										r.SavedRule = &v
									}
								}
								if err != nil {
									r.ErrorCode, r.Error = "invalid_request", err.Error()
									var typed *RuleMutationError
									if errors.As(err, &typed) {
										r.ErrorCode = typed.Code
									}
								}
							}
						case "observed-rule-preview", "observed-rule-save":
							if readonly || r.ReadOnly || !permissions.CanManageRules || e.Mode == "host-monitor" {
								r.ErrorCode, r.Error = "read_only", "Rule management unavailable on this endpoint"
							} else if q.ObservedDraft == nil || (q.Operation == "observed-rule-preview" && q.ObservedTarget == nil) || (q.Operation == "observed-rule-save" && (q.PreviewToken == "" || len(q.PreviewToken) > 128)) {
								r.ErrorCode, r.Error = "invalid_request", "Explicit observed draft and target/preview token required"
							} else {
								var err error
								if q.Operation == "observed-rule-preview" {
									var v ObservedPreview
									v, err = e.PreviewObservedRule(q.Generation, *q.ObservedTarget, *q.ObservedDraft, cred.Uid, admin, r.Enforcement)
									if err == nil {
										// Collection may take time: report freshly sampled health,
										// separately from the verified executable's storage authority.
										if e.Enforcement != nil {
											health := e.Enforcement()
											r.Enforcement = &health
											v.Enforcement, _ = coverage(e.Mode, v.Rule.Filter.Direction, &health)
										}
										r.ObservedPreview = &v
									}
								} else {
									var saved policy.Rule
									saved, r.ScopePreview, r.Replayed, err = e.SaveObservedRule(q.Generation, q.PreviewToken, *q.ObservedDraft, cred.Uid, admin)
									if err == nil {
										r.SavedRule = &saved
									}
								}
								if err != nil {
									r.ErrorCode, r.Error = "invalid_request", err.Error()
									var typed *RuleMutationError
									if errors.As(err, &typed) {
										r.ErrorCode = typed.Code
									}
								}
							}
						case "policy-view", "policy-explain":
							if readonly || e.Mode == "host-monitor" {
								r.Error = "Policy metadata requires the authenticated primary endpoint"
								r.ErrorCode = "primary_required"
							} else {
								func() {
									e.policyQueryMu.Lock()
									defer e.policyQueryMu.Unlock()
									// Re-sample after request decoding, in the same ordering
									// as metadata sequences. No queue/policy lock is held here.
									if e.Enforcement != nil {
										health := e.Enforcement()
										r.Enforcement = &health
										r.ReadOnly = readonly || (health.State != "active" && e.Mode != "daemon-monitor")
										p := e.permissions(cred.Uid, r.ReadOnly)
										r.Permissions = &p
									}
									var err error
									if q.Operation == "policy-view" {
										v, er := e.PolicyView(q.Generation, q.ExpectedPolicyToken, cred.Uid, admin, r.Enforcement)
										err = er
										if err == nil {
											err = boundedPolicyResponse(v)
										}
										if err == nil {
											r.PolicyView = &v
										}
									} else {
										v, er := e.PolicyExplain(q.Generation, q.ExpectedPolicyToken, q.EventIDs, cred.Uid, admin, r.Enforcement)
										err = er
										if err == nil {
											err = boundedPolicyResponse(v)
										}
										if err == nil {
											r.PolicyExplanations = &v
										}
									}
									if err != nil {
										r.Error = err.Error()
										r.ErrorCode = "limit_exceeded"
										var typed *RuleMutationError
										if errors.As(err, &typed) {
											r.ErrorCode = typed.Code
										}
									}
								}()
							}
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
									r.Rules, r.RuleStates = e.RuleInventory(cred.Uid, admin)
								} else if e.Activity == nil {
									r.Error = "observer unavailable"
								}
							}
						case "rule-preview", "rule-save":
							if q.Rule != nil && q.Rule.Filter.NetworkZone != "" {
								if er := e.zoneRevision(q.Rule.Filter.NetworkZone, q.ZoneRevision); er != nil {
									r.ErrorCode, r.Error = "zone_conflict", er.Error()
									break
								}
							}
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

func decisionError(r *Response, err error) {
	if err == nil {
		return
	}
	r.ErrorCode, r.Error = "invalid_request", err.Error()
	var typed *decisionlog.QueryError
	if errors.As(err, &typed) {
		r.ErrorCode = typed.Code
	}
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

func trafficStatusFor(s udpaccount.Status, admin bool) udpaccount.Status {
	if !admin {
		s.Scope = "self"
		s.Missed = 0
		s.Partial = true
		s.Reason = "User-scoped measurements only; collector lifecycle/global telemetry require explicit administration"
	}
	return s
}
