package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"flowgate/internal/accounting"
	"flowgate/internal/decisionlog"
	"flowgate/internal/essential"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/queuehealth"
	"flowgate/internal/readiness"
	"flowgate/internal/udpaccount"
	"flowgate/internal/uploadshape"
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
	UploadConfig        *uploadshape.Config        `json:"upload_config,omitempty"`
	HistoryQuery        *accounting.HistoryQuery   `json:"history_query,omitempty"`
	HistoryOptions      *accounting.HistoryOptions `json:"history_options,omitempty"`
	EndpointDraft       *EndpointDraft             `json:"endpoint_draft,omitempty"`
	EssentialOptions    *essential.Options         `json:"essential_options,omitempty"`
	NetworkZone         string                     `json:"network_zone,omitempty"`
	ZoneTarget          *ZoneTarget                `json:"zone_target,omitempty"`
	ZoneRevision        string                     `json:"zone_revision,omitempty"`
	Remember            *RememberFields            `json:"remember,omitempty"`
	DurationSeconds     int64                      `json:"duration_seconds,omitempty"`
	ProtectionID        string                     `json:"protection_id,omitempty"`
	EvaluationID        string                     `json:"evaluation_id,omitempty"`
	RequestID           string                     `json:"request_id,omitempty"`
	Profile             string                     `json:"profile,omitempty"`
	DecisionQuery       json.RawMessage            `json:"decision_query,omitempty"`
	DecisionID          string                     `json:"decision_id,omitempty"`
	CollectorGeneration string                     `json:"collector_generation,omitempty"`
	ObservedTarget      *ObservedTarget            `json:"observed_target,omitempty"`
	ObservedDraft       *ObservedDraft             `json:"observed_draft,omitempty"`
	PreviewToken        string                     `json:"preview_token,omitempty"`

	ExpectedPolicyToken string       `json:"expected_policy_token,omitempty"`
	EventIDs            []string     `json:"event_ids,omitempty"`
	Generation          string       `json:"generation,omitempty"`
	EventID             string       `json:"event_id,omitempty"`
	BasisRuleID         string       `json:"basis_rule_id,omitempty"`
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
	UploadShaping    *uploadshape.Snapshot       `json:"upload_shaping,omitempty"`
	UsageHistory     *accounting.HistorySnapshot `json:"usage_history,omitempty"`
	HistorySettings  *accounting.HistorySettings `json:"history_settings,omitempty"`
	QueueHealth      *queuehealth.Snapshot       `json:"queue_health,omitempty"`
	EndpointPreview  *EndpointPreview            `json:"endpoint_preview,omitempty"`
	ObservedUsage    *accounting.Snapshot        `json:"observed_usage,omitempty"`
	RuntimeChecks    []readiness.Check           `json:"runtime_checks,omitempty"`
	SnapshotRevision string                      `json:"snapshot_revision,omitempty"`
	SnapshotAt       time.Time                   `json:"snapshot_at,omitempty"`
	EssentialPreview *EssentialPreview           `json:"essential_preview,omitempty"`
	EssentialReceipt *EssentialReceipt           `json:"essential_receipt,omitempty"`
	EssentialStatus  *EssentialStatus            `json:"essential_status,omitempty"`
	Build            *BuildIdentity              `json:"build,omitempty"`
	DecisionPreview  *DecisionPreview            `json:"decision_preview,omitempty"`
	DecisionReceipt  *DecisionReceipt            `json:"decision_receipt,omitempty"`
	NetworkZones     *identity.NetworkZones      `json:"network_zones,omitempty"`
	ZoneMigration    *ZoneMigrationPreview       `json:"zone_migration,omitempty"`
	ZonePreview      *ZonePreview                `json:"zone_preview,omitempty"`
	RuleStates       map[string]RuleTargetState  `json:"rule_states,omitempty"`
	Protection       *ProtectionStatus           `json:"protection,omitempty"`
	Evaluation       *EvaluationStatus           `json:"evaluation,omitempty"`
	DecisionLog      *decisionlog.Page           `json:"decision_log,omitempty"`
	DecisionRecord   *decisionlog.Record         `json:"decision_record,omitempty"`
	TrafficMonitor   *udpaccount.Status          `json:"traffic_monitor,omitempty"`
	ObservedPreview  *ObservedPreview            `json:"observed_preview,omitempty"`
	RequestRule      *RequestRulePreview         `json:"request_rule_preview,omitempty"`
	Replayed         bool                        `json:"replayed,omitempty"`

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
	ProcessLeases      *[]ProcessLease            `json:"process_leases,omitempty"`
	// queue-reconcile-v1: other requests this operation settled (left awaiting).
	Settled []SettledRequest `json:"settled,omitempty"`
	// request-for-a-while-v1: the lease created from an ended request, which
	// itself stays ended (request_ended true; never decided or delivered).
	ProcessLease *ProcessLease `json:"process_lease,omitempty"`
	RequestEnded bool          `json:"request_ended,omitempty"`
	// decision-for-a-while-durations-v1: the exact allowed lease durations.
	ForAWhileDurations []int64 `json:"for_a_while_durations,omitempty"`
	Decision           *Event  `json:"decision,omitempty"`
	Error              string  `json:"error,omitempty"`

	// local-pair-v1: decide-pair result (both sides of one local connection).
	Pair *PairDecision `json:"pair,omitempty"`
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
	releaseSnapshots, err := e.listReads.acquire(e)
	if err != nil {
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
					r := Response{Build: e.Build, Capabilities: []string{ConditionalDeleteCapability, ConditionalMutationCapability, "explicit-administrator-v1"}, Version: 1, Generation: e.Generation, ReadOnly: readonly, Mode: e.Mode, ServerTime: time.Now(), PeerUID: cred.Uid}
					if e.UploadShaping != nil {
						r.Capabilities = append(r.Capabilities, "experimental-native-upload-v1", "experimental-native-download-v1", "experimental-traffic-priority-v1", "experimental-zone-shaping-v1")
					}
					if e.RuntimeChecks != nil {
						r.RuntimeChecks = e.RuntimeChecks()
					}
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
						r.Capabilities = append(r.Capabilities, "explicit-root-sharing-v1", PolicyExplanationCapability, ObservedRuleCapability, ProcessRuleCapability, ObservedAnyProtocolCapability, DecisionZoneCapability, ApplicationPolicyCapability, DecisionRememberFieldsCapability, StoredAskCapability, RequestApplicationRuleCapability, ForAWhileCapability, ForAWhileDurationsCapability, QueueReconcileCapability, RequestForAWhileCapability, LocalPairCapability, RequestSandboxIdentityCapability, RuleFromBasisCapability)
						r.ForAWhileDurations = ForAWhileDurations
					}
					if e.Evaluation != nil {
						r.Capabilities = append(r.Capabilities, EvaluationCapability)

					}
					if p := e.listReads.published.Load(); e.Essential != nil || (p != nil && p.hasPresets) {
						r.Capabilities = append(r.Capabilities, EssentialCapability, EssentialExclusionCapability, EssentialAssistanceCapability)
					}
					if e.Protection != nil {
						r.Capabilities = append(r.Capabilities, ProtectionCapability)
					}
					if e.Traffic != nil {
						r.Capabilities = append(r.Capabilities, "daemon-udp-monitor-v1")
					}
					if e.Decisions != nil {
						r.Capabilities = append(r.Capabilities, DecisionLogCapability)
					}
					if e.UsageHistory != nil {
						r.Capabilities = append(r.Capabilities, accounting.HistoryCapability)
					}
					if e.ObservedUsage != nil {
						r.Capabilities = append(r.Capabilities, accounting.Capability)
					}
					if e.Activity != nil {
						r.Capabilities = append(r.Capabilities, "activity-initiation-v1", "application-display-metadata-v1", "activity-initiation-events-v1")
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
					if e.Protection != nil {
						v := e.Protection.ProtectionStatus()
						r.Protection = &v
						if v.State != "stopped" || v.DesiredMode != "monitoring" {
							r.Enforcement = &EnforcementStatus{State: v.State, Profile: v.Profile, Detail: v.Reason}
						}
					}
					admin := e.administrator(cred.Uid)
					health := e.QueueHealth.Snapshot(admin)
					r.QueueHealth = &health
					r.Capabilities = append(r.Capabilities, queuehealth.Capability)
					permissions := e.permissions(cred.Uid, r.ReadOnly)
					if r.Evaluation != nil {
						permissions.CanDecide = !readonly && (r.Evaluation.State == "active" || (r.Protection != nil && r.Protection.State == "active"))
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
						var zones identity.NetworkZones
						var cachedList ListSnapshot
						if q.Operation == "list" {
							cachedList, err = e.listReads.read(cred.Uid, admin, time.Now())
							if err != nil {
								r.ErrorCode = "snapshot_unavailable"
								r.Error = err.Error()
								json.NewEncoder(c).Encode(r)
								return
							}
							zones = cachedList.Zones
							r.SnapshotRevision, r.SnapshotAt = cachedList.Revision, cachedList.At
						} else {
							zones = e.CurrentZones()
						}
						r.Capabilities = append(r.Capabilities, ListSnapshotCapability)
						r.NetworkZones = &zones
						r.Capabilities = append(r.Capabilities, NetworkZoneCapability)
						if zones.Model == identity.AutomaticZoneModel {
							r.Capabilities = append(r.Capabilities, AutomaticNetworkZoneCapability, ZoneMigrationCapability)
						}
						if admin && permissions.CanManageMachineRules && !readonly {
							r.Capabilities = append(r.Capabilities, NetworkEndpointCapability)
						}
						switch q.Operation {
						case "endpoint-rule-preview", "endpoint-rule-save":
							if readonly {
								r.ErrorCode, r.Error = "read_only", "Read-only endpoint"
							} else if !admin || !permissions.CanManageMachineRules {
								r.ErrorCode, r.Error = "forbidden", "Network endpoint authority requires configured administrator"
							} else if q.EndpointDraft == nil || (q.Operation == "endpoint-rule-save" && (q.PreviewToken == "" || len(q.PreviewToken) > 128)) {
								r.ErrorCode, r.Error = "invalid_request", "Explicit endpoint draft and save preview token required"
							} else if q.Operation == "endpoint-rule-preview" {
								v, err := e.PreviewEndpointRule(q.Generation, *q.EndpointDraft, cred.Uid, admin, r.Enforcement)
								decisionError(&r, err)
								if err == nil {
									r.EndpointPreview = &v
								}
							} else {
								v, sentence, replayed, err := e.SaveEndpointRule(q.Generation, q.PreviewToken, *q.EndpointDraft, cred.Uid, admin)
								decisionError(&r, err)
								if err == nil {
									r.SavedRule = &v
									r.ScopePreview = sentence
									r.Replayed = replayed
								}
							}
						case "essential-status", "essential-preview", "essential-apply", "essential-remove-preview", "essential-remove":
							c.SetDeadline(time.Now().Add(20 * time.Second))
							if !admin || (q.Operation != "essential-status" && (!permissions.CanManageRules || readonly)) {
								r.ErrorCode, r.Error = "forbidden", "Essential machine policy requires administrator on primary endpoint"
							} else if q.Generation != e.Generation {
								r.ErrorCode, r.Error = "generation_conflict", "Daemon changed"
							} else {
								var er error
								switch q.Operation {
								case "essential-status":
									var v EssentialStatus
									v, er = e.EssentialStatus()
									r.EssentialStatus = &v
									if er == nil && q.PreviewToken != "" {
										var receipt EssentialReceipt
										receipt, er = e.EssentialReceipt(q.Generation, q.PreviewToken, cred.Uid)
										if er == nil {
											r.EssentialReceipt = &receipt
										}
									}
								case "essential-preview", "essential-remove-preview":
									if q.EssentialOptions == nil {
										er = mutationError("invalid_request", "Explicit essential_options required")
									} else {
										op := "apply"
										if q.Operation == "essential-remove-preview" {
											op = "remove"
										}
										var v EssentialPreview
										v, er = e.PreviewEssential(q.Generation, op, *q.EssentialOptions, cred.Uid)
										if er == nil {
											r.EssentialPreview = &v
										}
									}
								default:
									if q.EssentialOptions == nil || q.PreviewToken == "" || len(q.PreviewToken) > 128 {
										er = mutationError("invalid_request", "Preset token and exact options required")
									} else {
										op := "apply"
										if q.Operation == "essential-remove" {
											op = "remove"
										}
										var v EssentialReceipt
										v, r.Replayed, er = e.ApplyEssential(q.Generation, q.PreviewToken, op, *q.EssentialOptions, cred.Uid)
										if er == nil {
											r.EssentialReceipt = &v
										}
									}
								}
								if er != nil {
									r.ErrorCode, r.Error = "preset_conflict", er.Error()
									var typed *RuleMutationError
									if errors.As(er, &typed) {
										r.ErrorCode = typed.Code
									}
								}
							}
						case "protection-readiness", "protection-start", "protection-stop":
							if e.Protection == nil {
								r.ErrorCode, r.Error = "unavailable", "Continuous protection unavailable"
							} else if q.Operation != "protection-readiness" && !permissions.CanControlProtection {
								r.ErrorCode, r.Error = "forbidden", "Explicit protection permission on primary endpoint required"
							} else if q.Generation != e.Generation {
								r.ErrorCode, r.Error = "generation_conflict", "Daemon generation changed; refresh state"
							} else {
								var v ProtectionStatus
								var er error
								switch q.Operation {
								case "protection-readiness":
									v, er = e.Protection.ProtectionReadiness(q.Profile)
								case "protection-start":
									v, er = e.Protection.ProtectionStart(q.ProtectionID, q.RequestID, q.Profile)
								case "protection-stop":
									v, er = e.Protection.ProtectionStop(q.ProtectionID)
								}
								r.Protection = &v
								r.Enforcement = &EnforcementStatus{State: v.State, Profile: v.Profile, Detail: v.Reason}
								permissions.CanDecide = !readonly && v.State == "active"
								r.Permissions = &permissions
								if er != nil {
									r.ErrorCode, r.Error = "protection_conflict", er.Error()
									var typed *RuleMutationError
									if errors.As(er, &typed) {
										r.ErrorCode = typed.Code
									}
								}
							}
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
								zones := e.CurrentZones()
								r.NetworkZones = &zones
								r.Capabilities = append(r.Capabilities, NetworkZoneCapability)
								if zones.Model == identity.AutomaticZoneModel {
									r.Capabilities = append(r.Capabilities, AutomaticNetworkZoneCapability, ZoneMigrationCapability)
								}
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
								zones := e.CurrentZones()
								r.NetworkZones = &zones
								r.Capabilities = append(r.Capabilities, NetworkZoneCapability)
								if zones.Model == identity.AutomaticZoneModel {
									r.Capabilities = append(r.Capabilities, AutomaticNetworkZoneCapability, ZoneMigrationCapability)
								}
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
										r.Settled = e.ObservedSettled(q.PreviewToken)
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
						case "request-rule-preview", "request-rule-save":
							if readonly || r.ReadOnly || !permissions.CanManageRules || e.Mode == "host-monitor" {
								r.ErrorCode, r.Error = "read_only", "Rule management unavailable on this endpoint"
							} else if q.ID == "" || len(q.ID) > 64 || (q.Operation == "request-rule-save" && (q.PreviewToken == "" || len(q.PreviewToken) > 128)) {
								r.ErrorCode, r.Error = "invalid_request", "Request id and, for save, preview token required"
							} else {
								var err error
								o := RememberOptions{q.Remember, q.DurationSeconds}
								if q.Operation == "request-rule-preview" {
									var v RequestRulePreview
									if v, err = e.PreviewRequestRule(q.Generation, q.ID, q.Action, q.Scope, q.NetworkZone, q.ZoneRevision, cred.Uid, admin, o); err == nil {
										r.RequestRule = &v
									}
								} else {
									var saved policy.Rule
									if saved, r.ScopePreview, r.Replayed, r.Settled, err = e.SaveRequestRuleSettled(q.Generation, q.PreviewToken, q.ID, q.Action, q.Scope, q.NetworkZone, q.ZoneRevision, cred.Uid, admin, o); err == nil {
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

						case "upload-status", "upload-configure":
							v, er := e.uploadRequest(q, admin, readonly)
							usageHistoryError(&r, er)
							if er == nil {
								r.UploadShaping = &v
							}
						case "usage-history":
							if q.HistoryQuery == nil {
								r.ErrorCode, r.Error = "invalid_request", "Explicit history query required"
							} else {
								v, er := e.UsageHistoryRead(q.Generation, *q.HistoryQuery, cred.Uid, admin)
								usageHistoryError(&r, er)
								if er == nil {
									r.UsageHistory = &v
								}
							}
						case "usage-history-configure":
							if q.HistoryOptions == nil {
								r.ErrorCode, r.Error = "invalid_request", "Explicit history settings required"
							} else {
								v, er := e.UsageHistoryConfigure(q.Generation, *q.HistoryOptions, admin, readonly || !permissions.CanManageMachineRules)
								usageHistoryError(&r, er)
								if er == nil {
									r.HistorySettings = &v
								}
							}
						case "observed-usage":
							if e.ObservedUsage == nil {
								r.ErrorCode, r.Error = "unavailable", "Observed usage is unavailable"
							} else if e.Mode == "host-monitor" && e.APIUID == nil && cred.Uid != uint32(os.Geteuid()) {
								r.ErrorCode, r.Error = "forbidden", "not authorized"
							} else {
								snapshot := e.ObservedUsage.Snapshot(cred.Uid, admin)
								r.ObservedUsage = &snapshot
							}
						case "list":
							if e.Mode == "host-monitor" && e.APIUID == nil && cred.Uid != uint32(os.Geteuid()) {
								r.Error = "not authorized"
								r.ErrorCode = "forbidden"
							} else {
								if e.Activity != nil {
									snapshot := ClassifyActivity(e.Activity(), *r.NetworkZones)
									if e.APIUID != nil {
										snapshot = activityFor(snapshot, cred.Uid, admin)
									}
									r.Activity = &snapshot
								}
								if e.Mode != "host-monitor" {
									r.Events = cachedList.Events
									r.ProcessLeases = &cachedList.Leases
									r.NetworkZones = &cachedList.Zones
									r.Rules, r.RuleStates = cachedList.Rules, cachedList.RuleStates
									if r.Activity != nil {
										snapshot := ClassifyActivity(*r.Activity, cachedList.Zones)
										r.Activity = &snapshot
									}
								} else if e.Activity == nil {
									r.Error = "observer unavailable"
								}
							}
						case "zone-migration-preview", "zone-migration-save":
							if readonly || !permissions.CanManageRules {
								r.ErrorCode, r.Error = "forbidden", "Migration requires current rule-management authority"
							} else if q.Operation == "zone-migration-preview" {
								v, err := e.PreviewZoneMigration(q.Generation, q.ID, q.ExpectedVersion, q.ZoneRevision, cred.Uid, admin)
								decisionError(&r, err)
								if err == nil {
									r.ZoneMigration = &v
								}
							} else {
								v, sentence, replayed, err := e.SaveZoneMigration(q.Generation, q.ID, q.ExpectedVersion, q.ZoneRevision, q.PreviewToken, cred.Uid, admin)
								decisionError(&r, err)
								if err == nil {
									r.SavedRule = &v
									r.ScopePreview = sentence
									r.Replayed = replayed
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
								var rule policy.Rule
								var preview string
								var err error
								if q.BasisRuleID != "" && q.ID == "" && q.EventID == "" {
									rule, preview, err = e.CreateRuleFromBasis(q.BasisRuleID, *q.Rule, cred.Uid, admin, q.Operation == "rule-save")
								} else {
									rule, preview, err = e.EditRule(q.ID, q.EventID, q.ExpectedVersion, *q.Rule, cred.Uid, admin, q.Operation == "rule-save")
								}
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
							} else if err := e.ChangeRule(q.Generation, q.ID, q.Action, q.ExpectedVersion, cred.Uid, admin); err != nil {
								r.ErrorCode, r.Error = "invalid_request", err.Error()
								var typed *RuleMutationError
								if errors.As(err, &typed) {
									r.ErrorCode = typed.Code
								}
							}
						case "decision-preview", "decision-status":
							if readonly || e.Mode == "host-monitor" {
								r.ErrorCode, r.Error = "forbidden", "Decision previews/receipts require authenticated primary endpoint"
							} else if q.Operation == "decision-preview" && !permissions.CanDecide {
								r.ErrorCode, r.Error = "unavailable", "No current decision authority"
							} else {
								var err error
								if q.Operation == "decision-preview" {
									var v DecisionPreview
									v, err = e.PreviewDecision(q.Generation, q.ID, q.Action, q.Scope, q.NetworkZone, q.ZoneRevision, cred.Uid, admin, RememberOptions{q.Remember, q.DurationSeconds})
									if err == nil {
										r.DecisionPreview = &v
									}
								} else {
									var v DecisionReceipt
									v, err = e.DecisionStatus(q.Generation, q.PreviewToken, cred.Uid, admin)
									if err == nil {
										r.DecisionReceipt = &v
									}
								}
								if err != nil {
									r.Error = err.Error()
									r.ErrorCode = "invalid_request"
									var typed *RuleMutationError
									if errors.As(err, &typed) {
										r.ErrorCode = typed.Code
									}
								}
							}
						case "request-for-a-while":
							// For a while from an ended request whose process still runs:
							// creates the process lease only; the request stays ended.
							if readonly || r.ReadOnly || e.Mode == "host-monitor" {
								r.ErrorCode, r.Error = "read_only", "read-only API"
							} else if !permissions.CanDecide {
								r.ErrorCode, r.Error = "unavailable", "decision unavailable in non-enforcing/read-only mode"
							} else if q.ID == "" || len(q.ID) > 64 {
								r.ErrorCode, r.Error = "invalid_request", "Request id required"
							} else {
								l, settled, err := e.ForAWhileFromRequest(q.Generation, q.ID, q.Action, q.DurationSeconds, cred.Uid, admin)
								if err != nil {
									r.ErrorCode, r.Error = "invalid_request", err.Error()
									var typed *RuleMutationError
									if errors.As(err, &typed) {
										r.ErrorCode = typed.Code
									}
								} else {
									r.ProcessLease, r.Settled, r.RequestEnded = &l, settled, true
									r.ScopePreview = endedLeaseSentence(l)
								}
							}
						case "decide-pair":
							// local-pair-v1: both sides of one verified local connection.
							if readonly || r.ReadOnly || e.Mode == "host-monitor" {
								r.ErrorCode, r.Error = "read_only", "read-only API"
							} else if !permissions.CanDecide {
								r.ErrorCode, r.Error = "unavailable", "decision unavailable in non-enforcing/read-only mode"
							} else {
								v, settled, err := e.DecidePair(q.Generation, q.EventIDs, q.Action, q.Scope, q.DurationSeconds, cred.Uid, admin)
								if err != nil {
									r.ErrorCode, r.Error = "invalid_request", err.Error()
									var typed *RuleMutationError
									if errors.As(err, &typed) {
										r.ErrorCode = typed.Code
									}
								} else {
									r.Pair, r.Settled, r.ScopePreview = &v, settled, v.Sentence
								}
							}
						case "decide":
							if q.Generation != "" && q.Generation != e.Generation {
								r.ErrorCode, r.Error = "generation_conflict", "Daemon generation changed; request is no longer actionable"
								break
							}
							if !permissions.CanDecide {
								r.Error = "decision unavailable in non-enforcing/read-only mode"
								r.ErrorCode = "unavailable"
							} else if r.ReadOnly {
								r.Error = "read-only API"
							} else {
								var v Event
								var err error
								if q.PreviewToken != "" {
									var rule policy.Rule
									v, rule, r.Replayed, r.Settled, err = e.DecideReviewedSettled(q.Generation, q.ID, q.Action, q.Scope, q.NetworkZone, q.ZoneRevision, q.PreviewToken, cred.Uid, admin, RememberOptions{q.Remember, q.DurationSeconds})
									if err == nil {
										r.SavedRule = &rule
									}
								} else if q.NetworkZone != "" || q.ZoneRevision != "" || q.Remember != nil || (q.DurationSeconds != 0 && q.Scope != ForAWhileScope) {
									err = mutationError("preview_required", "Explicit network scope requires reviewed decision token")
								} else {
									// For a while: duration_seconds is the lease duration (absent = 15 s).
									v, r.Settled, err = e.DecideSettled(q.ID, q.Action, q.Scope, q.DurationSeconds, cred.Uid, admin)
								}
								if err != nil {
									r.Error = err.Error()
									var typed *RuleMutationError
									if errors.As(err, &typed) {
										r.ErrorCode = typed.Code
									}
								} else {
									r.Decision = &v
								}
							}
						default:
							r.Error = "unknown operation"
						}
					}
					if q.Version == 1 && q.Operation != "list" {
						if publishErr := e.listReads.publishAfter(e, q.Operation); publishErr != nil {
							r.ErrorCode = "snapshot_unavailable"
							r.Error = "Operation completed; list publication failed. Refresh before any retry: " + publishErr.Error()
						}
						// Keep the error reply decodable if publication failed. The revision
						// then identifies the last good snapshot, not the failed mutation.
						if published := e.listReads.published.Load(); published != nil {
							r.SnapshotRevision, r.SnapshotAt = published.revision, published.at
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
	return &snapshotListener{Listener: l, release: releaseSnapshots}, nil
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
