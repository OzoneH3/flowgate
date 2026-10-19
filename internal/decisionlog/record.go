// Package decisionlog persists firewall decision records captured at decision
// time. It is a separate private SQLite file beside the rule database so that
// log growth, failure or schema changes never affect stored rules. Recording is
// non-blocking: packet handling never waits for log I/O.
package decisionlog

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"time"
)

// Record kinds. A pending record is an initiation awaiting a user answer; a
// final record is the disposition FlowGate applied; a gap reports lost records.
const (
	KindPending = "pending"
	KindFinal   = "final"
	KindGap     = "gap"
)

// Decision sources recorded by the engine.
var Sources = map[string]bool{
	"rule": true, "attribution": true, "capacity": true, "default_ask": true,
	"user": true, "timeout": true, "identity_changed": true, "policy_change": true,
	"rule_edit": true, "shutdown": true,
}

type Flow struct {
	NetworkScope identity.NetworkScope `json:"network_scope"`
	Direction    string                `json:"direction"`
	Protocol     string                `json:"protocol"`
	Family       string                `json:"family"`
	Local        string                `json:"local"`
	Remote       string                `json:"remote"`
	Interface    uint32                `json:"interface_index"`
}
type Application struct {
	Key        string `json:"key"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Executable string `json:"executable"`
	Revision   string `json:"revision"`
}
type Attribution struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// RuleSnapshot is the rule exactly as evaluated at decision time. Version is a
// decimal string so JavaScript clients keep the exact uint64.
type RuleSnapshot struct {
	Preset      *policy.Preset `json:"preset,omitempty"`
	TargetScope string         `json:"target_scope"`
	ID          string         `json:"id"`
	Version     string         `json:"version"`
	Action      string         `json:"action"`
	Priority    int            `json:"priority"`
	Disabled    bool           `json:"disabled"`
	Created     time.Time      `json:"created"`
	Expires     time.Time      `json:"expires"`
	Filter      policy.Filter  `json:"filter"`
}
type Decision struct {
	Action        string        `json:"action"`
	Source        string        `json:"source"`
	Scope         string        `json:"scope,omitempty"`
	Reason        string        `json:"reason"`
	Rule          *RuleSnapshot `json:"rule,omitempty"`
	MatchingRules []string      `json:"matching_rules,omitempty"`
	DecidedByUID  *uint32       `json:"decided_by_uid,omitempty"`
}

// Verdict states: accept_submitted/drop_submitted (kernel verdict call
// succeeded), submission_failed, held (packet retained pending a decision),
// deferred (applies to held packets at the next queue flush and to later
// packets of this flow lease), none (no packet verdict attached).
type Verdict struct {
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}
type Gap struct {
	Dropped *uint64 `json:"dropped,omitempty"`
	Reason  string  `json:"reason"`
}

// Aggregation describes capacity observations, not a count of unique flows.
type Aggregation struct {
	Observations uint64    `json:"observations"`
	First        time.Time `json:"first_seen"`
	Last         time.Time `json:"last_seen"`
	WindowMS     int       `json:"window_ms"`
}
type Record struct {
	EvaluationID string       `json:"evaluation_id,omitempty"`
	Aggregation  *Aggregation `json:"aggregation,omitempty"`
	ID           string       `json:"id"`
	Sequence     string       `json:"sequence"`
	Time         time.Time    `json:"time"`
	Generation   string       `json:"generation"`
	Mode         string       `json:"mode"`
	Kind         string       `json:"kind"`
	RequestID    string       `json:"request_id,omitempty"`
	Flow         *Flow        `json:"flow,omitempty"`
	Application  *Application `json:"application"`
	PrincipalUID *uint32      `json:"principal_uid"`
	Attribution  *Attribution `json:"attribution,omitempty"`
	Decision     *Decision    `json:"decision,omitempty"`
	Verdict      *Verdict     `json:"verdict,omitempty"`
	// Delivery is always not_observed: FlowGate never observes receiver delivery.
	Delivery string `json:"delivery,omitempty"`
	Gap      *Gap   `json:"gap,omitempty"`
}

func Snapshot(r policy.Rule) *RuleSnapshot {
	scope := "application"
	if r.Filter.AllPrograms {
		scope = "zone"
	}
	if !r.Filter.Process.IsZero() {
		scope = "process"
	}
	if r.Preset != nil && r.Filter.AllPrograms {
		scope = "system"
	}
	return &RuleSnapshot{Preset: r.Preset, TargetScope: scope, ID: r.ID, Version: uitoa(r.Version), Action: r.Action, Priority: r.Priority, Disabled: r.Disabled, Created: r.Created, Expires: r.Expires, Filter: r.Filter}
}
