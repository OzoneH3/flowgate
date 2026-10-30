package identity

import (
	"encoding/json"
	diagnostics "flowgate/internal/serveprofile"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// BindingChange describes evidence, not a new permission identity. An absent
// socket/owner does not establish that an executable changed or a process exited.
type BindingChange struct {
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}
type ProcessRecheck struct {
	PID     int             `json:"pid"`
	State   string          `json:"state"`
	Changes []BindingChange `json:"changes,omitempty"`
}
type PendingRevalidation struct {
	Processes []ProcessRecheck `json:"processes,omitempty"`
	Code      string           `json:"code"`
	Reason    string           `json:"reason"`
	CheckedAt time.Time        `json:"checked_at"`
	Changes   []BindingChange  `json:"changes"`
}

// ComparePendingBinding explains the existing strict fingerprint/attribution
// rejection. It never turns a failed check into authority.
func ComparePendingBinding(before, after Attribution, at time.Time) (result PendingRevalidation) {
	defer func() {
		diagnostics.EvidenceKey(true, "pending:"+before.Fingerprint, func() any {
			return map[string]any{"kind": "pending_revalidation", "at": at, "before": diagnosticAttribution(before), "after": diagnosticAttribution(after), "result": result}
		})
	}()
	r := PendingRevalidation{Code: "identity_changed", Reason: "Request binding changed; no decision or rule saved", CheckedAt: at}
	add := func(field, a, b string) {
		if a != b {
			if len(r.Changes) >= 64 {
				return
			}
			if len(a) > 1024 {
				a = a[:1024] + "… (truncated)"
			}
			if len(b) > 1024 {
				b = b[:1024] + "… (truncated)"
			}
			r.Changes = append(r.Changes, BindingChange{field, a, b})
		}
	}
	sockets := func(a Attribution) string {
		var ids []string
		for _, s := range a.Sockets {
			ids = append(ids, fmt.Sprintf("%s/%d/%s", s.NetNS, s.Inode, s.Cookie))
		}
		sort.Strings(ids)
		return strings.Join(ids, ",")
	}
	owners := func(a Attribution) string {
		var ids []string
		for _, p := range a.Owners {
			ids = append(ids, fmt.Sprintf("%d:%s", p.PID, p.Start))
		}
		sort.Strings(ids)
		return strings.Join(ids, ",")
	}
	add("socket_inode_cookie", sockets(before), sockets(after))
	// Runtime-table evidence is part of a Wine fingerprint: name which part changed
	// (holder rows, including transient TCP state, or the census helper instance).
	if before.Table != nil || after.Table != nil {
		table := func(a Attribution) (string, string) {
			if a.Table == nil {
				return "unavailable", "unavailable"
			}
			b, _ := json.Marshal(a.Table.Owners)
			return string(b), a.Table.Generation
		}
		beforeRows, beforeGeneration := table(before)
		afterRows, afterGeneration := table(after)
		add("runtime_table_holders", beforeRows, afterRows)
		add("runtime_table_generation", beforeGeneration, afterGeneration)
	}
	add("owner_pid_start_set", owners(before), owners(after))
	old := map[int]Process{}
	for _, p := range before.Owners {
		old[p.PID] = p
	}
	for _, p := range after.Owners {
		q, ok := old[p.PID]
		if !ok {
			continue
		}
		prefix := fmt.Sprintf("process[%d].", p.PID)
		add(prefix+"start_ticks", q.Start, p.Start)
		add(prefix+"uid", fmt.Sprint(q.UID), fmt.Sprint(p.UID))
		add(prefix+"boot_id", q.BootID, p.BootID)
		add(prefix+"pidns", q.PIDNS, p.PIDNS)
		add(prefix+"netns", q.NetNS, p.NetNS)
		add(prefix+"mountns", q.MountNS, p.MountNS)
		add(prefix+"executable", q.Executable, p.Executable)
		add(prefix+"executable_revision", q.ExecutableRevision, p.ExecutableRevision)
		add(prefix+"application_key", q.Application.Key, p.Application.Key)
		add(prefix+"application_revision", q.Application.Revision, p.Application.Revision)
	}
	app := func(a Attribution) string {
		if a.Application == nil {
			return "unavailable"
		}
		return a.Application.Key + ":" + a.Application.Revision
	}
	add("application", app(before), app(after))
	add("visibility_complete", fmt.Sprint(before.VisibilityComplete), fmt.Sprint(after.VisibilityComplete))
	add("attribution_status", before.Status, after.Status)
	add("fingerprint", before.Fingerprint, after.Fingerprint)
	if len(before.Sockets) > 0 && len(after.Sockets) == 0 && (after.ReasonCode == ReasonNoSocketObserved || (after.ReasonCode == "" && after.Reason == "no visible matching socket")) {
		r.Code = "connection_ended"
		r.Reason = "Connection ended: original socket is no longer present; process/executable change is not established"
	} else if sockets(before) != sockets(after) && len(before.Sockets) > 0 && len(after.Sockets) > 0 {
		r.Code = "connection_ended"
		r.Reason = "Connection ended or replaced: socket inode/cookie binding changed; replacement connection was not approved"
	} else if after.Application == nil && before.Fingerprint == after.Fingerprint {
		r.Reason = "Request attribution is no longer available; executable/process change is not established"
	}
	return r
}

// A separate process recheck helps distinguish socket closure from process exit
// or exec. It is diagnostic only: a current process is NEVER substituted as the
// owner of the original flow or used to admit its held packets.
func RecheckPendingProcesses(original Attribution) []ProcessRecheck {
	var out []ProcessRecheck
	for i, old := range original.Owners {
		if i >= 4 {
			break
		}
		if old.PID <= 0 {
			continue
		}
		check := ProcessRecheck{PID: old.PID, State: "unavailable"}
		current, err := Inspect(old.PID)
		if err != nil {
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", old.PID)); os.IsNotExist(err) {
				check.State = "exited"
			}
		} else {
			before, after := Attribution{Owners: []Process{old}}, Attribution{Owners: []Process{current}}
			delta := ComparePendingBinding(before, after, time.Now())
			for _, change := range delta.Changes {
				if strings.HasPrefix(change.Field, fmt.Sprintf("process[%d].", old.PID)) {
					check.Changes = append(check.Changes, change)
				}
			}
			check.State = "same"
			if len(check.Changes) > 0 {
				check.State = "changed"
			}
		}
		out = append(out, check)
	}
	return out
}
