package identity

import (
	"encoding/json"
	diagnostics "flowgate/internal/serveprofile"
	"time"
)

// Only already-collected observations are projected. No extra /proc/netlink or
// runtime queries, no payloads, command lines or environment. Truncation explicit.
func diagnosticAttribution(a Attribution) map[string]any {
	sockets := a.Sockets
	if len(sockets) > 8 {
		sockets = sockets[:8]
	}
	owners := make([]map[string]any, 0, min(16, len(a.Owners)))
	for _, p := range a.Owners[:min(16, len(a.Owners))] {
		owners = append(owners, map[string]any{"pid": p.PID, "start": p.Start, "uid": p.UID, "netns": p.NetNS, "pidns": p.PIDNS, "mountns": p.MountNS, "boot": p.BootID, "exe": p.Executable, "exe_revision": p.ExecutableRevision, "witness": p.HolderWitness, "kind": p.Application.Kind, "prefix": p.Application.Prefix, "app_revision": p.Application.Revision})
	}
	return map[string]any{"source": a.diagnosticSource, "hint_age_ns": a.diagnosticHintAge.Nanoseconds(), "dump_end": a.diagnosticDumpEnd, "recheck_begin": a.diagnosticRecheckBegin, "recheck_end": a.diagnosticRecheckEnd, "recheck_sockets": a.diagnosticRecheck[:min(8, len(a.diagnosticRecheck))], "recheck_count": len(a.diagnosticRecheck), "holder_attempts": a.diagnosticHolderAttempts, "first_holder_issues": a.diagnosticFirstIssues[:min(16, len(a.diagnosticFirstIssues))], "holder_issues": a.diagnosticIssues[:min(16, len(a.diagnosticIssues))], "socket_issues": a.diagnosticSocketIssues, "begin": a.diagnosticBegin, "end": a.diagnosticEnd, "status": a.Status, "reason_code": a.ReasonCode, "complete": a.VisibilityComplete, "sockets": sockets, "socket_count": len(a.Sockets), "owners": owners, "owner_count": len(a.Owners)}
}
func diagnosticTable(s tableSnapshot, rows []WindowsOwner) map[string]any {
	return map[string]any{"begin": s.diagnosticBegin, "end": s.diagnosticEnd, "schema": s.Schema, "version": s.Version, "family": s.Family, "complete": s.Complete, "error": s.Error, "total_rows": len(s.Rows), "matching_rows": rows[:min(8, len(rows))], "matching_count": len(rows)}
}
func diagnosticBookends(f Flow, a, b Attribution, broker *Process, first, second tableSnapshot, rows, rows2 []WindowsOwner, result Attribution, rowsValid bool) {
	diagnostics.EvidenceKey(result.Status != "corroborated-runtime-table", "wine:"+f.Key(), func() any {
		x, _ := json.Marshal(rows)
		y, _ := json.Marshal(rows2)
		checks := map[string]bool{"second_rows_valid": rowsValid, "same_sockets": fingerprint(nil, a.Sockets) == fingerprint(nil, b.Sockets), "fresh_complete": b.VisibilityComplete, "same_runtime_rows": string(x) == string(y), "same_broker": sameBrokerGeneration(*broker, b.Owners)}
		return map[string]any{"kind": "wine_bookends", "at": time.Now().UTC(), "flow": f, "observation_only": true, "initial": diagnosticAttribution(a), "fresh": diagnosticAttribution(b), "broker_pid": broker.PID, "broker_start": broker.Start, "first": diagnosticTable(first, rows), "second": diagnosticTable(second, rows2), "comparisons": checks, "result": result.ReasonCode}
	})
}

func diagnosticNoSocket(source string, f Flow, sockets []Socket, begin time.Time) {
	diagnostics.EvidenceKey(true, "no_socket:"+f.Key(), func() any {
		same := make([]Socket, 0, 8)
		count := 0
		for _, s := range sockets {
			if s.Local.Port() == f.Local.Port() {
				count++
				if len(same) < 8 {
					same = append(same, s)
				}
			}
		}
		return map[string]any{"kind": "no_socket", "source": source, "observation_only": true, "flow": f, "begin": begin, "end": diagnostics.ObservationTime(), "dump_count": len(sockets), "same_port_count": count, "same_port_sockets": same}
	})
}
