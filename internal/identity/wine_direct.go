package identity

import (
	"encoding/json"
	diagnostics "flowgate/internal/serveprofile"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Private read-only request numbers are enabled only for these exact tested
// server binaries. Public owner-table support remains version-family based.
const directWine11Build = "af283894589c9df40b7d74f5366a8e8112b671c28199bc4e933fc4cedcd249ff"
const directWine1120Build = "c9a0c615ddd8ba168b9fdf5efaaa4769cb2369782c766b579157ed0a5520977e"

func processPIDContract(version, build string) bool {
	return (version == "11.0" && build == directWine11Build) || (version == "11.20" && build == directWine1120Build)
}
func (w *WineTable) processPIDContract(version string) bool {
	return w.session != nil && processPIDContract(version, w.session.Build)
}

func directUnresolved(a Attribution) bool {
	return a.VisibilityComplete && len(a.Sockets) == 1 && len(a.Owners) == 1 && a.Owners[0].Application.Kind == "wine-unresolved" && a.Owners[0].Application.Prefix != ""
}

func wineClientPeer(client, broker Process) bool {
	if client.UID != broker.UID || client.NetNS != broker.NetNS || client.MountNS != broker.MountNS || client.Application.Prefix != broker.Application.Prefix {
		return false
	}
	cf, e := socketFDs(client.PID)
	if e != nil {
		return false
	}
	bf, e := socketFDs(broker.PID)
	if e != nil {
		return false
	}
	peers, e := unixPeers()
	if e != nil {
		return false
	}
	for fd := range cf {
		if bf[peers[fd]] && peers[peers[fd]] == fd {
			return true
		}
	}
	return false
}

// Candidates still pass the ordinary configured runtime executable validation.
// A name or prefix only narrows this bounded search; the Unix peer proves the
// client belongs to the candidate server generation.
func directBrokerCandidates(a Attribution) []Process {
	if !directUnresolved(a) {
		return nil
	}
	client := a.Owners[0]
	entries, e := os.ReadDir("/proc")
	if e != nil {
		return nil
	}
	var out []Process
	deadline := time.Now().Add(500 * time.Millisecond)
	for _, entry := range entries {
		if time.Now().After(deadline) {
			return nil
		}
		pid, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		exe := link("/proc/" + entry.Name() + "/exe")
		if filepath.Base(exe) != "wineserver" {
			continue
		}
		p, e := Inspect(pid)
		if e == nil && wineClientPeer(client, p) {
			out = append(out, p)
		}
	}
	return out
}

func (w *WineTable) resolveDirect(f Flow, a Attribution) Attribution {
	fail := func(code, reason string) Attribution {
		a.Application = nil
		a.Association = nil
		a.Status = "unidentified"
		a.setReason(code, reason)
		return a
	}
	broker := w.session.Broker
	if broker.PIDNS != link("/proc/self/ns/pid") || a.Owners[0].PIDNS != broker.PIDNS {
		return fail(ReasonRuntimeCapabilityUnavailable, "direct Wine process PID namespace is unsupported")
	}
	if w.requiredSchema != 3 || !w.processPIDContract(w.version) {
		return fail(ReasonRuntimeCapabilityUnavailable, "runtime process-image census capability unavailable")
	}
	if !w.session.current() || !wineClientPeer(a.Owners[0], broker) || !w.sameServer(&broker) {
		return fail(ReasonRuntimeEvidenceIncomplete, "direct Wine client/broker relationship unavailable")
	}
	first, e := w.snapshotFamily("process", 4)
	if e != nil {
		return fail(ReasonRuntimeCensusUnavailable, e.Error())
	}
	again := Resolve(f)
	second, e := w.snapshotFamily("process", 4)
	if e != nil {
		return fail(ReasonRuntimeCensusUnavailable, e.Error())
	}
	gate := "complete"
	valid := func() bool {
		if !directUnresolved(again) {
			gate = "fresh_direct_unresolved"
			return false
		}
		if fingerprint(a.Owners, a.Sockets) != fingerprint(again.Owners, again.Sockets) {
			gate = "socket_holder_fingerprint"
			return false
		}
		if !w.session.current() {
			gate = "session_generation"
			return false
		}
		if !wineClientPeer(again.Owners[0], broker) {
			gate = "client_peer"
			return false
		}
		if !w.sameServer(&broker) {
			gate = "helper_peer"
			return false
		}
		return true
	}()
	diagnostics.EvidenceKey(!valid, "direct:"+f.Key(), func() any {
		matching := func(s tableSnapshot) []WindowsOwner {
			var rows []WindowsOwner
			for _, r := range s.Rows {
				if r.UnixPID == a.Owners[0].PID {
					rows = append(rows, r)
				}
			}
			return rows
		}
		return map[string]any{"kind": "direct_bookends", "observation_only": true, "flow": f, "failed_gate": gate, "initial": diagnosticAttribution(a), "fresh": diagnosticAttribution(again), "first": diagnosticTable(first, matching(first)), "second": diagnosticTable(second, matching(second))}
	})
	if !valid {
		return fail(ReasonRuntimeOwnershipChanged, "direct Wine ownership changed during process census")
	}
	proof := func(p Process, path, revision string) bool {
		matches := wineTableImageVisible(p, path, revision, string(readBound(fmt.Sprintf("/proc/%d/maps", p.PID), 2<<20)))
		current, e := Inspect(p.PID)
		return matches && e == nil && current.Start == p.Start && current.UID == p.UID && current.NetNS == p.NetNS && current.MountNS == p.MountNS && current.ExecutableRevision == p.ExecutableRevision && current.Application.Prefix == p.Application.Prefix
	}
	return w.finishDirectCensus(a, again, broker, first, second, proof)
}

func (w *WineTable) finishDirectCensus(a, again Attribution, broker Process, first, second tableSnapshot, proof func(Process, string, string) bool) Attribution {
	a.Application = nil
	a.Association = nil
	a.Status = "unidentified"
	a.setReason(ReasonRuntimeIdentityUnverified, "direct Wine runtime image not uniquely corroborated")
	if !directUnresolved(a) || !directUnresolved(again) || first.Schema != 3 || second.Schema != 3 || first.Kind != "process-images" || second.Kind != "process-images" || !first.Complete || !second.Complete || first.Error != 0 || second.Error != 0 || first.Version != second.Version || !w.processPIDContract(first.Version) || fingerprint(a.Owners, a.Sockets) != fingerprint(again.Owners, again.Sockets) {
		return a
	}
	p := a.Owners[0]
	if p.PIDNS != broker.PIDNS || p.PIDNS != link("/proc/self/ns/pid") || p.UID != broker.UID || p.NetNS != broker.NetNS || p.MountNS != broker.MountNS || p.Application.Prefix != w.prefix || broker.Application.Prefix != w.prefix {
		return a
	}
	var chosen *Application
	var holder WindowsOwner
	for _, row := range first.Rows {
		if row.PID == 0 || row.Created == 0 || row.Image == "" || row.UnixPID <= 0 {
			return a
		}
		if row.UnixPID != p.PID {
			continue
		}
		win := strings.ReplaceAll(row.Image, "\\", "/")
		if len(win) < 3 || win[1] != ':' || win[2] != '/' {
			continue
		}
		path, e := filepath.EvalSymlinks(filepath.Join(w.prefix, "dosdevices", strings.ToLower(win[:1])+":", win[3:]))
		if e != nil {
			continue
		}
		revision := stamp(path)
		if revision == "" || !proof(p, path, revision) || !proof(again.Owners[0], path, revision) {
			continue
		}
		// The same Windows PID/creation/image must survive the kernel census.
		stable := false
		for _, end := range second.Rows {
			if row == end {
				stable = true
				break
			}
		}
		if !stable {
			return a
		}
		if chosen != nil {
			return a
		}
		app := Application{Kind: "wine", Name: filepath.Base(path), Executable: path, Revision: revision, Prefix: w.prefix, Runtime: w.broker, Evidence: []string{"runtime Unix PID, process image and creation time in two fresh censuses", "exact mapped PE header and section file identity in the sole Linux socket owner", "pinned same-user same-prefix Wine server Unix peer"}}
		app.Key = ApplicationKey(p.UID, app)
		app.DisplayName = app.Name + " · via Wine"
		chosen = &app
		holder = row
	}
	if chosen == nil {
		return a
	}
	count := 0
	for _, row := range second.Rows {
		if row.PID == 0 || row.Created == 0 || row.Image == "" || row.UnixPID <= 0 {
			return a
		}
		if row.UnixPID != p.PID {
			continue
		}
		win := strings.ReplaceAll(row.Image, "\\", "/")
		if len(win) < 3 || win[1] != ':' || win[2] != '/' {
			continue
		}
		path, e := filepath.EvalSymlinks(filepath.Join(w.prefix, "dosdevices", strings.ToLower(win[:1])+":", win[3:]))
		if e != nil {
			continue
		}
		revision := stamp(path)
		if row == holder && (path != chosen.Executable || revision != chosen.Revision) {
			return a
		}
		if revision != "" && proof(again.Owners[0], path, revision) {
			if row != holder {
				return a
			}
			count++
		}
	}
	if count != 1 {
		return a
	}
	holder.CreationTime = strconv.FormatUint(holder.Created, 10)
	a.Application = chosen
	a.Status = "corroborated-runtime-table"
	a.setReason(ReasonRuntimeOwnerObserved, "sole Linux socket owner corroborated by stable runtime process image and mapped PE file")
	a.Table = &TableEvidence{DirectPID: p.PID, DirectStart: p.Start, Runtime: first.Version, Prefix: w.prefix, BrokerPID: broker.PID, BrokerStart: broker.Start, UID: broker.UID, SocketCookie: a.Sockets[0].Cookie, Owners: []WindowsOwner{holder}, Generation: w.generation, Method: "direct Linux socket owner; two runtime process-image censuses bookending fresh kernel ownership, mapped PE identity and broker Unix peer"}
	b, _ := json.Marshal(a.Table)
	a.Fingerprint = digest(fingerprint(a.Owners, a.Sockets) + string(b) + chosen.Revision)
	return a
}
