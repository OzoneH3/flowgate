package identity

// Turn fresh descriptor observations into process candidates. A file-table
// class is not an identity class: every member's actual credentials, namespaces,
// executable and generation must agree before selecting a representative.
import (
	"encoding/json"
	diagnostics "flowgate/internal/serveprofile"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
)

type holderTaskFacts struct {
	Group                 int
	Start, Exe, Revision  string
	NetNS, MountNS, PIDNS string
	Credentials           string
	UID                   uint32
}

func (f holderTaskFacts) sameIdentity(g holderTaskFacts) bool {
	f.Start, g.Start = "", ""
	return f == g
}

func readHolderFacts(h Holder, m HolderMember) (holderTaskFacts, error) {
	defer diagnostics.Begin(diagnostics.ProcessFacts).End()
	base := fmt.Sprintf("/proc/%d/task/%d", h.TGID, m.TID)
	start, _, err := processStat(base)
	if err != nil || start != m.Start {
		return holderTaskFacts{}, fmt.Errorf("holder generation changed")
	}
	f := holderTaskFacts{Start: start, Exe: link(base + "/exe"), NetNS: link(base + "/ns/net"), MountNS: link(base + "/ns/mnt"), PIDNS: link(base + "/ns/pid")}
	if st, err := executableStat(base + "/exe"); err == nil {
		f.Revision = statStamp(st)
	}
	status := readBound(base+"/status", 65537)
	if len(status) == 0 || len(status) > 65536 || strings.Contains(string(status), "State:\tZ") {
		return f, fmt.Errorf("holder status unavailable")
	}
	var uid, gid, groups string
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "Tgid:":
			if len(fields) == 2 {
				f.Group, _ = strconv.Atoi(fields[1])
			}
		case "Uid:", "Gid:":
			if len(fields) != 5 {
				return f, fmt.Errorf("holder credentials incomplete")
			}
			for i, value := range fields[1:] {
				n, e := strconv.ParseUint(value, 10, 32)
				if e != nil {
					return f, fmt.Errorf("holder credentials malformed")
				}
				if fields[0] == "Uid:" && i == 1 {
					f.UID = uint32(n)
				}
			}
			if fields[0] == "Uid:" {
				uid = strings.Join(fields[1:], ":")
			} else {
				gid = strings.Join(fields[1:], ":")
			}
		case "Groups:":
			for _, value := range fields[1:] {
				if _, e := strconv.ParseUint(value, 10, 32); e != nil {
					return f, fmt.Errorf("holder groups malformed")
				}
			}
			groups = "groups:" + strings.Join(fields[1:], ":")
		}
	}
	f.Credentials = uid + "/" + gid + "/" + groups
	if f.Group != h.TGID || uid == "" || gid == "" || groups == "" || f.Exe == "" || f.Revision == "" || f.NetNS == "" || f.MountNS == "" || f.PIDNS == "" {
		return f, fmt.Errorf("holder identity incomplete")
	}
	end, _, e := processStat(base)
	if e != nil || end != start {
		return f, fmt.Errorf("holder generation changed")
	}
	return f, nil
}

type inspectedHolder struct {
	holder  Holder
	facts   holderTaskFacts
	process Process
}

type holderIdentities struct {
	diagnosticAttempts    int
	diagnosticFirstIssues []string
	Owners                map[string][]Process
	Complete              bool
	Issues                []string
	SocketIssues          map[string]string
	Unavailable           int
	// Reconciled counts holders whose task set changed within the same inspected
	// table and passed full re-verification (every current member re-read twice,
	// runtime classification re-run, descriptor and topology rechecked).
	Reconciled    int
	retryTopology bool
}

// inspectHolderIdentities verifies every member with cheap raw proc facts,
// then runs full application inspection once per proven file table. It does
// not reread multi-megabyte mappings for every thread in the same table.
func inspectHolderIdentities(c HolderCensus, inspect func(int) (Process, error)) holderIdentities {
	return inspectHolderIdentitiesWith(c, inspect, readHolderFacts, func(path, socket string) bool {
		target, err := os.Readlink(path)
		return err == nil && target == socket
	}, c.RecheckDetail)
}

// A proven descriptor-table class is identified only within this immutable
// census. Reuse below is native-only, never shared across snapshots or processes.
type holderInspectionKey struct {
	group        int
	start        string
	leaderExited bool
	first        HolderMember
}

func inspectionKey(h Holder) holderInspectionKey {
	return holderInspectionKey{h.TGID, h.GroupStart, h.LeaderExited, h.Members[0]}
}

type nativeHolderInspection struct {
	invalid  bool
	selected holderTaskFacts
	holder   Holder
	before   []holderTaskFacts
	process  Process
	holders  []Holder
}

func inspectHolderIdentitiesWith(c HolderCensus, inspect func(int) (Process, error), facts func(Holder, HolderMember) (holderTaskFacts, error), descriptor func(string, string) bool, recheck func() HolderRecheck) holderIdentities {
	out := holderIdentities{Owners: map[string][]Process{}, Complete: c.Complete, Issues: append([]string(nil), c.Issues...), SocketIssues: map[string]string{}}
	for socket, codes := range c.SocketIssues {
		out.SocketIssues[socket] = strings.Join(codes, ";")
	}
	fail := func(code string) {
		out.Complete = false
		if !slices.Contains(out.Issues, code) && len(out.Issues) < 16 {
			out.Issues = append(out.Issues, code)
		}
	}
	late := func() bool { return c.src.late() }
	identityFailed := false
	failedTasks := map[int]bool{}
	failSocket := func(h Holder, code string) {
		identityFailed = true
		fail(code)
		out.SocketIssues[h.Socket] = code
		for _, m := range h.Members {
			failedTasks[m.TID] = true
		}
		out.Unavailable = len(failedTasks)
	}
	classes := map[string][]inspectedHolder{}
	native := map[holderInspectionKey]*nativeHolderInspection{}
	for _, h := range c.Holders {
		if late() {
			fail("time_limit")
			return out
		}
		if len(h.Members) == 0 || (!h.Proven && len(h.Members) > 1) {
			failSocket(h, "holder_members_unproven")
			continue
		}
		if h.Proven {
			if old := native[inspectionKey(h)]; old != nil {
				if !slices.Equal(old.holder.Members, h.Members) {
					old.invalid = true
					failSocket(h, "holder_members_changed")
					continue
				}
				// Every descriptor is still checked. All member identities are
				// bookended again below, after the last associated socket.
				if !descriptor(h.FDPath, h.Socket) {
					failSocket(h, "holder_inspection_changed")
					continue
				}
				old.holders = append(old.holders, h)
				classes[h.Socket] = append(classes[h.Socket], inspectedHolder{h, old.selected, old.process})
				continue
			}
		}
		before := make([]holderTaskFacts, len(h.Members))
		valid := true
		choice := 0
		for i, m := range h.Members {
			if late() {
				fail("time_limit")
				return out
			}
			f, err := facts(h, m)
			if err != nil || f.Group != h.TGID || f.Start != m.Start {
				valid = false
				break
			}
			before[i] = f
			if i > 0 && !f.sameIdentity(before[0]) {
				valid = false
				break
			}
			if m.TID == h.TGID {
				choice = i
			}
		}
		if !valid {
			failSocket(h, "holder_identity_ambiguous")
			continue
		}
		if late() {
			fail("time_limit")
			return out
		}
		p, err := inspect(h.Members[choice].TID)
		f := before[choice]
		if err != nil || p.PID != h.Members[choice].TID || p.ThreadGroup != h.TGID || p.Start != f.Start || p.UID != f.UID || p.Executable != f.Exe || p.ExecutableRevision != f.Revision || p.NetNS != f.NetNS || p.MountNS != f.MountNS || p.PIDNS != f.PIDNS || p.BootID == "" {
			failSocket(h, "holder_inspection_changed")
			continue
		}
		for i, m := range h.Members {
			if late() {
				fail("time_limit")
				return out
			}
			after, e := facts(h, m)
			if e != nil || after != before[i] {
				valid = false
				break
			}
		}
		if !valid || !descriptor(h.FDPath, h.Socket) {
			failSocket(h, "holder_inspection_changed")
			continue
		}
		// Keep existing non-native live-leader support, without extending runtime
		// authority to worker-only descriptors or merging separate runtime tables.
		if p.PID != p.ThreadGroup && !exactNativeHolder(p) {
			failSocket(h, "runtime_worker_unverified")
			continue
		}
		if h.Proven && exactNativeHolder(p) {
			copyHolder := h
			copyHolder.Members = slices.Clone(h.Members)
			native[inspectionKey(h)] = &nativeHolderInspection{holder: copyHolder, before: before, process: p, selected: f, holders: []Holder{h}}
		}
		classes[h.Socket] = append(classes[h.Socket], inspectedHolder{h, f, p})
	}
	if late() {
		fail("time_limit")
		return out
	}
	// A changed native member withdraws every socket that shared its inspection,
	// including the first. RecheckDetail still verifies topology and every FD.
	for key, entry := range native {
		if len(entry.holders) == 1 && !entry.invalid {
			continue
		} // unchanged single-socket path
		valid := !entry.invalid
		if late() {
			fail("time_limit")
			return out
		}
		// Also re-inspect runtime classification once at the far bookend. Raw
		// executable facts alone cannot detect a process loading a runtime.
		current, err := inspect(entry.process.PID)
		if err != nil || !exactNativeHolder(current) || current.ThreadGroup != entry.process.ThreadGroup || current.Application.Prefix != entry.process.Application.Prefix || fingerprint([]Process{current}, nil) != fingerprint([]Process{entry.process}, nil) {
			valid = false
		}
		for i, m := range entry.holder.Members {
			if late() {
				fail("time_limit")
				return out
			}
			after, err := facts(entry.holder, m)
			if err != nil || after != entry.before[i] {
				valid = false
				break
			}
		}
		if valid {
			continue
		}
		for _, h := range entry.holders {
			failSocket(h, "holder_inspection_changed")
			rows := classes[h.Socket][:0]
			for _, candidate := range classes[h.Socket] {
				if !candidate.holder.Proven || inspectionKey(candidate.holder) != key {
					rows = append(rows, candidate)
				}
			}
			classes[h.Socket] = rows
		}
	}
	// Recheck failures are local where the census can name the changed group.
	// Unknown completeness keeps locally read metadata but cannot advertise an
	// application association or authorize any Resolve result.
	identityClean := !identityFailed
	detail := recheck()
	out.retryTopology = identityClean && retryableHolderTopology(c, detail)
	if detail.Err != nil {
		fail("holder_census_incomplete")
		for socket := range classes {
			out.SocketIssues[socket] = "holder_census_incomplete"
		}
	}
	if len(detail.Groups) != 0 {
		fail("holder_groups_changed")
	}
	for socket, hs := range classes {
		kept := hs[:0]
		for _, h := range hs {
			if code, failed := detail.Groups[h.holder.TGID]; failed {
				failSocket(h.holder, code)
			} else {
				kept = append(kept, h)
			}
		}
		classes[socket] = kept
	}
	// Same-table membership churn: re-verify the fresh task set completely, per
	// group and atomically, under the census deadline. Any failure withdraws
	// every holder of that group. Nothing is accepted on topology alone.
	// Retry aggregation is monotonic across every group: one identity or I/O
	// failure makes the whole attempt terminal, whatever other groups report.
	reconcileFailed, reconcileTopologyOnly := false, true
	for _, tgid := range slices.Sorted(maps.Keys(detail.Reconcilable)) {
		code, staged := reconcileHolderChurn(tgid, detail, classes, inspect, facts, descriptor, late)
		if code == "" {
			for _, s := range staged {
				e := classes[s.socket][s.index]
				if n := native[inspectionKey(e.holder)]; n != nil {
					n.holder.Members = slices.Clone(s.holder.Members)
					n.before = s.first
				}
				if !slices.Equal(e.holder.Members, s.holder.Members) {
					out.Reconciled++
				}
				e.holder = s.holder
				classes[s.socket][s.index] = e
			}
			continue
		}
		reconcileFailed = true
		if !holderTopologyChange(code) {
			reconcileTopologyOnly = false
		}
		for socket, hs := range classes {
			kept := hs[:0]
			for _, h := range hs {
				if h.holder.TGID == tgid && h.holder.Proven {
					failSocket(h.holder, code)
				} else {
					kept = append(kept, h)
				}
			}
			classes[socket] = kept
		}
		for _, h := range detail.Reconcilable[tgid] {
			failSocket(h, code)
		}
	}
	if reconcileFailed {
		// A failed re-verification is retryable only when every failure was a
		// plain topology change of an otherwise clean census; any identity or
		// visibility failure in any group is terminal.
		out.retryTopology = identityClean && reconcileTopologyOnly && retryableHolderTopology(c, detail)
	}
	for _, socket := range detail.Appeared {
		fail("holder_appeared")
		out.SocketIssues[socket] = "holder_appeared"
	}
	for socket, hs := range classes {
		groups := map[int][]inspectedHolder{}
		for _, h := range hs {
			groups[h.holder.TGID] = append(groups[h.holder.TGID], h)
		}
		for _, group := range groups {
			first := group[0]
			merge := len(group) == 1
			if len(group) > 1 {
				merge = true
				for _, h := range group {
					if !h.holder.Proven || h.holder.GroupStart != first.holder.GroupStart || !h.facts.sameIdentity(first.facts) || !exactNativeHolder(h.process) || h.process.Application.Key != first.process.Application.Key || h.process.Application.Revision != first.process.Application.Revision {
						merge = false
						break
					}
				}
			}
			if merge {
				out.Owners[socket] = append(out.Owners[socket], holderRepresentative(group))
			} else {
				for _, h := range group {
					out.Owners[socket] = append(out.Owners[socket], holderRepresentative([]inspectedHolder{h}))
				}
			}
		}
		slices.SortFunc(out.Owners[socket], func(a, b Process) int { return a.PID - b.PID })
	}
	return out
}

// stagedHolder is a fully re-verified replacement for one inspected holder,
// applied only if every holder of its group passed.
type stagedHolder struct {
	socket string
	index  int
	holder Holder
	first  []holderTaskFacts
}

// reconcileHolderChurn re-verifies one group's fresh holders against the
// holders inspected earlier. Fresh holders are grouped by table class
// (representative task): identity is re-established once per class, exactly as
// the first inspection did, then every holder's descriptor is re-read, then the
// class is bookended again. Each fresh holder must map to an inspected, proven,
// exact-native holder of the same table and socket whose inspection all holders
// of the class share; every current member is read and compared with the
// inspected identity and with the census generation of surviving tasks; the
// inspected task is re-classified at its original generation; every member is
// read again; finally the fresh group's topology is rechecked. It returns ""
// with the staged replacements only when all of that passed; otherwise the
// code that fails the whole group. The census deadline bounds every step;
// nothing is retried here.
func reconcileHolderChurn(tgid int, detail HolderRecheck, classes map[string][]inspectedHolder, inspect func(int) (Process, error), facts func(Holder, HolderMember) (holderTaskFacts, error), descriptor func(string, string) bool, late func() bool) (string, []stagedHolder) {
	verify := detail.verify[tgid]
	if detail.Err != nil || verify == nil {
		return "membership_changed", nil
	}
	type tableClass struct {
		rep     int
		holders []Holder
	}
	var order []int
	byRep := map[int]*tableClass{}
	for _, fh := range detail.Reconcilable[tgid] {
		rep, ok := holderRep(fh)
		if !ok || !fh.Proven || fh.LeaderExited || fh.TGID != tgid || len(fh.Members) == 0 {
			return "membership_changed", nil
		}
		c := byRep[rep]
		if c == nil {
			c = &tableClass{rep: rep}
			byRep[rep] = c
			order = append(order, rep)
		}
		c.holders = append(c.holders, fh)
	}
	var staged []stagedHolder
	for _, rep := range order {
		cl := byRep[rep]
		if late() {
			return "time_limit", nil
		}
		// Every fresh holder of the class must map to an inspected holder of the
		// same table, and those inspected holders must share one inspection.
		var ref *inspectedHolder
		indexes := make([]int, len(cl.holders))
		for i, fh := range cl.holders {
			if !slices.Equal(fh.Members, cl.holders[0].Members) {
				return "membership_changed", nil
			}
			indexes[i] = -1
			for j, h := range classes[fh.Socket] {
				if h.holder.TGID != tgid || !h.holder.Proven || h.holder.GroupStart != fh.GroupStart {
					continue
				}
				if r, ok := holderRep(h.holder); ok && r == rep {
					indexes[i] = j
					break
				}
			}
			if indexes[i] < 0 {
				return "membership_changed", nil
			}
			e := classes[fh.Socket][indexes[i]]
			if ref == nil {
				ref = &e
			} else if e.process.PID != ref.process.PID || e.process.Start != ref.process.Start || !e.facts.sameIdentity(ref.facts) || !slices.Equal(e.holder.Members, ref.holder.Members) {
				return "holder_inspection_changed", nil
			}
		}
		entry := *ref
		if !exactNativeHolder(entry.process) || entry.process.ThreadGroup != tgid {
			return "runtime_worker_unverified", nil
		}
		members := cl.holders[0].Members
		survivors := map[int]string{}
		for _, m := range entry.holder.Members {
			survivors[m.TID] = m.Start
		}
		inspected := false
		first := make([]holderTaskFacts, len(members))
		for i, m := range members {
			if late() {
				return "time_limit", nil
			}
			// A surviving TID must keep its census generation: no TID reuse.
			if start, known := survivors[m.TID]; known && start != m.Start {
				return "holder_inspection_changed", nil
			}
			if m.TID == entry.process.PID {
				if m.Start != entry.process.Start {
					return "holder_inspection_changed", nil
				}
				inspected = true
			}
			f, err := facts(cl.holders[0], m)
			if err != nil || f.Group != tgid || f.Start != m.Start {
				return "holder_inspection_changed", nil
			}
			if !f.sameIdentity(entry.facts) {
				return "holder_identity_ambiguous", nil
			}
			first[i] = f
		}
		if !inspected {
			// The task whose full inspection stands for this table must still be
			// a member; otherwise this is a different inspection, not churn.
			return "holder_inspection_changed", nil
		}
		if late() {
			return "time_limit", nil
		}
		// Runtime classification bookend on the originally inspected task,
		// compared before any witness is derived from the new member set.
		original := entry.process
		original.HolderWitness = ""
		current, err := inspect(original.PID)
		if err != nil {
			return "holder_inspection_changed", nil
		}
		current.HolderWitness = ""
		if !exactNativeHolder(current) || current.PID != original.PID || current.ThreadGroup != tgid || current.Start != original.Start || current.Application.Prefix != original.Application.Prefix || fingerprint([]Process{current}, nil) != fingerprint([]Process{original}, nil) {
			return "holder_inspection_changed", nil
		}
		// Per-descriptor checks for every socket of the class.
		for _, fh := range cl.holders {
			if late() {
				return "time_limit", nil
			}
			if !descriptor(fh.FDPath, fh.Socket) {
				return "holder_inspection_changed", nil
			}
		}
		// Final bookend of the whole class after the descriptors were read.
		for i, m := range members {
			if late() {
				return "time_limit", nil
			}
			after, err := facts(cl.holders[0], m)
			if err != nil || after != first[i] {
				return "holder_inspection_changed", nil
			}
		}
		for i, fh := range cl.holders {
			staged = append(staged, stagedHolder{fh.Socket, indexes[i], fh, first})
		}
	}
	if late() {
		return "time_limit", nil
	}
	if err := verify(); err != nil {
		return err.Error(), nil
	}
	return "", staged
}

func exactNativeHolder(p Process) bool {
	return p.Application.Kind == "native" && p.Application.Executable == p.Executable && p.Application.Revision == p.ExecutableRevision && RuntimeRuleBlocked(&p.Application) == "" && LiveRuleable(p.Application)
}

func holderRepresentative(group []inspectedHolder) Process {
	p := group[0].process
	var members []HolderMember
	for _, h := range group {
		if h.process.PID == h.holder.TGID || (p.PID != h.holder.TGID && h.process.PID < p.PID) {
			p = h.process
		}
		members = append(members, h.holder.Members...)
	}
	if p.PID != p.ThreadGroup || len(group) > 1 {
		slices.SortFunc(members, func(a, b HolderMember) int { return a.TID - b.TID })
		b, _ := json.Marshal(struct {
			Group              int
			Start, Credentials string
			Members            []HolderMember
		}{p.ThreadGroup, group[0].holder.GroupStart, group[0].facts.Credentials, members})
		p.HolderWitness = digest(string(b))
	}
	return p
}
