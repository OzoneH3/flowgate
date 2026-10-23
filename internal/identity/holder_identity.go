package identity

// Turn fresh descriptor observations into process candidates. A file-table
// class is not an identity class: every member's actual credentials, namespaces,
// executable and generation must agree before selecting a representative.
import (
	"encoding/json"
	"fmt"
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
	base := fmt.Sprintf("/proc/%d/task/%d", h.TGID, m.TID)
	start, _, err := processStat(base)
	if err != nil || start != m.Start {
		return holderTaskFacts{}, fmt.Errorf("holder generation changed")
	}
	f := holderTaskFacts{Start: start, Exe: link(base + "/exe"), Revision: stamp(base + "/exe"), NetNS: link(base + "/ns/net"), MountNS: link(base + "/ns/mnt"), PIDNS: link(base + "/ns/pid")}
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
	Owners       map[string][]Process
	Complete     bool
	Issues       []string
	SocketIssues map[string]string
	Unavailable  int
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
	failedTasks := map[int]bool{}
	failSocket := func(h Holder, code string) {
		fail(code)
		out.SocketIssues[h.Socket] = code
		for _, m := range h.Members {
			failedTasks[m.TID] = true
		}
		out.Unavailable = len(failedTasks)
	}
	classes := map[string][]inspectedHolder{}
	for _, h := range c.Holders {
		if late() {
			fail("time_limit")
			return out
		}
		if len(h.Members) == 0 || (!h.Proven && len(h.Members) > 1) {
			failSocket(h, "holder_members_unproven")
			continue
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
		classes[h.Socket] = append(classes[h.Socket], inspectedHolder{h, f, p})
	}
	if late() {
		fail("time_limit")
		return out
	}
	// Recheck failures are local where the census can name the changed group.
	// Unknown completeness keeps locally read metadata but cannot advertise an
	// application association or authorize any Resolve result.
	detail := recheck()
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
