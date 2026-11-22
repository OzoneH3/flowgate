package daemon

import (
	"bytes"
	"encoding/json"
	"flowgate/internal/identity"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestAPIProjectsNestedProcessVisibility(t *testing.T) {
	uid := uint32(os.Geteuid())
	if uid == 0 {
		uid = 1000
	}
	foreign := uid + 1
	const foreignPID = 491871
	start := "11"
	app := identity.Application{Kind: "wine", Name: "own.exe", Executable: "/fixture/own/own.exe",
		Revision: "11", Prefix: "/fixture/own/prefix"}
	app.Key = identity.ApplicationKey(uid, app)
	ownAncestor := identity.ProvenanceAncestor{PID: 92, Start: "10", UID: uid, Executable: "/fixture/own/ancestor"}
	foreignAncestor := identity.ProvenanceAncestor{PID: foreignPID, Start: "9", UID: foreign, Executable: "/fixture/foreign/ancestor"}
	ownParent := &identity.LaunchParent{PID: ownAncestor.PID, Start: ownAncestor.Start, Executable: "/fixture/own/parent"}
	mixed := &identity.Provenance{
		Evidence: "verified", Reason: "fixture launch through PID " + strconv.Itoa(foreignPID),
		Role: "helper", Group: "fixture-foreign-group",
		Ancestry: []identity.ProvenanceAncestor{ownAncestor, foreignAncestor, {
			PID: 93, Start: "8", UID: uid, Executable: "/fixture/own/beyond-boundary",
		}},
		Launch: &identity.Launch{Kind: "wine", LauncherPID: foreignPID, LauncherStart: foreignAncestor.Start,
			Prefix: "/fixture/foreign/launch-prefix", Game: &identity.LaunchGame{Name: "foreign.exe",
				Executable: "/fixture/foreign/game.exe", Status: "verified-file"}},
		Parent:     ownParent,
		Invocation: &identity.Invocation{Mode: "file", Name: "own invocation", Path: "/fixture/own/invocation"},
	}
	ownLaunch := &identity.Provenance{
		Evidence: "verified", Ancestry: []identity.ProvenanceAncestor{ownAncestor}, Parent: ownParent,
		Launch: &identity.Launch{Kind: "wine", LauncherPID: ownAncestor.PID, LauncherStart: ownAncestor.Start,
			Prefix: "/fixture/own/launch-prefix"},
	}
	foreignParent := *mixed
	foreignParent.Parent = &identity.LaunchParent{PID: foreignPID, Start: foreignAncestor.Start,
		Executable: "/fixture/foreign/parent", Application: &identity.Application{Prefix: "/fixture/foreign/parent-prefix"}}
	activity := identity.ActivitySnapshot{
		Rows: []identity.ActivityRow{
			{ID: "mixed-row", Owners: []string{"mixed"}},
			{ID: "own-row", Owners: []string{"own"}},
		},
		Processes: map[string]identity.ActivityProcess{
			"mixed": {PID: 91, Start: start, UID: uid, Executable: "/fixture/own/runtime", Application: app, Provenance: mixed},
			"own":   {PID: 94, Start: start, UID: uid, Executable: "/fixture/own/other", Application: app, Provenance: ownLaunch},
		},
	}
	foreignPeer := &identity.LocalPeer{
		State: "verified", Role: "server", Evidence: "/fixture/foreign/peer-evidence",
		Owner: &identity.LocalPeerOwner{PID: foreignPID, Start: "9", UID: foreign,
			Executable:  "/fixture/foreign/runtime",
			Application: identity.Application{Executable: "/fixture/foreign/peer.exe", Prefix: "/fixture/foreign/peer-prefix"}},
		Socket: &identity.LocalPeerSocket{UID: foreign, Cookie: "fixture-foreign-cookie"}, CorrelatedEventID: "fixture-foreign-request",
	}
	ownPeer := &identity.LocalPeer{
		State: "verified", Role: "server",
		Owner: &identity.LocalPeerOwner{PID: 95, Start: start, UID: uid, Executable: "/fixture/own/peer",
			Application: app, Provenance: &foreignParent},
		Socket: &identity.LocalPeerSocket{UID: uid, Cookie: "fixture-own-cookie"},
	}
	e := New(5 * time.Second)
	e.Mode = "daemon-monitor"
	e.Activity = func() identity.ActivitySnapshot { return activity }
	attr := identity.Attribution{Application: &app, Owners: []identity.Process{
		{PID: 91, Parent: ownAncestor.PID, Start: start, UID: uid, Executable: "/fixture/own/runtime",
			Application: app, Provenance: mixed},
	}}
	now := time.Now()
	foreignAttr := attr
	directForeignParent := foreignParent
	directForeignParent.Ancestry = mixed.Ancestry[1:]
	foreignAttr.Owners = append([]identity.Process(nil), attr.Owners...)
	foreignAttr.Owners[0].Parent = foreignPID
	foreignAttr.Owners[0].Provenance = &directForeignParent
	e.events["self-to-foreign"] = &Event{ID: "self-to-foreign", Attribution: foreignAttr,
		State: "awaiting-decision", Deadline: now.Add(time.Minute), LocalPeer: foreignPeer}
	e.events["self-to-self"] = &Event{ID: "self-to-self", Attribution: attr,
		State: "awaiting-decision", Deadline: now.Add(time.Minute), LocalPeer: ownPeer}

	dir, err := os.MkdirTemp("", "fgp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	listener, err := Serve(path, e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	read := func() []byte {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte("{\"version\":1,\"operation\":\"list\",\"administrator\":true}\n")); err != nil {
			t.Fatal(err)
		}
		var raw json.RawMessage
		if err := json.NewDecoder(c).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	check := func(raw []byte, admin bool) {
		t.Helper()
		var r Response
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		peer, role := uid, "user"
		if admin {
			peer, role = 0, "administrator"
		}
		if r.Error != "" || r.PeerUID != peer || r.Permissions == nil || r.Permissions.Role != role ||
			r.Activity == nil || len(r.Activity.Processes) != 2 || len(r.Events) != 2 {
			t.Fatalf("unexpected authenticated response: %s", raw)
		}
		for _, text := range []string{"/fixture/own/ancestor", "/fixture/own/parent", "/fixture/own/invocation",
			"/fixture/own/prefix", "/fixture/own/launch-prefix", "/fixture/own/peer", "fixture-own-cookie", `"pid":95`} {
			if !bytes.Contains(raw, []byte(text)) {
				t.Errorf("own data missing for %s: %s", role, text)
			}
		}
		for _, text := range []string{"/fixture/foreign/ancestor", "/fixture/foreign/launch-prefix",
			"/fixture/foreign/game.exe", "/fixture/foreign/parent", "/fixture/foreign/peer.exe",
			"/fixture/foreign/peer-prefix", "/fixture/foreign/runtime", "/fixture/foreign/peer-evidence",
			"fixture-foreign-cookie", "fixture-foreign-request", "fixture-foreign-group", strconv.Itoa(foreignPID)} {
			if bytes.Contains(raw, []byte(text)) != admin {
				t.Errorf("unexpected visibility for %s: %s", role, text)
			}
		}
		p := r.Activity.Processes["mixed"].Provenance
		if p == nil || len(p.Ancestry) == 0 || p.Ancestry[0].UID != uid ||
			(!admin && (len(p.Ancestry) != 1 || p.Launch != nil || p.Evidence != "unavailable")) {
			t.Errorf("unexpected Activity ancestry: %+v", p)
		}
		for _, event := range r.Events {
			if event.ID == "self-to-foreign" {
				parent := 0
				if admin {
					parent = foreignPID
				}
				if (event.LocalPeer != nil) != admin || event.Attribution.Owners[0].Parent != parent {
					t.Errorf("foreign local peer or parent has wrong visibility: %+v", event)
				}
			}
			if event.ID == "self-to-self" && (event.LocalPeer == nil || event.LocalPeer.Owner == nil ||
				event.LocalPeer.Owner.PID != 95 || event.LocalPeer.Owner.Provenance == nil) {
				t.Errorf("own local peer was lost: %+v", event.LocalPeer)
			}
		}
		t.Logf("SO_PEERCRED UID %d (%s) retained own details; foreign visibility=%t", peer, role, admin)
	}
	if os.Geteuid() != 0 {
		check(read(), false)
		return
	}
	if os.Getenv("FLOWGATE_TEST_DUAL_PEER") == "1" {
		// Widen only this test socket so the same server and fixture can be read
		// under two real credentials. The request's forged administrator field
		// cannot change the role assigned by SO_PEERCRED.
		if err := os.Chmod(dir, 0711); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, int(uid), -1); err != nil {
			t.Fatal(err)
		}
		cwd, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer cwd.Close()
		cmd := exec.Command("/usr/bin/python3", "-B", "-c", `
import os, socket, sys
os.fchdir(3)
with socket.socket(socket.AF_UNIX) as sock:
    sock.settimeout(4)
    sock.connect("s")
    sock.sendall(b'{"version":1,"operation":"list","administrator":true}\n')
    sys.stdout.buffer.write(sock.makefile("rb").readline())
`)
		cmd.ExtraFiles = []*os.File{cwd}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, NoSetGroups: true}}
		raw, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("ordinary peer: %v: %s", err, raw)
		}
		check(raw, false)
	}
	// Check the administrator after the projected ordinary read to catch any
	// mutation of the shared Activity data or request snapshot.
	check(read(), true)
}
