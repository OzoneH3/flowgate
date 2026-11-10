package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flowgate/internal/identity"
	diagnostics "flowgate/internal/serveprofile"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestProfileRequestAuthorizationAndGeneration(t *testing.T) {
	e := New(0)
	e.Profiler = diagnostics.NewRecorder(context.Background(), func() any {
		t.Error("rejected request sampled engine state")
		return nil
	})
	defer e.Profiler.Close()
	for _, op := range []string{"profile-status", "profile-start", "profile-stop", "profile-fetch"} {
		for _, tc := range []struct {
			name       string
			admin, ro  bool
			generation string
			code       string
		}{
			{"ordinary", false, false, e.Generation, "forbidden"},
			{"ordinary-monitor", false, true, e.Generation, "forbidden"},
			{"administrator-monitor", true, true, e.Generation, "read_only"},
			{"missing-generation", true, false, "", "stale_generation"},
			{"stale-generation", true, false, "previous", "stale_generation"},
		} {
			t.Run(op+"/"+tc.name, func(t *testing.T) {
				var r Response
				e.profileRequest(Request{Operation: op, Generation: tc.generation, DurationSeconds: 5, ID: "private", ProfileArtifact: "cpu.pprof"}, tc.admin, tc.ro, &r)
				if r.ErrorCode != tc.code || r.Profile != nil || r.ProfileChunk != nil {
					t.Fatalf("private profile operation escaped authorization: %+v", r)
				}
			})
		}
	}
	if e.Profiler.Status().Active != nil {
		t.Fatal("rejected operation started capture")
	}
}

func TestProfileRequestUnavailable(t *testing.T) {
	e := New(0)
	for _, op := range []string{"profile-status", "profile-start", "profile-stop", "profile-fetch"} {
		var r Response
		e.profileRequest(Request{Operation: op, Generation: e.Generation}, true, false, &r)
		if r.ErrorCode != "profile_unavailable" || r.Profile != nil || r.ProfileChunk != nil {
			t.Fatalf("nil profiler changed API behavior: %+v", r)
		}
	}
}

func profileAPISocket(t *testing.T, e *Engine, readonly bool) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "p-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path, err := filepath.Abs(filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	l, err := Serve(path, e, readonly)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return path
}

func TestProfileAPIPrivateSocketContract(t *testing.T) {
	e := New(0)
	e.Profiler = diagnostics.NewRecorder(context.Background(), nil)
	defer e.Profiler.Close()
	for _, ro := range []bool{true, false} {
		path := profileAPISocket(t, e, ro)
		r, err := Call(path, Request{Version: 1, Operation: "profile-status", Generation: e.Generation})
		want := ""
		if os.Getuid() != 0 {
			want = "forbidden"
		} else if ro {
			want = "read_only"
		}
		if r.ErrorCode != want || (want == "") != (err == nil) {
			t.Fatalf("SO_PEERCRED/endpoint access mismatch: readonly=%v response=%+v err=%v", ro, r, err)
		}
		if slices.Contains(r.Capabilities, DaemonProfileCapability) != (want == "") {
			t.Fatal("profile capability does not match the authenticated endpoint")
		}
		if want != "" && (r.Profile != nil || r.ProfileChunk != nil) {
			t.Fatal("private profile state disclosed")
		}
	}
}

func TestProfileAPIClientCannotGrantAuthority(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("ordinary peer negative requires non-root UID")
	}
	e := New(0)
	e.Profiler = diagnostics.NewRecorder(context.Background(), nil)
	defer e.Profiler.Close()
	path := profileAPISocket(t, e, false)
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := json.NewEncoder(c).Encode(map[string]any{"version": 1, "operation": "profile-start", "generation": e.Generation, "duration_seconds": 5, "administrator": true, "uid": 0}); err != nil {
		t.Fatal(err)
	}
	var r Response
	if err := json.NewDecoder(c).Decode(&r); err != nil {
		t.Fatal(err)
	}
	if r.ErrorCode != "forbidden" || e.Profiler.Status().Active != nil || r.Profile != nil {
		t.Fatalf("request fields granted profiling authority: %+v", r)
	}
}

func TestProfileAPIActualCapture(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("administrator Unix-peer integration runs in an isolated root user namespace")
	}
	e := New(0)
	e.Profiler = diagnostics.NewRecorder(context.Background(), func() any { return map[string]string{"generation": e.Generation} })
	defer e.Profiler.Close()
	path := profileAPISocket(t, e, false)
	r, err := Call(path, Request{Version: 1, Operation: "profile-start", Generation: e.Generation, DurationSeconds: 5})
	if err != nil || r.Profile == nil || r.Profile.Active == nil || r.Profile.Active.ID == "" {
		t.Fatalf("capture not started: %+v %v", r, err)
	}
	id := r.Profile.Active.ID
	deadline := time.Now().Add(5 * time.Second)
	for r.Profile.Active != nil && r.Profile.Active.State != "running" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		r, err = Call(path, Request{Version: 1, Operation: "profile-status", Generation: e.Generation})
		if err != nil || r.Profile == nil {
			t.Fatal("capture status failed", r, err)
		}
	}
	if r.Profile.Active == nil || r.Profile.Active.State != "running" {
		t.Fatal("capture did not enter running state", r)
	}
	if r, err = Call(path, Request{Version: 1, Operation: "profile-stop", Generation: "old", ID: id}); err == nil || r.ErrorCode != "stale_generation" || e.Profiler.Status().Active == nil {
		t.Fatal("stale stop affected current capture", r, err)
	}
	r, err = Call(path, Request{Version: 1, Operation: "profile-stop", Generation: e.Generation, ID: id})
	if err != nil || r.Profile == nil {
		t.Fatal("capture stop failed", r, err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for r.Profile.Active != nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		r, err = Call(path, Request{Version: 1, Operation: "profile-status", Generation: e.Generation})
		if err != nil || r.Profile == nil {
			t.Fatal("capture completion status failed", r, err)
		}
	}
	if r.Profile.Active != nil || len(r.Profile.Recent) != 1 || r.Profile.Recent[0].ID != id || len(r.Profile.Recent[0].Artifacts) == 0 {
		t.Fatal("capture not retained", r, err)
	}
	if !slices.Contains(r.Profile.Recent[0].Artifacts, "summary.json") || !slices.Contains(r.Profile.Recent[0].Artifacts, "cpu.pprof") {
		t.Fatal("running capture omitted summary or CPU profile", r)
	}
	for _, artifact := range r.Profile.Recent[0].Artifacts {
		var data []byte
		var digest string
		for {
			fetched, err := Call(path, Request{Version: 1, Operation: "profile-fetch", Generation: e.Generation, ID: id, ProfileArtifact: artifact, ProfileOffset: int64(len(data))})
			if err != nil || fetched.ProfileChunk == nil || len(fetched.ProfileChunk.Data) == 0 {
				t.Fatal("artifact did not survive chunked JSON/base64 wire round trip", artifact, fetched, err)
			}
			chunk := fetched.ProfileChunk
			if chunk.Offset != int64(len(data)) || len(chunk.Data) > 256*1024 || chunk.Total < int64(len(data)+len(chunk.Data)) || (digest != "" && digest != chunk.SHA256) {
				t.Fatal("invalid chunk bounds or changing digest", chunk)
			}
			digest = chunk.SHA256
			data = append(data, chunk.Data...)
			if int64(len(data)) == chunk.Total {
				break
			}
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != digest {
			t.Fatal("artifact digest does not match decoded chunks")
		}
	}
	if r, err = Call(path, Request{Version: 1, Operation: "profile-fetch", Generation: e.Generation, ID: id, ProfileArtifact: "../cpu.pprof"}); err == nil || r.ErrorCode != "profile_failed" || r.ProfileChunk != nil {
		t.Fatal("artifact traversal accepted", r, err)
	}
}

func TestProfileOperationsDoNotRepublishPolicy(t *testing.T) {
	e := New(0)
	e.Now = func() time.Time { t.Fatal("profile operation invoked policy publication"); return time.Time{} }
	for _, operation := range []string{"profile-status", "profile-start", "profile-stop", "profile-fetch"} {
		if err := e.listReads.publishAfter(e, operation); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProfileSnapshotUsesPublishedAggregates(t *testing.T) {
	e := New(0)
	e.Now = func() time.Time { t.Fatal("profile invoked policy work"); return time.Time{} }
	e.Resolve = func(identity.Flow) identity.Attribution {
		t.Fatal("profile invoked attribution")
		return identity.Attribution{}
	}
	at := time.Now()
	e.listReads.published.Store(&publishedList{revision: "42", at: at, socketStatus: []byte(`{"entries":2,"fast_packets":75,"failure":{"not":"scalar"},"flows":[{"application":"private-app"}],"interface_coverage":{"private":"data"},"timelines":["private-timeline"]}`)})
	activityReads := 0
	e.Activity = func() identity.ActivitySnapshot {
		activityReads++
		return identity.ActivitySnapshot{Sequence: 12, Rows: []identity.ActivityRow{{ID: "private-socket"}}, Processes: map[string]identity.ActivityProcess{"private-id": {Executable: "private-exe"}}}
	}
	result := e.ProfileSnapshot()
	if result["snapshot_revision"] != "42" || result["snapshot_at"] != at || activityReads != 1 {
		t.Fatal("profile lost cached snapshot provenance", result)
	}
	gate := result["socket_authorization"].(map[string]any)
	if gate["flows_count"] != float64(2) || gate["fast_packets"] != float64(75) || gate["failure"] != nil {
		t.Fatal("profile gate counts invalid", gate)
	}
	activity := result["activity"].(map[string]any)
	if activity["rows"] != 1 || activity["processes"] != 1 || activity["sequence"] != uint64(12) {
		t.Fatal("profile activity summary invalid", activity)
	}
	encoded, err := json.Marshal(result)
	if err != nil || strings.Contains(string(encoded), "private-") || strings.Contains(string(encoded), "interface_coverage") || strings.Contains(string(encoded), "timelines") {
		t.Fatal("profile retained full identity/flow maps", string(encoded), err)
	}
}
