package identity_test

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Explicit opt-in real-runtime test, run in the disposable network namespace.
// Receiver bytes establish fixture execution, not FlowGate kernel enforcement.
func TestBestEffortElectronRealRuntime(t *testing.T) {
	runtime := os.Getenv("FLOWGATE_ELECTRON_RUNTIME")
	if runtime == "" {
		t.Skip("set FLOWGATE_ELECTRON_RUNTIME inside scripts/lab.sh")
	}
	if os.Getenv("FLOWGATE_PARENT_NETNS") == "" {
		t.Fatal("isolated namespace required")
	}
	var received atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1); fmt.Fprint(w, "fixture receiver") }))
	defer server.Close()
	makeApp := func(name string, asar bool) string {
		dir := t.TempDir()
		pkg, _ := json.Marshal(map[string]string{"name": name, "productName": "Synthetic " + name, "main": "main.js"})
		js := fmt.Sprintf(`const {app,net}=require('electron');app.whenReady().then(async()=>{await net.fetch(%q);console.log('READY');setInterval(()=>{},1000)});`, server.URL)
		if !asar {
			os.WriteFile(filepath.Join(dir, "package.json"), pkg, 0600)
			os.WriteFile(filepath.Join(dir, "entry.cjs"), []byte(js), 0600)
			return filepath.Join(dir, "entry.cjs")
		}
		index, _ := json.Marshal(map[string]any{"files": map[string]any{"package.json": map[string]any{"size": len(pkg), "offset": "0"}, "main.js": map[string]any{"size": len(js), "offset": fmt.Sprint(len(pkg))}}})
		padded := (len(index) + 4 + 3) &^ 3
		b := make([]byte, 16+((len(index)+3)&^3))
		binary.LittleEndian.PutUint32(b, 4)
		binary.LittleEndian.PutUint32(b[4:], uint32(padded+4))
		binary.LittleEndian.PutUint32(b[8:], uint32(padded))
		binary.LittleEndian.PutUint32(b[12:], uint32(len(index)))
		copy(b[16:], index)
		b = append(b, pkg...)
		b = append(b, []byte(js)...)
		path := filepath.Join(dir, "app.asar")
		os.WriteFile(path, b, 0600)
		return path
	}
	start := func(path string) (identity.Process, func()) {
		t.Helper()
		cmd := exec.Command(runtime, "--no-sandbox", "--ozone-platform=headless", "--disable-gpu", "--disable-dev-shm-usage", "--user-data-dir="+t.TempDir(), path)
		cmd.Env = append(os.Environ(), "ELECTRON_RUN_AS_NODE=", "NODE_OPTIONS=", "XDG_CACHE_HOME="+t.TempDir())
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		stdout, _ := cmd.StdoutPipe()
		stderr, err := os.Create(filepath.Join(t.TempDir(), "runtime.log"))
		if err != nil {
			t.Fatal(err)
		}
		defer stderr.Close()
		cmd.Stderr = stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		var once sync.Once
		stop := func() { once.Do(func() { syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); cmd.Wait() }) }
		t.Cleanup(stop)
		ready := make(chan bool, 1)
		go func() {
			s := bufio.NewScanner(stdout)
			for s.Scan() {
				if strings.TrimSpace(s.Text()) == "READY" {
					ready <- true
					return
				}
			}
			ready <- false
		}()
		select {
		case ok := <-ready:
			if !ok {
				t.Fatalf("runtime failed: %s", stderr.Name())
			}
		case <-time.After(15 * time.Second):
			t.Fatalf("runtime timed out: %s", stderr.Name())
		}
		p, err := identity.Inspect(cmd.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		if !identity.BestEffortElectron(p.Application) || !identity.LiveRuleable(p.Application) {
			t.Fatalf("candidate not matched: %+v / %+v", p.Application, p.Application.Hosted)
		}
		// Find the actual NetworkService child: its bundle association must agree.
		dirs, _ := os.ReadDir("/proc")
		matched := false
		for _, d := range dirs {
			var pid int
			if _, e := fmt.Sscan(d.Name(), &pid); e != nil {
				continue
			}
			q, e := identity.Inspect(pid)
			if e == nil && q.Parent == p.PID && q.Application.Hosted != nil && len(q.Application.Hosted.Chain) > 0 && q.Application.Hosted.Chain[0].Type == "utility" && q.Application.Key == p.Application.Key {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatal("network service did not share candidate identity")
		}
		return p, stop
	}
	alpha := makeApp("alpha", true)
	beta := makeApp("beta", false)
	p, stop := start(alpha)
	q, _ := start(beta)
	if p.Application.Key == q.Application.Key {
		t.Fatal("two applications merged")
	}
	f, _ := identity.ParseFlow("tcp", "outgoing", "192.0.2.1:40000", "198.51.100.1:443")
	rule := policy.Rule{ID: "saved", Schema: 2, Version: 1, Action: "allow", Executable: p.Application.Executable, Filter: policy.Filter{Application: p.Application.Key, Revision: p.Application.Revision, UID: p.UID, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}}
	// Exercise the real Remember preview/commit path with a live resolver-issued
	// identity. Flow/socket values here are synthetic; not a kernel-delivery test.
	engine := daemon.New(time.Minute)
	engine.SaveRules = func(rules []policy.Rule) error { rule = rules[len(rules)-1]; return nil }
	engine.Resolve = func(identity.Flow) identity.Attribution {
		return identity.Attribution{Application: &p.Application, Owners: []identity.Process{p}, Sockets: []identity.Socket{{Cookie: "fixture", Inode: 1}}, VisibilityComplete: true, Fingerprint: "fixture"}
	}
	event := engine.Observe(f, "fixture")
	// The published API list round-trips through immutable JSON. Its display
	// target must survive without restoring a resolver receipt on decoded data.
	apiDir := t.TempDir()
	if err := os.Chmod(apiDir, 0700); err != nil {
		t.Fatal(err)
	}
	endpoint := filepath.Join(apiDir, "api")
	listener, err := daemon.Serve(endpoint, engine, false)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := net.Dial("unix", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(conn, `{"version":1,"operation":"list"}`)
	var reply struct {
		Events []struct {
			Attribution struct {
				Application identity.Application      `json:"application"`
				Target      identity.PermissionTarget `json:"permission_target"`
			} `json:"attribution"`
		} `json:"events"`
	}
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if len(reply.Events) != 1 || reply.Events[0].Attribution.Target.Kind != "application" {
		t.Fatalf("snapshot lost application target: %+v", reply)
	}
	if identity.BestEffortElectron(reply.Events[0].Attribution.Application) {
		t.Fatal("snapshot restored authority")
	}
	opts := daemon.RememberOptions{Fields: &daemon.RememberFields{}}
	preview, err := engine.PreviewDecision(engine.Generation, event.ID, "allow", "persistent", "any", engine.Zones.Revision, p.UID, true, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = engine.DecideReviewed(engine.Generation, event.ID, "allow", "persistent", "any", engine.Zones.Revision, preview.Token, p.UID, true, opts); err != nil {
		t.Fatal(err)
	}
	engine.CloseProcessTargets()
	encoded, _ := json.Marshal(rule)
	var saved policy.Rule
	if err := json.Unmarshal(encoded, &saved); err != nil {
		t.Fatal(err)
	}
	attr := func(p identity.Process) identity.Attribution {
		return identity.Attribution{Application: &p.Application, Owners: []identity.Process{p}, VisibilityComplete: true}
	}
	if got, _, _ := policy.Evaluate([]policy.Rule{saved}, f, attr(q), time.Now()); got == "allow" {
		t.Fatal("beta inherited alpha rule")
	}
	// Retain a successfully resolved application while alive, then save only a
	// future rule after exit. This remains a synthetic flow/real identity check.
	ended := daemon.New(time.Minute)
	now := time.Now()
	ended.Now = func() time.Time { return now }
	ended.SaveRules = func(rules []policy.Rule) error { return nil }
	ended.Resolve = engine.Resolve
	old := ended.Observe(f, "ended-fixture")
	stop()
	now = now.Add(2 * time.Minute)
	future, err := ended.PreviewRequestRule(ended.Generation, old.ID, "allow", "persistent", "any", ended.Zones.Revision, p.UID, true, opts)
	if err != nil {
		t.Fatal("retained candidate lost after exit", err)
	}
	futureRule, _, _, err := ended.SaveRequestRule(ended.Generation, future.Token, old.ID, "allow", "persistent", "any", ended.Zones.Revision, p.UID, true, opts)
	if err != nil {
		t.Fatal(err)
	}
	if ended.RetainedState(old.ID, old.Attribution.Fingerprint) != "drop" {
		t.Fatal("ended connection revived")
	}
	ended.CloseProcessTargets()
	again, _ := start(alpha)
	if got, _, _ := policy.Evaluate([]policy.Rule{futureRule}, f, attr(again), time.Now()); got != "allow" {
		t.Fatal("future rule failed", got)
	}
	// A fresh daemon loads only rule data and resolves the new process normally.
	fresh := daemon.New(time.Minute)
	if err := fresh.SetRules([]policy.Rule{saved}); err != nil {
		t.Fatal(err)
	}
	fresh.Resolve = func(identity.Flow) identity.Attribution { return attr(again) }
	if got := fresh.Observe(f, "after-restart"); got.State != "allowed" {
		t.Fatal("restart lost rule", got.State)
	}
	fresh.CloseProcessTargets()
	if again.Application.Key != p.Application.Key {
		t.Fatal("relaunch changed application key")
	}
	if got, _, _ := policy.Evaluate([]policy.Rule{saved}, f, attr(again), time.Now()); got != "allow" {
		t.Fatalf("saved rule did not survive relaunch: %s", got)
	}
	f.Direction = "incoming"
	if got, _, _ := policy.Evaluate([]policy.Rule{saved}, f, attr(again), time.Now()); got == "allow" {
		t.Fatal("direction widened")
	}
	f.Direction = "outgoing"
	other := again
	other.UID++
	other.Application.Key = identity.ApplicationKey(other.UID, other.Application)
	if got, _, _ := policy.Evaluate([]policy.Rule{saved}, f, attr(other), time.Now()); got == "allow" {
		t.Fatal("user widened")
	}
	for _, narrow := range []policy.Filter{
		{Protocol: "udp"}, {RemoteAddress: "203.0.113.99"}, {RemotePort: 8443}, {NetworkZone: "local"},
	} {
		r := saved
		if narrow.Protocol != "" {
			r.Filter.Protocol = narrow.Protocol
		}
		if narrow.RemoteAddress != "" {
			r.Filter.RemoteAddress = narrow.RemoteAddress
		}
		if narrow.RemotePort != 0 {
			r.Filter.RemotePort = narrow.RemotePort
		}
		if narrow.NetworkZone != "" {
			r.Filter.NetworkZone = narrow.NetworkZone
		}
		if got, _, _ := policy.Evaluate([]policy.Rule{r}, f, attr(again), time.Now()); got == "allow" {
			t.Fatalf("optional scope widened: %+v", narrow)
		}
	}
	blocked := saved
	blocked.Action = "block"
	if got, _, _ := policy.Evaluate([]policy.Rule{blocked}, f, attr(again), time.Now()); got != "block" {
		t.Fatal("separate deny lost")
	}
	legacy := saved
	legacy.Filter.Application = identity.ApplicationKey(p.UID, identity.Application{Kind: "native", Executable: runtime})
	if got, _, _ := policy.Evaluate([]policy.Rule{legacy}, f, attr(again), time.Now()); got == "allow" {
		t.Fatal("legacy runtime rule migrated")
	}
	// A serialized identity is presentation, not a fresh resolver receipt.
	raw, _ := json.Marshal(again.Application)
	var reported identity.Application
	json.Unmarshal(raw, &reported)
	if identity.BestEffortElectron(reported) || identity.RuntimeRuleBlocked(&reported) == "" {
		t.Fatal("stored/client metadata became fresh authority")
	}
	if received.Load() != 3 {
		t.Fatalf("receiver requests: %d", received.Load())
	}
	t.Logf("three real receiver requests; distinct ASAR/script applications; persistent serialized rule matches only alpha after relaunch")
}
