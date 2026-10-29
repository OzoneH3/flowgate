package identity_test

import (
	"bufio"
	"encoding/json"
	"flowgate/internal/identity"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Real runtime identity evidence only; this is not a firewall delivery test.
func TestNodeUtilitiesRealRuntime(t *testing.T) {
	runtime := os.Getenv("FLOWGATE_ELECTRON_RUNTIME")
	if runtime == "" {
		t.Skip("real Electron runtime opt-in")
	}
	if os.Getenv("FLOWGATE_PARENT_NETNS") == "" {
		t.Fatal("isolated namespace required")
	}
	var keys []string
	for _, name := range []string{"synthetic-alpha", "synthetic-beta"} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "package.json"), []byte(fmt.Sprintf(`{"name":%q}`, name)), 0600)
		os.WriteFile(filepath.Join(dir, "modules.asar"), []byte("fixture open archive"), 0600)
		os.WriteFile(filepath.Join(dir, "worker.cjs"), []byte(`const fs=require('original-fs');if(process.argv[2]==='owned') fs.openSync(process.argv[3],'r');process.parentPort.postMessage(process.pid);setInterval(()=>{},1000)`), 0600)
		js := `const {app,utilityProcess}=require('electron');const fs=require('original-fs');const path=require('path');app.whenReady().then(()=>{const archive=path.join(__dirname,'modules.asar');fs.openSync(archive,'r');for(const role of ['owned','foreign']){const p=utilityProcess.fork(path.join(__dirname,'worker.cjs'),[role,archive]);p.on('message',pid=>console.log(role+':'+pid))}});`
		entry := filepath.Join(dir, "entry.cjs")
		os.WriteFile(entry, []byte(js), 0600)
		cmd := exec.Command(runtime, "--no-sandbox", "--ozone-platform=headless", "--disable-gpu", "--user-data-dir="+t.TempDir(), entry)
		cmd.Env = append(os.Environ(), "ELECTRON_RUN_AS_NODE=", "NODE_OPTIONS=", "XDG_CACHE_HOME="+t.TempDir())
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		stdout, _ := cmd.StdoutPipe()
		logfile, _ := os.Create(filepath.Join(dir, "runtime.log"))
		defer logfile.Close()
		cmd.Stderr = logfile
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); cmd.Wait() })
		ready := make(chan string, 4)
		go func() {
			scan := bufio.NewScanner(stdout)
			for scan.Scan() {
				ready <- scan.Text()
			}
		}()
		children := map[string]int{}
		deadline := time.After(15 * time.Second)
		for len(children) < 2 {
			select {
			case line := <-ready:
				role, number, ok := strings.Cut(line, ":")
				if ok && (role == "owned" || role == "foreign") {
					children[role], _ = strconv.Atoi(number)
				}
			case <-deadline:
				t.Fatalf("utility startup timeout: %s", logfile.Name())
			}
		}
		main, err := identity.Inspect(cmd.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := identity.Inspect(children["owned"])
		if err != nil {
			t.Fatal(err)
		}
		foreign, err := identity.Inspect(children["foreign"])
		if err != nil {
			t.Fatal(err)
		}
		if !identity.BestEffortElectron(owned.Application) || owned.Application.Hosted.Scope != "node-utilities" {
			t.Fatalf("owned unmatched: %+v", owned.Application.Hosted)
		}
		if owned.Application.Key == main.Application.Key {
			t.Fatal("main rule inherited")
		}
		if identity.BestEffortElectron(foreign.Application) {
			t.Fatal("utility without package evidence matched")
		}
		var clone identity.Application
		raw, _ := json.Marshal(owned.Application)
		json.Unmarshal(raw, &clone)
		if identity.BestEffortElectron(clone) {
			t.Fatal("JSON minted match receipt")
		}
		if err := identity.VerifyInstanceExecutable(owned.PID, owned.Start, owned.Application); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, owned.Application.Key)
	}
	if keys[0] == keys[1] {
		t.Fatal("packages share utility rule")
	}
}
