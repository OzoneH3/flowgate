// Disposable UI-contract fixture. Service/configuration discovery is explicitly
// simulated; API, native executable identity, storage and receipts are real.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"flowgate/internal/daemon"
	"flowgate/internal/essential"
	"flowgate/internal/identity"
	"flowgate/internal/store"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	dir := flag.String("dir", "", "private fixture directory")
	flag.Parse()
	if *dir == "" {
		panic("dir required")
	}
	parent := os.Getenv("FLOWGATE_PARENT_NETNS")
	if parent == "" || parent == identity.NetNS() {
		panic("disposable network namespace required")
	}
	if err := os.MkdirAll(*dir, 0700); err != nil {
		panic(err)
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.53:53")
	if err != nil {
		panic(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp4", "127.0.0.53:53")
	if err != nil {
		panic(err)
	}
	defer tcp.Close()
	process, err := identity.Inspect(os.Getpid())
	if err != nil {
		panic(err)
	}
	unit := ""
	env := essential.Environment{Sockets: identity.Sockets, Read: func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "/cmdline") {
			return []byte("fixture\x00--port=41641\x00"), nil
		}
		return os.ReadFile(path)
	}, Inspect: func(pid int) (identity.Process, error) {
		p, err := identity.Inspect(pid)
		p.Cgroup = "0::/system.slice/" + unit
		return p, err
	}, Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "systemctl":
			unit = args[1]
			return []byte("ActiveState=active\nMainPID=" + strconv.Itoa(process.PID)), nil
		case "resolvectl":
			return []byte(`[{"ifname":"test0","ifindex":2,"dnsOverTLS":"no","servers":[{"addressString":"192.0.2.53","port":53}]}]`), nil
		case "nmcli":
			if args[0] == "-t" {
				return []byte("fixture-uuid:test0\n"), nil
			}
			return []byte("auto\nauto"), nil
		case "timedatectl":
			return []byte("ServerName=fixture.invalid\nServerAddress=192.0.2.123"), nil
		}
		return nil, fmt.Errorf("unhandled fixture discovery %s", name)
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := daemon.New(10 * time.Second)
	defer e.CloseProcessTargets()
	uid := uint32(os.Getuid())
	e.APIUID = &uid
	e.AdministratorUID = &uid
	e.Mode = "daemon-monitor"
	e.Enforcement = func() daemon.EnforcementStatus {
		return daemon.EnforcementStatus{State: "stopped", Detail: "Disposable preset contract fixture, discovery simulated; no enforcement"}
	}
	db, err := store.OpenExclusive(filepath.Join(*dir, "rules.db"))
	if err != nil {
		panic(err)
	}
	defer db.Close()
	rules, err := db.Load()
	if err != nil {
		panic(err)
	}
	if err = e.SetRules(rules); err != nil {
		panic(err)
	}
	e.SaveRules = db.Replace
	e.ConfigureEssential(ctx, env)
	path := filepath.Join(*dir, "api.sock")
	api, err := daemon.Serve(path, e, false)
	if err != nil {
		panic(err)
	}
	defer api.Close()
	observer, err := daemon.Serve(path+".monitor", e, true)
	if err != nil {
		panic(err)
	}
	defer observer.Close()
	b, _ := json.MarshalIndent(map[string]any{"endpoint": path, "generation": e.Generation, "dir": *dir, "label": "isolated real API/storage/native fixture with simulated system configuration; no enforcement"}, "", "  ")
	os.WriteFile(filepath.Join(*dir, "ready.json"), b, 0600)
	fmt.Println("READY", string(b))
	for {
		if _, err := os.Stat(filepath.Join(*dir, "quit")); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("CLEANED owned fixture only")
}
