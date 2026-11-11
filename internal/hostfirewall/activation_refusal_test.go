package hostfirewall

import (
	"context"
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/readiness"
	"fmt"
	ct "github.com/ti-mo/conntrack"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUnsupportedEstablishedTCPSelfConnection(t *testing.T) {
	endpoint := netip.MustParseAddrPort("[::1]:46081")
	err := validateEstablishedTCP(context.Background(), []identity.Socket{{Protocol: "tcp", State: 1, Local: endpoint, Remote: endpoint, Inode: 42}}, nil)
	if _, ok := err.(*unsupportedEstablishedTCP); !ok {
		t.Fatalf("not a typed compatibility refusal: %v", err)
	}
	if !strings.Contains(err.Error(), "[::1]:46081 -> [::1]:46081 (inode 42)") {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := validateEstablishedTCP(ctx, []identity.Socket{{Protocol: "tcp", State: 1, Local: endpoint, Remote: endpoint}}, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := validateEstablishedTCP(context.Background(), []identity.Socket{{Protocol: "tcp", State: 10, Local: endpoint, Remote: endpoint}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := validateBootstrap(context.Background(), []identity.Socket{{Protocol: "tcp", State: 1, Local: endpoint, Remote: endpoint}}, []ct.Flow{{Mark: approved}}); err == nil {
		t.Fatal("collision ignored")
	} else if _, unsupported := err.(*unsupportedEstablishedTCP); unsupported {
		t.Fatal("collision misclassified as compatibility refusal")
	}

}

func TestUnsupportedRefusalDoesNotFinishAnotherLifecycle(t *testing.T) {
	m := configuredProtection(t)
	m.continuous = true
	m.status.ID = strings.Repeat("b", 32)
	m.status.State = "starting"
	m.done = make(chan struct{})
	m.finishUnsupported(strings.Repeat("a", 32), &unsupportedEstablishedTCP{}, func() error { t.Fatal("validated another lifecycle"); return nil }, func() error { t.Fatal("cleaned another lifecycle"); return nil })
	if m.status.State != "starting" || m.status.Cleanup != "not_needed" {
		t.Fatal(m.status)
	}
	select {
	case <-m.done:
		t.Fatal("finished another lifecycle")
	default:
	}
}

func TestUnsupportedRefusalPersistenceAndCleanup(t *testing.T) {
	refusal := &unsupportedEstablishedTCP{}
	for _, mode := range []string{"normal", "stop", "validation-error", "cleanup-error", "persistence-error"} {
		t.Run(mode, func(t *testing.T) {
			m := configuredProtection(t)
			m.continuous = true
			m.status.ID = strings.Repeat("a", 32)
			m.status.State = "starting"
			m.done = make(chan struct{})
			if err := m.saveDesired("both"); err != nil {
				t.Fatal(err)
			}
			if mode == "stop" {
				if err := m.saveDesired("monitoring"); err != nil {
					t.Fatal(err)
				}
				m.status.State = "stopping"
			}
			if mode == "persistence-error" {
				m.desiredPath = filepath.Join(m.desiredPath, "missing", "desired.json")
			}
			called := false
			validate := func() error {
				if mode == "validation-error" {
					return errors.New("owned guard changed")
				}
				return nil
			}
			cleanup := func() error {
				called = true
				if m.desiredMode != "monitoring" {
					t.Fatal("cleanup preceded durable monitoring")
				}
				b, err := os.ReadFile(m.desiredPath)
				if err != nil || !strings.Contains(string(b), `"monitoring"`) {
					t.Fatal(string(b), err)
				}
				if mode == "cleanup-error" {
					return errors.New("cleanup ownership lost")
				}
				return nil
			}
			handled, refusalErr := m.finishUnsupported(m.status.ID, refusal, validate, cleanup)
			status := m.ProtectionStatus()
			if mode == "normal" || mode == "stop" {
				if !handled || refusalErr != nil {
					t.Fatal(handled, refusalErr)
				}
				if !called || status.DesiredMode != "monitoring" || status.Cleanup != "confirmed" {
					t.Fatal(status, called)
				}
				want := "stopped"
				if mode == "stop" {
					want = "stopped"
				}
				if status.State != want {
					t.Fatal(status)
				}
			} else {
				if handled || refusalErr == nil || status.State != "starting" {
					t.Fatal(handled, refusalErr, status)
				}
				select {
				case <-m.done:
					t.Fatal("helper consumed caller's failure completion")
				default:
				}
				if mode != "cleanup-error" && called {
					t.Fatal("cleanup ran after failed proof/persistence")
				}
			}
		})
	}
}

// Runs only in a disconnected disposable guest namespace. The independent UDP
// receiver is a different process in a peer network namespace, not API status.
func TestActivationRefusalKernelRace(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("FLOWGATE_PARENT_NETNS") == "" || os.Getenv("FLOWGATE_PARENT_NETNS") == identity.NetNS() || os.Getenv("ACTIVATION_RECEIVER") == "" {
		t.Skip("isolated receiver fixture required")
	}
	mode := os.Getenv("ACTIVATION_CASE")
	m := configuredProtection(t)
	root := filepath.Dir(m.dir)
	apiDir, dataDir := filepath.Join(root, "api"), filepath.Join(root, "data")
	if err := os.Mkdir(apiDir, 0711); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	m.socket = filepath.Join(apiDir, "daemon.sock")
	m.database = filepath.Join(dataDir, "rules.db")
	m.probe = func() []readiness.Check { return nil }
	var self net.Conn
	createUntracked := func(ctx context.Context) error {
		addr := &net.TCPAddr{IP: net.IPv6loopback, Port: 46081}
		var err error
		self, err = (&net.Dialer{LocalAddr: addr, Timeout: time.Second}).DialContext(ctx, "tcp6", addr.String())
		if err != nil {
			return err
		}
		// Explicitly remove only this fixture connection's conntrack entry. This
		// models a socket that becomes untracked after the successful preflight.
		conntrack, err := ct.Dial(nil)
		if err != nil {
			return err
		}
		defer conntrack.Close()
		fs, err := conntrack.Dump(nil)
		if err != nil {
			return err
		}
		for _, f := range fs {
			orig := f.TupleOrig
			if orig.Proto.Protocol == 6 && orig.Proto.SourcePort == 46081 && orig.Proto.DestinationPort == 46081 && orig.IP.SourceAddress.IsLoopback() && orig.IP.DestinationAddress.IsLoopback() {
				if err := conntrack.Delete(f); err != nil {
					return err
				}
			}
		}
		if err := checkEstablishedTCP(ctx); err == nil {
			return fmt.Errorf("fixture self-connection remained tracked")
		}
		return nil // Socket appeared after the successful read-only observation.
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var unlockGuard chan struct{}
	if mode == "stop-guard-race" {
		if err := os.Mkdir(m.dir, 0700); err != nil {
			t.Fatal(err)
		}
		locked := make(chan struct{})
		unlockGuard = make(chan struct{})
		go func() { _ = evaluationLock(m.dir, func() error { close(locked); <-unlockGuard; return nil }) }()
		<-locked
	}
	m.establishedPreflight = func(ctx context.Context) error {
		if mode == "stop-guard-race" {
			close(entered)
			<-release
			return errors.New("injected generic read failure")
		}
		if mode == "stop-race" {
			close(entered)
			<-release
			return ctx.Err()
		}
		if err := checkEstablishedTCP(ctx); err != nil {
			return err
		}
		if err := createUntracked(ctx); err != nil {
			return err
		}
		if mode == "persistence-error" {
			m.desiredPath = filepath.Join(m.desiredPath, "bad")
			return checkEstablishedTCP(ctx)
		}
		return nil
	}
	if mode == "persisted-both" || mode == "preexisting-guard" {
		if err := createUntracked(context.Background()); err != nil {
			t.Fatal(err)
		}
		if mode == "persisted-both" {
			if err := m.saveDesired("both"); err != nil {
				t.Fatal(err)
			}
		} else if err := InstallGuard(m.dir); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		if self != nil {
			self.Close()
		}
	}()
	if mode == "joined-error" {
		m.runner = func(ctx context.Context, ready func() error) error {
			return errors.Join(ready(), errors.New("injected independent queue failure"))
		}
	}
	if mode == "foreign-guard" {
		original := m.prepare
		m.prepare = func() (string, error) {
			exe, err := original()
			if err != nil {
				return "", err
			}
			if _, err = nft("add", "rule", "inet", GuardTable, "output", "counter"); err != nil {
				return "", err
			}
			return exe, nil
		}
	}
	started, err := m.ProtectionStart("", strings.Repeat("a", 32), "both")
	if err != nil {
		t.Fatal(err)
	}
	if mode == "stop-race" || mode == "stop-guard-race" {
		<-entered
		if mode == "stop-guard-race" {
			close(release)
			time.Sleep(100 * time.Millisecond)
		}
		if _, err := m.ProtectionStop(started.ID); err != nil {
			t.Fatal(err)
		}
		if mode == "stop-race" {
			close(release)
		} else {
			close(unlockGuard)
		}
	}
	expected := "stopped"
	if mode == "foreign-guard" || mode == "joined-error" || mode == "persisted-both" || mode == "preexisting-guard" || mode == "persistence-error" {
		expected = "degraded"
	}
	waitEvaluation(t, m, expected)
	status := m.ProtectionStatus()
	t.Logf("case=%s protection=%+v", mode, status)
	listing, err := nft("list", "tables")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("udp", os.Getenv("ACTIVATION_RECEIVER"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	_, sendErr := conn.Write([]byte("independent-receiver-proof"))
	reply := make([]byte, 128)
	n, deliveryErr := 0, sendErr
	if sendErr == nil {
		n, deliveryErr = conn.Read(reply)
	}
	if expected == "stopped" {
		if status.DesiredMode != "monitoring" || status.Cleanup != "confirmed" || strings.Contains(string(listing), "flowgate") {
			t.Fatal(status, string(listing))
		}
		if deliveryErr != nil || string(reply[:n]) != "independent-receiver-proof" {
			t.Fatal("clean refusal blocked unrelated receiver", deliveryErr)
		}
	} else {
		if status.Cleanup != "unconfirmed" || !strings.Contains(string(listing), GuardTable) || deliveryErr == nil {
			t.Fatal("integrity failure did not stay fail-closed", status, string(listing), deliveryErr)
		}
	}
	t.Logf("kernel=%s independent_delivery=%t", listing, deliveryErr == nil)
	// Only the test namespace is discarded afterward. Never remove foreign or
	// modified guard objects as part of production refusal cleanup.
}
