package uploadshape

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"flowgate/internal/identity"
	"golang.org/x/sys/unix"
)

type Service interface {
	Resume()
	Snapshot() Snapshot
	HasWineResolver() bool
	Offer(identity.Flow, identity.Attribution)
	Configure(uint64, Config) (Snapshot, error)
}

var ErrInterfaceUnavailable = errors.New("shaping interface unavailable")

// Discovered publishes the startup diagnosis while routes or compatibility are
// unsettled. The first qualified interface becomes the manager's immutable
// target. Active shaping and its ownership journal never migrate implicitly.
type Discovered struct {
	opts        Options
	preferences Preferences
	manager     atomic.Pointer[Manager]
	pending     atomic.Pointer[Snapshot]
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	start       sync.Once
	prepare     func(context.Context) (string, *Manager, error)
}

func NewDiscovered(ctx context.Context, opts Options, p Preferences, save func(Preferences) error) *Discovered {
	ctx, cancel := context.WithCancel(ctx)
	d := &Discovered{opts: opts, preferences: p, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	d.publish("", "Waiting for a usable default-route interface")
	d.prepare = func(ctx context.Context) (string, *Manager, error) {
		device, err := defaultInterface(identity.CollectNetwork())
		if err != nil {
			return "", nil, err
		}
		opts.Interface = device
		if err = validateOptions(opts); err != nil {
			return device, nil, err
		}
		// If recovering a generation, the existing controller checks the journal
		// identity before removal. A journal on another interface cannot migrate.
		if err = cleanupProcess(opts); err != nil {
			return device, nil, err
		}
		if err = checkCompatibility(ctx, opts); err != nil {
			return device, nil, err
		}
		m, err := New(opts, p, save)
		return device, m, err
	}
	return d
}

func (d *Discovered) publish(device, reason string) {
	p := d.preferences
	d.pending.Store(&Snapshot{DeploymentMode: "automatic", InterfacePending: true, Interface: device, Version: 1,
		Status: "Unsupported", LastError: reason, Enabled: p.Enabled, Caps: p.Caps,
		UploadBudget: p.UploadBudget, DownloadBudget: p.DownloadBudget})
}

func (d *Discovered) Resume() {
	d.start.Do(func() {
		go func() {
			defer close(d.done)
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for d.ctx.Err() == nil {
				device, m, err := d.prepare(d.ctx)
				if err == nil {
					d.manager.Store(m)
					m.Resume()
					return
				}
				d.publish(device, err.Error())
				select {
				case <-d.ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	})
}

func (d *Discovered) Close() {
	d.cancel()
	d.start.Do(func() { close(d.done) })
	<-d.done
	if m := d.manager.Load(); m != nil {
		m.Close()
	}
}

func (d *Discovered) Snapshot() Snapshot {
	if m := d.manager.Load(); m != nil {
		s := m.Snapshot()
		s.DeploymentMode = "automatic"
		return s
	}
	return *d.pending.Load()
}

func (d *Discovered) HasWineResolver() bool { return d.opts.WineResolve != nil }

func (d *Discovered) Offer(f identity.Flow, a identity.Attribution) {
	if m := d.manager.Load(); m != nil {
		m.Offer(f, a)
	}
}

func (d *Discovered) Configure(version uint64, c Config) (Snapshot, error) {
	if m := d.manager.Load(); m != nil {
		s, err := m.Configure(version, c)
		s.DeploymentMode = "automatic"
		return s, err
	}
	return Snapshot{}, fmt.Errorf("%w: %s", ErrInterfaceUnavailable, d.pending.Load().LastError)
}

func defaultInterface(s identity.NetworkSnapshot) (string, error) {
	if s.State != "ready" {
		return "", fmt.Errorf("Default route discovery unavailable: %s", s.Reason)
	}
	active := map[uint32]string{}
	for _, link := range s.Links {
		if link.Flags&(unix.IFF_UP|unix.IFF_LOWER_UP|unix.IFF_LOOPBACK) == unix.IFF_UP|unix.IFF_LOWER_UP {
			active[link.Index] = link.Name
		}
	}
	type bestRoute struct {
		metric uint32
		routes []identity.NetworkRoute
	}
	best := map[bool]bestRoute{}
	for _, r := range s.Routes {
		prefix, err := netip.ParsePrefix(r.Prefix)
		if err != nil || prefix.Bits() != 0 || r.Type != unix.RTN_UNICAST {
			continue
		}
		if r.Table != unix.RT_TABLE_MAIN {
			return "", fmt.Errorf("Automatic shaping cannot choose among policy routing tables")
		}
		family := prefix.Addr().Is4()
		old := best[family]
		if len(old.routes) == 0 || r.Priority < old.metric {
			old = bestRoute{metric: r.Priority}
		}
		if r.Priority == old.metric {
			old.routes = append(old.routes, r)
		}
		best[family] = old
	}
	var device string
	for _, family := range best {
		for _, route := range family.routes {
			if route.Interface == 0 || route.Options != "" {
				return "", fmt.Errorf("Default route has multipath or route-specific selection")
			}
			name, ok := active[route.Interface]
			if !ok {
				return "", fmt.Errorf("Waiting for carrier on the preferred default-route interface")
			}
			if device != "" && device != name {
				return "", fmt.Errorf("Default routes select multiple interfaces; configure one explicitly")
			}
			device = name
		}
	}
	if device == "" {
		return "", fmt.Errorf("Waiting for a usable default route")
	}
	return device, nil
}

func checkCompatibility(ctx context.Context, o Options) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	result, err := exec.CommandContext(ctx, "/usr/bin/python3", "-I", o.Helpers+"/controller.py", "--preflight",
		"--host-trial", "--interface", o.Interface, "--helpers", o.Helpers, "--state", o.State).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) != 0 {
			return fmt.Errorf("Shaping compatibility check failed for %s: %s", o.Interface, strings.TrimSpace(string(ee.Stderr)))
		}
		return fmt.Errorf("Shaping compatibility check failed for %s: %w", o.Interface, err)
	}
	var check struct {
		Supported bool
		Reasons   []string
	}
	if err = json.Unmarshal(result, &check); err != nil {
		return fmt.Errorf("Invalid compatibility result for %s: %w", o.Interface, err)
	}
	if !check.Supported {
		return fmt.Errorf("%s: %s", o.Interface, strings.Join(check.Reasons, "; "))
	}
	return nil
}
