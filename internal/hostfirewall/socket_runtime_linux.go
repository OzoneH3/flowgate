//go:build socketprototype

package hostfirewall

import (
	"context"
	"errors"
	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"fmt"
	"sync"
)

// RoutedSocketSessionFactory is opt-in startup wiring. Construction itself
// performs no kernel operation. The Evaluation invokes it only after creating
// its private chain, before recording the final table digest.
func RoutedSocketSessionFactory(e *daemon.Engine, resolvers daemon.SocketSessionResolvers) SocketSessionFactory {
	return func(ctx context.Context, table, chain string) (SocketSessionResources, error) {
		if err := socketgrant.EnsureBPFMatch(); err != nil {
			return nil, err
		}
		guard, err := identity.NewLinkGuard()
		if err != nil {
			return nil, err
		}
		kernel, err := socketgrant.OpenRoutedKernel(table, chain)
		if err != nil {
			guard.Close()
			return nil, err
		}
		owner := &routedSocketSession{engine: e, backend: socketgrant.RetainForSession(kernel), guard: guard}
		for _, link := range guard.Links() {
			if err = kernel.AddInterface(link.Index); err != nil {
				return owner, fmt.Errorf("install socket gate on interface %d: %w", link.Index, err)
			}
		}
		sessionResolvers := resolvers
		installed, skipped := guard.Links(), guard.SkippedLinks()
		coverage := &daemon.SocketInterfaceCoverage{Maximum: 32, QueueOnlyTotal: len(skipped), QueueOnlyTruncated: len(skipped) > 32}
		for _, link := range installed {
			coverage.Installed = append(coverage.Installed, daemon.SocketInterface{Index: link.Index, Name: link.Name})
		}
		for _, link := range skipped[:min(len(skipped), 32)] {
			coverage.QueueOnly = append(coverage.QueueOnly, daemon.SocketInterface{Index: link.Index, Name: link.Name})
		}
		sessionResolvers.InterfaceCoverage = coverage
		sessionResolvers.Diagnostics = func() map[string]any {
			out := map[string]any{}
			if resolvers.Diagnostics != nil {
				for k, v := range resolvers.Diagnostics() {
					out[k] = v
				}
			}
			out["interface_coverage"] = map[string]any{"installed": append([]identity.NetworkLink(nil), installed...), "queue_only": append([]identity.NetworkLink(nil), skipped...), "maximum": 32, "new_links": "queue until next protection session", "link_identity_change": "changed interface retired; surviving interfaces retain acceleration", "coverage_scope": "activation snapshot; current coverage is in socket_authorization.interface_coverage"}
			return out
		}
		if err = e.StartSessionSocketAuthorization(ctx, owner.backend, sessionResolvers); err != nil {
			return owner, err
		}
		owner.started = true
		watchctx, cancel := context.WithCancel(ctx)
		owner.cancel = cancel
		owner.done = make(chan struct{})
		go func() {
			defer close(owner.done)
			err := guard.RunRetiring(watchctx, func(link identity.NetworkLink, reason string) error {
				return e.RetireSocketInterface(link.Index, reason)
			})
			if watchctx.Err() == nil {
				// Never remove a rule behind the owner's digest. This session remains
				// queued after identity uncertainty; a deliberate restart can rebuild.
				_ = e.DisableSocketAuthorization(err)
			}
		}()
		return owner, nil
	}
}

type routedSocketSession struct {
	mu      sync.Mutex
	engine  *daemon.Engine
	backend *socketgrant.SessionBackend
	guard   *identity.LinkGuard
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
	stopped bool
}

func (s *routedSocketSession) Disable() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.started {
		err = s.engine.DisableSocketAuthorization(errors.New("protection session stopping"))
	}
	return errors.Join(err, s.backend.Close())
}
func (s *routedSocketSession) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Holding this owner lock never blocks the watcher: it only uses Engine.
	if s.cancel != nil {
		s.cancel()
	}
	if s.guard != nil {
		_ = s.guard.Close()
		s.guard = nil
	}
	if s.done != nil {
		<-s.done
		s.done = nil
	}
	var err error
	if s.started && !s.stopped {
		err = s.engine.StopSocketAuthorization()
		s.stopped = true
	}
	return errors.Join(err, s.backend.Close())
}
func (s *routedSocketSession) ReleaseAfterTableDeletion() error {
	// Stop joins all users even if epoch0 fails. After that, independent kernel
	// rule-absence proof is sufficient to release; a map-write error is not.
	_ = s.Stop()
	return s.backend.ReleaseAfterTableDeletion()
}
