//go:build socketprototype

package main

import (
	"flowgate/internal/daemon"
	"flowgate/internal/hostfirewall"
)

// Configuration is inert until the owner starts a continuous protection session.
func configureSocketAuthorization(evaluation *hostfirewall.Evaluation, e *daemon.Engine, resolvers daemon.SocketSessionResolvers) error {
	return evaluation.ConfigureSocketSession(hostfirewall.RoutedSocketSessionFactory(e, resolvers))
}
