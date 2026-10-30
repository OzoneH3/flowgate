//go:build !socketprototype

package main

import (
	"errors"
	"flowgate/internal/daemon"
	"flowgate/internal/hostfirewall"
)

func configureSocketAuthorization(_ *hostfirewall.Evaluation, _ *daemon.Engine, _ daemon.SocketSessionResolvers) error {
	return errors.New("socket authorization is unavailable in this build; omit --socket-authorization to use queue protection")
}
