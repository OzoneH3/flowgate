package hostfirewall

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type testSocketSession struct {
	stops, releases     int
	stopErr, releaseErr error
}

func (s *testSocketSession) Disable() error                   { return s.stopErr }
func (s *testSocketSession) Stop() error                      { s.stops++; return s.stopErr }
func (s *testSocketSession) ReleaseAfterTableDeletion() error { s.releases++; return s.releaseErr }
func TestSocketSessionOwnerSurvivesDisableAndCleanupFailures(t *testing.T) {
	s := &testSocketSession{stopErr: errors.New("epoch unavailable"), releaseErr: errors.New("rule present")}
	m := &Evaluation{socketSession: s}
	if m.stopSocketSession() == nil || s.stops != 1 || s.releases != 0 || m.socketSession != s {
		t.Fatal("disable lost audited owner")
	}
	if m.releaseSocketSession() == nil || m.socketSession != s {
		t.Fatal("failed cleanup lost retry owner")
	}
	s.releaseErr = nil
	if err := m.releaseSocketSession(); err != nil || m.socketSession != nil || s.releases != 2 {
		t.Fatal("verified deletion did not release", err)
	}
	if err := m.releaseSocketSession(); err != nil || s.releases != 2 {
		t.Fatal("release not idempotent", err)
	}
}
func TestSocketSessionAbsentLeavesOrdinaryLifecycleUnchanged(t *testing.T) {
	m := &Evaluation{}
	if err := m.stopSocketSession(); err != nil {
		t.Fatal(err)
	}
	if err := m.releaseSocketSession(); err != nil {
		t.Fatal(err)
	}
}

func TestSocketSessionFactoryRetainsPartialOwner(t *testing.T) {
	s := &testSocketSession{}
	m := &Evaluation{}
	if err := m.ConfigureSocketSession(func(ctx context.Context, table, chain string) (SocketSessionResources, error) {
		if table != Table || chain != "socket_output" {
			t.Fatal("wrong owned target", table, chain)
		}
		return s, errors.New("partial install")
	}); err != nil {
		t.Fatal(err)
	}
	if m.prepareSocketSession(context.Background()) != nil || m.socketSession != s || m.SocketSessionFailure() == nil {
		t.Fatal("partial owner discarded")
	}
	if m.ConfigureSocketSession(nil) == nil {
		t.Fatal("replaced live owner")
	}
	if err := m.stopSocketSession(); err != nil || s.stops != 2 {
		t.Fatal("partial owner not stopped", err)
	}
	if err := m.releaseSocketSession(); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureSocketSession(nil); err != nil {
		t.Fatal(err)
	}
}
func TestSocketGateChainPreservesQueueFallbackAndLaterAdmission(t *testing.T) {
	base := profileRules("token", "both")
	with := profileRulesWithSocketGate("token", "both", true)
	addition := "add chain inet flowgate_host socket_output\nadd rule inet flowgate_host output meta nfproto ipv4 meta l4proto udp jump socket_output\n"
	if strings.Replace(with, addition, "", 1) != base {
		t.Fatal("gate changed existing firewall behavior")
	}
	if strings.Count(with, addition) != 1 {
		t.Fatal("missing or duplicate gate chain")
	}
	gate := strings.Index(with, addition)
	if strings.Index(with, "output ct state invalid") >= gate || strings.Index(with, "output meta l4proto udp jump inspect") <= gate {
		t.Fatal("incorrect admission ordering")
	}
	if !strings.Contains(with, "admit_output { type filter hook output priority 11;") {
		t.Fatal("later admission removed")
	}
	if profileRulesWithSocketGate("token", "incoming", true) != profileRules("token", "incoming") {
		t.Fatal("incoming-only profile changed")
	}
}

func TestDigestFormatIsExplicitAndLegacyCompatible(t *testing.T) {
	legacy, err := tableListingArgs(Table, "")
	if err != nil || strings.Join(legacy, " ") != "-j list table inet flowgate_host" {
		t.Fatal(legacy, err)
	}
	numeric, err := tableListingArgs(Table, numericDigestFormat)
	if err != nil || strings.Join(numeric, " ") != "-j -n list table inet flowgate_host" {
		t.Fatal(numeric, err)
	}
	if _, err := tableListingArgs(Table, "unknown"); err == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestSocketSessionFreshStartClearsOldFailure(t *testing.T) {
	m := &Evaluation{}
	attempts := 0
	m.ConfigureSocketSession(func(context.Context, string, string) (SocketSessionResources, error) {
		attempts++
		if attempts == 1 {
			return &testSocketSession{}, errors.New("old optional setup failure")
		}
		return &testSocketSession{}, nil
	})
	if err := m.prepareSocketSession(context.Background()); err != nil || m.SocketSessionFailure() == nil {
		t.Fatal("missing old failure", err)
	}
	if err := m.stopSocketSession(); err != nil {
		t.Fatal(err)
	}
	if err := m.releaseSocketSession(); err != nil {
		t.Fatal(err)
	}
	if err := m.prepareSocketSession(context.Background()); err != nil || m.SocketSessionFailure() != nil {
		t.Fatal("failure survived fresh start", err, m.SocketSessionFailure())
	}
}
