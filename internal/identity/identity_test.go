package identity

import (
	"net"
	"os"
	"testing"
)

func TestRealSocketDiagnostics(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ss, err := Sockets()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range ss {
		if s.Local.String() == l.Addr().String() && s.State == 10 && s.Inode != 0 && s.Cookie != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("real listener absent")
	}
	p, err := Inspect(os.Getpid())
	if err != nil || p.Start == "" || p.Application.Key == "" {
		t.Fatal(p, err)
	}
}
func TestListenerCandidates(t *testing.T) {
	f, _ := ParseFlow("tcp", "incoming", "127.0.0.1:80", "127.0.0.1:90")
	s := Socket{Protocol: "tcp", Local: f.Local, State: 10}
	if !matches(s, f) {
		t.Fatal("specific listener")
	}
	s.State = 1
	if matches(s, f) {
		t.Fatal("accepted socket treated as listener")
	}
}
