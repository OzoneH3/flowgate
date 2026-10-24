package hostfirewall

import (
	"context"
	"errors"
	"flowgate/internal/identity"
	ct "github.com/ti-mo/conntrack"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCutoverOrderingAndFailureBoundaries(t *testing.T) {
	for _, failure := range []int{-1, 0, 1, 2, 3} {
		calls := 0
		steps := []func() error{}
		for i := 0; i < 4; i++ {
			step := i
			steps = append(steps, func() error {
				if calls != step {
					t.Fatal("cutover order", calls, step)
				}
				calls++
				if failure == step {
					return errors.New("injected")
				}
				return nil
			})
		}
		err := cutoverProfileWith(context.Background(), steps[0], steps[1], steps[2], steps[3])
		want := 4
		if failure >= 0 {
			want = failure + 1
		}
		if calls != want || (err != nil) != (failure >= 0) {
			t.Fatal(failure, calls, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := false
	err := cutoverProfileWith(ctx, func() error { return nil }, func() error { return nil }, func() error { cancel(); return nil }, func() error { finished = true; return nil })
	if err == nil || finished {
		t.Fatal("cutoff after cancellation", err)
	}
	for _, profile := range []string{"incoming", "both"} {
		r := preservationRules(strings.Repeat("a", 32))
		final := "delete table inet " + Table + "\n" + profileRules(strings.Repeat("a", 32), profile)
		if strings.Contains(r, "queue") || strings.Count(r, "ct mark set ct mark | 0x20000000 accept") != 2 || !strings.Contains(final, "queue num 101") {
			t.Fatal("temporary/final shape", r, final)
		}
	}
}
func TestCutoverPreservationIncludesConfirmedTCPUDPOnly(t *testing.T) {
	fs := []ct.Flow{}
	for _, p := range []uint8{6, 17, 1} {
		for _, confirmed := range []bool{true, false} {
			f := ct.Flow{}
			f.TupleOrig.Proto.Protocol = p
			if confirmed {
				f.Status.Value = 8
			}
			fs = append(fs, f)
		}
	}
	count := 0
	if err := preserveConfirmed(context.Background(), fs, func(f ct.Flow, m uint32) error {
		if m != preserved || !f.Status.Confirmed() {
			t.Fatal(f, m)
		}
		count++
		return nil
	}); err != nil || count != 2 {
		t.Fatal(count, err)
	}
}

// Real packet/conntrack proof is restricted to the disposable lab namespace.
func TestActivationCutoverConcurrentTCPReceivers(t *testing.T) {
	if os.Getenv("FLOWGATE_PARENT_NETNS") == "" || os.Getenv("FLOWGATE_PARENT_NETNS") == identity.NetNS() {
		t.Skip("disposable lab namespace required")
	}
	if err := batch("add table inet cutover_fixture\nadd chain inet cutover_fixture track { type filter hook input priority 0; policy accept; }\nadd rule inet cutover_fixture track ct state established counter\n"); err != nil {
		t.Fatal(err)
	}
	defer nft("delete", "table", "inet", "cutover_fixture")
	for _, profile := range []string{"incoming", "both"} {
		for _, family := range []string{"tcp4", "tcp6"} {
			t.Run(profile+"/"+family, func(t *testing.T) {
				address := "127.0.0.1:0"
				if family == "tcp6" {
					address = "[::1]:0"
				}
				listener, err := net.Listen(family, address)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				peers := []net.Conn{}
				clients := []net.Conn{}
				defer func() {
					for _, c := range clients {
						c.Close()
					}
					for _, c := range peers {
						c.Close()
					}
					nft("delete", "table", "inet", Table)
					if er := clearMarks(); er != nil {
						t.Error(er)
					}
				}()
				connect := func() {
					c, er := net.DialTimeout(family, listener.Addr().String(), time.Second)
					if er != nil {
						t.Fatal(er)
					}
					clients = append(clients, c)
					s, er := listener.Accept()
					if er != nil {
						t.Fatal(er)
					}
					peers = append(peers, s)
				}
				var expectedDigest string
				token := strings.Repeat("b", 32)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				err = cutoverProfileWith(ctx,
					func() error {
						er := bootstrapContext(ctx, func() error { return nil })
						if er == nil {
							connect()
						}
						return er
					},
					func() error {
						if err := batch(preservationRules(token)); err != nil {
							return err
						}
						var er error
						expectedDigest, er = tableDigest()
						return er
					},
					func() error {
						fs, er := flows()
						if er != nil {
							return er
						}
						connect()
						return preserveConfirmed(ctx, fs, setMark)
					},
					func() error { return finishCutover(ctx, token, profile, expectedDigest) },
				)
				if err != nil {
					t.Fatal(err)
				}
				// These connections were established in both former race windows. Verify
				// actual post-cutoff payload delivery, not merely a mark or API response.
				for i, c := range clients {
					c.SetDeadline(time.Now().Add(time.Second))
					peers[i].SetDeadline(time.Now().Add(time.Second))
					if _, err = c.Write([]byte("payload")); err != nil {
						t.Fatal(err)
					}
					b := make([]byte, 7)
					if _, err = io.ReadFull(peers[i], b); err != nil || string(b) != "payload" {
						t.Fatal("pre-cutoff connection stranded", i, err, string(b))
					}
				}
				// No queue consumer: a new SYN after the cutoff must fail closed even if
				// another pre-cutoff flow used the same destination listener.
				c, er := net.DialTimeout(family, listener.Addr().String(), 250*time.Millisecond)
				if er == nil {
					c.Close()
					t.Fatal("post-cutoff connection bypassed queue")
				}
			})
		}
	}
}

func TestCutoverRefusesMarkCollision(t *testing.T) {
	f := ct.Flow{}
	f.Mark = approved
	f.TupleOrig.Proto.Protocol = 6
	f.Status.Value = 8
	if err := preserveConfirmed(context.Background(), []ct.Flow{f}, func(ct.Flow, uint32) error { t.Fatal("foreign mark overwritten"); return nil }); err == nil {
		t.Fatal("foreign mark accepted")
	}
}
func TestCutoverFinishRefusesChangedTemporaryTable(t *testing.T) {
	if os.Getenv("FLOWGATE_PARENT_NETNS") == "" || os.Getenv("FLOWGATE_PARENT_NETNS") == identity.NetNS() {
		t.Skip("disposable lab namespace required")
	}
	for _, mode := range []string{"foreign-token", "structural-change"} {
		t.Run(mode, func(t *testing.T) {
			token := strings.Repeat("c", 32)
			if err := batch(preservationRules(token)); err != nil {
				t.Fatal(err)
			}
			defer nft("delete", "table", "inet", Table)
			digest, err := tableDigest()
			if err != nil {
				t.Fatal(err)
			}
			if mode == "foreign-token" {
				err = batch("delete table inet " + Table + "\n" + strings.Replace(preservationRules(token), "flowgate:"+token, "foreign-owner", 1))
			} else {
				err = batch("add rule inet " + Table + " input counter\n")
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := tableDigest()
			if err != nil {
				t.Fatal(err)
			}
			if err = finishCutover(context.Background(), token, "both", digest); err == nil {
				t.Fatal("changed startup table replaced")
			}
			after, err := tableDigest()
			if err != nil || after != before {
				t.Fatal("foreign/modified table not retained", err)
			}
			// The caller's rollback still owns a same-token table. Foreign-token
			// replacement must survive that cleanup; same-token cleanup removes
			// our temporary resource, rather than publishing changed rules.
			cleanupErr := remove(Record{Token: token})
			if mode == "foreign-token" {
				if cleanupErr == nil {
					t.Fatal("cleanup accepted foreign token")
				}
				after, err = tableDigest()
				if err != nil || after != before {
					t.Fatal("cleanup changed foreign table", err)
				}
			} else if cleanupErr != nil {
				t.Fatal(cleanupErr)
			} else if present, err := owns(Record{Token: token}); err != nil || present {
				t.Fatal("owned rollback incomplete", err)
			}

		})
	}
}
