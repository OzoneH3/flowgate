// Native fast-handshake fixture: role comes from actual Dial/Accept, never endpoint guesses.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"time"
)

type row struct {
	Cookie string `json:"cookie"`
	Role   string `json:"role"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
}

func describe(c *net.TCPConn, role string) row {
	raw, _ := c.SyscallConn()
	var cookie uint64
	var err error
	raw.Control(func(fd uintptr) { cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE) })
	if err != nil {
		panic(err)
	}
	var b [8]byte
	binary.NativeEndian.PutUint64(b[:], cookie)
	return row{hex.EncodeToString(b[:]), role, c.LocalAddr().String(), c.RemoteAddr().String()}
}
func main() {
	enc := json.NewEncoder(os.Stdout)
	scan := bufio.NewScanner(os.Stdin)
	var held []*net.TCPConn
	listeners := map[string]*net.TCPListener{}
	for family, host := range map[string]string{"tcp4": "127.0.0.1:0", "tcp6": "[::1]:0"} {
		a, e := net.ResolveTCPAddr(family, host)
		if e != nil {
			panic(e)
		}
		l, e := net.ListenTCP(family, a)
		if e != nil {
			panic(e)
		}
		defer l.Close()
		listeners[family] = l
	}
	enc.Encode(map[string]any{"ready": true, "pid": os.Getpid()})
	for scan.Scan() {
		var q struct {
			Op string `json:"op"`
			N  int    `json:"n"`
		}
		json.Unmarshal(scan.Bytes(), &q)
		switch q.Op {
		case "open":
			if q.N < 1 || q.N > 64 {
				q.N = 8
			}
			out := []row{}
			start := time.Now()
			for _, family := range []string{"tcp4", "tcp6"} {
				l := listeners[family]
				for i := 0; i < q.N; i++ {
					ch := make(chan *net.TCPConn, 1)
					go func() {
						c, e := l.AcceptTCP()
						if e != nil {
							panic(e)
						}
						ch <- c
					}()
					c, e := net.DialTimeout(family, l.Addr().String(), time.Second)
					if e != nil {
						panic(e)
					}
					client := c.(*net.TCPConn)
					server := <-ch
					// Actual exchange proves the ordinary completed connection, without stalling SYN states.
					client.Write([]byte("x"))
					var b [1]byte
					if _, e = server.Read(b[:]); e != nil {
						panic(e)
					}
					held = append(held, client, server)
					out = append(out, describe(client, "outgoing"), describe(server, "incoming"))
				}
			}
			enc.Encode(map[string]any{"rows": out, "duration_ns": time.Since(start).Nanoseconds()})
		case "close":
			for _, c := range held {
				c.SetLinger(0)
				c.Close()
			}
			held = nil
			enc.Encode(map[string]bool{"closed": true})
		case "quit":
			return
		default:
			fmt.Fprintln(os.Stderr, "unsupported fixture command")
			return
		}
	}

}
