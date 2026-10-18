// Disposable same-executable instances with independent TCP/UDP receivers.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

func main() {
	base, _ := strconv.Atoi(os.Args[1])
	host4, host6 := "10.79.0.1", "fd79::1"
	// Optional explicit bind addresses for the separately authorized host peer.
	// This fixture still runs as the ordinary selected user, never as root.
	if len(os.Args) == 4 {
		host4, host6 = os.Args[2], os.Args[3]
		if net.ParseIP(host4).To4() == nil || net.ParseIP(host6) == nil {
			panic("invalid native fixture bind addresses")
		}
	}
	var mu sync.Mutex
	var jobs sync.WaitGroup
	counts := map[string]int{}
	ports := map[string]int{}
	count := func(k string) { mu.Lock(); counts[k]++; mu.Unlock() }
	for _, family := range []string{"4", "6"} {
		host := host4
		if family == "6" {
			host = host6
		}
		for i, proto := range []string{"tcp", "udp"} {
			key := proto + family
			port := base + i
			if family == "6" {
				port += 2
			}
			ports[key] = port
			if proto == "tcp" {
				l, e := net.Listen(key, net.JoinHostPort(host, strconv.Itoa(port)))
				if e != nil {
					panic(e)
				}
				go func(k string, l net.Listener) {
					for {
						c, e := l.Accept()
						if e != nil {
							return
						}
						go func(c net.Conn) {
							defer c.Close()
							b := make([]byte, 128)
							if n, e := c.Read(b); e == nil && n > 0 {
								count(k)
								c.Write(b[:n])
							}
						}(c)
					}
				}(key, l)
			} else {
				u, e := net.ListenPacket(key, net.JoinHostPort(host, strconv.Itoa(port)))
				if e != nil {
					panic(e)
				}
				go func(k string, u net.PacketConn) {
					b := make([]byte, 128)
					for {
						n, a, e := u.ReadFrom(b)
						if e != nil {
							return
						}
						if n > 0 {
							count(k)
							u.WriteTo(b[:n], a)
						}
					}
				}(key, u)
			}
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.Encode(map[string]any{"pid": os.Getpid(), "ports": ports})
	scan := bufio.NewScanner(os.Stdin)
	for scan.Scan() {
		var q struct {
			Op       string `json:"op"`
			Protocol string `json:"protocol"`
			V6       bool   `json:"v6"`
		}
		json.Unmarshal(scan.Bytes(), &q)
		switch q.Op {
		case "settle":
			jobs.Wait()
		case "quit":
			return
		case "exec":
			syscall.Exec("/bin/sleep", []string{"sleep", "30"}, os.Environ())
			return
		case "send":
			key := q.Protocol + "4"
			host := "10.79.0.2"
			port := 43000
			if q.Protocol == "udp" {
				port = 43001
			}
			if q.V6 {
				key = q.Protocol + "6"
				host = "fd79::2"
			}
			jobs.Add(1)
			go func() {
				defer jobs.Done()
				c, e := net.DialTimeout(key, net.JoinHostPort(host, strconv.Itoa(port)), 2*time.Second)
				if e != nil {
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(2 * time.Second))
				c.Write([]byte("process-fixture"))
				c.Read(make([]byte, 128))
			}()
		}
		mu.Lock()
		copy := map[string]int{}
		for k, v := range counts {
			copy[k] = v
		}
		mu.Unlock()
		if e := enc.Encode(map[string]any{"counts": copy}); e != nil {
			fmt.Fprintln(os.Stderr, e)
			return
		}
	}
}
