// Disposable same-executable instances with independent TCP/UDP receivers.
package main

import (
	"bufio"
	"context"
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
	// A held disposable prompt fixture needs time for an actual GUI decision.
	// Default suite behavior stays two seconds; never controls the host daemon.
	timeout := 2 * time.Second
	if raw := os.Getenv("FLOWGATE_FIXTURE_TIMEOUT_SECONDS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 60 {
			panic("fixture timeout must be 1..60 seconds")
		}
		timeout = time.Duration(n) * time.Second
	}
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
	type sendResult struct {
		Remote string `json:"remote"`
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	}
	var lastSend *sendResult
	// Open outgoing sends; "close" cancels/closes them while the process stays alive.
	open := map[int]context.CancelFunc{}
	nextOpen := 0
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
			Op        string `json:"op"`
			TimeoutMS int    `json:"timeout_ms"`
			Protocol  string `json:"protocol"`
			V6        bool   `json:"v6"`
			// Optional explicit destination inside the private fixture prefixes.
			Host string `json:"host"`
			Port int    `json:"port"`
			// Writes on the same socket and their spacing.
			Repeat     int `json:"repeat"`
			IntervalMS int `json:"interval_ms"`
		}
		json.Unmarshal(scan.Bytes(), &q)
		switch q.Op {
		case "settle":
			jobs.Wait()
		case "quit":
			return
		case "close":
			mu.Lock()
			for id, cancel := range open {
				cancel()
				delete(open, id)
			}
			mu.Unlock()
		case "exec":
			syscall.Exec("/bin/sleep", []string{"sleep", "30"}, os.Environ())
			return
		case "send":
			key := q.Protocol + "4"
			host := "10.79.0.2"
			if p := os.Getenv("FLOWGATE_FIXTURE_PEER4"); p != "" {
				host = p
			}
			port := 43000
			if q.Protocol == "udp" {
				port = 43001
			}
			if q.V6 {
				key = q.Protocol + "6"
				host = "fd79::2"
				if p := os.Getenv("FLOWGATE_FIXTURE_PEER6"); p != "" {
					host = p
				}
			}
			if p := os.Getenv("FLOWGATE_FIXTURE_PEER_PORT"); p != "" {
				n, err := strconv.Atoi(p)
				if err != nil || n < 1024 || n > 65534 {
					panic("invalid peer fixture port")
				}
				port = n
				if q.Protocol == "udp" {
					port++
				}
			}
			if q.Host != "" {
				ip := net.ParseIP(q.Host)
				_, p4, _ := net.ParseCIDR("10.79.0.0/24")
				_, p6, _ := net.ParseCIDR("fd79::/64")
				privateLab := false
				if parent := os.Getenv("FLOWGATE_PARENT_NETNS"); parent != "" {
					current, err := os.Readlink("/proc/self/ns/net")
					privateLab = err == nil && current != parent
				}
				if ip == nil || !(p4.Contains(ip) || p6.Contains(ip) || privateLab) || (ip.To4() == nil) != q.V6 {
					panic("fixture destination outside private prefixes")
				}
				host = q.Host
			}
			if q.Port != 0 {
				if q.Port < 1024 || q.Port > 65534 {
					panic("invalid fixture destination port")
				}
				port = q.Port
			}
			if net.ParseIP(host) == nil {
				panic("invalid fixture peer")
			}
			sendTimeout := timeout
			if q.TimeoutMS != 0 {
				if q.TimeoutMS < 100 || q.TimeoutMS > 60000 {
					panic("fixture timeout_ms must be 100..60000")
				}
				sendTimeout = time.Duration(q.TimeoutMS) * time.Millisecond
			}
			repeat, interval := 1, 300*time.Millisecond
			if q.Repeat != 0 {
				if q.Repeat < 1 || q.Repeat > 30 {
					panic("repeat must be 1..30")
				}
				repeat = q.Repeat
			}
			if q.IntervalMS != 0 {
				if q.IntervalMS < 50 || q.IntervalMS > 5000 {
					panic("interval_ms must be 50..5000")
				}
				interval = time.Duration(q.IntervalMS) * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
			mu.Lock()
			id := nextOpen
			nextOpen++
			open[id] = cancel
			mu.Unlock()
			jobs.Add(1)
			go func() {
				defer jobs.Done()
				defer func() { mu.Lock(); delete(open, id); mu.Unlock(); cancel() }()
				result := sendResult{Remote: net.JoinHostPort(host, strconv.Itoa(port)), Status: "cancelled"}
				defer func() { mu.Lock(); lastSend = &result; mu.Unlock() }()
				var d net.Dialer
				c, e := d.DialContext(ctx, key, result.Remote)
				if e != nil {
					result.Status, result.Error = "dial-failed", e.Error()
					return
				}
				defer c.Close()
				// "close" or the timeout ends the socket.
				go func() { <-ctx.Done(); c.Close() }()
				c.SetDeadline(time.Now().Add(sendTimeout))
				for i := 0; i < repeat; i++ {
					if i > 0 {
						select {
						case <-ctx.Done():
							return
						case <-time.After(interval):
						}
					}
					if _, e := c.Write([]byte("process-fixture")); e != nil {
						result.Status, result.Error = "write-failed", e.Error()
						return
					}
				}
				if n, err := c.Read(make([]byte, 128)); n > 0 {
					result.Status = "received"
				} else if err != nil {
					result.Status, result.Error = "read-failed", err.Error()
				}
			}()
		}
		mu.Lock()
		copy := map[string]int{}
		for k, v := range counts {
			copy[k] = v
		}
		reply := map[string]any{"counts": copy}
		if q.Op == "settle" && lastSend != nil {
			reply["last_send"] = *lastSend
		}
		mu.Unlock()
		if e := enc.Encode(reply); e != nil {
			fmt.Fprintln(os.Stderr, e)
			return
		}
	}
}
