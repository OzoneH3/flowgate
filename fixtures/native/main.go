// A small independent receiver, built under two paths to test application rules.
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	c, e := net.ListenPacket("udp4", os.Args[1])
	if e != nil {
		panic(e)
	}
	defer c.Close()
	fmt.Println("READY")
	b := make([]byte, 128)
	for {
		n, _, e := c.ReadFrom(b)
		if e != nil {
			panic(e)
		}
		if n > 0 {
			fmt.Println("RECEIVED")
		}
	}
}
