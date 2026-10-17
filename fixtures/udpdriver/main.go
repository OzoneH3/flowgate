// Isolated verification fixture only. Not a production launch/authorization path.
package main

import (
	"context"
	"flowgate/internal/identity"
	"flowgate/internal/udpaccount"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

func main() {
	if len(os.Args) != 4 || os.Getenv("FLOWGATE_PARENT_NETNS") == "" || os.Getenv("FLOWGATE_PARENT_NETNS") == identity.NetNS() {
		panic("requires explicitly disposable namespace")
	}
	uid, e := strconv.ParseUint(os.Args[3], 10, 32)
	if e != nil {
		panic(e)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if e = udpaccount.Run(ctx, os.Args[1], os.Args[2], uint32(uid)); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
