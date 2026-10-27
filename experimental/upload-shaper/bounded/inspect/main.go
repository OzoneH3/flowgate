// Read-only inventory for the isolated bounded-discovery fixture.
package main

import (
	"encoding/json"
	"flowgate/internal/identity"
	"fmt"
	"os"
)

func main() {
	ss, e := identity.SocketsLimited(4096)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(ss)
}
