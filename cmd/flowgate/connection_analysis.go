package main

import (
	"encoding/json"
	"flag"
	"flowgate/internal/daemon"
	"fmt"
	"io"
	"time"
)

func connectionAnalysisCommand(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("connection-analyze", flag.ContinueOnError)
	socket := flags.String("socket", monitorSocket+".monitor", "authenticated Activity API socket")
	watch := flags.Duration("watch", 0, "watch duration (350ms..10s; zero rechecks once)")
	port := flags.Uint("local-port", 0, "restrict analysis to this local port")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *port > 65535 || *watch < 0 || (*watch > 0 && *watch < 350*time.Millisecond) ||
		*watch > 10*time.Second {
		return fmt.Errorf("expected --local-port 0..65535 and --watch 0 or 350ms..10s")
	}
	reply, err := daemon.Call(*socket, daemon.Request{Version: 1, Operation: "connection-analyze",
		ConnectionAnalysis: &daemon.ConnectionAnalysisQuery{WatchMS: int(watch.Milliseconds()), LocalPort: uint16(*port)}})
	if err == nil && reply.ConnectionAnalysis == nil {
		return fmt.Errorf("this Activity API does not support connection analysis")
	}
	if err != nil && reply.ErrorCode == "" {
		return err
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if writeErr := encoder.Encode(reply); writeErr != nil {
		return writeErr
	}
	return err
}
