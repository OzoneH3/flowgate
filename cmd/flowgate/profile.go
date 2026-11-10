package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"flowgate/internal/daemon"
	"flowgate/internal/serveprofile"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const profileCapability = "daemon-profile-v1"

var profileArtifacts = []string{"cpu.pprof", "summary.json"}

type profileCLIClient struct {
	call func(string, daemon.Request) (daemon.Response, error)
	wait func(context.Context, time.Duration) error
}

func profileCommand(args []string, out io.Writer) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return profileCLI(ctx, args, out, profileCLIClient{call: daemon.Call, wait: profileWait})
}

func profileWait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// An interrupted/expired call is never retried. In particular, a start whose
// response was lost might have succeeded: the operator must inspect status.
func (c profileCLIClient) request(ctx context.Context, socket string, q daemon.Request, generation string) (daemon.Response, error) {
	if err := ctx.Err(); err != nil {
		return daemon.Response{}, err
	}
	type result struct {
		r   daemon.Response
		err error
	}
	ch := make(chan result, 1)
	go func() { r, err := c.call(socket, q); ch <- result{r, err} }()
	select {
	case <-ctx.Done():
		return daemon.Response{}, ctx.Err()
	case got := <-ch:
		if got.err != nil {
			return got.r, fmt.Errorf("%s: %s: %w", q.Operation, got.r.ErrorCode, got.err)
		}
		if got.r.Error != "" {
			return got.r, fmt.Errorf("%s: %s: %s", q.Operation, got.r.ErrorCode, got.r.Error)
		}
		if generation != "" && got.r.Generation != generation {
			return got.r, fmt.Errorf("daemon generation changed; %s was not retried", q.Operation)
		}
		return got.r, nil
	}
}

func profileCLI(ctx context.Context, args []string, out io.Writer, client profileCLIClient) error {
	usage := "profile status|start|stop|fetch|capture --socket PATH [--seconds 30] [--id ID] [--output NEW_DIRECTORY]"
	if len(args) == 0 {
		return errors.New(usage)
	}
	op := args[0]
	if !slices.Contains([]string{"status", "start", "stop", "fetch", "capture"}, op) {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("profile "+op, flag.ContinueOnError)
	fs.SetOutput(out)
	socket := fs.String("socket", "", "primary control socket (required)")
	seconds := fs.Int64("seconds", 30, "capture duration, 5 to 60 seconds")
	id := fs.String("id", "", "exact capture ID; required for stop/fetch")
	output := fs.String("output", "", "new private output directory; required for capture/fetch")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *socket == "" {
		return errors.New(usage)
	}
	var secondsSet bool
	fs.Visit(func(f *flag.Flag) { secondsSet = secondsSet || f.Name == "seconds" })
	if op == "start" || op == "capture" {
		if *seconds < 5 || *seconds > 60 || *id != "" {
			return errors.New("start/capture requires 5..60 seconds and no --id")
		}
	} else if secondsSet {
		return errors.New("--seconds is only valid for start/capture")
	}
	if op == "stop" || op == "fetch" {
		if *id == "" {
			return errors.New("stop/fetch requires the exact --id from profile status/start")
		}
	} else if *id != "" {
		return errors.New("--id is only valid for stop/fetch")
	}
	if (op == "capture" || op == "fetch") != (*output != "") {
		return errors.New("--output is required only for capture/fetch and must name a new directory")
	}

	initial, err := client.request(ctx, *socket, daemon.Request{Version: 1, Operation: "list"}, "")
	if err != nil {
		return err
	}
	// Capability is endpoint-specific. list.ReadOnly can also describe degraded
	// protection, which must not prevent an authorized diagnostic capture.
	if initial.Generation == "" || initial.Permissions == nil || initial.Permissions.Role != "administrator" || !slices.Contains(initial.Capabilities, profileCapability) {
		return errors.New("daemon profiling is unavailable: use a supported primary control socket as its configured administrator")
	}
	generation := initial.Generation
	request := func(ctx context.Context, operation string, captureID string, artifact string, offset int64) (daemon.Response, error) {
		q := daemon.Request{Version: 1, Operation: operation, Generation: generation, ID: captureID, ProfileArtifact: artifact, ProfileOffset: offset}
		if operation == "profile-start" {
			q.DurationSeconds = *seconds
		}
		return client.request(ctx, *socket, q, generation)
	}

	var dir *os.File
	if *output != "" {
		dir, err = newProfileOutput(*output)
		if err != nil {
			return err // no start was sent
		}
		defer dir.Close()
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if op == "status" || op == "stop" {
		r, err := request(ctx, "profile-"+op, *id, "", 0)
		if err != nil {
			return err
		}
		return enc.Encode(r.Profile)
	}

	if op == "start" || op == "capture" {
		r, err := request(ctx, "profile-start", "", "", 0)
		if err != nil {
			return fmt.Errorf("%w; start was not retried; inspect profile status before starting again", err)
		}
		if r.Profile == nil || r.Profile.Active == nil || r.Profile.Active.ID == "" {
			return errors.New("start response has no capture ID; inspect profile status before starting again")
		}
		*id = r.Profile.Active.ID
		if err := enc.Encode(r.Profile); err != nil {
			return fmt.Errorf("capture %s started but status output failed: %w", *id, err)
		}
		if op == "start" {
			return nil
		}
	}

	captureCtx := ctx
	if op == "capture" {
		var cancel context.CancelFunc
		captureCtx, cancel = context.WithTimeout(ctx, time.Duration(*seconds+15)*time.Second)
		defer cancel()
	}
	var capture serveprofile.CaptureStatus
	for {
		r, err := request(captureCtx, "profile-status", "", "", 0)
		if err != nil {
			if op == "capture" && ctx.Err() != nil {
				stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_, stopErr := request(stopCtx, "profile-stop", *id, "", 0)
				cancel()
				if stopErr != nil {
					return fmt.Errorf("capture %s interrupted; stop failed (%v); recording remains time-bounded: %w", *id, stopErr, err)
				}
			}
			return fmt.Errorf("capture %s: %w; use profile status/fetch to recover retained artifacts", *id, err)
		}
		var found bool
		capture, found = findProfileCapture(r.Profile, *id)
		if !found {
			return fmt.Errorf("capture %s is absent or expired; no other capture was fetched", *id)
		}
		if capture.State == "finished" || capture.State == "canceled" || capture.State == "failed" {
			break
		}
		if op == "fetch" {
			return fmt.Errorf("capture %s is still %s; wait or stop that exact capture first", *id, capture.State)
		}
		if err := client.wait(captureCtx, time.Second); err != nil {
			// The next request observes cancellation and follows the same exact-ID
			// stop path. A duration timeout does not cancel another client's work.
			continue
		}
	}
	var missing []string
	for _, artifact := range profileArtifacts {
		if !slices.Contains(capture.Artifacts, artifact) {
			missing = append(missing, artifact)
			continue
		}
		data, err := fetchProfileArtifact(captureCtx, artifact, func(ctx context.Context, offset int64) (daemon.Response, error) {
			return request(ctx, "profile-fetch", *id, artifact, offset)
		})
		if err != nil {
			return err
		}
		if err := writeProfileOutput(dir, artifact, data); err != nil {
			return fmt.Errorf("capture %s retained on daemon; output failed (no overwrite or retry): %w", *id, err)
		}
	}
	if err := enc.Encode(struct {
		Generation string                     `json:"generation"`
		Capture    serveprofile.CaptureStatus `json:"capture"`
		Output     string                     `json:"output"`
	}{generation, capture, dir.Name()}); err != nil {
		return err
	}
	if capture.State != "finished" || len(missing) != 0 {
		return fmt.Errorf("capture %s was %s; partial artifacts saved; missing=%v: %s", *id, capture.State, missing, capture.Error)
	}
	return nil
}

func findProfileCapture(s *serveprofile.Status, id string) (serveprofile.CaptureStatus, bool) {
	if s != nil {
		if s.Active != nil && s.Active.ID == id {
			return *s.Active, true
		}
		for _, c := range s.Recent {
			if c.ID == id {
				return c, true
			}
		}
	}
	return serveprofile.CaptureStatus{}, false
}

func newProfileOutput(path string) (*os.File, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, fmt.Errorf("output must be a new directory: %w", err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || st.Mode().Perm() != 0700 || stat.Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, errors.New("output directory must be owned by the caller with mode 0700")
	}
	return f, nil
}

func writeProfileOutput(dir *os.File, name string, data []byte) error {
	if !slices.Contains(profileArtifacts, name) {
		return errors.New("unrecognized profile artifact")
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
}

// Fetch bounded chunks into bounded local memory and verify their common hash
// before writing any artifact. A partial or changed response is never resumed
// under a different generation, capture ID or artifact name.
func fetchProfileArtifact(ctx context.Context, artifact string, fetch func(context.Context, int64) (daemon.Response, error)) ([]byte, error) {
	limit := int64(8 << 20)
	if artifact == "summary.json" {
		limit = 2 << 20
	} else if artifact != "cpu.pprof" {
		return nil, errors.New("unrecognized profile artifact")
	}
	var data bytes.Buffer
	var total int64
	var expectedHash string
	for {
		offset := int64(data.Len())
		r, err := fetch(ctx, offset)
		if err != nil {
			return nil, err
		}
		c := r.ProfileChunk
		if c == nil || c.Offset != offset || c.Total <= 0 || c.Total > limit || len(c.Data) == 0 || len(c.Data) > 256<<10 || int64(len(c.Data)) > c.Total-offset {
			return nil, fmt.Errorf("invalid bounded chunk for %s at offset %d", artifact, offset)
		}
		hash, err := hex.DecodeString(c.SHA256)
		if err != nil || len(hash) != sha256.Size {
			return nil, fmt.Errorf("invalid checksum for %s", artifact)
		}
		if offset == 0 {
			total, expectedHash = c.Total, c.SHA256
		} else if c.Total != total || c.SHA256 != expectedHash {
			return nil, fmt.Errorf("%s changed during fetch", artifact)
		}
		data.Write(c.Data)
		if int64(data.Len()) == total {
			sum := sha256.Sum256(data.Bytes())
			if hex.EncodeToString(sum[:]) != expectedHash {
				return nil, fmt.Errorf("checksum mismatch for %s", artifact)
			}
			return data.Bytes(), nil
		}
	}
}
