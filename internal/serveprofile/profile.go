package serveprofile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const profileLimit = 8 << 20

var errLimit = errors.New("diagnostic output limit reached")

// No network listener, signals, payloads or automatic retries. A configured
// administrator may trigger the root-armed manual mode through the local API.
// The root service environment is the sole opt-in. Each process captures once.
func StartFromEnvironment(ctx context.Context, sample func() any) func() {
	dir := os.Getenv("FLOWGATE_PROFILE_DIR")
	if dir == "" {
		return func() {}
	}
	child, cancel := context.WithCancel(ctx)
	manualMode := os.Getenv("FLOWGATE_PROFILE_MANUAL") == "1"
	var trigger chan struct{}
	if manualMode {
		manual.Lock()
		if manual.trigger != nil {
			manual.Unlock()
			cancel()
			return func() {}
		}
		trigger = make(chan struct{}, 1)
		manual.trigger = trigger
		manual.state = "armed"
		manual.Unlock()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		delay, duration := 20*time.Second, 60*time.Second
		if manualMode {
			select {
			case <-child.Done():
				manualState("canceled", nil)
				return
			case <-trigger:
			}
			delay, duration = 0, 120*time.Second
			manualState("starting", nil)
		}
		if err := capture(child, dir, delay, duration, sample); err != nil {
			if manualMode {
				manualState("failed", err)
			}
			log.Printf("private diagnostics: %v (enforcement unchanged)", err)
		} else if manualMode {
			manualState("finished", nil)
		}
	}()
	return func() { cancel(); <-done }
}

type cappedWriter struct {
	dst  io.Writer
	left int64
	err  error
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if int64(len(p)) > w.left {
		w.err = errLimit
		return 0, w.err
	}
	n, err := w.dst.Write(p)
	w.left -= int64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}

// Walk without following any symlink and pin the final private directory FD.
// Output never uses a pathname after this check, including if an ancestor moves.
func privateDirectory(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("profile directory must be absolute and clean")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0700 {
		unix.Close(fd)
		return -1, fmt.Errorf("profile directory must be service-owned mode0700")
	}
	return fd, nil
}
func createAt(dir int, name string) (*os.File, error) {
	fd, err := unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func usage() map[string]int64 {
	var u unix.Rusage
	if unix.Getrusage(unix.RUSAGE_SELF, &u) != nil {
		return nil
	}
	return map[string]int64{"user_cpu_us": u.Utime.Sec*1000000 + u.Utime.Usec, "system_cpu_us": u.Stime.Sec*1000000 + u.Stime.Usec, "lifetime_max_rss_kib": u.Maxrss}
}

var captureMu sync.Mutex // Go CPU/mutex profiling is process-global.
func capture(ctx context.Context, dir string, delay, duration time.Duration, samples ...func() any) error {
	if duration <= 0 || duration > 120*time.Second || delay < 0 || delay > 60*time.Second {
		return fmt.Errorf("profile timing out of bounds")
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	if !captureMu.TryLock() {
		return fmt.Errorf("profile already running")
	}
	defer captureMu.Unlock()
	fd, err := privateDirectory(dir)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	names := []string{"cpu.pprof", "mutex.pprof", "summary.json", "started.json"}
	files := make([]*os.File, 0, len(names))
	for _, name := range names {
		f, e := createAt(fd, name)
		if e != nil {
			for i, f := range files {
				f.Close()
				unix.Unlinkat(fd, names[i], 0)
			}
			return fmt.Errorf("create private diagnostics: %w", e)
		}
		files = append(files, f)
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	cpu := &cappedWriter{dst: files[0], left: profileLimit}
	if err = pprof.StartCPUProfile(cpu); err != nil {
		return err
	}
	fraction := runtime.SetMutexProfileFraction(20)
	var stateBefore, stateAfter any
	if len(samples) > 0 && samples[0] != nil {
		stateBefore = samples[0]()
	}
	start := time.Now()
	before := usage()
	s := &session{from: start, until: start.Add(duration)}
	active.Store(s)
	started := map[string]any{"started_at": start.UTC(), "maximum_duration_seconds": duration.Seconds(), "pid": os.Getpid(), "scope": "process CPU samples; elapsed histograms overlap; no packet payloads"}
	err = json.NewEncoder(files[3]).Encode(started)
	if err != nil {
		active.Store(nil)
		runtime.SetMutexProfileFraction(fraction)
		pprof.StopCPUProfile()
		return err
	}
	manual.Lock()
	if manual.state == "starting" {
		manual.state = "running"
	}
	manual.Unlock()
	log.Printf("private diagnostics: bounded sample started (maximum %.0f seconds)", duration.Seconds())
	stop := time.NewTimer(duration)
	canceled := false
	select {
	case <-ctx.Done():
		canceled = true
	case <-stop.C:
	}
	stop.Stop()
	active.Store(nil)
	end := time.Now()
	after := usage()
	if len(samples) > 0 && samples[0] != nil {
		stateAfter = samples[0]()
	}
	runtime.SetMutexProfileFraction(fraction)
	pprof.StopCPUProfile()
	errorsFound := []string{}
	if cpu.err != nil {
		errorsFound = append(errorsFound, "cpu: "+cpu.err.Error())
	}
	mutex := &cappedWriter{dst: files[1], left: profileLimit}
	if err = pprof.Lookup("mutex").WriteTo(mutex, 0); err != nil {
		errorsFound = append(errorsFound, "mutex: "+err.Error())
	}
	result := snapshot(s)
	result["schema"] = "private-profile-v1"
	result["started_at"] = start.UTC()
	result["finished_at"] = end.UTC()
	result["elapsed_seconds"] = end.Sub(start).Seconds()
	result["state_before"] = stateBefore
	result["state_after"] = stateAfter
	result["usage_before"] = before
	result["usage_after"] = after
	result["canceled"] = canceled
	result["errors"] = errorsFound
	result["mutex_sample_fraction"] = 20
	result["interpretation"] = "CPU stack samples and process CPU delta are execution. Elapsed histograms include blocking/scheduling and overlap; do not add nested stages or compare them as CPU percentages. Mutex profile is sampled contention, not all off-CPU time. Worker visits include census retries. Verdicts are submission outcomes, not receiver delivery. No total offered network-packet denominator."
	metadata := &cappedWriter{dst: files[2], left: 2 << 20}
	if err = json.NewEncoder(metadata).Encode(result); err != nil {
		return err
	}
	for _, f := range files {
		if err = f.Sync(); err != nil {
			return err
		}
	}
	log.Print("private diagnostics: sample finished; private files retained, capture disabled")
	if len(errorsFound) != 0 {
		return fmt.Errorf("incomplete profile: %v", errorsFound)
	}
	return nil
}
