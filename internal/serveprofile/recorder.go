package serveprofile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"time"
)

// On-demand captures are private administrator diagnostics. Nothing samples until
// Start, no filesystem paths enter the daemon, and no listener is opened here.
const (
	DefaultDuration  = 30 * time.Second
	MaxDuration      = 60 * time.Second
	summaryLimit     = 2 << 20
	retainedCaptures = 2
)

type CaptureStatus struct {
	ID              string    `json:"id"`
	State           string    `json:"state"`
	Error           string    `json:"error,omitempty"`
	StartedAt       time.Time `json:"started_at,omitempty"`
	FinishedAt      time.Time `json:"finished_at,omitempty"`
	DurationSeconds int64     `json:"duration_seconds"`
	Artifacts       []string  `json:"artifacts,omitempty"`
}
type Status struct {
	Active *CaptureStatus  `json:"active,omitempty"`
	Recent []CaptureStatus `json:"recent"`
}
type recording struct {
	status    CaptureStatus
	artifacts map[string][]byte
	hashes    map[string]string
	cancel    context.CancelFunc
	done      chan struct{}
}
type Recorder struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	sample  func() any
	current *recording
	recent  []*recording
	closed  bool
}

func NewRecorder(ctx context.Context, sample func() any) *Recorder {
	ctx, cancel := context.WithCancel(ctx)
	return &Recorder{ctx: ctx, cancel: cancel, sample: sample}
}
func copyCapture(s CaptureStatus) CaptureStatus {
	s.Artifacts = append([]string(nil), s.Artifacts...)
	return s
}
func (r *Recorder) statusLocked() Status {
	s := Status{Recent: []CaptureStatus{}}
	if r.current != nil {
		x := copyCapture(r.current.status)
		s.Active = &x
	}
	for _, v := range r.recent {
		s.Recent = append(s.Recent, copyCapture(v.status))
	}
	return s
}
func (r *Recorder) Status() Status { r.mu.Lock(); defer r.mu.Unlock(); return r.statusLocked() }

func (r *Recorder) Start(seconds int64) (Status, error) {
	if seconds == 0 {
		seconds = int64(DefaultDuration / time.Second)
	}
	if seconds < 5 || seconds > int64(MaxDuration/time.Second) {
		return r.Status(), fmt.Errorf("profile duration must be 5..60 seconds")
	}
	return r.start(time.Duration(seconds) * time.Second)
}

// Internal duration permits short lifecycle tests, without exposing an unbounded
// or sub-five-second API mode. Global captureMu also excludes legacy profiling.
func (r *Recorder) start(duration time.Duration) (Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ctx.Err() != nil {
		return r.statusLocked(), fmt.Errorf("profiler closed")
	}
	if r.current != nil {
		return r.statusLocked(), fmt.Errorf("profile already running")
	}
	if !captureMu.TryLock() {
		return r.statusLocked(), fmt.Errorf("another process profile is running")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		captureMu.Unlock()
		return r.statusLocked(), err
	}
	ctx, cancel := context.WithCancel(r.ctx)
	v := &recording{status: CaptureStatus{ID: hex.EncodeToString(id[:]), State: "requested", DurationSeconds: int64(duration / time.Second)}, cancel: cancel, done: make(chan struct{})}
	r.current = v
	go r.run(ctx, v, duration)
	return r.statusLocked(), nil
}
func (r *Recorder) Stop(id string) (Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id == "" || r.current == nil || r.current.status.ID != id {
		return r.statusLocked(), fmt.Errorf("active profile ID does not match")
	}
	r.current.cancel()
	return r.statusLocked(), nil
}

const ArtifactChunkLimit = 256 << 10

// ArtifactChunk is immutable by copy. Fetch cannot allocate an entire profile
// per connection; the API transports at most 256 KiB before base64 encoding.
type ArtifactChunk struct {
	Data   []byte `json:"data"`
	Offset int64  `json:"offset"`
	Total  int64  `json:"total"`
	SHA256 string `json:"sha256"`
}

func (r *Recorder) Fetch(id, name string, offset int64) (ArtifactChunk, error) {
	if name != "cpu.pprof" && name != "summary.json" {
		return ArtifactChunk{}, fmt.Errorf("unknown profile artifact")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.recent {
		if v.status.ID == id {
			data, ok := v.artifacts[name]
			if !ok {
				return ArtifactChunk{}, fmt.Errorf("profile artifact unavailable")
			}
			if offset < 0 || offset > int64(len(data)) {
				return ArtifactChunk{}, fmt.Errorf("profile offset out of bounds")
			}
			end := offset + ArtifactChunkLimit
			if end > int64(len(data)) {
				end = int64(len(data))
			}
			return ArtifactChunk{Data: append([]byte(nil), data[offset:end]...), Offset: offset, Total: int64(len(data)), SHA256: v.hashes[name]}, nil
		}
	}
	return ArtifactChunk{}, fmt.Errorf("profile not complete or no longer retained")
}
func (r *Recorder) Close() {
	r.mu.Lock()
	r.closed = true
	r.cancel()
	v := r.current
	r.mu.Unlock()
	if v != nil {
		<-v.done
	}
}
func (r *Recorder) run(ctx context.Context, v *recording, duration time.Duration) {
	// The API caller is labelled separately; this goroutine owns capture overhead.
	pprof.SetGoroutineLabels(pprof.WithLabels(ctx, pprof.Labels("flowgate_work", "profiling")))
	// A final state is published only once CPU sampling has stopped and the global
	// instrumentation pointer is removed. Closing the daemon waits for this cleanup.
	defer close(v.done)
	defer v.cancel()
	var cpu, summary bytes.Buffer
	w := &cappedWriter{dst: &cpu, left: profileLimit}
	result := map[string]any{"schema": "daemon-profile-v1", "id": v.status.ID, "pid": os.Getpid(), "go_version": runtime.Version(), "gomaxprocs": runtime.GOMAXPROCS(0), "requested_duration_seconds": duration.Seconds(), "scope": "daemon Go CPU stack samples and process CPU totals; no kernel callee stacks or helper process stacks"}
	var captureErr error
	state := "finished"
	start := time.Now()
	end := start
	if ctx.Err() != nil {
		state = "canceled"
	} else if err := pprof.StartCPUProfile(w); err != nil {
		captureErr = err
		state = "failed"
	} else {
		// Metadata readers are fixed daemon callbacks of already-published state. They
		// do not perform a new ownership census or consume accounting collector rows.
		if r.sample != nil {
			result["state_before"] = r.sample()
		}
		start = time.Now()
		before := usage()
		s := &session{from: start, until: start.Add(duration)}
		active.Store(s)
		r.mu.Lock()
		v.status.State = "running"
		v.status.StartedAt = start
		r.mu.Unlock()
		timer := time.NewTimer(duration)
		select {
		case <-timer.C:
		case <-ctx.Done():
			state = "canceled"
		}
		timer.Stop()
		active.Store(nil)
		end = time.Now()
		after := usage()
		pprof.StopCPUProfile()
		if r.sample != nil {
			result["state_after"] = r.sample()
		}
		for k, x := range snapshot(s) {
			result[k] = x
		}
		result["usage_before"], result["usage_after"] = before, after
		result["cpu_profile_envelope"] = "Go sampling includes brief metadata/setup and profiler flush outside the process CPU bookends; use profile duration and summary timestamps separately"
		if w.err != nil {
			captureErr = fmt.Errorf("cpu profile incomplete: %w", w.err)
			state = "failed"
		}
	}
	result["started_at"], result["finished_at"], result["elapsed_seconds"] = start.UTC(), end.UTC(), end.Sub(start).Seconds()
	result["state"] = state
	result["interpretation"] = "CPU samples are execution. Elapsed stage histograms overlap and include waiting; do not add inclusive stacks. FD-table attempts are not full censuses. Kernel execution is not resolved into kernel callee stacks; helper CPU is outside this daemon profile. No mutex profile is captured, because its process-lifetime samples would contaminate repeated windows."
	if captureErr != nil {
		result["error"] = captureErr.Error()
	}
	sw := &cappedWriter{dst: &summary, left: summaryLimit}
	if err := json.NewEncoder(sw).Encode(result); err != nil {
		captureErr = fmt.Errorf("profile summary incomplete: %w", err)
		state = "failed"
		summary.Reset()
		sw = &cappedWriter{dst: &summary, left: summaryLimit}
		_ = json.NewEncoder(sw).Encode(map[string]any{"schema": "daemon-profile-v1", "id": v.status.ID, "state": "failed", "error": captureErr.Error(), "started_at": start.UTC(), "finished_at": end.UTC(), "scope": "summary limit reached; detailed metadata omitted"})
	}
	artifacts := map[string][]byte{}
	if cpu.Len() > 0 && w.err == nil {
		artifacts["cpu.pprof"] = cpu.Bytes()
	}
	if summary.Len() > 0 && sw.err == nil {
		artifacts["summary.json"] = summary.Bytes()
	}
	// Release global sampling ownership before publishing completion. Start still
	// sees current!=nil until the status lock below, so it cannot race completion.
	captureMu.Unlock()
	r.mu.Lock()
	v.status.State = state
	v.status.StartedAt = start
	v.status.FinishedAt = end
	if captureErr != nil {
		v.status.Error = captureErr.Error()
	}
	for _, name := range []string{"cpu.pprof", "summary.json"} {
		if _, ok := artifacts[name]; ok {
			v.status.Artifacts = append(v.status.Artifacts, name)
		}
	}
	v.artifacts = artifacts
	v.hashes = map[string]string{}
	for name, data := range artifacts {
		h := sha256.Sum256(data)
		v.hashes[name] = hex.EncodeToString(h[:])
	}
	r.current = nil
	r.recent = append(r.recent, v)
	if len(r.recent) > retainedCaptures {
		r.recent[0] = nil
		r.recent = r.recent[1:]
	}
	r.mu.Unlock()
}
