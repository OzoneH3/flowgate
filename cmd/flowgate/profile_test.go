package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flowgate/internal/daemon"
	"flowgate/internal/serveprofile"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func profileTestDirectory(t *testing.T) string {
	t.Helper()
	if err := os.MkdirAll("../../.workspace/tmp", 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("../../.workspace/tmp", "profile-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func profileTestResponse() daemon.Response {
	return daemon.Response{Generation: "generation-a", Capabilities: []string{profileCapability}, Permissions: &daemon.Permissions{Role: "administrator"}}
}

func profileTestChunk(data []byte, offset int64) *serveprofile.ArtifactChunk {
	h := sha256.Sum256(data)
	end := min(offset+256<<10, int64(len(data)))
	return &serveprofile.ArtifactChunk{Offset: offset, Total: int64(len(data)), SHA256: hex.EncodeToString(h[:]), Data: data[offset:end]}
}

type profileCLIMock struct {
	mu          sync.Mutex
	calls       []daemon.Request
	statusCalls int
	terminal    string
	modify      func(daemon.Request, *daemon.Response) error
}

func (m *profileCLIMock) call(_ string, q daemon.Request) (daemon.Response, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, q)
	r := profileTestResponse()
	switch q.Operation {
	case "list":
	case "profile-start":
		r.Profile = &serveprofile.Status{Active: &serveprofile.CaptureStatus{ID: "capture-a", State: "running"}}
	case "profile-stop":
		r.Profile = &serveprofile.Status{Recent: []serveprofile.CaptureStatus{{ID: q.ID, State: "canceled", Artifacts: profileArtifacts}}}
	case "profile-status":
		m.statusCalls++
		state := m.terminal
		if state == "" {
			state = "finished"
		}
		r.Profile = &serveprofile.Status{Recent: []serveprofile.CaptureStatus{{ID: "capture-a", State: state, Artifacts: profileArtifacts}}}
	case "profile-fetch":
		data := []byte("cpu data")
		if q.ProfileArtifact == "summary.json" {
			data = []byte(`{"complete":true}`)
		}
		r.ProfileChunk = profileTestChunk(data, q.ProfileOffset)
	default:
		return r, errors.New("unexpected request")
	}
	if m.modify != nil {
		return r, m.modify(q, &r)
	}
	return r, nil
}

func (m *profileCLIMock) client() profileCLIClient {
	return profileCLIClient{call: m.call, wait: func(context.Context, time.Duration) error { return nil }}
}

func TestProfileCLICapturePinsGenerationAndWritesPrivateArtifacts(t *testing.T) {
	dir := filepath.Join(profileTestDirectory(t), "capture")
	m := &profileCLIMock{}
	var out bytes.Buffer
	if err := profileCLI(context.Background(), []string{"capture", "--socket", "test.sock", "--seconds", "5", "--output", dir}, &out, m.client()); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil || st.Mode().Perm() != 0700 {
		t.Fatal(st, err)
	}
	for _, name := range profileArtifacts {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal(name, st, err)
		}
	}
	starts, fetches := 0, 0
	for _, q := range m.calls {
		if q.Operation == "list" {
			continue
		}
		if q.Generation != "generation-a" {
			t.Fatal("request unpinned", q)
		}
		if q.Operation == "profile-start" {
			starts++
			if q.DurationSeconds != 5 {
				t.Fatal(q)
			}
		}
		if q.Operation == "profile-fetch" {
			fetches++
			if q.ID != "capture-a" || q.ProfileOffset != 0 {
				t.Fatal(q)
			}
		}
	}
	if starts != 1 || fetches != 2 || !strings.Contains(out.String(), "capture-a") {
		t.Fatal(starts, fetches, out.String())
	}
}

func TestProfileCLIExistingOutputRefusesBeforeStart(t *testing.T) {
	dir := profileTestDirectory(t)
	m := &profileCLIMock{}
	err := profileCLI(context.Background(), []string{"capture", "--socket", "s", "--output", dir}, &bytes.Buffer{}, m.client())
	if err == nil || !strings.Contains(err.Error(), "new directory") || len(m.calls) != 1 {
		t.Fatal(err, m.calls)
	}
}

func TestProfileCLIChangedGenerationDoesNotFetchOrRetry(t *testing.T) {
	m := &profileCLIMock{modify: func(q daemon.Request, r *daemon.Response) error {
		if q.Operation == "profile-start" {
			r.Generation = "new-generation"
		}
		return nil
	}}
	err := profileCLI(context.Background(), []string{"start", "--socket", "s"}, &bytes.Buffer{}, m.client())
	if err == nil || !strings.Contains(err.Error(), "generation changed") || len(m.calls) != 2 {
		t.Fatal(err, m.calls)
	}
}

func TestProfileCLIStartFailureDoesNotRetry(t *testing.T) {
	m := &profileCLIMock{modify: func(q daemon.Request, r *daemon.Response) error {
		if q.Operation == "profile-start" {
			return errors.New("response lost")
		}
		return nil
	}}
	err := profileCLI(context.Background(), []string{"start", "--socket", "s"}, &bytes.Buffer{}, m.client())
	if err == nil || !strings.Contains(err.Error(), "not retried") || len(m.calls) != 2 {
		t.Fatal(err, m.calls)
	}
}

func TestProfileCLICanceledResultSavesOnlyItsArtifacts(t *testing.T) {
	dir := filepath.Join(profileTestDirectory(t), "capture")
	m := &profileCLIMock{terminal: "canceled"}
	err := profileCLI(context.Background(), []string{"capture", "--socket", "s", "--output", dir}, &bytes.Buffer{}, m.client())
	if err == nil || !strings.Contains(err.Error(), "partial artifacts saved") {
		t.Fatal(err)
	}
	for _, name := range profileArtifacts {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProfileCLIInterruptStopsExactCaptureOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := filepath.Join(profileTestDirectory(t), "capture")
	m := &profileCLIMock{terminal: "running"}
	client := m.client()
	client.wait = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	err := profileCLI(ctx, []string{"capture", "--socket", "s", "--output", dir}, &bytes.Buffer{}, client)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	stops := 0
	for _, q := range m.calls {
		if q.Operation == "profile-stop" {
			stops++
			if q.ID != "capture-a" || q.Generation != "generation-a" {
				t.Fatal(q)
			}
		}
	}
	if stops != 1 {
		t.Fatal(m.calls)
	}
}

func TestProfileCLIFetchWriteFailureDoesNotOverwriteOrRetry(t *testing.T) {
	dir := filepath.Join(profileTestDirectory(t), "capture")
	m := &profileCLIMock{modify: func(q daemon.Request, r *daemon.Response) error {
		if q.Operation == "profile-fetch" {
			return os.WriteFile(filepath.Join(dir, "cpu.pprof"), []byte("must remain"), 0600)
		}
		return nil
	}}
	err := profileCLI(context.Background(), []string{"fetch", "--socket", "s", "--id", "capture-a", "--output", dir}, &bytes.Buffer{}, m.client())
	if err == nil || !strings.Contains(err.Error(), "output failed") {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "cpu.pprof"))
	if string(got) != "must remain" || len(m.calls) != 3 {
		t.Fatal(string(got), m.calls)
	}
}

func TestProfileCLIRequiresExplicitIDAndCapability(t *testing.T) {
	for _, op := range []string{"stop", "fetch"} {
		m := &profileCLIMock{}
		if err := profileCLI(context.Background(), []string{op, "--socket", "s"}, &bytes.Buffer{}, m.client()); err == nil || len(m.calls) != 0 {
			t.Fatal(op, err, m.calls)
		}
	}
	m := &profileCLIMock{modify: func(q daemon.Request, r *daemon.Response) error { r.Capabilities = nil; return nil }}
	if err := profileCLI(context.Background(), []string{"start", "--socket", "s"}, &bytes.Buffer{}, m.client()); err == nil || len(m.calls) != 1 {
		t.Fatal(err, m.calls)
	}
}

func TestProfileCLIChunkBoundariesAndChecksum(t *testing.T) {
	data := bytes.Repeat([]byte("a"), 300000)
	var offsets []int64
	got, err := fetchProfileArtifact(context.Background(), "cpu.pprof", func(_ context.Context, offset int64) (daemon.Response, error) {
		offsets = append(offsets, offset)
		return daemon.Response{ProfileChunk: profileTestChunk(data, offset)}, nil
	})
	if err != nil || !bytes.Equal(got, data) || len(offsets) != 2 || offsets[1] != 256<<10 {
		t.Fatal(err, len(got), offsets)
	}
	for _, fault := range []string{"offset", "total", "hash", "empty", "changed", "huge"} {
		t.Run(fault, func(t *testing.T) {
			_, err := fetchProfileArtifact(context.Background(), "cpu.pprof", func(_ context.Context, offset int64) (daemon.Response, error) {
				c := profileTestChunk(data, offset)
				switch fault {
				case "offset":
					c.Offset++
				case "total":
					c.Total = 8<<20 + 1
				case "hash":
					c.SHA256 = strings.Repeat("0", 64)
				case "empty":
					c.Data = nil
				case "changed":
					if offset > 0 {
						c.SHA256 = strings.Repeat("0", 64)
					}
				case "huge":
					c.Data = data
				}
				return daemon.Response{ProfileChunk: c}, nil
			})
			if err == nil {
				t.Fatal("accepted", fault)
			}
		})
	}
}

func TestProfileCLIFailedSummaryStillExported(t *testing.T) {
	dir := filepath.Join(profileTestDirectory(t), "capture")
	m := &profileCLIMock{terminal: "failed", modify: func(q daemon.Request, r *daemon.Response) error {
		if q.Operation == "profile-status" {
			r.Profile.Recent[0].Artifacts = []string{"summary.json"}
			r.Profile.Recent[0].Error = "profile unavailable"
		}
		return nil
	}}
	err := profileCLI(context.Background(), []string{"fetch", "--socket", "s", "--id", "capture-a", "--output", dir}, &bytes.Buffer{}, m.client())
	if err == nil || !strings.Contains(err.Error(), "partial artifacts saved") {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "summary.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "cpu.pprof")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestProfileCLIAdvertisedPrimaryCapabilityWorksWhileProtectionReadOnly(t *testing.T) {
	m := &profileCLIMock{modify: func(q daemon.Request, r *daemon.Response) error {
		r.ReadOnly = true // degraded protection is distinct from a companion endpoint
		return nil
	}}
	if err := profileCLI(context.Background(), []string{"status", "--socket", "s"}, &bytes.Buffer{}, m.client()); err != nil {
		t.Fatal(err)
	}
	if len(m.calls) != 2 || m.calls[1].Operation != "profile-status" {
		t.Fatal(m.calls)
	}
}
