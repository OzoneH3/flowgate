package daemon

import (
	"encoding/json"
	"flowgate/internal/identity"
	"reflect"
	"time"
)

const (
	ConnectionAnalysisCapability = "activity-connection-analysis-v1"
	maxAnalysisWatchMS           = 10000
	analysisInterval             = 350 * time.Millisecond
	analysisGrace                = 12 * time.Second
	analysisRowLimit             = 64
	analysisConnectionBytes      = 3 * 1024 * 1024 // Leave room for API metadata under the desktop's 4 MiB limit.
	analysisHistoryLimit         = 8
	analysisHolderLimit          = 8
)

type ConnectionAnalysisQuery struct {
	WatchMS   int    `json:"watch_ms,omitempty"`
	LocalPort uint16 `json:"local_port,omitempty"`
}

func (q *ConnectionAnalysisQuery) timeout() time.Duration {
	if q == nil || q.WatchMS < 0 || q.WatchMS > maxAnalysisWatchMS {
		return analysisGrace
	}
	return time.Duration(q.WatchMS)*time.Millisecond + analysisGrace
}

type ConnectionAnalysis struct {
	Scope                string                `json:"observation_scope"`
	BaselineCollected    time.Time             `json:"baseline_collected_at"`
	BaselineComplete     bool                  `json:"baseline_complete"`
	Started              time.Time             `json:"started_at"`
	Finished             time.Time             `json:"finished_at"`
	IntervalMS           int64                 `json:"interval_ms"`
	Samples              []AnalysisSample      `json:"samples"`
	Connections          []*AnalyzedConnection `json:"connections"`
	BaselineUnidentified int                   `json:"baseline_unidentified"`
	Recovered            int                   `json:"recovered"`
	LatestVerified       int                   `json:"latest_verified"`
	CollectionMS         int64                 `json:"collection_ms"`
	Truncated            bool                  `json:"truncated"`
}

type AnalysisSample struct {
	Started    time.Time `json:"started_at"`
	Collected  time.Time `json:"collected_at"`
	DurationMS int64     `json:"duration_ms"`
	Complete   bool      `json:"complete"`
}

type AnalyzedConnection struct {
	Socket           identity.Socket         `json:"socket"`
	OriginalAt       time.Time               `json:"original_observed_at"`
	OriginalCategory string                  `json:"original_category"`
	OriginalReason   string                  `json:"original_reason"`
	FromActivity     bool                    `json:"from_activity"`
	Observations     []ConnectionObservation `json:"observations"`
	LastSampledAt    time.Time               `json:"last_sampled_at"`
	HistoryTruncated bool                    `json:"history_truncated,omitempty"`
	recovered        bool
}

type ConnectionObservation struct {
	At               time.Time            `json:"observed_at"`
	Category         string               `json:"category"`
	Reason           string               `json:"reason"`
	Local            string               `json:"local,omitempty"`
	Remote           string               `json:"remote,omitempty"`
	Holders          []AnalysisHolder     `json:"holders"`
	HoldersTruncated bool                 `json:"holders_truncated,omitempty"`
	Application      *AnalysisApplication `json:"verified_application,omitempty"`
}

type AnalysisHolder struct {
	PID                int                   `json:"pid"`
	ThreadGroup        int                   `json:"thread_group_pid,omitempty"`
	Start              string                `json:"start_ticks"`
	UID                uint32                `json:"uid"`
	Executable         string                `json:"executable,omitempty"`
	WindowsImage       *AnalysisWindowsImage `json:"windows_image,omitempty"`
	WindowsImageReason string                `json:"windows_image_reason,omitempty"`
}

// AnalysisWindowsImage describes a process, not an owner of the socket as a
// whole. It intentionally has no application key or policy target.
type AnalysisWindowsImage struct {
	Name       string `json:"name"`
	Executable string `json:"executable,omitempty"`
	Prefix     string `json:"prefix,omitempty"`
}

type AnalysisApplication struct {
	Name       string `json:"name,omitempty"`
	Key        string `json:"key"`
	Revision   string `json:"revision"`
	Executable string `json:"executable,omitempty"`
	Kind       string `json:"kind"`
	Prefix     string `json:"prefix,omitempty"`
	Source     string `json:"source"`
}

// Keep the same grouping as Activity, including the separate kernel lifecycle
// group for inode-zero TIME_WAIT. A single visible process has its own group.
func analysisUnidentified(row identity.ActivityRow) bool {
	return !analysisLifecycle(row) && row.RuntimeApplication == nil &&
		(row.DisplayApplication == nil || row.DisplayApplication.Key == "" || len(row.Owners) <= 1) &&
		len(row.Owners) != 1
}

func analysisLifecycle(row identity.ActivityRow) bool {
	return row.Socket.Protocol == "tcp" && row.Socket.State == 6 && row.Socket.Inode == 0 &&
		len(row.Owners) == 0 && row.OwnershipCategory == "no-userspace-inode" &&
		row.RuntimeApplication == nil && row.DisplayApplication == nil
}

func analysisHolders(s identity.ActivitySnapshot, row identity.ActivityRow, sample *identity.ConnectionSample) ([]AnalysisHolder, bool) {
	holders := make([]AnalysisHolder, 0, min(len(row.Owners), analysisHolderLimit))
	for _, id := range row.Owners[:min(len(row.Owners), analysisHolderLimit)] {
		if p, ok := s.Processes[id]; ok {
			holder := AnalysisHolder{PID: p.PID, ThreadGroup: p.ThreadGroup, Start: p.Start,
				UID: p.UID, Executable: boundedAnalysisPath(p.Executable)}
			if sample != nil {
				reason, checked := sample.WineHolderChecks[id]
				holder.WindowsImage, holder.WindowsImageReason = analysisWindowsImage(p, reason, checked)
			}
			holders = append(holders, holder)
		}
	}
	return holders, len(row.Owners) > analysisHolderLimit || row.OwnershipCategory == "holders-truncated"
}

func analysisWindowsImage(p identity.ActivityProcess, reason string, checked bool) (*AnalysisWindowsImage, string) {
	a := p.Application
	if a.Kind != "wine" && a.Kind != "wine-unresolved" {
		return nil, ""
	}
	if a.Prefix == "" {
		return nil, "A Wine prefix could not be verified for this process"
	}
	if a.Kind != "wine" || a.Runtime != p.Executable || a.Name == "" || a.Executable == "" ||
		a.Revision == "" || a.Key != identity.ApplicationKey(p.UID, a) {
		return nil, "No mapped Windows executable was corroborated for this Wine holder"
	}
	if !checked {
		return nil, "The Windows image and Wine prefix were not rechecked before collection finished"
	}
	if reason != "" {
		return nil, reason
	}
	image := &AnalysisWindowsImage{Name: boundedAnalysisPath(a.Name), Executable: boundedAnalysisPath(a.Executable),
		Prefix: boundedAnalysisPath(a.Prefix)}
	if image.Name == "" {
		return nil, "The verified Windows executable name exceeds the report limit"
	}
	return image, ""
}

func boundedAnalysisPath(path string) string {
	if len(path) > 512 {
		return ""
	}
	return path
}

func analysisApplication(s identity.ActivitySnapshot, row identity.ActivityRow) *AnalysisApplication {
	var app identity.Application
	var source string
	switch {
	case row.RuntimeApplication != nil:
		p, ok := runtimeActivityOwner(s, row)
		if !ok || row.RuntimeApplication.DisplaySource != "" || p.Application.Prefix == "" {
			return nil
		}
		app, source = p.Application, "wine-runtime-census"
	case row.OwnershipCategory == "visible-holder" && len(row.Owners) == 1:
		p, ok := s.Processes[row.Owners[0]]
		if !ok || !identity.LiveRuleable(p.Application) {
			return nil
		}
		app, source = p.Application, "descriptor-holder-census"
	default:
		return nil
	}
	return &AnalysisApplication{Name: boundedAnalysisPath(app.Name), Key: app.Key,
		Revision: boundedAnalysisPath(app.Revision), Executable: boundedAnalysisPath(app.Executable),
		Kind: app.Kind, Prefix: boundedAnalysisPath(app.Prefix), Source: source}
}

func (r *AnalyzedConnection) record(at time.Time, observation ConnectionObservation) {
	observation.At = at
	r.LastSampledAt = at
	if n := len(r.Observations); n != 0 {
		previous := r.Observations[n-1]
		previous.At = at
		if reflect.DeepEqual(previous, observation) {
			return
		}
		if n == analysisHistoryLimit {
			copy(r.Observations[1:], r.Observations[2:])
			r.Observations = r.Observations[:n-1]
			r.HistoryTruncated = true
		}
	}
	r.Observations = append(r.Observations, observation)
	r.recovered = r.recovered || (r.FromActivity && observation.Application != nil)
}

func analysisConnection(row identity.ActivityRow, at time.Time, fromActivity bool) *AnalyzedConnection {
	socket := row.Socket
	socket.Counters = nil
	return &AnalyzedConnection{Socket: socket, OriginalAt: at, FromActivity: fromActivity,
		OriginalCategory: row.OwnershipCategory, OriginalReason: row.Evidence,
		Observations: []ConnectionObservation{}}
}

func (e *Engine) analyzeConnections(query *ConnectionAnalysisQuery, uid uint32, admin bool, scope string) (*ConnectionAnalysis, string, string) {
	if e.Activity == nil || e.ConnectionSample == nil {
		return nil, "unavailable", "Connection analysis requires a running Activity observer"
	}
	if query == nil {
		query = &ConnectionAnalysisQuery{}
	}
	if query.WatchMS < 0 || query.WatchMS > maxAnalysisWatchMS {
		return nil, "invalid_request", "watch_ms must be between 0 and 10000"
	}
	if !e.connectionAnalysis.TryLock() {
		return nil, "analysis_busy", "Another connection analysis is running"
	}
	defer e.connectionAnalysis.Unlock()

	baseline := e.activityForPeer(e.Activity(), uid, admin)
	if baseline.Error != "" || baseline.Collected.IsZero() {
		return nil, "snapshot_unavailable", "No current Activity snapshot is available"
	}
	result := &ConnectionAnalysis{Scope: scope, BaselineCollected: baseline.Collected,
		BaselineComplete: baseline.Complete, Started: time.Now(), IntervalMS: analysisInterval.Milliseconds(),
		Samples: []AnalysisSample{}, Connections: []*AnalyzedConnection{}}
	known := make(map[string]bool)
	tracked := make(map[string]*AnalyzedConnection)
	for _, row := range baseline.Rows {
		if query.LocalPort != 0 && row.Socket.Local.Port() != query.LocalPort {
			continue
		}
		key := identity.ConnectionKey(row.Socket)
		if !analysisUnidentified(row) {
			if key != "" {
				known[key] = true
			}
			continue
		}
		result.BaselineUnidentified++
		if len(result.Connections) == analysisRowLimit {
			result.Truncated = true
			continue
		}
		record := analysisConnection(row, baseline.Collected, true)
		holders, truncated := analysisHolders(baseline, row, nil)
		record.record(baseline.Collected, ConnectionObservation{Category: row.OwnershipCategory,
			Reason: row.Evidence, Local: row.Socket.Local.String(), Remote: row.Socket.Remote.String(),
			Holders: holders, HoldersTruncated: truncated})
		result.Connections = append(result.Connections, record)
		if key != "" {
			tracked[key] = record
		} else {
			record.record(result.Started, ConnectionObservation{Category: "unverifiable-socket",
				Reason: "Socket has no usable cookie and namespace identity", Holders: []AnalysisHolder{}})
		}
	}

	end := result.Started.Add(time.Duration(query.WatchMS) * time.Millisecond)
	for {
		sample := e.ConnectionSample(query.LocalPort)
		s := e.activityForPeer(sample.Activity, uid, admin)
		result.CollectionMS += s.DurationMS
		result.Samples = append(result.Samples, AnalysisSample{
			Started: s.Started, Collected: s.Collected, DurationMS: s.DurationMS, Complete: s.Complete})
		seen := make(map[string]bool)
		for _, row := range s.Rows {
			key := identity.ConnectionKey(row.Socket)
			if key == "" || (query.LocalPort != 0 && row.Socket.Local.Port() != query.LocalPort) {
				continue
			}
			record := tracked[key]
			if record == nil {
				if query.WatchMS == 0 || known[key] || analysisLifecycle(row) {
					continue
				}
				if len(result.Connections) == analysisRowLimit {
					result.Truncated = true
					continue
				}
				record = analysisConnection(row, s.Collected, false)
				tracked[key] = record
				result.Connections = append(result.Connections, record)
			}
			seen[key] = true
			observation := ConnectionObservation{Category: "unconfirmed-socket",
				Reason: "Socket generation was not confirmed after holder inspection", Holders: []AnalysisHolder{}}
			if sample.Confirmed[key] {
				holders, truncated := analysisHolders(s, row, &sample)
				observation = ConnectionObservation{Category: row.OwnershipCategory, Reason: row.Evidence,
					Local: row.Socket.Local.String(), Remote: row.Socket.Remote.String(),
					Holders: holders, HoldersTruncated: truncated, Application: analysisApplication(s, row)}
			}
			record.record(s.Collected, observation)
		}
		for key, record := range tracked {
			if !seen[key] {
				record.record(s.Collected, ConnectionObservation{Category: "not-observed",
					Reason: "Socket generation was not observed in this caller's view", Holders: []AnalysisHolder{}})
			}
		}
		if delay := time.Until(end); delay <= analysisInterval {
			break
		}
		time.Sleep(analysisInterval)
	}

	budget := analysisConnectionBytes
	for i, record := range result.Connections {
		encoded, err := json.Marshal(record)
		if err != nil || len(encoded)+1 > budget {
			result.Connections = result.Connections[:i]
			result.Truncated = true
			break
		}
		budget -= len(encoded) + 1
		if record.recovered {
			result.Recovered++
		}
		if record.Observations[len(record.Observations)-1].Application != nil {
			result.LatestVerified++
		}
		result.Truncated = result.Truncated || record.HistoryTruncated
	}
	result.Finished = time.Now()
	return result, "", ""
}
