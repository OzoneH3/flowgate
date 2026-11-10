# On-demand daemon CPU profiling

The primary control API advertises `daemon-profile-v1` to its configured
administrator. It supports bounded Go CPU profiling without restarting a daemon
that already includes this implementation. Older installed binaries need a
separately approved guarded release before these operations exist. This feature
opens no HTTP listener and does not change firewall permissions, protection mode,
accounting, shaping or the fast path.

No sampling starts at daemon startup. An explicit `profile-start` request records
5–60 seconds (30 seconds by default). Only one CPU capture, including the legacy
root-armed diagnostic facility, can run in a process at a time. No environment
variable or system profiling setting is needed for this API.

## CLI

Run the matched `flowgate` binary as the administrator already authorized on the
primary control socket. The CLI does not invoke sudo or widen socket permissions.
The `--socket` flag is required; a companion or observer socket cannot profile.
Use a new, explicit output directory for each capture:

```sh
flowgate profile status --socket /run/flowgate-api/daemon.sock
flowgate profile capture --socket /run/flowgate-api/daemon.sock --seconds 30 --output /home/flowgate-user/Apps/flowgate/.workspace/profile-quiet
flowgate profile capture --socket /run/flowgate-api/daemon.sock --seconds 30 --output /home/flowgate-user/Apps/flowgate/.workspace/profile-playing
```

Start the second command when the ordinary workload of interest is happening.
The recorder generates no traffic or synthetic load. A quiet observation and a
busy observation should use the same build and relevant settings, with the actual
workload and any changes recorded separately.

For nonblocking control or recovery after a terminal interruption:

```sh
flowgate profile start --socket /run/flowgate-api/daemon.sock --seconds 30
flowgate profile status --socket /run/flowgate-api/daemon.sock
flowgate profile stop --socket /run/flowgate-api/daemon.sock --id CAPTURE_ID
flowgate profile fetch --socket /run/flowgate-api/daemon.sock --id CAPTURE_ID --output /home/flowgate-user/Apps/flowgate/.workspace/profile-recovered
```

`start` returns an exact capture ID. `stop` requires that ID and only cancels the
matching active capture. `fetch` only exports that exact completed ID; it never
substitutes the most recent capture. `capture` starts once, polls once per second,
and fetches its artifacts when it finishes. Its wait is bounded by the requested
duration plus 15 seconds. A Ctrl-C attempts one exact-ID stop; the daemon's own
time limit still applies if that request fails. A lost start response is never
automatically retried: inspect status first.

The CLI pins the daemon generation from `list` for every subsequent operation.
A restart, missing capture, expired retention or API failure stops the command
without a new start or cross-generation fetch. Output directories are created
with mode 0700 and must not exist. Artifact files are mode 0600, created
exclusively through the pinned directory FD, with no overwrite. A local output
failure leaves the daemon's retained capture available for a new `fetch` into a
new directory. Failed or canceled captures export available artifacts and return
an explicit nonzero/incomplete result.

## Data and limits

A successful capture provides:

- `cpu.pprof`: Go runtime CPU stack samples, capped at 8 MiB.
- `summary.json`: up to 2 MiB of process user/system CPU bookends, elapsed stage
  histograms, profiling counters and bounded evidence, plus cached daemon state
  before and after the capture. The capture also records PID, Go version,
  GOMAXPROCS and requested duration. The state includes the build, iterator status,
  activity, queue, accounting, shaping and fast-path diagnostics available to
  this daemon. Missing facilities stay missing; collection does not start them.

The daemon retains the last two completed captures and the active capture in
memory. Captures disappear on process exit or retention eviction. Artifact byte
limits do not describe total transient heap use during serialization. If an
artifact exceeds its limit, the capture is failed explicitly; a bounded failure
summary remains available. The daemon accepts no client filesystem path and
writes no profile file itself.

`profile-fetch` returns at most 256 KiB per chunk, with `offset`, total length
and SHA256. The CLI checks offsets, stable totals and hashes, the artifact limit,
and the complete checksum before writing each file. The only accepted artifact
names are `cpu.pprof` and `summary.json`.

Profiles can contain machine-wide process identity, executable paths, addresses
and stack names. They are administrator-only diagnostic artifacts; review them
before sharing. Packet payloads are not captured.

## Interpretation

Use the exact matching daemon binary when examining a profile:

```sh
go tool pprof -top /path/to/matched/flowgate /path/to/capture/cpu.pprof
go tool pprof -top -cum /path/to/matched/flowgate /path/to/capture/cpu.pprof
go tool pprof -tags /path/to/matched/flowgate /path/to/capture/cpu.pprof
```

The `flat` column is exclusive sampled cost. `cum` includes callees; inclusive
percentages overlap and must not be added. Caller stacks and available subsystem
labels help distinguish queued authorization, established-connection ownership
checks, Activity/Wine collection, accounting, shaping and API work. Unlabelled
runtime, allocation and garbage-collection work still needs stack analysis.
Labels identify executing goroutines, not an exact allocation of all concurrent
GC cost to its original caller. Activity labels are attached at an operation
entry during capture; an operation already in progress when capture starts may
be unlabelled initially. Its function stacks are still sampled.

For comparable CPU usage, subtract `usage_before` from `usage_after` and divide
CPU microseconds by `elapsed_seconds * 10000` to get percent of one core. User and
system CPU can be reported separately. CPU stack sampling includes brief
metadata/setup and profiler flush outside these bookends; the summary records
that envelope. Profiling itself has overhead, which must be reported rather than
assumed to be zero.

Elapsed stage histograms are wall time, including waits. They are not CPU cost,
and nested stages overlap. A holder census is not one process's FD-table scan;
`holder_proc_tables` and `holder_iterator_tables` count table attempts, while
stage call counts describe their respective operations. Use stacks and counter
rates together before concluding which callers duplicate work. Counts alone do
not establish that two calls inspected identical process generations or sockets.

This Go profile does **not** resolve kernel callee stacks and does not sample GUI,
controller or Wine-observer helper processes. Process system-CPU bookends expose
system-time totals, but cannot attribute that time to kernel functions. Those
processes and kernel work require a separate authorized external capture. The
built-in profiler does not adjust kernel profiling settings or enable such a
capture. It is an observation facility, not a full-system profiler or proof of
packet delivery.

## API contract

All operations require the primary administrative endpoint and the exact
`generation` obtained from `list`:

```json
{"version":1,"operation":"profile-start","generation":"GENERATION","duration_seconds":30}
{"version":1,"operation":"profile-status","generation":"GENERATION"}
{"version":1,"operation":"profile-stop","generation":"GENERATION","id":"CAPTURE_ID"}
{"version":1,"operation":"profile-fetch","generation":"GENERATION","id":"CAPTURE_ID","profile_artifact":"cpu.pprof","profile_offset":0}
```

`profile` contains `active` and `recent` capture status records: ID, state
(`requested`, `running`, `finished`, `canceled`, `failed`), error, start/end times,
requested duration and available artifacts. The fetch response contains
`profile_chunk:{data,offset,total,sha256}`, with binary data base64-encoded by
JSON. Permission, generation, availability and capture errors remain explicit;
clients must not retry mutations automatically.
