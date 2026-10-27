Isolated binding-capacity/latency fixture (experimental, not a host tool)

Read docs/UPLOAD-SHAPING-CAPACITY.txt for the measured outcome and limitations.
run.py requires the existing disposable netdevsim guest, private namespace,
/work/m1 helpers and daemon, and private /work/.workspace/m1 evidence directory.
It must never run against a physical host. No host activation is authorized.

sender.c is the existing native sender with explicit TRACE diagnostics added.
TRACE OFF does not query TCP_INFO. peer.py retains bounded per-phase timing
metadata; TRACE ON adds last-skb software timestamps. trace_controller.py accepts
source/destination paths and generates a private controller copy with bounded
nested stage tracing. Acceptance uses the unchanged production controller;
only the final diagnostic pair uses the generated copy.

The committed run.py/peer.py/sender.c are the exact ladder1 staged sources.
The trace generator reproduces the staged diagnostic controller exactly when
applied to the21684d9 production controller. No diagnostic build enters the
release/update path. Existing helper/daemon/BPF binaries are reused.

Resource/run envelope used: one TCG vCPU,2GiB guest; host user scope capped at
3GiB,150%CPU,64tasks,2000second VM timeout. No concurrent build/VM. Four phases
per32/64/128 level plus two diagnostics;45s bulk perphase,400lowrate records.
Each enabled phase waits for the actual binding count, not config acceptance.
Stage/export scripts and hashes are retained in .workspace/shaping-ladder.

Important: the disabled receiver was heavily delayed, so the relative latency
criterion is not a readiness test. Deny send failures in the finalfive phases
limit new128-enabled receiver evidence. VM_RESULT=0 means completion, not release
approval. Sender errors lack errno; do not classify their cause from this data.
